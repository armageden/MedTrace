import Resolver from '@forge/resolver';
import { ComplianceEngine } from './compliance-engine';
import { SeederService } from './seeder';
import {
  authorizeAndFilterLiveSuiteDetailed,
  redactBlastRadiusReport,
} from './seeder-identity';
import {
  LiveIngestionService,
  ConfluencePageUpdatedEvent,
  ConfluencePageUpdatedResult,
  JiraIssueUpdatedEvent,
  JiraIssueUpdatedResult,
} from './ingestion';
import { AuditLogService, MAX_AUDIT_LOG_PAGE_LIMIT } from './audit-log';
import { TeamworkGraphService } from './teamwork-graph';
import { rovoActionHandler } from './mcp-server';
import { workflowValidatorHandler } from './workflow-validator';
import { isForgeRuntime } from './runtime';
import { validateHttpsUrl } from './crypto-utils';
import {
  AuthorizationTarget,
  AuthorizedCaller,
  ForgeExtensionPayload,
  ForgeResolverContext,
  ForgeResolverRequest,
  assertAuthorizedOperator,
  assertAuthorizedReader,
  assertJiraOperatorPermissions,
  assertJiraSiteAdminPermissions,
  assertOperatorAuthorizedForTarget,
  filterAuditEntriesForCaller,
  filterLiveSuiteForCaller,
  verifyJiraIdentity,
} from './rbac';
import {
  WebtriggerHttpError,
  WebtriggerRequest,
  WebtriggerResponse,
  claimNonce,
  claimNonceDetailed,
  createInMemoryNonceStore,
  getNonceStore,
  mcpWebtriggerHandler,
  setNonceStore,
  verifyHmacSignature,
} from './webtrigger';
import {
  AuditLogEntry,
  ComplianceSummary,
  MedTraceResolverMap,
  PART11_ATTESTATION_PHRASE,
  VerificationTest,
} from './types';

export type {
  AuthorizationTarget,
  AuthorizedCaller,
  ForgeExtensionPayload,
  ForgeResolverContext,
  ForgeResolverRequest,
} from './rbac';
export {
  assertAuthorizedOperator,
  assertAuthorizedReader,
  assertOperatorAuthorizedForTarget,
} from './rbac';
export type { WebtriggerRequest, WebtriggerResponse } from './webtrigger';
export {
  WebtriggerHttpError,
  claimNonce,
  claimNonceDetailed,
  createInMemoryNonceStore,
  getNonceStore,
  mcpWebtriggerHandler,
  setNonceStore,
  verifyHmacSignature,
} from './webtrigger';

const ALLOWED_TEST_STATUSES: ReadonlySet<VerificationTest['status']> = new Set([
  'PASSED',
  'FAILED',
  'UNTESTED',
  'IN_PROGRESS',
]);

const resolver = new Resolver();

function defineTypedResolver<K extends keyof MedTraceResolverMap & string>(
  key: K,
  handler: (
    req: ForgeResolverRequest<MedTraceResolverMap[K]['payload']>
  ) => Promise<MedTraceResolverMap[K]['response']>
): void {
  resolver.define<MedTraceResolverMap[K]['payload'], MedTraceResolverMap[K]['response']>(
    key,
    async (req) => {
      const typedReq: ForgeResolverRequest<MedTraceResolverMap[K]['payload']> = {
        payload: req.payload,
        context: req.context,
      };
      return handler(typedReq);
    }
  );
}

// =========================================================================
// Custom UI Bridge Resolvers (Typed & RBAC-Protected)
// =========================================================================

defineTypedResolver('getComplianceSuite', async (req) => {
  const caller = await assertAuthorizedReader(req);
  const rawSuite = await SeederService.getActiveComplianceSuite({ projectKey: caller.projectKey });
  const skipReconcile = req.payload?.skipReconcile === true;
  const suite = skipReconcile
    ? rawSuite
    : await LiveIngestionService.reconcileConfluenceSpecs(rawSuite, {
        actorAccountId: caller.accountId,
        projectKey: caller.projectKey,
      });
  return filterLiveSuiteForCaller(caller, suite);
});

defineTypedResolver('seedDemoSuite', async (req) => {
  const caller = await assertAuthorizedOperator(req);
  const confirmOverwriteLive = req.payload?.confirmOverwriteLive === true;
  const existing = await SeederService.getSuiteWithVersion();
  const isInitializedLive =
    existing.summary.datasetMode === 'LIVE' && existing.summary.initialized;

  if (isInitializedLive) {
    if (!confirmOverwriteLive) {
      throw new Error(
        'Refusing to overwrite initialized LIVE compliance suite with DEMO data without explicit confirmOverwriteLive: true.'
      );
    }
    await assertJiraSiteAdminPermissions(caller.accountId);
  }

  const seeded = await SeederService.seedEnterpriseDemoSuite(caller.accountId, 'FORGE_USER_SESSION', {
    confirmOverwriteLive,
    authorizedSiteAdmin: isInitializedLive,
  });
  return {
    ...seeded,
    summary: await filterLiveSuiteForCaller(caller, seeded.summary),
  };
});

defineTypedResolver('syncLiveSuite', async (req) => {
  const rawProjectKey =
    typeof req.payload?.projectKey === 'string' && req.payload.projectKey.trim().length > 0
      ? req.payload.projectKey.trim()
      : undefined;
  const rawSpaceId =
    typeof req.payload?.spaceId === 'string' && req.payload.spaceId.trim().length > 0
      ? req.payload.spaceId.trim()
      : undefined;

  const caller = await assertAuthorizedOperator(req, {
    projectKey: rawProjectKey,
    spaceId: rawSpaceId,
  });
  if (isForgeRuntime() && caller.extensionType.startsWith('confluence:') && !rawProjectKey) {
    await verifyJiraIdentity(caller.accountId);
    await assertJiraOperatorPermissions(caller.projectKey);
  }

  const rawJql =
    typeof req.payload?.jql === 'string' && req.payload.jql.trim().length > 0
      ? req.payload.jql.trim()
      : undefined;

  if (rawJql && /\bproject\b\s*(=|!=|\bin\b|\bnot\s+in\b)/i.test(rawJql)) {
    throw new Error('Forbidden: Custom JQL cannot specify or override project scope.');
  }

  let scopedJql = rawJql;
  if (scopedJql && caller.projectKey) {
    const orderMatch = /\border\s+by\b/i.exec(scopedJql);
    const filterPart = (orderMatch ? scopedJql.slice(0, orderMatch.index) : scopedJql).trim();
    const orderPart = orderMatch ? scopedJql.slice(orderMatch.index).trim() : '';
    scopedJql = filterPart
      ? `project = "${caller.projectKey}" AND (${filterPart})${orderPart ? ` ${orderPart}` : ''}`
      : `project = "${caller.projectKey}"${orderPart ? ` ${orderPart}` : ''}`;
  }

  const pageToken =
    typeof req.payload?.pageToken === 'string' && req.payload.pageToken.trim().length > 0
      ? req.payload.pageToken.trim()
      : undefined;

  const syncResult = await LiveIngestionService.syncFromAtlassian(
    {
      projectKey: caller.projectKey,
      spaceId: rawSpaceId || caller.spaceId,
      jql: scopedJql,
      includeUntaggedIssues: req.payload?.includeUntaggedIssues === true,
      ...(typeof req.payload?.resumeFromCursor === 'boolean'
        ? { resumeFromCursor: req.payload.resumeFromCursor }
        : {}),
      ...(pageToken ? { pageToken } : {}),
      callerMode: 'USER',
    },
    caller.accountId
  );

  const filteredSummary = await filterLiveSuiteForCaller(caller, syncResult.summary);
  const filteredWarnings = Array.isArray(syncResult.warnings)
    ? syncResult.warnings.filter((w) => !/belonging to other Jira project/i.test(w))
    : [];
  return {
    ...syncResult,
    warnings: filteredWarnings,
    summary: filteredSummary,
  };
});

defineTypedResolver('remediateGap', async (req) => {
  const caller = await assertAuthorizedOperator(req);
  const hazardKey = typeof req.payload?.hazardKey === 'string' ? req.payload.hazardKey.trim() : '';
  if (!hazardKey) {
    throw new Error('Bad Request: hazardKey is required.');
  }
  await assertOperatorAuthorizedForTarget(req, { hazardKey });
  const updated = await SeederService.remediateClassCGap(hazardKey, caller.accountId, {
    simulate: req.payload?.simulate === true,
    attestationConfirmed: req.payload?.attestationConfirmed === true,
    meaning: typeof req.payload?.meaning === 'string' ? req.payload.meaning.trim() : undefined,
    authMethod: 'FORGE_USER_SESSION',
  });
  return filterLiveSuiteForCaller(caller, updated);
});

defineTypedResolver('recordTestResult', async (req) => {
  const caller = await assertAuthorizedOperator(req);
  const hazardKey =
    typeof req.payload?.hazardKey === 'string' && req.payload.hazardKey.trim().length > 0
      ? req.payload.hazardKey.trim()
      : undefined;
  const testKey =
    typeof req.payload?.testKey === 'string' && req.payload.testKey.trim().length > 0
      ? req.payload.testKey.trim()
      : undefined;
  const linkId =
    typeof req.payload?.linkId === 'string' && req.payload.linkId.trim().length > 0
      ? req.payload.linkId.trim()
      : undefined;

  if (!hazardKey && !testKey && !linkId) {
    throw new Error('Bad Request: hazardKey, testKey, or linkId is required.');
  }

  const rawStatus = req.payload?.status;
  if (typeof rawStatus !== 'string' || !ALLOWED_TEST_STATUSES.has(rawStatus as VerificationTest['status'])) {
    throw new Error('Bad Request: status must be one of PASSED, FAILED, UNTESTED, or IN_PROGRESS.');
  }

  let normalizedEvidenceUrl: string | undefined;
  if (req.payload?.evidenceUrl !== undefined) {
    if (typeof req.payload.evidenceUrl !== 'string') {
      throw new Error('Bad Request: evidenceUrl must be a string.');
    }
    const trimmedUrl = req.payload.evidenceUrl.trim();
    normalizedEvidenceUrl = trimmedUrl === '' ? '' : validateHttpsUrl(trimmedUrl);
  }

  await assertOperatorAuthorizedForTarget(req, {
    hazardKey,
    testKey: testKey ?? '',
    linkId,
  });

  const updated = await SeederService.recordTestResult({
    hazardKey,
    testKey,
    linkId,
    status: rawStatus as VerificationTest['status'],
    evidenceUrl: normalizedEvidenceUrl,
    executionDate:
      typeof req.payload?.executionDate === 'string' ? req.payload.executionDate : undefined,
    notes: typeof req.payload?.notes === 'string' ? req.payload.notes : undefined,
    actorAccountId: caller.accountId,
    authMethod: 'FORGE_USER_SESSION',
  });
  return filterLiveSuiteForCaller(caller, updated);
});

defineTypedResolver('signOffPart11', async (req) => {
  const caller = await assertAuthorizedOperator(req);
  const hazardKey = typeof req.payload?.hazardKey === 'string' ? req.payload.hazardKey.trim() : '';
  if (!hazardKey) {
    throw new Error('Bad Request: hazardKey is required.');
  }

  const specId =
    typeof req.payload?.specId === 'string' && req.payload.specId.trim().length > 0
      ? req.payload.specId.trim()
      : undefined;
  const linkId =
    typeof req.payload?.linkId === 'string' && req.payload.linkId.trim().length > 0
      ? req.payload.linkId.trim()
      : undefined;

  const meaning = typeof req.payload?.meaning === 'string' ? req.payload.meaning.trim() : '';
  const attestationPhrase =
    typeof req.payload?.attestationPhrase === 'string' ? req.payload.attestationPhrase.trim() : '';
  const attestationConfirmed = req.payload?.attestationConfirmed === true;
  const attestationChecked = req.payload?.attestationChecked === true;

  if (!attestationConfirmed || !attestationChecked) {
    throw new Error(
      'Part 11 attestation: Both attestationConfirmed and attestationChecked confirmation flags must be true.'
    );
  }
  if (attestationPhrase !== PART11_ATTESTATION_PHRASE) {
    throw new Error(
      `21 CFR Part 11 Violation: Exact attestationPhrase "${PART11_ATTESTATION_PHRASE}" is required.`
    );
  }
  if (meaning.length < 5) {
    throw new Error(
      '21 CFR Part 11 §11.50 Violation: A non-empty signature meaning (>= 5 chars) is required.'
    );
  }

  await assertOperatorAuthorizedForTarget(req, { hazardKey, specId, linkId });

  const updated = await SeederService.signOffPart11({
    hazardKey,
    specId,
    linkId,
    attestation: {
      meaning,
      attestationPhrase,
      attestationConfirmed: true,
      attestationChecked: true,
    },
    actorAccountId: caller.accountId,
    authMethod: 'PART11_ATTESTATION',
    extensionType: caller.extensionType,
    projectKey: caller.projectKey,
    spaceKey: caller.spaceKey,
  });
  return filterLiveSuiteForCaller(caller, updated);
});

defineTypedResolver('queryGraphContext', async (req) => {
  const rawPayloadIssue =
    typeof req.payload?.issueKey === 'string' && req.payload.issueKey.trim().length > 0
      ? req.payload.issueKey.trim()
      : '';
  const rawContextIssue =
    typeof req.context?.extension?.issue?.key === 'string' &&
    req.context.extension.issue.key.trim().length > 0
      ? req.context.extension.issue.key.trim()
      : '';
  const issueKey = (rawPayloadIssue || rawContextIssue).toUpperCase() || undefined;

  await assertAuthorizedReader(req, issueKey ? { issueKey } : undefined);
  if (!issueKey) {
    return null;
  }

  return TeamworkGraphService.queryIssueGraphContext(issueKey, {
    callerMode: 'USER',
    includeSpecOwners: true,
  });
});

defineTypedResolver('bindIssueToHazard', async (req) => {
  const rawIssueKey =
    typeof req.payload?.issueKey === 'string' && req.payload.issueKey.trim().length > 0
      ? req.payload.issueKey.trim().toUpperCase()
      : undefined;
  const caller = await assertAuthorizedOperator(
    req,
    rawIssueKey ? { issueKey: rawIssueKey } : undefined
  );

  const hazardKey = typeof req.payload?.hazardKey === 'string' ? req.payload.hazardKey.trim() : '';
  if (!hazardKey || !rawIssueKey) {
    throw new Error('Bad Request: Both hazardKey and issueKey are required.');
  }

  const linkId =
    typeof req.payload?.linkId === 'string' && req.payload.linkId.trim().length > 0
      ? req.payload.linkId.trim()
      : undefined;

  await assertOperatorAuthorizedForTarget(req, { hazardKey, linkId });

  const rawSummary = await SeederService.bindIssueToHazard(
    hazardKey,
    rawIssueKey,
    caller.accountId,
    'FORGE_USER_SESSION',
    {
      callerMode: 'USER',
      linkId,
    }
  );
  const summary = await filterLiveSuiteForCaller(caller, rawSummary);

  return {
    success: true,
    summary,
  };
});

defineTypedResolver('createReverificationTask', async (req) => {
  const rawIssueKey =
    typeof req.payload?.issueKey === 'string' && req.payload.issueKey.trim().length > 0
      ? req.payload.issueKey.trim().toUpperCase()
      : undefined;
  const caller = await assertAuthorizedOperator(
    req,
    rawIssueKey ? { issueKey: rawIssueKey } : undefined
  );

  const hazardKey =
    typeof req.payload?.hazardKey === 'string' && req.payload.hazardKey.trim().length > 0
      ? req.payload.hazardKey.trim()
      : undefined;
  const linkId =
    typeof req.payload?.linkId === 'string' && req.payload.linkId.trim().length > 0
      ? req.payload.linkId.trim()
      : undefined;

  if (!hazardKey && !linkId && !rawIssueKey) {
    throw new Error('Bad Request: hazardKey, linkId, or issueKey is required.');
  }

  await assertOperatorAuthorizedForTarget(req, {
    hazardKey,
    linkId,
    workKey: rawIssueKey,
  });

  const result = await SeederService.createReverificationTask({
    hazardKey,
    linkId,
    issueKey: rawIssueKey,
    summary: typeof req.payload?.summary === 'string' ? req.payload.summary : undefined,
    reason: typeof req.payload?.reason === 'string' ? req.payload.reason : undefined,
    actorAccountId: caller.accountId,
    callerMode: 'USER',
    authMethod: 'FORGE_USER_SESSION',
  });

  return {
    ...result,
    summary: await filterLiveSuiteForCaller(caller, result.summary),
  };
});

defineTypedResolver('simulateTransition', async (req) => {
  const isGlobalScope = req.payload?.scope === 'global';
  const rawPayloadIssue =
    typeof req.payload?.issueKey === 'string' && req.payload.issueKey.trim().length > 0
      ? req.payload.issueKey.trim()
      : '';
  const rawContextIssue = isGlobalScope
    ? ''
    : typeof req.context?.extension?.issue?.key === 'string' &&
        req.context.extension.issue.key.trim().length > 0
      ? req.context.extension.issue.key.trim()
      : '';
  const issueKey = isGlobalScope
    ? undefined
    : (rawPayloadIssue || rawContextIssue).toUpperCase() || undefined;

  const caller = await assertAuthorizedReader(req, issueKey ? { issueKey } : undefined);

  if (!issueKey) {
    let rawSuite = await SeederService.getActiveComplianceSuite({ projectKey: caller.projectKey });
    if (isForgeRuntime() && rawSuite.datasetMode === 'LIVE' && rawSuite.initialized !== false) {
      rawSuite = await LiveIngestionService.reconcileConfluenceSpecs(rawSuite, {
        actorAccountId: caller.accountId,
        projectKey: caller.projectKey,
        allowAppFallback: true,
      });
    }
    const scopedSuite = await filterLiveSuiteForCaller(caller, rawSuite);
    if (scopedSuite.datasetMode === 'LIVE' || caller.projectKey) {
      const outcome = ComplianceEngine.evaluateIssueReleaseGate(undefined, scopedSuite);
      return {
        ...outcome,
        evaluatedIssueKey: undefined,
      };
    }
  }

  const result = await workflowValidatorHandler(
    issueKey
      ? { issue: { key: issueKey }, transition: { name: 'Done' } }
      : { transition: { name: 'Done' } }
  );

  return {
    ...result,
    evaluatedIssueKey: issueKey,
  };
});

defineTypedResolver('analyzeBlastRadius', async (req) => {
  const caller = await assertAuthorizedReader(req);
  const triggerKey = typeof req.payload?.triggerKey === 'string' ? req.payload.triggerKey.trim() : '';
  if (!triggerKey) {
    throw new Error('Bad Request: triggerKey is required.');
  }
  const initialSuite = await SeederService.getActiveComplianceSuite({ projectKey: caller.projectKey });
  const rawSuite = await LiveIngestionService.reconcileConfluenceSpecs(initialSuite, {
    actorAccountId: caller.accountId,
    projectKey: caller.projectKey,
  });
  if (
    rawSuite.datasetMode !== 'LIVE' ||
    rawSuite.initialized === false ||
    rawSuite.traceLinks.length === 0
  ) {
    return ComplianceEngine.computeBlastRadius(triggerKey, rawSuite);
  }
  const runtimeActive = isForgeRuntime();
  if (runtimeActive && caller.extensionType.toLowerCase().startsWith('confluence:')) {
    await verifyJiraIdentity(caller.accountId);
  }
  const { unredactedSuite, restrictedPageIds } = await authorizeAndFilterLiveSuiteDetailed(rawSuite, {
    extensionType: caller.extensionType,
    projectKey: caller.projectKey,
    checkConfluencePages: true,
  });
  const report = ComplianceEngine.computeBlastRadius(triggerKey, unredactedSuite);
  return redactBlastRadiusReport(report, unredactedSuite.traceLinks, restrictedPageIds);
});

defineTypedResolver('getAuditLog', async (req) => {
  const caller = await assertAuthorizedReader(req);
  const rawLimit =
    typeof req.payload?.limit === 'number' && Number.isFinite(req.payload.limit)
      ? Math.floor(req.payload.limit)
      : 50;
  const limit = Math.max(1, Math.min(MAX_AUDIT_LOG_PAGE_LIMIT, rawLimit));
  let cursorBeforeSeq =
    typeof req.payload?.beforeSeq === 'number' &&
    Number.isFinite(req.payload.beforeSeq) &&
    req.payload.beforeSeq > 0
      ? Math.floor(req.payload.beforeSeq)
      : undefined;

  const rawSuite = await SeederService.getActiveComplianceSuite();
  const collectedNewestFirst: AuditLogEntry[] = [];
  // shortcut: scans up to 25 pages (5,000 entries) / 8s to preserve the AuditLogEntry[] contract; switch to a cursor envelope if ledgers outgrow this.
  const MAX_SCAN_PAGES = 25;
  const scanDeadline = Date.now() + 8_000;

  for (let page = 0; page < MAX_SCAN_PAGES; page++) {
    if (page > 0 && Date.now() >= scanDeadline) break;
    const batch = await AuditLogService.getAuditLog(MAX_AUDIT_LOG_PAGE_LIMIT, cursorBeforeSeq);
    if (batch.length === 0) break;

    const filteredBatch = await filterAuditEntriesForCaller(caller, batch, rawSuite);
    for (let i = filteredBatch.length - 1; i >= 0; i--) {
      collectedNewestFirst.push(filteredBatch[i]);
      if (collectedNewestFirst.length >= limit) break;
    }

    const oldestSeq = batch[0].seq;
    if (collectedNewestFirst.length >= limit || oldestSeq <= 1 || batch.length < MAX_AUDIT_LOG_PAGE_LIMIT) {
      break;
    }
    cursorBeforeSeq = oldestSeq;
  }

  return collectedNewestFirst.reverse();
});

defineTypedResolver('verifyAuditChain', async (req) => {
  await assertAuthorizedReader(req);
  const payload = req.payload;
  const options: { fromSeq?: number; maxEntries?: number; expectedPrevHash?: string } = {};
  if (typeof payload?.fromSeq === 'number' && Number.isFinite(payload.fromSeq) && payload.fromSeq >= 1) {
    options.fromSeq = Math.floor(payload.fromSeq);
  }
  if (
    typeof payload?.maxEntries === 'number' &&
    Number.isFinite(payload.maxEntries) &&
    payload.maxEntries >= 1
  ) {
    options.maxEntries = Math.min(500, Math.floor(payload.maxEntries));
  } else {
    const envMax = Number(process.env.MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES);
    options.maxEntries =
      Number.isFinite(envMax) && envMax >= 1 ? Math.min(500, Math.floor(envMax)) : 200;
  }
  if (typeof payload?.expectedPrevHash === 'string' && payload.expectedPrevHash.trim() !== '') {
    options.expectedPrevHash = payload.expectedPrevHash.trim();
  }
  return AuditLogService.verifyAuditChain(options);
});

export const resolverHandler = resolver.getDefinitions();

// =========================================================================
// Confluence Event Trigger (Live Ingestion Sync)
// =========================================================================

/**
 * Handles Confluence `avi:confluence:updated:page` product events to incrementally resync affected SRS requirements.
 */
export async function confluencePageUpdatedTrigger(
  event: ConfluencePageUpdatedEvent
): Promise<ConfluencePageUpdatedResult> {
  return LiveIngestionService.handleConfluencePageUpdated(event);
}

/**
 * Handles Jira `avi:jira:updated:issue`, `avi:jira:created:issuelink`, and `avi:jira:deleted:issuelink`
 * product events to automatically refresh affected LIVE trace links.
 */
export async function jiraIssueUpdatedTrigger(
  event: JiraIssueUpdatedEvent
): Promise<JiraIssueUpdatedResult> {
  return LiveIngestionService.handleJiraIssueUpdated(event);
}

export { rovoActionHandler, workflowValidatorHandler };
