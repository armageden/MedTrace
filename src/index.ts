import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';
import crypto from 'crypto';
import { ComplianceEngine } from './compliance-engine';
import { SeederService } from './seeder';
import {
  LiveIngestionService,
  ConfluencePageUpdatedEvent,
  ConfluencePageUpdatedResult,
} from './ingestion';
import { AuditLogService } from './audit-log';
import { TeamworkGraphService } from './teamwork-graph';
import { McpToolService, rovoActionHandler } from './mcp-server';
import { workflowValidatorHandler } from './workflow-validator';
import { isForgeRuntime } from './runtime';
import { validateHttpsUrl } from './crypto-utils';
import {
  MAX_TIMESTAMP_AGE_MS,
  MAX_FUTURE_SKEW_MS,
  NONCE_TTL_MS,
  NonceStore,
  getNonceStore,
  setNonceStore,
  createInMemoryNonceStore,
  NonceClaimResult,
} from './nonce-store';
import {
  MedTraceResolverMap,
  PART11_ATTESTATION_PHRASE,
  VerificationTest,
} from './types';

export interface ForgeExtensionPayload {
  type?: string;
  project?: {
    key?: string;
    id?: string;
  };
  issue?: {
    key?: string;
    id?: string;
  };
  space?: {
    key?: string;
    id?: string;
  };
  content?: {
    id?: string;
    type?: string;
  };
}

export interface ForgeResolverContext {
  accountId?: string;
  cloudId?: string;
  installContext?: string;
  principal?: {
    accountId?: string;
  };
  extension?: ForgeExtensionPayload;
  permissions?: string[];
}

export interface ForgeResolverRequest<TPayload = unknown> {
  payload?: TPayload;
  context?: ForgeResolverContext;
}

export interface AuthorizedCaller {
  accountId: string;
  extensionType: string;
  projectKey?: string;
  spaceKey?: string;
  spaceId?: string;
  contentId?: string;
}

export interface AuthorizationTarget {
  projectKey?: string;
  issueKey?: string;
  spaceId?: string;
  contentId?: string;
}

export interface WebtriggerRequest {
  method?: string;
  body?: unknown;
  path?: string;
  headers?: Record<string, string | string[] | undefined>;
  queryParameters?: Record<string, string | string[] | undefined>;
  query?: Record<string, string | undefined>;
}

export interface WebtriggerResponse {
  statusCode: number;
  headers: { [key: string]: string[] };
  body: string;
}

export class WebtriggerHttpError extends Error {
  public readonly statusCode: number;
  public readonly publicMessage: string;

  constructor(statusCode: number, publicMessage: string) {
    super(publicMessage);
    this.name = 'WebtriggerHttpError';
    this.statusCode = statusCode;
    this.publicMessage = publicMessage;
  }
}

const PROJECT_KEY_RE = /^[A-Z][A-Z0-9_]{0,20}$/;
const ISSUE_KEY_RE = /^[A-Z][A-Z0-9_]{0,20}-\d+$/;
const CONFLUENCE_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const CONFLUENCE_GLOBAL_SPACES_PROBE_LIMIT = 10;

const ALLOWED_TEST_STATUSES: ReadonlySet<VerificationTest['status']> = new Set([
  'PASSED',
  'FAILED',
  'UNTESTED',
  'IN_PROGRESS',
]);

const ALLOWED_WEBTRIGGER_POST_ACTIONS: ReadonlySet<string> = new Set([
  'status',
  'seed',
  'remediate',
  'verify',
  'verify-release-gate',
  'validate',
  'simulate_transition',
]);

const resolver = new Resolver();

function extractCallerAccountId(req?: ForgeResolverRequest<unknown>): string | undefined {
  const direct = req?.context?.accountId;
  if (typeof direct === 'string' && direct.trim().length > 0) {
    return direct.trim();
  }
  const principal = req?.context?.principal?.accountId;
  if (typeof principal === 'string' && principal.trim().length > 0) {
    return principal.trim();
  }
  return undefined;
}

interface NormalizedAuthScope {
  extensionType: string;
  isConfluence: boolean;
  effectiveProjectKey?: string;
  effectiveIssueKey?: string;
  effectiveSpaceId?: string;
  effectiveContentId?: string;
  extSpaceKey?: string;
  hasExplicitJiraTarget: boolean;
  hasExplicitConfluenceTarget: boolean;
}

function normalizeAndValidateScope(
  ext: ForgeExtensionPayload | undefined,
  target?: AuthorizationTarget
): NormalizedAuthScope {
  const extensionType = typeof ext?.type === 'string' ? ext.type.trim().toLowerCase() : '';
  const isConfluence = extensionType.startsWith('confluence');

  const extProjectKey =
    typeof ext?.project?.key === 'string' && ext.project.key.trim().length > 0
      ? ext.project.key.trim().toUpperCase()
      : undefined;
  const rawTargetProjectKey =
    typeof target?.projectKey === 'string' && target.projectKey.trim().length > 0
      ? target.projectKey.trim().toUpperCase()
      : undefined;

  if (rawTargetProjectKey && !PROJECT_KEY_RE.test(rawTargetProjectKey)) {
    throw new Error('Bad Request: Invalid Jira projectKey format.');
  }

  const rawTargetIssueKey =
    typeof target?.issueKey === 'string' && target.issueKey.trim().length > 0
      ? target.issueKey.trim().toUpperCase()
      : undefined;

  if (rawTargetIssueKey && !ISSUE_KEY_RE.test(rawTargetIssueKey)) {
    throw new Error('Bad Request: Invalid Jira issueKey format.');
  }

  if (extProjectKey && rawTargetProjectKey && rawTargetProjectKey !== extProjectKey) {
    throw new Error(
      `Forbidden: Cross-project override is not permitted (${rawTargetProjectKey} !== ${extProjectKey}).`
    );
  }

  if (extProjectKey && rawTargetIssueKey) {
    const issueProject = rawTargetIssueKey.split('-')[0];
    if (issueProject !== extProjectKey) {
      throw new Error(
        `Forbidden: Cross-project issue access is not permitted (${rawTargetIssueKey} outside project ${extProjectKey}).`
      );
    }
  }

  if (rawTargetProjectKey && rawTargetIssueKey) {
    const issueProject = rawTargetIssueKey.split('-')[0];
    if (issueProject !== rawTargetProjectKey) {
      throw new Error(
        `Forbidden: Target issue ${rawTargetIssueKey} does not belong to project ${rawTargetProjectKey}.`
      );
    }
  }

  const rawTargetSpaceId =
    typeof target?.spaceId === 'string' && target.spaceId.trim().length > 0
      ? target.spaceId.trim()
      : undefined;
  if (rawTargetSpaceId && !CONFLUENCE_ID_RE.test(rawTargetSpaceId)) {
    throw new Error('Bad Request: Invalid Confluence spaceId format.');
  }

  const rawTargetContentId =
    typeof target?.contentId === 'string' && target.contentId.trim().length > 0
      ? target.contentId.trim()
      : undefined;
  if (rawTargetContentId && !CONFLUENCE_ID_RE.test(rawTargetContentId)) {
    throw new Error('Bad Request: Invalid Confluence contentId format.');
  }

  const extSpaceId =
    typeof ext?.space?.id === 'string' && ext.space.id.trim().length > 0
      ? ext.space.id.trim()
      : undefined;
  const extContentId =
    typeof ext?.content?.id === 'string' && ext.content.id.trim().length > 0
      ? ext.content.id.trim()
      : undefined;
  const extSpaceKey =
    typeof ext?.space?.key === 'string' && ext.space.key.trim().length > 0
      ? ext.space.key.trim()
      : undefined;

  return {
    extensionType: ext?.type || 'jira:globalPage',
    isConfluence,
    effectiveProjectKey: rawTargetProjectKey || extProjectKey,
    effectiveIssueKey: rawTargetIssueKey,
    effectiveSpaceId: rawTargetSpaceId || extSpaceId,
    effectiveContentId: rawTargetContentId || extContentId,
    extSpaceKey,
    hasExplicitJiraTarget: Boolean(rawTargetProjectKey || rawTargetIssueKey),
    hasExplicitConfluenceTarget: Boolean(rawTargetSpaceId || rawTargetContentId),
  };
}

interface JiraPermissionEntry {
  havePermission?: boolean;
}

interface JiraPermissionsResponse {
  permissions?: Record<string, JiraPermissionEntry | undefined>;
}

function isHttpOk(res: { ok?: boolean; status: number }): boolean {
  return typeof res.ok === 'boolean' ? res.ok : res.status >= 200 && res.status < 300;
}

async function verifyJiraIdentity(expectedAccountId: string): Promise<void> {
  const res = await api.asUser().requestJira(route`/rest/api/3/myself`);
  if (!isHttpOk(res)) {
    throw new Error(`Forbidden: Jira user session validation failed (HTTP ${res.status}).`);
  }
  const myself = (await res.json().catch(() => ({}))) as {
    accountId?: unknown;
    active?: unknown;
  };
  if (myself.active === false) {
    throw new Error('Forbidden: Jira user account is inactive.');
  }
  if (
    typeof myself.accountId === 'string' &&
    myself.accountId.trim().length > 0 &&
    myself.accountId.trim() !== expectedAccountId
  ) {
    throw new Error('Forbidden: Authenticated Jira session account mismatch.');
  }
}

async function assertJiraReaderPermissions(projectKey?: string, issueKey?: string): Promise<void> {
  const permRoute = issueKey
    ? route`/rest/api/3/mypermissions?issueKey=${issueKey}&permissions=BROWSE_PROJECTS`
    : projectKey
    ? route`/rest/api/3/mypermissions?projectKey=${projectKey}&permissions=BROWSE_PROJECTS`
    : route`/rest/api/3/mypermissions?permissions=BROWSE_PROJECTS`;

  const res = await api.asUser().requestJira(permRoute);
  if (!isHttpOk(res)) {
    throw new Error(`Forbidden: Jira user lacks permission (${res.status}).`);
  }
  const data = (await res.json().catch(() => ({}))) as JiraPermissionsResponse;
  const browsePerm = data.permissions?.BROWSE_PROJECTS;
  if (browsePerm !== undefined) {
    if (browsePerm.havePermission !== true) {
      throw new Error('Forbidden: Requires Jira BROWSE_PROJECTS permission.');
    }
    return;
  }
  // Compatibility fallback when a mock only populates operator permission keys
  const hasEditOrAdmin =
    data.permissions?.EDIT_ISSUES?.havePermission === true ||
    data.permissions?.ADMINISTER_PROJECTS?.havePermission === true;
  if (!hasEditOrAdmin) {
    throw new Error('Forbidden: Requires Jira BROWSE_PROJECTS permission.');
  }
}

async function assertJiraOperatorPermissions(projectKey?: string, issueKey?: string): Promise<void> {
  const permRoute = issueKey
    ? route`/rest/api/3/mypermissions?issueKey=${issueKey}&permissions=BROWSE_PROJECTS,EDIT_ISSUES,ADMINISTER_PROJECTS`
    : projectKey
    ? route`/rest/api/3/mypermissions?projectKey=${projectKey}&permissions=BROWSE_PROJECTS,EDIT_ISSUES,ADMINISTER_PROJECTS`
    : route`/rest/api/3/mypermissions?permissions=EDIT_ISSUES,ADMINISTER_PROJECTS`;

  const res = await api.asUser().requestJira(permRoute);
  if (!isHttpOk(res)) {
    throw new Error(`Forbidden: Jira user lacks permission (${res.status}).`);
  }
  const data = (await res.json().catch(() => ({}))) as JiraPermissionsResponse;
  const browsePerm = data.permissions?.BROWSE_PROJECTS;
  if (browsePerm !== undefined && browsePerm.havePermission === false) {
    throw new Error('Forbidden: Requires Jira BROWSE_PROJECTS permission.');
  }
  const canEdit = data.permissions?.EDIT_ISSUES?.havePermission === true;
  const canAdmin = data.permissions?.ADMINISTER_PROJECTS?.havePermission === true;
  if (!canEdit && !canAdmin) {
    throw new Error('Forbidden: Requires Jira EDIT_ISSUES or ADMINISTER_PROJECTS permission.');
  }
}

interface ConfluenceOperation {
  operation?: unknown;
  targetType?: unknown;
}

interface ConfluenceSpaceSummary {
  id?: unknown;
  key?: unknown;
  type?: unknown;
}

function hasConfluencePageWriteOps(operations: ConfluenceOperation[]): boolean {
  return operations.some((op) => {
    const opName = typeof op.operation === 'string' ? op.operation.trim().toLowerCase() : '';
    const targetType = typeof op.targetType === 'string' ? op.targetType.trim().toLowerCase() : '';
    return (
      targetType === 'page' &&
      (opName === 'update' || opName === 'delete' || opName === 'administer')
    );
  });
}

function hasConfluenceSpaceWriteOps(operations: ConfluenceOperation[]): boolean {
  return operations.some((op) => {
    const opName = typeof op.operation === 'string' ? op.operation.trim().toLowerCase() : '';
    const targetType = typeof op.targetType === 'string' ? op.targetType.trim().toLowerCase() : '';
    if (opName === 'administer' && (targetType === 'space' || targetType === 'page' || targetType === '')) {
      return true;
    }
    return (
      (opName === 'create' || opName === 'update' || opName === 'delete') &&
      (targetType === 'page' || targetType === 'space')
    );
  });
}

async function verifyConfluenceIdentity(expectedAccountId: string): Promise<void> {
  const userRes = await api.asUser().requestConfluence(route`/wiki/rest/api/user/current`);
  if (!isHttpOk(userRes)) {
    throw new Error('Forbidden: Confluence user session lacks access.');
  }
  const userData = (await userRes.json().catch(() => ({}))) as {
    accountId?: unknown;
    type?: unknown;
  };
  if (
    userData.type === 'anonymous' ||
    typeof userData.accountId !== 'string' ||
    userData.accountId.trim() !== expectedAccountId
  ) {
    throw new Error('Forbidden: Authenticated Confluence user identity mismatch.');
  }
}

async function assertConfluenceReaderPermissions(spaceId?: string, contentId?: string): Promise<void> {
  if (contentId) {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/pages/${contentId}`);
    if (!isHttpOk(res)) {
      throw new Error(`Forbidden: Confluence user lacks read access to page ${contentId}.`);
    }
    return;
  }
  if (spaceId) {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces/${spaceId}`);
    if (!isHttpOk(res)) {
      throw new Error(`Forbidden: Confluence user lacks read access to space ${spaceId}.`);
    }
    return;
  }
  const res = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces?limit=1`);
  if (!isHttpOk(res)) {
    throw new Error('Forbidden: Confluence user session lacks access.');
  }
}

async function assertConfluenceOperatorPermissions(spaceId?: string, contentId?: string): Promise<void> {
  if (contentId) {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/pages/${contentId}/operations`);
    if (!isHttpOk(res)) {
      throw new Error(`Forbidden: Confluence user lacks edit access to page ${contentId}.`);
    }
    const data = (await res.json().catch(() => ({}))) as { operations?: unknown };
    const ops = Array.isArray(data.operations) ? (data.operations as ConfluenceOperation[]) : [];
    if (!hasConfluencePageWriteOps(ops)) {
      throw new Error('Forbidden: Requires Confluence page update or administer permission.');
    }
    return;
  }

  if (spaceId) {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces/${spaceId}/operations`);
    if (!isHttpOk(res)) {
      throw new Error(`Forbidden: Confluence user lacks operator access to space ${spaceId}.`);
    }
    const data = (await res.json().catch(() => ({}))) as { operations?: unknown };
    const ops = Array.isArray(data.operations) ? (data.operations as ConfluenceOperation[]) : [];
    if (!hasConfluenceSpaceWriteOps(ops)) {
      throw new Error('Forbidden: Requires Confluence space create/update/administer permission.');
    }
    return;
  }

  const spacesRes = await api
    .asUser()
    .requestConfluence(route`/wiki/api/v2/spaces?type=global&limit=25`);
  if (!isHttpOk(spacesRes)) {
    throw new Error('Forbidden: Confluence user session lacks access.');
  }
  const spacesData = (await spacesRes.json().catch(() => ({}))) as { results?: unknown };
  const globalSpaces = (Array.isArray(spacesData.results) ? (spacesData.results as ConfluenceSpaceSummary[]) : []).filter(
    (s) => {
      if (typeof s.id !== 'string' || s.id.trim().length === 0) return false;
      const spaceType = typeof s.type === 'string' ? s.type.trim().toLowerCase() : '';
      return spaceType === '' || spaceType === 'global';
    }
  );

  for (const space of globalSpaces.slice(0, CONFLUENCE_GLOBAL_SPACES_PROBE_LIMIT)) {
    const sid = String(space.id).trim();
    const opRes = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces/${sid}/operations`);
    if (!isHttpOk(opRes)) continue;
    const opData = (await opRes.json().catch(() => ({}))) as { operations?: unknown };
    const ops = Array.isArray(opData.operations) ? (opData.operations as ConfluenceOperation[]) : [];
    if (hasConfluenceSpaceWriteOps(ops)) {
      return;
    }
  }

  throw new Error(
    'Forbidden: Confluence operator requires create, update, or administer permission in at least one global space.'
  );
}

/**
 * Verifies authenticated Atlassian caller identity and read permissions (`BROWSE_PROJECTS` / Confluence space/page read),
 * enforcing cross-project confused-deputy checks before executing any read resolver.
 */
export async function assertAuthorizedReader(
  req?: ForgeResolverRequest<unknown>,
  target?: AuthorizationTarget
): Promise<AuthorizedCaller> {
  const accountId = extractCallerAccountId(req);
  if (!accountId) {
    throw new Error('Unauthorized: Authenticated Atlassian accountId is required in resolver context.');
  }

  const scope = normalizeAndValidateScope(req?.context?.extension, target);

  if (isForgeRuntime()) {
    const checkConfluence = scope.isConfluence || scope.hasExplicitConfluenceTarget;
    const checkJira = !scope.isConfluence || scope.hasExplicitJiraTarget;

    if (checkConfluence) {
      await verifyConfluenceIdentity(accountId);
      await assertConfluenceReaderPermissions(scope.effectiveSpaceId, scope.effectiveContentId);
    }

    if (checkJira) {
      await verifyJiraIdentity(accountId);
      await assertJiraReaderPermissions(scope.effectiveProjectKey, scope.effectiveIssueKey);
    }
  }

  return {
    accountId,
    extensionType: scope.extensionType,
    projectKey: scope.effectiveProjectKey,
    spaceKey: scope.extSpaceKey,
    spaceId: scope.effectiveSpaceId,
    contentId: scope.effectiveContentId,
  };
}

/**
 * Verifies authenticated Atlassian caller identity and write/admin permissions (`EDIT_ISSUES` / `ADMINISTER_PROJECTS`,
 * or Confluence page/global-space write operations), blocking read-only viewers and cross-project overrides.
 */
export async function assertAuthorizedOperator(
  req?: ForgeResolverRequest<unknown>,
  target?: AuthorizationTarget
): Promise<AuthorizedCaller> {
  const accountId = extractCallerAccountId(req);
  if (!accountId) {
    throw new Error('Unauthorized: Authenticated Atlassian accountId is required in resolver context.');
  }

  const scope = normalizeAndValidateScope(req?.context?.extension, target);

  if (isForgeRuntime()) {
    const checkConfluence = scope.isConfluence || scope.hasExplicitConfluenceTarget;
    const checkJira = !scope.isConfluence || scope.hasExplicitJiraTarget;

    if (checkConfluence) {
      await verifyConfluenceIdentity(accountId);
      await assertConfluenceOperatorPermissions(scope.effectiveSpaceId, scope.effectiveContentId);
    }

    if (checkJira) {
      await verifyJiraIdentity(accountId);
      await assertJiraOperatorPermissions(scope.effectiveProjectKey, scope.effectiveIssueKey);
    }
  }

  return {
    accountId,
    extensionType: scope.extensionType,
    projectKey: scope.effectiveProjectKey,
    spaceKey: scope.extSpaceKey,
    spaceId: scope.effectiveSpaceId,
    contentId: scope.effectiveContentId,
  };
}

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
  await assertAuthorizedReader(req);
  return SeederService.getActiveComplianceSuite();
});

defineTypedResolver('seedDemoSuite', async (req) => {
  const caller = await assertAuthorizedOperator(req);
  const confirmOverwriteLive = req.payload?.confirmOverwriteLive === true;
  return SeederService.seedEnterpriseDemoSuite(caller.accountId, 'FORGE_USER_SESSION', {
    confirmOverwriteLive,
  });
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

  return LiveIngestionService.syncFromAtlassian(
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
});

defineTypedResolver('remediateGap', async (req) => {
  const caller = await assertAuthorizedOperator(req);
  const hazardKey = typeof req.payload?.hazardKey === 'string' ? req.payload.hazardKey.trim() : '';
  if (!hazardKey) {
    throw new Error('Bad Request: hazardKey is required.');
  }
  return SeederService.remediateClassCGap(hazardKey, caller.accountId, {
    simulate: req.payload?.simulate === true,
    attestationConfirmed: req.payload?.attestationConfirmed === true,
    meaning: typeof req.payload?.meaning === 'string' ? req.payload.meaning.trim() : undefined,
    authMethod: 'FORGE_USER_SESSION',
  });
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

  return SeederService.recordTestResult({
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
  const passwordConfirmed = req.payload?.passwordConfirmed === true;

  if (!attestationConfirmed || !passwordConfirmed) {
    throw new Error(
      '21 CFR Part 11 Violation: Both attestationConfirmed and passwordConfirmed re-authentication flags must be true.'
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

  const clientPublicKeySpki =
    typeof req.payload?.clientPublicKeySpki === 'string' &&
    req.payload.clientPublicKeySpki.trim().length > 0
      ? req.payload.clientPublicKeySpki.trim()
      : undefined;
  const clientSignatureBase64 =
    typeof req.payload?.clientSignatureBase64 === 'string' &&
    req.payload.clientSignatureBase64.trim().length > 0
      ? req.payload.clientSignatureBase64.trim()
      : undefined;

  // Derive signer role server-side rather than trusting client-supplied role/signedBy fields.
  const role = 'Authorized Atlassian User';

  return SeederService.signOffPart11({
    hazardKey,
    specId,
    linkId,
    attestation: {
      role,
      meaning,
      attestationPhrase,
      attestationConfirmed: true,
      passwordConfirmed: true,
      ...(clientPublicKeySpki ? { clientPublicKeySpki } : {}),
      ...(clientSignatureBase64 ? { clientSignatureBase64 } : {}),
    },
    actorAccountId: caller.accountId,
    authMethod: 'PART11_ATTESTATION',
    extensionType: caller.extensionType,
    projectKey: caller.projectKey,
    spaceKey: caller.spaceKey,
  });
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

  return TeamworkGraphService.queryIssueGraphContext(issueKey, { callerMode: 'USER' });
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

  const summary = await SeederService.bindIssueToHazard(
    hazardKey,
    rawIssueKey,
    caller.accountId,
    'FORGE_USER_SESSION',
    {
      callerMode: 'USER',
      linkId,
    }
  );

  return {
    success: true,
    summary,
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

  await assertAuthorizedReader(req, issueKey ? { issueKey } : undefined);

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
  await assertAuthorizedReader(req);
  const triggerKey = typeof req.payload?.triggerKey === 'string' ? req.payload.triggerKey.trim() : '';
  if (!triggerKey) {
    throw new Error('Bad Request: triggerKey is required.');
  }
  const suite = await SeederService.getActiveComplianceSuite();
  return ComplianceEngine.computeBlastRadius(triggerKey, suite);
});

defineTypedResolver('getAuditLog', async (req) => {
  await assertAuthorizedReader(req);
  const rawLimit =
    typeof req.payload?.limit === 'number' && Number.isFinite(req.payload.limit)
      ? Math.floor(req.payload.limit)
      : 50;
  const limit = Math.max(1, Math.min(500, rawLimit));
  const beforeSeq =
    typeof req.payload?.beforeSeq === 'number' &&
    Number.isFinite(req.payload.beforeSeq) &&
    req.payload.beforeSeq > 0
      ? Math.floor(req.payload.beforeSeq)
      : undefined;

  return AuditLogService.getAuditLog(limit, beforeSeq);
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

// =========================================================================
// Authenticated MCP & CI/CD Webtrigger (HMAC + Nonce Replay Protection)
// =========================================================================

/**
 * Verifies an HMAC-SHA256 request signature over `timestamp.nonce.payload` using timing-safe comparison.
 * Fails closed (`false`) when `secret` is missing/empty or any header/input is malformed.
 */
export function verifyHmacSignature(
  payload: string,
  timestamp: string,
  signatureHeader: string,
  secret: string,
  nonce: string = ''
): boolean {
  if (typeof secret !== 'string' || secret.trim() === '') return false;
  if (typeof payload !== 'string') return false;
  if (typeof timestamp !== 'string' || !/^\d+$/.test(timestamp.trim())) return false;
  if (typeof signatureHeader !== 'string' || !/^sha256=[a-f0-9]{64}$/i.test(signatureHeader.trim())) {
    return false;
  }

  const cleanTimestamp = timestamp.trim();
  const cleanNonce = typeof nonce === 'string' ? nonce : '';
  const signingInput = cleanNonce
    ? `${cleanTimestamp}.${cleanNonce}.${payload}`
    : `${cleanTimestamp}.${payload}`;
  const providedHex = signatureHeader.trim().slice('sha256='.length).toLowerCase();
  const expectedHex = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest('hex');

  const sigBuf = Buffer.from(providedHex, 'hex');
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (sigBuf.length !== expectedBuf.length || sigBuf.length !== 32) {
    return false;
  }
  return crypto.timingSafeEqual(sigBuf, expectedBuf);
}

/**
 * Atomically claims a request nonce through the active `NonceStore`, distinguishing replays from storage failures.
 */
export async function claimNonceDetailed(
  nonce: string,
  store: NonceStore = getNonceStore(),
  ttlMs: number = NONCE_TTL_MS
): Promise<NonceClaimResult> {
  const cleanNonce = typeof nonce === 'string' ? nonce.trim() : '';
  if (!cleanNonce) return 'REPLAY';

  // Keep the single `nonce:` prefix; NonceStore hashes the key once via `toKvsNonceKey`.
  const storageKey = `nonce:${cleanNonce}`;
  const now = Date.now();

  if (typeof store.claimDetailed === 'function') {
    return store.claimDetailed(storageKey, { consumedAt: now }, ttlMs);
  }
  if (typeof store.claim === 'function') {
    try {
      const claimed = await store.claim(storageKey, { consumedAt: now }, ttlMs);
      return claimed ? 'CLAIMED' : 'REPLAY';
    } catch (err: unknown) {
      console.error('[MedTrace NonceStore] claim failed:', err instanceof Error ? err.message : 'Unknown error');
      return 'STORAGE_ERROR';
    }
  }

  const existing = await store.get(storageKey);
  if (existing && now - existing.consumedAt < ttlMs) {
    return 'REPLAY';
  }
  await store.set(storageKey, { consumedAt: now });
  return 'CLAIMED';
}

/**
 * Atomically claims a request nonce and returns `true` when accepted or `false` on replay/rejection.
 */
export async function claimNonce(
  nonce: string,
  store: NonceStore = getNonceStore(),
  ttlMs: number = NONCE_TTL_MS
): Promise<boolean> {
  return (await claimNonceDetailed(nonce, store, ttlMs)) === 'CLAIMED';
}

export { getNonceStore, setNonceStore, createInMemoryNonceStore };

function getHeader(
  headers: Record<string, string | string[] | undefined> | undefined,
  name: string
): string | undefined {
  if (!headers) return undefined;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      if (Array.isArray(v)) {
        return typeof v[0] === 'string' ? v[0] : undefined;
      }
      return typeof v === 'string' ? v : undefined;
    }
  }
  return undefined;
}

function timingSafeSecretEquals(provided: string, expected: string): boolean {
  const hashA = crypto.createHash('sha256').update(provided).digest();
  const hashB = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

function jsonResponse(
  statusCode: number,
  payload: unknown,
  extraHeaders?: Record<string, string[]>
): WebtriggerResponse {
  return {
    statusCode,
    headers: {
      'Content-Type': ['application/json'],
      ...(extraHeaders || {}),
    },
    body: JSON.stringify(payload),
  };
}

/**
 * Forge webtrigger entrypoint for authenticated MCP/CI-CD requests.
 * Enforces fail-closed HMAC verification, asymmetric timestamp bounds `[-300s, +30s]`, single-use nonces,
 * strict HTTP method/body/action validation, LIVE-mode mutation guards, and sanitized error responses.
 */
export async function mcpWebtriggerHandler(request: WebtriggerRequest): Promise<WebtriggerResponse> {
  const configuredSecret = process.env.MEDTRACE_MCP_SECRET;
  if (typeof configuredSecret !== 'string' || configuredSecret.trim() === '') {
    return jsonResponse(500, {
      error: 'Server misconfiguration: MEDTRACE_MCP_SECRET must be configured in Forge environment (fail-closed).',
    });
  }

  const method =
    request.method === undefined
      ? request.body !== undefined
        ? 'POST'
        : 'GET'
      : String(request.method).trim().toUpperCase();

  if (method !== 'GET' && method !== 'POST') {
    return jsonResponse(
      405,
      { error: `Method Not Allowed: ${method || '(empty)'}. Supported methods: GET, POST.` },
      { Allow: ['GET, POST'] }
    );
  }

  const rawTimestampHeader = getHeader(request.headers, 'x-medtrace-timestamp');
  const timestampHeader = typeof rawTimestampHeader === 'string' ? rawTimestampHeader.trim() : '';
  if (!timestampHeader) {
    return jsonResponse(401, {
      error: 'Unauthorized: Missing x-medtrace-timestamp header.',
    });
  }
  if (!/^\d+$/.test(timestampHeader)) {
    return jsonResponse(401, {
      error: 'Unauthorized: Invalid x-medtrace-timestamp format (epoch milliseconds required).',
    });
  }

  const rawNonce =
    getHeader(request.headers, 'x-medtrace-nonce') ??
    getHeader(request.headers, 'x-medtrace-event-id');
  const nonceHeader = typeof rawNonce === 'string' ? rawNonce.trim() : '';
  if (!nonceHeader || nonceHeader.length > 256) {
    return jsonResponse(401, {
      error: 'Unauthorized: Missing or invalid x-medtrace-nonce header (1-256 characters required).',
    });
  }

  const signatureHeader = getHeader(request.headers, 'x-medtrace-signature')?.trim();
  if (!signatureHeader || !/^sha256=[a-f0-9]{64}$/i.test(signatureHeader)) {
    return jsonResponse(401, {
      error: 'Unauthorized: Missing or invalid x-medtrace-signature header.',
    });
  }

  const suppliedKey = getHeader(request.headers, 'x-medtrace-key');
  if (suppliedKey !== undefined && !timingSafeSecretEquals(suppliedKey, configuredSecret)) {
    return jsonResponse(401, { error: 'Unauthorized: Invalid MedTrace MCP key.' });
  }

  const reqTime = Number(timestampHeader);
  const now = Date.now();
  if (!Number.isSafeInteger(reqTime)) {
    return jsonResponse(401, { error: 'Unauthorized: Invalid x-medtrace-timestamp value.' });
  }
  if (now - reqTime > MAX_TIMESTAMP_AGE_MS || reqTime - now > MAX_FUTURE_SKEW_MS) {
    return jsonResponse(401, {
      error: 'Unauthorized: Request timestamp outside allowed replay window.',
    });
  }

  let rawBody: string;
  if (typeof request.body === 'string') {
    rawBody = request.body;
  } else if (request.body === undefined || request.body === null) {
    rawBody = '';
  } else if (!isForgeRuntime() && typeof request.body === 'object') {
    rawBody = JSON.stringify(request.body);
  } else {
    return jsonResponse(401, { error: 'Unauthorized: Malformed request body.' });
  }

  if (!verifyHmacSignature(rawBody, timestampHeader, signatureHeader, configuredSecret, nonceHeader)) {
    return jsonResponse(401, { error: 'Unauthorized: Invalid HMAC-SHA256 request signature.' });
  }

  const claimOutcome = await claimNonceDetailed(nonceHeader, getNonceStore(), NONCE_TTL_MS);
  if (claimOutcome === 'REPLAY') {
    return jsonResponse(409, {
      error: 'Conflict: Replay attack detected — nonce has already been consumed within TTL window.',
    });
  }
  if (claimOutcome === 'STORAGE_ERROR') {
    return jsonResponse(500, {
      error: 'Internal Server Error: Replay protection store unavailable.',
    });
  }

  try {
    if (method === 'GET') {
      if (rawBody !== '') {
        throw new WebtriggerHttpError(400, 'Bad Request: GET requests must not include a request body.');
      }

      const rawQueryAction =
        (Array.isArray(request.queryParameters?.action)
          ? request.queryParameters?.action[0]
          : request.queryParameters?.action) ?? request.query?.action;
      const cleanQueryAction =
        typeof rawQueryAction === 'string' && rawQueryAction.trim().length > 0
          ? rawQueryAction.trim()
          : undefined;
      if (cleanQueryAction && cleanQueryAction !== 'status' && cleanQueryAction !== 'get-suite') {
        throw new WebtriggerHttpError(
          400,
          `Bad Request: Unsupported GET query action "${cleanQueryAction}". Use POST for mutations.`
        );
      }

      const suite = await SeederService.getActiveComplianceSuite();
      return jsonResponse(200, suite);
    }

    if (rawBody.trim() === '') {
      throw new WebtriggerHttpError(400, 'Bad Request: POST requests must include a JSON object body.');
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      throw new WebtriggerHttpError(400, 'Bad Request: Malformed JSON payload.');
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new WebtriggerHttpError(400, 'Bad Request: JSON payload must be a plain object.');
    }

    const body = parsed as Record<string, unknown>;
    const action = typeof body.action === 'string' ? body.action.trim() : '';
    if (!action || !ALLOWED_WEBTRIGGER_POST_ACTIONS.has(action)) {
      throw new WebtriggerHttpError(
        400,
        `Bad Request: Unknown or missing webtrigger action "${action || '(empty)'}".`
      );
    }

    switch (action) {
      case 'status': {
        const suite = await SeederService.getActiveComplianceSuite();
        return jsonResponse(200, suite);
      }

      case 'seed': {
        const active = await SeederService.getActiveComplianceSuite();
        if (active.datasetMode === 'LIVE') {
          throw new WebtriggerHttpError(
            403,
            'Forbidden: Cannot overwrite a LIVE compliance suite with demo data via webtrigger.'
          );
        }
        const summary = await SeederService.seedEnterpriseDemoSuite(
          'service:mcp-webtrigger',
          'HMAC_WEBTRIGGER'
        );
        return jsonResponse(200, { success: true, summary });
      }

      case 'remediate': {
        const active = await SeederService.getActiveComplianceSuite();
        if (active.datasetMode === 'LIVE') {
          throw new WebtriggerHttpError(
            403,
            'Forbidden: Cannot auto-remediate gaps on a LIVE compliance suite via webtrigger.'
          );
        }
        const hazardKey = typeof body.hazardKey === 'string' ? body.hazardKey.trim() : '';
        if (!hazardKey) {
          throw new WebtriggerHttpError(400, 'Bad Request: hazardKey is required for remediate action.');
        }
        const exists = active.traceLinks.some(
          (link) => link.hazard.key.toLowerCase() === hazardKey.toLowerCase()
        );
        if (!exists) {
          throw new WebtriggerHttpError(
            404,
            `Not Found: Hazard ${hazardKey} not found in active compliance suite; nothing was remediated.`
          );
        }
        const summary = await SeederService.remediateClassCGap(hazardKey, 'service:mcp-webtrigger', {
          simulate: body.simulate === true,
          attestationConfirmed: body.attestationConfirmed === true,
          meaning: typeof body.meaning === 'string' ? body.meaning.trim() : undefined,
          authMethod: 'HMAC_WEBTRIGGER',
        });
        return jsonResponse(200, { success: true, summary });
      }

      case 'verify': {
        const result = await McpToolService.verifyIecCompliance({
          prDiff: typeof body.prDiff === 'string' ? body.prDiff : '',
          componentName: typeof body.componentName === 'string' ? body.componentName : undefined,
          issueKey:
            typeof body.issueKey === 'string' && body.issueKey.trim() !== ''
              ? body.issueKey.trim()
              : undefined,
        });
        return jsonResponse(200, result);
      }

      case 'verify-release-gate': {
        const issueKey =
          typeof body.issueKey === 'string' && body.issueKey.trim() !== ''
            ? body.issueKey.trim()
            : undefined;
        const requireLiveMode = body.requireLiveMode === true;
        const suite = await SeederService.getActiveComplianceSuite(
          issueKey ? { issueKeyFilter: issueKey } : undefined
        );

        if (
          requireLiveMode &&
          (suite.datasetMode !== 'LIVE' || suite.initialized === false || suite.totalHazards === 0)
        ) {
          return jsonResponse(403, {
            result: false,
            releaseBlocked: true,
            datasetMode: suite.datasetMode,
            initialized: suite.initialized ?? false,
            errorMessage:
              'Safety Gate Blocked: Release gate requires an initialized LIVE compliance suite (DEMO or uninitialized suites cannot authorize clinical release).',
          });
        }

        const gate = ComplianceEngine.evaluateIssueReleaseGate(issueKey, suite);
        return jsonResponse(gate.result ? 200 : 403, {
          ...gate,
          evaluatedIssueKey: issueKey,
        });
      }

      case 'validate':
      case 'simulate_transition': {
        const issueKey =
          typeof body.issueKey === 'string' && body.issueKey.trim() !== ''
            ? body.issueKey.trim()
            : undefined;
        const transitionName =
          typeof body.transitionName === 'string' && body.transitionName.trim() !== ''
            ? body.transitionName.trim()
            : 'Done';

        const outcome = await workflowValidatorHandler(
          issueKey
            ? { issue: { key: issueKey }, transition: { name: transitionName } }
            : { transition: { name: transitionName } }
        );
        return jsonResponse(200, {
          ...outcome,
          evaluatedIssueKey: issueKey,
        });
      }

      default:
        throw new WebtriggerHttpError(400, `Bad Request: Unsupported action "${action}".`);
    }
  } catch (err: unknown) {
    if (err instanceof WebtriggerHttpError) {
      return jsonResponse(err.statusCode, { error: err.publicMessage });
    }
    const errorId = crypto.randomUUID();
    console.error(
      `[MedTrace MCP Webtrigger] Error (${errorId}):`,
      err instanceof Error ? err.message : 'Unknown error'
    );
    return jsonResponse(500, {
      error: 'Internal Server Error: Request could not be processed.',
      errorId,
    });
  }
}

export { rovoActionHandler, workflowValidatorHandler };
