import api, { route } from '@forge/api';
import { ComplianceEngine } from './compliance-engine';
import { JIRA_ISSUE_KEY_RE, JIRA_PROJECT_KEY_RE } from './crypto-utils';
import { LiveIngestionService } from './ingestion';
import { isForgeRuntime } from './runtime';
import { SeederService } from './seeder';
import { verifyJiraIdentity } from './rbac';
import {
  authorizeAndFilterLiveSuiteDetailed,
  AuthorizedLiveSuiteResult,
  checkJiraBrowsePermissionDetailed,
  extractAllJiraIssueKeysFromLink,
  extractAllJiraProjectKeysFromLink,
  extractJiraProjectKeyFromRawKey,
  extractPrimaryJiraProjectKeyFromLink,
  hasJiraBrowsePermissionForCaller,
  redactBlastRadiusReport,
} from './seeder-identity';
import { fetchSpecOwnersFromTeamworkGraph, resolveConfluenceCloudId } from './teamwork-graph';
import {
  BlastRadiusReport,
  ComplianceSummary,
  ConfluenceSpec,
  IsoHazard,
  JiraWorkItem,
  Part11Signature,
  RiskClass,
  SpecOwnerRef,
  TraceLink,
  VerificationTest,
} from './types';

const SHORT_SAFETY_TOKEN_RE = /^(?:pwm|mcu|adc|dac|hil|srs|iso|iec|fda|cfr|sha|crc|spi|i2c|can|ble|rtc|wdt|dma|isr)$/i;
const MAX_ROVO_TEXT_SCAN_CHARS = 100_000;

const STOP_WORDS = new Set([
  'with', 'from', 'that', 'this', 'must', 'every', 'during', 'within', 'clause',
  'test', 'tests', 'spec', 'specs', 'jira', 'confluence', 'hazard', 'issue', 'issues',
  'firmware', 'software', 'system', 'systems', 'verification', 'safety', 'implement',
  'updated', 'modified', 'version', 'approved', 'pending', 'passed', 'failed',
  'require', 'required', 'requires', 'check', 'checks', 'verify', 'verified',
  'change', 'changes', 'code', 'file', 'files', 'diff', 'component', 'module',
  'status', 'review', 'error', 'warning', 'data', 'value', 'values', 'none', 'null',
  'true', 'false', 'when', 'where', 'which', 'their', 'there', 'these', 'those',
  'into', 'about', 'after', 'before', 'under', 'over', 'between', 'against',
]);

const ALLOWED_ROVO_ACTIONS = new Set([
  'get-hazard-lineage-action',
  'get-hazard-lineage',
  'verify-iec-compliance-action',
  'verify-iec-compliance',
  'create-reverification-task-action',
  'create-reverification-task',
]);

export interface HazardLineageFoundResponse {
  found: true;
  datasetMode: 'DEMO' | 'LIVE';
  initialized: boolean;
  traceLink: TraceLink;
  matchedLinks?: TraceLink[];
  regulatoryStatus: TraceLink['complianceState'];
  riskClass: RiskClass;
  safetyRequirement: string;
  testStatus: VerificationTest['status'];
  part11Valid: boolean;
  hazard: IsoHazard;
  spec: ConfluenceSpec;
  work: JiraWorkItem;
  test: VerificationTest;
  signature: Part11Signature;
  complianceState: TraceLink['complianceState'];
  violations: string[];
  specOwners?: SpecOwnerRef[];
  teamworkGraphStatus?: 'OK' | 'EMPTY' | 'ERROR';
}

export interface HazardLineageNotFoundResponse {
  found: false;
  datasetMode: 'DEMO' | 'LIVE';
  initialized: boolean;
  queriedKey: string;
  message: string;
  availableKeys?: Array<{
    hazardKey: string;
    workKey: string;
    specId: string;
    testKey: string;
  }>;
}

export interface HazardLineageSummaryResponse {
  projectName: string;
  datasetMode: 'DEMO' | 'LIVE';
  initialized: boolean;
  totalHazards: number;
  verifiedPercentage: string;
  releaseBlocked: boolean;
  syncIncomplete?: boolean;
  blockingReasons: string[];
  traceLinks: Array<{
    id: string;
    hazardKey: string;
    riskClass: RiskClass;
    severity?: IsoHazard['severity'];
    requirementSpec: string;
    workKey: string;
    testKey: string;
    testStatus: VerificationTest['status'];
    complianceState: TraceLink['complianceState'];
    signatureValid: boolean;
  }>;
}

export type HazardLineageResponse =
  | HazardLineageFoundResponse
  | HazardLineageNotFoundResponse
  | HazardLineageSummaryResponse;

export interface IecComplianceVerificationResponse {
  standards: string[];
  datasetMode: 'DEMO' | 'LIVE';
  initialized: boolean;
  configuredChecksPassed: boolean;
  verifiedCoveragePercentage: string;
  classCSummary: {
    totalClassC: number;
    status: 'BLOCKED_BY_SAFETY_GATE' | 'CONFIGURED_CHECKS_PASSED';
  };
  signatureDriftDetected: boolean;
  touchesSafetyCriticalCode: boolean;
  affectedHazards: string[];
  activeViolations: string[];
  remediationGuidance: string[];
  graphBlastRadius?: {
    trigger: string;
    severity: BlastRadiusReport['impactSeverity'];
    traversalPath: BlastRadiusReport['traversalPath'];
    blockedWorkItems: string[];
    invalidatedTests: string[];
    executionTimeMs: number;
  };
}

export interface RovoActionContext {
  moduleKey?: string;
  accountId?: string;
  cloudId?: string;
  principal?: { accountId?: string };
  extension?: {
    type?: string;
    project?: { key?: string; id?: string };
    issue?: { key?: string; id?: string };
    space?: { key?: string; id?: string };
    content?: { id?: string; type?: string };
  };
}

export interface RovoActionInputs {
  issueKey?: string;
  hazardKey?: string;
  prDiff?: string;
  componentName?: string;
  summary?: string;
  reason?: string;
}

export interface RovoActionPayload extends RovoActionInputs {
  context?: RovoActionContext;
  actionKey?: string;
  key?: string;
  inputs?: RovoActionInputs;
}

export interface RovoActionErrorResponse {
  error: string;
  availableTools?: string[];
}

class RovoAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RovoAuthError';
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function extractMeaningfulTokens(text: string): string[] {
  const bounded = text.length > MAX_ROVO_TEXT_SCAN_CHARS ? text.slice(0, MAX_ROVO_TEXT_SCAN_CHARS) : text;
  const tokens = bounded.toLowerCase().match(/\b[a-z0-9][a-z0-9_-]{2,}\b/g) || [];
  return Array.from(
    new Set(
      tokens.filter(
        (t) => !STOP_WORDS.has(t) && (t.length >= 4 || SHORT_SAFETY_TOKEN_RE.test(t))
      )
    )
  );
}

function collectCanonicalLinkKeys(link: TraceLink): string[] {
  return [
    link.hazard?.key,
    link.hazard?.id,
    link.work?.key,
    link.work?.id,
    link.test?.testKey,
    link.test?.id,
    link.spec?.id,
    link.spec?.pageId,
    link.signature?.id,
  ]
    .filter((val): val is string => typeof val === 'string' && val.trim() !== '')
    .map((val) => val.trim().toLowerCase());
}

function findLinksMatchingTextTokens(fullText: string, traceLinks: TraceLink[]): TraceLink[] {
  const inputTokenSet = new Set(extractMeaningfulTokens(fullText));
  if (inputTokenSet.size === 0) return [];

  const matched: TraceLink[] = [];
  for (const link of traceLinks) {
    const corpus = `${link.spec?.title || ''} ${link.spec?.contentSnippet || ''} ${link.hazard?.title || ''} ${link.work?.title || ''}`;
    const linkTokens = extractMeaningfulTokens(corpus);
    if (linkTokens.some((tok) => inputTokenSet.has(tok))) {
      matched.push(link);
    }
  }
  return matched;
}

interface RovoExtensionScope {
  extensionType: string;
  projectKey?: string;
  issueKey?: string;
  spaceId?: string;
  contentId?: string;
}

function extractRovoExtensionScope(
  ctx: RovoActionContext,
  payloadCtx?: RovoActionContext
): RovoExtensionScope {
  const extensionType = String(ctx.extension?.type || payloadCtx?.extension?.type || '').trim();
  const rawProjectKey = ctx.extension?.project?.key ?? payloadCtx?.extension?.project?.key;
  const rawIssueKey = ctx.extension?.issue?.key ?? payloadCtx?.extension?.issue?.key;
  const rawSpaceId = ctx.extension?.space?.id ?? payloadCtx?.extension?.space?.id;
  const rawContentId = ctx.extension?.content?.id ?? payloadCtx?.extension?.content?.id;

  const projectKey =
    typeof rawProjectKey === 'string' && rawProjectKey.trim() !== ''
      ? rawProjectKey.trim().toUpperCase()
      : undefined;
  if (projectKey && !JIRA_PROJECT_KEY_RE.test(projectKey)) {
    throw new RovoAuthError('Forbidden: Invalid Jira projectKey in extension context.');
  }

  const issueKey =
    typeof rawIssueKey === 'string' && rawIssueKey.trim() !== ''
      ? rawIssueKey.trim().toUpperCase()
      : undefined;
  if (issueKey && !JIRA_ISSUE_KEY_RE.test(issueKey)) {
    throw new RovoAuthError('Forbidden: Invalid Jira issueKey in extension context.');
  }

  const spaceId =
    typeof rawSpaceId === 'string' && rawSpaceId.trim() !== '' ? rawSpaceId.trim() : undefined;
  if (spaceId && !/^[a-zA-Z0-9_-]{1,64}$/.test(spaceId)) {
    throw new RovoAuthError('Forbidden: Invalid Confluence spaceId in extension context.');
  }

  const contentId =
    typeof rawContentId === 'string' && rawContentId.trim() !== '' ? rawContentId.trim() : undefined;
  if (contentId && !/^[a-zA-Z0-9_-]{1,64}$/.test(contentId)) {
    throw new RovoAuthError('Forbidden: Invalid Confluence contentId in extension context.');
  }

  return { extensionType, projectKey, issueKey, spaceId, contentId };
}

async function checkJiraBrowsePermission(target?: {
  issueKey?: string;
  projectKey?: string;
}): Promise<boolean> {
  const perm = await checkJiraBrowsePermissionDetailed(target);
  if (perm.inactive) {
    throw new RovoAuthError('Forbidden: User account is inactive.');
  }
  return perm.httpOk && perm.allowed;
}

async function assertRovoUserReadAccess(
  accountId: string,
  scope: RovoExtensionScope
): Promise<void> {
  if (scope.extensionType.toLowerCase().startsWith('confluence')) {
    const confResp = await api.asUser().requestConfluence(route`/wiki/rest/api/user/current`);
    if (confResp.status !== 200) {
      throw new RovoAuthError('Forbidden: Confluence user session lacks read access.');
    }
    const userData = (await confResp.json().catch(() => null)) as {
      accountId?: unknown;
      type?: unknown;
    } | null;
    if (
      userData?.type === 'anonymous' ||
      typeof userData?.accountId !== 'string' ||
      userData.accountId.trim() !== accountId
    ) {
      throw new RovoAuthError('Forbidden: Authenticated Confluence user identity mismatch.');
    }
    if (scope.contentId) {
      const pageResp = await api
        .asUser()
        .requestConfluence(route`/wiki/api/v2/pages/${scope.contentId}`);
      if (pageResp.status !== 200) {
        throw new RovoAuthError('Forbidden: Confluence user lacks read access to target page.');
      }
    } else if (scope.spaceId) {
      const spaceResp = await api
        .asUser()
        .requestConfluence(route`/wiki/api/v2/spaces/${scope.spaceId}`);
      if (spaceResp.status !== 200) {
        throw new RovoAuthError('Forbidden: Confluence user lacks read access to target space.');
      }
    }
    return;
  }

  try {
    await verifyJiraIdentity(accountId);
  } catch (err: unknown) {
    throw new RovoAuthError(err instanceof Error ? err.message : 'Forbidden: Jira user session validation failed.');
  }

  const hasJiraRead = await checkJiraBrowsePermission({
    issueKey: scope.issueKey,
    projectKey: scope.projectKey,
  });
  if (!hasJiraRead) {
    throw new RovoAuthError('Forbidden: Requires Jira BROWSE_PROJECTS permission.');
  }
}

async function scopeSuiteForRovoCaller(
  suite: ComplianceSummary,
  inputs: RovoActionInputs,
  scope: RovoExtensionScope
): Promise<AuthorizedLiveSuiteResult> {
  if (suite.datasetMode !== 'LIVE' || suite.initialized === false) {
    return { unredactedSuite: suite, outboundSuite: suite, restrictedPageIds: new Set<string>() };
  }

  const projectPermCache = new Map<string, boolean>();
  const issuePermCache = new Map<string, boolean>();

  const hasProjectAccess = async (projectKey: string): Promise<boolean> => {
    const clean = projectKey.trim().toUpperCase();
    if (scope.projectKey && clean !== scope.projectKey) {
      return false;
    }
    if (projectPermCache.has(clean)) {
      return projectPermCache.get(clean) === true;
    }
    const allowed = await hasJiraBrowsePermissionForCaller({ projectKey: clean });
    projectPermCache.set(clean, allowed);
    return allowed;
  };

  const hasIssueAccess = async (issueKey: string): Promise<boolean> => {
    const clean = issueKey.trim().toUpperCase();
    const issueProj = extractJiraProjectKeyFromRawKey(clean, 'JIRA_ISSUE');
    if (scope.projectKey && issueProj && issueProj !== scope.projectKey) {
      return false;
    }
    if (issuePermCache.has(clean)) {
      return issuePermCache.get(clean) === true;
    }
    const allowed = await hasJiraBrowsePermissionForCaller({ issueKey: clean });
    issuePermCache.set(clean, allowed);
    return allowed;
  };

  // Validate explicitly requested keys against EVERY associated Jira artifact permission before returning or searching.
  const lookupKeys: string[] = [];
  const seenLookupLower = new Set<string>();
  const addLookupKey = (rawKey?: string): void => {
    const trimmed = typeof rawKey === 'string' ? rawKey.trim() : '';
    if (!trimmed) return;
    const lower = trimmed.toLowerCase();
    if (!seenLookupLower.has(lower)) {
      seenLookupLower.add(lower);
      lookupKeys.push(trimmed);
    }
  };
  addLookupKey(inputs.issueKey);
  addLookupKey(inputs.hazardKey);
  const rawScan = `${inputs.prDiff || ''} ${inputs.componentName || ''} ${inputs.issueKey || ''}`;
  const textScan = rawScan.length > MAX_ROVO_TEXT_SCAN_CHARS ? rawScan.slice(0, MAX_ROVO_TEXT_SCAN_CHARS) : rawScan;
  for (const keyToken of textScan.match(/\b[A-Za-z][A-Za-z0-9_]{0,20}-\d+\b/g) || []) {
    addLookupKey(keyToken);
  }

  for (const key of lookupKeys) {
    const lower = key.toLowerCase();
    const matchedLinks = suite.traceLinks.filter((l) => collectCanonicalLinkKeys(l).includes(lower));
    if (matchedLinks.length > 0) {
      for (const link of matchedLinks) {
        const allIssueKeys = extractAllJiraIssueKeysFromLink(link);
        if (allIssueKeys.length > 0) {
          for (const linkedIssueKey of allIssueKeys) {
            if (!(await hasIssueAccess(linkedIssueKey))) {
              throw new RovoAuthError(
                `Forbidden: Caller lacks Jira BROWSE_PROJECTS permission for target scope (${linkedIssueKey}).`
              );
            }
          }
        } else {
          for (const projKey of extractAllJiraProjectKeysFromLink(link)) {
            if (!(await hasProjectAccess(projKey))) {
              throw new RovoAuthError(
                `Forbidden: Caller lacks Jira BROWSE_PROJECTS permission for project ${projKey}.`
              );
            }
          }
        }
      }
    } else {
      const cleanUpper = key.trim().toUpperCase();
      const isDirectIssueOrHazardArg =
        (inputs.issueKey && lower === inputs.issueKey.trim().toLowerCase()) ||
        (inputs.hazardKey && lower === inputs.hazardKey.trim().toLowerCase());
      const resolvedProj = extractJiraProjectKeyFromRawKey(cleanUpper, isDirectIssueOrHazardArg ? 'JIRA_ISSUE' : undefined);
      const isSyntheticDummy =
        cleanUpper.startsWith('HAZ-') || cleanUpper.startsWith('TEST-')
          ? !JIRA_ISSUE_KEY_RE.test(cleanUpper.replace(/^(?:HAZ|TEST)-/i, ''))
          : false;
      if (isDirectIssueOrHazardArg && !isSyntheticDummy && JIRA_ISSUE_KEY_RE.test(cleanUpper)) {
        if (!(await hasIssueAccess(cleanUpper))) {
          throw new RovoAuthError(
            `Forbidden: Caller lacks Jira BROWSE_PROJECTS permission for requested issue ${cleanUpper}.`
          );
        }
      } else if (isDirectIssueOrHazardArg && resolvedProj) {
        if (!(await hasProjectAccess(resolvedProj))) {
          throw new RovoAuthError(
            `Forbidden: Caller lacks Jira BROWSE_PROJECTS permission for project ${resolvedProj}.`
          );
        }
      }
    }
  }

  return authorizeAndFilterLiveSuiteDetailed(suite, {
    extensionType: scope.extensionType,
    projectKey: scope.projectKey,
    checkConfluencePages: true,
  });
}

/**
 * MedTrace MCP Tools & Rovo Action Handlers.
 * Serves both Atlassian Rovo agent invocations and external MCP coding assistants.
 */
export class McpToolService {
  /**
   * Tool: get-hazard-lineage-action
   * Retrieves a matching ISO 14971 hazard safety lineage or a reduced project summary.
   */
  public static async getHazardLineage(
    inputs?: {
      issueKey?: string;
      hazardKey?: string;
    },
    options?: {
      suite?: ComplianceSummary;
      cloudId?: string;
      includeAvailableKeys?: boolean;
      includeSpecOwners?: boolean;
    }
  ): Promise<HazardLineageResponse> {
    let suite = options?.suite ?? (await SeederService.getActiveComplianceSuite());
    const rawIssueKey = typeof inputs?.issueKey === 'string' ? inputs.issueKey.trim() : '';
    const rawHazardKey = typeof inputs?.hazardKey === 'string' ? inputs.hazardKey.trim() : '';
    const lookupKey = rawIssueKey || rawHazardKey;

    if (!options?.suite && isForgeRuntime() && suite.datasetMode === 'LIVE' && suite.initialized !== false) {
      const targetPageIds = lookupKey
        ? suite.traceLinks
            .filter((l) => collectCanonicalLinkKeys(l).includes(lookupKey.toLowerCase()))
            .map((l) => l.spec?.pageId)
            .filter((p): p is string => typeof p === 'string' && p.trim().length > 0)
        : undefined;
      if (!lookupKey || (targetPageIds && targetPageIds.length > 0)) {
        suite = await LiveIngestionService.reconcileConfluenceSpecs(suite, {
          ...(targetPageIds && targetPageIds.length > 0 ? { targetPageIds } : {}),
          allowAppFallback: true,
        });
      }
    }

    const initialized = suite.initialized ?? suite.traceLinks.length > 0;

    if (lookupKey) {
      const lower = lookupKey.toLowerCase();
      const matches = suite.traceLinks.filter((l) => collectCanonicalLinkKeys(l).includes(lower));
      if (matches.length > 0) {
        const match = matches[0];
        const found: HazardLineageFoundResponse = {
          found: true,
          datasetMode: suite.datasetMode,
          initialized,
          traceLink: match,
          ...(matches.length > 1 ? { matchedLinks: matches } : {}),
          regulatoryStatus: match.complianceState,
          riskClass: match.hazard.riskClass,
          safetyRequirement: match.spec.title,
          testStatus: match.test.status,
          part11Valid: match.signature.isValid,
          hazard: match.hazard,
          spec: match.spec,
          work: match.work,
          test: match.test,
          signature: match.signature,
          complianceState: match.complianceState,
          violations: match.violations,
        };
        const pageIds = matches
          .filter((m) => !m.spec.specRestricted)
          .map((m) => (typeof m.spec.pageId === 'string' ? m.spec.pageId.trim() : ''))
          .filter(Boolean);
        const cloudId = typeof options?.cloudId === 'string' ? options.cloudId.trim() : '';
        if (options?.includeSpecOwners === true && isForgeRuntime() && cloudId && pageIds.length > 0) {
          try {
            const { owners, status } = await fetchSpecOwnersFromTeamworkGraph(
              api.asUser(),
              cloudId,
              pageIds
            );
            found.specOwners = owners;
            found.teamworkGraphStatus = status;
          } catch (err: unknown) {
            console.warn(
              '[TeamworkGraph] specOwners lineage fetch notice:',
              err instanceof Error ? err.message : String(err)
            );
            found.teamworkGraphStatus = 'ERROR';
          }
        }
        return found;
      }

      return {
        found: false,
        datasetMode: suite.datasetMode,
        initialized,
        queriedKey: lookupKey,
        message: `No trace link found for key "${lookupKey}" in project "${suite.projectName}".`,
        ...(options?.includeAvailableKeys !== false
          ? {
              availableKeys: suite.traceLinks.map((l) => ({
                hazardKey: l.hazard.key,
                workKey: l.work.key,
                specId: l.spec.id,
                testKey: l.test.testKey,
              })),
            }
          : {}),
      };
    }

    return {
      projectName: suite.projectName,
      datasetMode: suite.datasetMode,
      initialized,
      totalHazards: suite.totalHazards,
      verifiedPercentage: `${suite.verifiedPercentage}%`,
      releaseBlocked: suite.releaseBlocked,
      ...(suite.syncIncomplete ? { syncIncomplete: true } : {}),
      blockingReasons: suite.blockingReasons,
      traceLinks: suite.traceLinks.map((l) => ({
        id: l.id,
        hazardKey: l.hazard.key,
        riskClass: l.hazard.riskClass,
        ...(l.hazard.severity ? { severity: l.hazard.severity } : {}),
        requirementSpec: l.spec.title,
        workKey: l.work.key,
        testKey: l.test.testKey,
        testStatus: l.test.status,
        complianceState: l.complianceState,
        signatureValid: l.signature.isValid,
      })),
    };
  }

  /**
   * Tool: verify-iec-compliance-action
   * Audits active codebase/sprint against configured traceability rules and signature evidence.
   * Fails closed on uninitialized suites, matches explicit canonical suite keys + word-boundary tokens,
   * and runs multi-trigger BFS blast-radius traversal.
   */
  public static async verifyIecCompliance(
    inputs?: {
      prDiff?: string;
      componentName?: string;
      issueKey?: string;
    },
    options?: {
      suite?: ComplianceSummary;
      unredactedSuite?: ComplianceSummary;
      restrictedPageIds?: ReadonlySet<string>;
    }
  ): Promise<IecComplianceVerificationResponse> {
    let suite = options?.suite ?? (await SeederService.getActiveComplianceSuite());
    if (
      !options?.suite &&
      !options?.unredactedSuite &&
      isForgeRuntime() &&
      suite.datasetMode === 'LIVE' &&
      suite.initialized !== false
    ) {
      suite = await LiveIngestionService.reconcileConfluenceSpecs(suite, {
        allowAppFallback: true,
        failClosedOnBudget: true,
      });
    }
    const evalSuite = options?.unredactedSuite ?? suite;
    const initialized = suite.initialized ?? suite.traceLinks.length > 0;

    if (!initialized || suite.traceLinks.length === 0) {
      return {
        standards: suite.standards,
        datasetMode: suite.datasetMode,
        initialized: false,
        configuredChecksPassed: false,
        verifiedCoveragePercentage: `${suite.verifiedPercentage}%`,
        classCSummary: {
          totalClassC: suite.classCCount,
          status: 'BLOCKED_BY_SAFETY_GATE',
        },
        signatureDriftDetected: suite.signatureDriftCount > 0,
        touchesSafetyCriticalCode: false,
        affectedHazards: ['None (Compliance suite is uninitialized)'],
        activeViolations: [
          'MedTrace compliance suite is uninitialized; run Live Sync before verifying release readiness.',
        ],
        remediationGuidance: [
          'Run Sync Live Atlassian in the MedTrace UI before verifying IEC 62304 compliance.',
        ],
        graphBlastRadius: undefined,
      };
    }

    const rawPrDiff = typeof inputs?.prDiff === 'string' ? inputs.prDiff : '';
    const prDiff =
      rawPrDiff.length > MAX_ROVO_TEXT_SCAN_CHARS
        ? rawPrDiff.slice(0, MAX_ROVO_TEXT_SCAN_CHARS)
        : rawPrDiff;
    const rawComponentName = typeof inputs?.componentName === 'string' ? inputs.componentName : '';
    const componentName =
      rawComponentName.length > MAX_ROVO_TEXT_SCAN_CHARS
        ? rawComponentName.slice(0, MAX_ROVO_TEXT_SCAN_CHARS)
        : rawComponentName;
    const issueKey = typeof inputs?.issueKey === 'string' ? inputs.issueKey.slice(0, 64) : '';
    const fullText = `${prDiff} ${componentName} ${issueKey}`;

    // 1. Match explicit keys present across all canonical fields in the active suite
    const suiteKeys = new Set(suite.traceLinks.flatMap((l) => collectCanonicalLinkKeys(l)));
    const rawKeyMatches = Array.from(new Set(fullText.match(/\b[A-Za-z]{2,10}-\d+\b/g) || [])).map((k) =>
      k.toLowerCase()
    );
    const keyMatches = rawKeyMatches.filter((k) => suiteKeys.has(k));
    const directIssueKey = issueKey.trim().toLowerCase();
    if (directIssueKey && suiteKeys.has(directIssueKey) && !keyMatches.includes(directIssueKey)) {
      keyMatches.push(directIssueKey);
    }

    // 2. Dynamic word-boundary token matching against real suite artifacts (run alongside keyMatches when diff/component text exists)
    let triggerKeys: string[] = [...keyMatches];
    let tokenMatchedLinks: TraceLink[] = [];
    const descriptiveText = `${prDiff} ${componentName}`.trim();
    if (descriptiveText) {
      tokenMatchedLinks = findLinksMatchingTextTokens(descriptiveText, suite.traceLinks);
      if (tokenMatchedLinks.length > 0) {
        triggerKeys = Array.from(
          new Set([
            ...triggerKeys,
            ...tokenMatchedLinks.map((l) => l.spec?.id || l.hazard.key).filter(Boolean),
          ])
        );
      }
    }

    // 3. Execute deterministic BFS blast-radius traversal on unredacted server-side suite, then redact outbound graph
    const blastRadiusRaw =
      triggerKeys.length > 0
        ? ComplianceEngine.computeMultiBlastRadius(triggerKeys, evalSuite)
        : undefined;
    const restrictedPageIds = options?.restrictedPageIds;
    const blastRadius =
      blastRadiusRaw && restrictedPageIds && restrictedPageIds.size > 0
        ? redactBlastRadiusReport(blastRadiusRaw, evalSuite.traceLinks, restrictedPageIds)
        : blastRadiusRaw;

    const affectedHazards =
      blastRadius && blastRadius.affectedHazardKeys.length > 0
        ? blastRadius.affectedHazardKeys.map((k) => {
            const l = suite.traceLinks.find((link) => link.hazard.key.toUpperCase() === k.toUpperCase());
            return l
              ? `${l.hazard.key} (${l.hazard.riskClass.replace('_', ' ')} - ${l.hazard.title.split(':')[0]})`
              : k;
          })
        : [];

    const triggerKeySet = new Set(triggerKeys.map((k) => k.toLowerCase()));
    const evalMatchedLinks = evalSuite.traceLinks.filter(
      (l) =>
        collectCanonicalLinkKeys(l).some((k) => triggerKeySet.has(k)) ||
        tokenMatchedLinks.some((tl) => tl.id === l.id)
    );

    const affectedHazardKeySet = new Set(
      (blastRadius?.affectedHazardKeys || []).map((k) => k.toUpperCase())
    );
    const evalTraversedLinks =
      affectedHazardKeySet.size > 0
        ? evalSuite.traceLinks.filter((l) => affectedHazardKeySet.has(l.hazard.key.toUpperCase()))
        : evalMatchedLinks;
    const traversedLinks =
      affectedHazardKeySet.size > 0
        ? suite.traceLinks.filter((l) => affectedHazardKeySet.has(l.hazard.key.toUpperCase()))
        : suite.traceLinks.filter((l) => evalMatchedLinks.some((em) => em.id === l.id));

    const isTargeted = affectedHazards.length > 0 || evalMatchedLinks.length > 0;
    const hasBlastRadiusGaps = Boolean(
      blastRadiusRaw &&
        (blastRadiusRaw.blockedWorkItemKeys.length > 0 ||
          blastRadiusRaw.invalidatedTestKeys.length > 0 ||
          blastRadiusRaw.invalidatedSignatureIds.length > 0)
    );
    const hasUnverifiedGaps = isTargeted
      ? evalMatchedLinks.some((l) => l.complianceState !== 'VERIFIED') ||
        evalTraversedLinks.some((l) => l.complianceState !== 'VERIFIED') ||
        hasBlastRadiusGaps
      : evalSuite.releaseBlocked;

    const canShip = !hasUnverifiedGaps;
    const activeViolations = isTargeted
      ? Array.from(new Set(traversedLinks.flatMap((l) => l.violations)))
      : suite.blockingReasons;

    let guidance: string[];
    if (hasUnverifiedGaps) {
      const actionItems = (blastRadius?.transitiveActionPlan || []).filter(
        (item) => !/All traversed artifacts are verified|no remediation required/i.test(item)
      );
      if (actionItems.length > 0 && blastRadius) {
        guidance = [
          `CRITICAL: Diff/Action impacts safety-critical graph rooted at ${blastRadius.triggerArtifact.title}.`,
          ...actionItems,
        ];
      } else if (traversedLinks.some((l) => l.violations.length > 0)) {
        guidance = traversedLinks.flatMap((l) =>
          l.violations.map((v) => `Open compliance gap (${l.hazard.key}): ${v}`)
        );
      } else if (suite.blockingReasons.length > 0) {
        guidance = suite.blockingReasons.map((r) => `Open compliance gap: ${r}`);
      } else {
        guidance = [
          'Unverified safety compliance state detected; resolve all hazard trace gaps before clinical release.',
        ];
      }
    } else {
      guidance = ['Configured traceability checks passed; independent regulatory assessment is still required.'];
    }

    return {
      standards: suite.standards,
      datasetMode: suite.datasetMode,
      initialized: true,
      configuredChecksPassed: canShip,
      verifiedCoveragePercentage: `${suite.verifiedPercentage}%`,
      classCSummary: {
        totalClassC: suite.classCCount,
        status: isTargeted
          ? canShip
            ? 'CONFIGURED_CHECKS_PASSED'
            : 'BLOCKED_BY_SAFETY_GATE'
          : suite.releaseBlocked
            ? 'BLOCKED_BY_SAFETY_GATE'
            : 'CONFIGURED_CHECKS_PASSED',
      },
      signatureDriftDetected: suite.signatureDriftCount > 0,
      touchesSafetyCriticalCode: Boolean(isTargeted),
      affectedHazards:
        affectedHazards.length > 0
          ? affectedHazards
          : ['None (No matched safety-critical artifacts in change scope)'],
      activeViolations,
      remediationGuidance: guidance,
      graphBlastRadius: blastRadius
        ? {
            trigger: blastRadius.triggerArtifact.title,
            severity: blastRadius.impactSeverity,
            traversalPath: blastRadius.traversalPath,
            blockedWorkItems: blastRadius.blockedWorkItemKeys,
            invalidatedTests: blastRadius.invalidatedTestKeys,
            executionTimeMs: blastRadius.executionTimeMs,
          }
        : undefined,
    };
  }
}

/**
 * Handler for manifest module: action (used by rovo:agent and rovo:mcp).
 * Enforces action allowlist, fails closed on missing/empty Forge accountId, verifies target-scoped
 * Jira/Confluence user read access, filters LIVE suites to authorized projects, sanitizes errors,
 * and never logs raw PR diff payloads.
 */
export interface CreateReverificationTaskActionResponse {
  success: boolean;
  createdIssueKey: string;
  linkedIssueKeys: string[];
  projectKey: string;
  hazardKey: string;
  alreadyExisted?: boolean;
  message: string;
}

export async function rovoActionHandler(
  payload?: RovoActionPayload | Record<string, unknown>,
  context?: RovoActionContext
): Promise<
  | HazardLineageResponse
  | IecComplianceVerificationResponse
  | CreateReverificationTaskActionResponse
  | RovoActionErrorResponse
> {
  const payloadObj = isPlainRecord(payload) ? payload : {};
  const payloadCtx = isPlainRecord(payloadObj.context) ? (payloadObj.context as RovoActionContext) : undefined;
  const ctx: RovoActionContext = context ?? payloadCtx ?? {};

  const actionKey = String(
    ctx.moduleKey || payloadCtx?.moduleKey || payloadObj.actionKey || payloadObj.key || ''
  ).trim();

  if (!ALLOWED_ROVO_ACTIONS.has(actionKey)) {
    return {
      error: `Unknown action: ${actionKey || '(missing)'}`,
      availableTools: [
        'get-hazard-lineage-action',
        'verify-iec-compliance-action',
        'create-reverification-task-action',
      ],
    };
  }

  const rawInputs: Record<string, unknown> = isPlainRecord(payloadObj.inputs)
    ? payloadObj.inputs
    : (() => {
        const { context: _ctx, actionKey: _ak, key: _k, ...rest } = payloadObj;
        return rest;
      })();

  const sanitizedInputs: RovoActionInputs = {
    ...(typeof rawInputs.issueKey === 'string' ? { issueKey: rawInputs.issueKey } : {}),
    ...(typeof rawInputs.hazardKey === 'string' ? { hazardKey: rawInputs.hazardKey } : {}),
    ...(typeof rawInputs.prDiff === 'string' ? { prDiff: rawInputs.prDiff } : {}),
    ...(typeof rawInputs.componentName === 'string' ? { componentName: rawInputs.componentName } : {}),
    ...(typeof rawInputs.summary === 'string' ? { summary: rawInputs.summary } : {}),
    ...(typeof rawInputs.reason === 'string' ? { reason: rawInputs.reason } : {}),
  };

  console.log('[MedTrace RovoAction] Dispatching action:', {
    actionKey,
    issueKey: sanitizedInputs.issueKey || sanitizedInputs.hazardKey || null,
    componentName: sanitizedInputs.componentName || null,
    hasPrDiff: Boolean(sanitizedInputs.prDiff),
  });

  try {
    const rawAccountId =
      context?.accountId ??
      context?.principal?.accountId ??
      payloadCtx?.accountId ??
      payloadCtx?.principal?.accountId;

    if (typeof rawAccountId === 'string' && rawAccountId.trim() === '') {
      throw new RovoAuthError('Unauthorized: Empty user accountId is not permitted.');
    }

    const accountId = typeof rawAccountId === 'string' ? rawAccountId.trim() : undefined;
    let scopedAuth: AuthorizedLiveSuiteResult | undefined;
    if (isForgeRuntime()) {
      if (!accountId) {
        throw new RovoAuthError(
          'Unauthorized: Authenticated user accountId is required in Forge runtime.'
        );
      }
      const extensionScope = extractRovoExtensionScope(ctx, payloadCtx);
      await assertRovoUserReadAccess(accountId, extensionScope);
      const rawSuite = await SeederService.getActiveComplianceSuite();
      scopedAuth = await scopeSuiteForRovoCaller(rawSuite, sanitizedInputs, extensionScope);
      if (
        actionKey !== 'create-reverification-task-action' &&
        actionKey !== 'create-reverification-task'
      ) {
        const accessiblePageIds = scopedAuth.unredactedSuite.traceLinks
          .map((l) => l.spec?.pageId)
          .filter(
            (pid): pid is string =>
              typeof pid === 'string' && pid.trim().length > 0 && !scopedAuth!.restrictedPageIds.has(pid)
          );
        if (accessiblePageIds.length > 0) {
          const reconciled = await LiveIngestionService.reconcileConfluenceSpecs(
            scopedAuth.unredactedSuite,
            {
              targetPageIds: accessiblePageIds,
              actorAccountId: accountId,
            }
          );
          if (reconciled !== scopedAuth.unredactedSuite) {
            scopedAuth = await scopeSuiteForRovoCaller(reconciled, sanitizedInputs, extensionScope);
          }
        }
      }
    }

    if (
      actionKey === 'create-reverification-task-action' ||
      actionKey === 'create-reverification-task'
    ) {
      if (!sanitizedInputs.hazardKey && !sanitizedInputs.issueKey) {
        return {
          error: 'Bad Request: hazardKey or issueKey is required to create a re-verification task.',
        };
      }
      if (isForgeRuntime()) {
        const extensionScope = extractRovoExtensionScope(ctx, payloadCtx);
        const requestedIssue = sanitizedInputs.issueKey?.trim().toUpperCase();
        const requestedHazard = sanitizedInputs.hazardKey?.trim().toUpperCase();
        const matchedHazardLink = requestedHazard
          ? scopedAuth?.unredactedSuite.traceLinks.find(
              (l) => l.hazard?.key?.trim().toUpperCase() === requestedHazard
            )
          : undefined;
        const targetProj =
          extractJiraProjectKeyFromRawKey(requestedIssue, 'JIRA_ISSUE') ||
          (matchedHazardLink ? extractPrimaryJiraProjectKeyFromLink(matchedHazardLink) : undefined) ||
          extensionScope.projectKey;
        const permRoute =
          requestedIssue && JIRA_ISSUE_KEY_RE.test(requestedIssue)
            ? route`/rest/api/3/mypermissions?issueKey=${requestedIssue}&permissions=EDIT_ISSUES,CREATE_ISSUES,ADMINISTER_PROJECTS`
            : targetProj
              ? route`/rest/api/3/mypermissions?projectKey=${targetProj}&permissions=EDIT_ISSUES,CREATE_ISSUES,ADMINISTER_PROJECTS`
              : route`/rest/api/3/mypermissions?permissions=EDIT_ISSUES,CREATE_ISSUES,ADMINISTER_PROJECTS`;
        const permResp = await api.asUser().requestJira(permRoute);
        if (permResp.status !== 200) {
          throw new RovoAuthError('Forbidden: Unable to verify Jira write permissions.');
        }
        const permData = (await permResp.json().catch(() => null)) as {
          permissions?: {
            EDIT_ISSUES?: { havePermission?: boolean };
            CREATE_ISSUES?: { havePermission?: boolean };
            ADMINISTER_PROJECTS?: { havePermission?: boolean };
          };
        } | null;
        const canWrite =
          permData?.permissions?.CREATE_ISSUES?.havePermission === true &&
          (permData?.permissions?.EDIT_ISSUES?.havePermission === true ||
            permData?.permissions?.ADMINISTER_PROJECTS?.havePermission === true);
        if (!canWrite) {
          throw new RovoAuthError(
            'Forbidden: Creating a Jira re-verification task requires CREATE_ISSUES and EDIT_ISSUES permissions.'
          );
        }
      }

      const created = await SeederService.createReverificationTask({
        hazardKey: sanitizedInputs.hazardKey,
        issueKey: sanitizedInputs.issueKey,
        summary: sanitizedInputs.summary,
        reason: sanitizedInputs.reason,
        actorAccountId: accountId || 'rovo-agent-user',
        callerMode: 'USER',
        authMethod: 'FORGE_USER_SESSION',
      });
      const matchedLink = created.summary.traceLinks.find(
        (l) => l.reverificationTaskKey === created.createdIssueKey
      );
      const failedLinks = created.failedLinkKeys ?? [];
      const missingLinks = created.missingLinkKeys ?? [];
      let actionMessage: string;
      if (failedLinks.length > 0) {
        actionMessage = `Created Jira re-verification task ${created.createdIssueKey} in project ${created.projectKey}, but failed to link: ${failedLinks.join(', ')}.${
          created.linkedIssueKeys.length > 0 ? ` Linked: ${created.linkedIssueKeys.join(', ')}.` : ''
        }`;
      } else if (created.alreadyExisted) {
        actionMessage =
          missingLinks.length > 0 || created.linksVerified === false
            ? `Found existing open Jira re-verification task ${created.createdIssueKey} in project ${created.projectKey}, but verified links are incomplete (linked: ${created.linkedIssueKeys.join(', ') || 'none'}; missing/unverified: ${missingLinks.join(', ') || 'unknown'}).`
            : `Found existing open Jira re-verification task ${created.createdIssueKey} in project ${created.projectKey}${
                created.linkedIssueKeys.length > 0 ? ` linked to ${created.linkedIssueKeys.join(', ')}.` : '.'
              }`;
      } else {
        actionMessage =
          created.linkedIssueKeys.length > 0
            ? `Created Jira re-verification task ${created.createdIssueKey} in project ${created.projectKey} linked to ${created.linkedIssueKeys.join(', ')}.`
            : `Created Jira re-verification task ${created.createdIssueKey} in project ${created.projectKey} (no native Jira issues were linked).`;
      }
      console.log('[MedTrace RovoAction] Completed:', {
        actionKey,
        success: created.success,
        createdIssueKey: created.createdIssueKey,
        alreadyExisted: Boolean(created.alreadyExisted),
        fullyLinked: created.fullyLinked ?? null,
        projectKey: created.projectKey,
      });
      return {
        success: created.success,
        ...(created.partialSuccess ? { partialSuccess: true } : {}),
        ...(typeof created.fullyLinked === 'boolean' ? { fullyLinked: created.fullyLinked } : {}),
        ...(typeof created.linksVerified === 'boolean' ? { linksVerified: created.linksVerified } : {}),
        createdIssueKey: created.createdIssueKey,
        linkedIssueKeys: created.linkedIssueKeys,
        ...(failedLinks.length > 0 ? { failedLinkKeys: failedLinks, linkErrors: created.linkErrors } : {}),
        ...(missingLinks.length > 0 ? { missingLinkKeys: missingLinks } : {}),
        projectKey: created.projectKey,
        hazardKey: matchedLink?.hazard.key || sanitizedInputs.hazardKey || '',
        ...(created.alreadyExisted ? { alreadyExisted: true } : {}),
        message: actionMessage,
      };
    }

    if (actionKey === 'get-hazard-lineage-action' || actionKey === 'get-hazard-lineage') {
      const rawCloudId = context?.cloudId ?? payloadCtx?.cloudId;
      const contextCloudId = typeof rawCloudId === 'string' && rawCloudId.trim() ? rawCloudId.trim() : undefined;
      const extensionType = String(ctx.extension?.type ?? payloadCtx?.extension?.type ?? '').toLowerCase();
      const cloudId = extensionType.startsWith('confluence')
        ? contextCloudId
        : resolveConfluenceCloudId();
      const res = await McpToolService.getHazardLineage(
        {
          issueKey: sanitizedInputs.issueKey,
          hazardKey: sanitizedInputs.hazardKey,
        },
        scopedAuth || cloudId
          ? {
              ...(scopedAuth ? { suite: scopedAuth.outboundSuite } : {}),
              ...(cloudId ? { cloudId } : {}),
            }
          : undefined
      );
      console.log('[MedTrace RovoAction] Completed:', {
        actionKey,
        initialized: res.initialized,
        datasetMode: res.datasetMode,
        found: 'found' in res ? res.found : true,
        totalHazards: 'totalHazards' in res ? res.totalHazards : undefined,
      });
      return res;
    }

    const res = await McpToolService.verifyIecCompliance(
      {
        prDiff: sanitizedInputs.prDiff,
        componentName: sanitizedInputs.componentName,
        issueKey: sanitizedInputs.issueKey,
      },
      scopedAuth
        ? {
            suite: scopedAuth.outboundSuite,
            unredactedSuite: scopedAuth.unredactedSuite,
            restrictedPageIds: scopedAuth.restrictedPageIds,
          }
        : undefined
    );
    console.log('[MedTrace RovoAction] Completed:', {
      actionKey,
      initialized: res.initialized,
      datasetMode: res.datasetMode,
      configuredChecksPassed: res.configuredChecksPassed,
      touchesSafetyCriticalCode: res.touchesSafetyCriticalCode,
      signatureDriftDetected: res.signatureDriftDetected,
    });
    return res;
  } catch (err: unknown) {
    if (err instanceof RovoAuthError) {
      return { error: err.message };
    }
    const errMsg = err instanceof Error ? err.message : 'Unknown error';
    console.error('[MedTrace RovoAction] Execution failed:', errMsg);
    return { error: 'Unable to execute MedTrace Rovo action.' };
  }
}
