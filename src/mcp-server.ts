import api, { route } from '@forge/api';
import { ComplianceEngine } from './compliance-engine';
import { isForgeRuntime } from './runtime';
import { SeederService } from './seeder';
import {
  BlastRadiusReport,
  ComplianceSummary,
  ConfluenceSpec,
  IsoHazard,
  JiraWorkItem,
  Part11Signature,
  RiskClass,
  TraceLink,
  VerificationTest,
} from './types';

const JIRA_PROJECT_KEY_RE = /^[A-Z][A-Z0-9_]{0,20}$/;
const JIRA_ISSUE_KEY_RE = /^[A-Z][A-Z0-9_]{0,20}-\d+$/;
const CONFLUENCE_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;

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
]);

const DEMO_KEYWORD_FALLBACKS: ReadonlyArray<{ specId: string; keywords: readonly string[] }> = [
  { specId: 'srs-104', keywords: ['bolus', 'clamp', 'motor', 'flow', 'pwm'] },
  { specId: 'srs-105', keywords: ['droplet', 'sensor', 'stall', 'photodiode'] },
  { specId: 'srs-106', keywords: ['oled', 'battery', 'voltage', 'spi'] },
];

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
}

export interface HazardLineageNotFoundResponse {
  found: false;
  datasetMode: 'DEMO' | 'LIVE';
  initialized: boolean;
  queriedKey: string;
  message: string;
  availableKeys: Array<{
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
  traceLinks: Array<{
    id: string;
    hazardKey: string;
    riskClass: RiskClass;
    severity: IsoHazard['severity'];
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
  canShipToClinicalProduction: boolean;
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
  const tokens = text.toLowerCase().match(/\b[a-z0-9][a-z0-9_-]{3,}\b/g) || [];
  return Array.from(new Set(tokens.filter((t) => !STOP_WORDS.has(t))));
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
  if (spaceId && !CONFLUENCE_ID_RE.test(spaceId)) {
    throw new RovoAuthError('Forbidden: Invalid Confluence spaceId in extension context.');
  }

  const contentId =
    typeof rawContentId === 'string' && rawContentId.trim() !== '' ? rawContentId.trim() : undefined;
  if (contentId && !CONFLUENCE_ID_RE.test(contentId)) {
    throw new RovoAuthError('Forbidden: Invalid Confluence contentId in extension context.');
  }

  return { extensionType, projectKey, issueKey, spaceId, contentId };
}

function extractProjectKeyFromJiraKey(key?: string): string | undefined {
  if (typeof key !== 'string') return undefined;
  const clean = key.trim().toUpperCase();
  if (!JIRA_ISSUE_KEY_RE.test(clean)) return undefined;
  return clean.split('-')[0];
}

async function checkJiraBrowsePermission(target?: {
  issueKey?: string;
  projectKey?: string;
}): Promise<boolean> {
  const permRoute = target?.issueKey
    ? route`/rest/api/3/mypermissions?issueKey=${target.issueKey}&permissions=BROWSE_PROJECTS`
    : target?.projectKey
    ? route`/rest/api/3/mypermissions?projectKey=${target.projectKey}&permissions=BROWSE_PROJECTS`
    : route`/rest/api/3/mypermissions?permissions=BROWSE_PROJECTS`;

  const permResp = await api.asUser().requestJira(permRoute);
  if (permResp.status !== 200) {
    return false;
  }

  const permData = (await permResp.json().catch(() => null)) as {
    active?: unknown;
    permissions?: { BROWSE_PROJECTS?: { havePermission?: unknown } };
  } | null;

  if (permData?.active === false) {
    throw new RovoAuthError('Forbidden: User account is inactive.');
  }
  return permData?.permissions?.BROWSE_PROJECTS?.havePermission === true;
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
): Promise<ComplianceSummary> {
  if (suite.datasetMode !== 'LIVE' || suite.initialized === false) {
    return suite;
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
    const allowed = await checkJiraBrowsePermission({ projectKey: clean });
    projectPermCache.set(clean, allowed);
    return allowed;
  };

  const hasIssueAccess = async (issueKey: string): Promise<boolean> => {
    const clean = issueKey.trim().toUpperCase();
    const issueProj = extractProjectKeyFromJiraKey(clean);
    if (scope.projectKey && issueProj && issueProj !== scope.projectKey) {
      return false;
    }
    if (issuePermCache.has(clean)) {
      return issuePermCache.get(clean) === true;
    }
    const allowed = await checkJiraBrowsePermission({ issueKey: clean });
    issuePermCache.set(clean, allowed);
    return allowed;
  };

  // Validate explicitly requested keys against target-level Jira permissions before returning or searching.
  const lookupKeys: string[] = [];
  if (inputs.issueKey && inputs.issueKey.trim() !== '') lookupKeys.push(inputs.issueKey.trim());
  if (inputs.hazardKey && inputs.hazardKey.trim() !== '') lookupKeys.push(inputs.hazardKey.trim());
  const textScan = `${inputs.prDiff || ''} ${inputs.componentName || ''} ${inputs.issueKey || ''}`;
  for (const keyToken of textScan.match(/\b[A-Za-z][A-Za-z0-9_]{0,20}-\d+\b/g) || []) {
    if (!lookupKeys.some((k) => k.toLowerCase() === keyToken.toLowerCase())) {
      lookupKeys.push(keyToken);
    }
  }

  for (const key of lookupKeys) {
    const lower = key.toLowerCase();
    const matchedLinks = suite.traceLinks.filter((l) => collectCanonicalLinkKeys(l).includes(lower));
    if (matchedLinks.length > 0) {
      for (const link of matchedLinks) {
        const workKey = link.work?.key?.trim().toUpperCase();
        if (workKey && JIRA_ISSUE_KEY_RE.test(workKey)) {
          if (!(await hasIssueAccess(workKey))) {
            throw new RovoAuthError(
              `Forbidden: Caller lacks Jira BROWSE_PROJECTS permission for target scope (${workKey}).`
            );
          }
        } else {
          const fallbackProj = extractProjectKeyFromJiraKey(link.hazard?.key);
          if (fallbackProj && !(await hasProjectAccess(fallbackProj))) {
            throw new RovoAuthError(
              `Forbidden: Caller lacks Jira BROWSE_PROJECTS permission for project ${fallbackProj}.`
            );
          }
        }
      }
    } else if (
      inputs.issueKey &&
      key.toLowerCase() === inputs.issueKey.trim().toLowerCase() &&
      JIRA_ISSUE_KEY_RE.test(key.trim().toUpperCase())
    ) {
      const cleanInputIssue = key.trim().toUpperCase();
      if (!(await hasIssueAccess(cleanInputIssue))) {
        throw new RovoAuthError(
          `Forbidden: Caller lacks Jira BROWSE_PROJECTS permission for requested issue ${cleanInputIssue}.`
        );
      }
    }
  }

  const authorizedLinks: TraceLink[] = [];
  for (const link of suite.traceLinks) {
    const projKey =
      extractProjectKeyFromJiraKey(link.work?.key) ??
      extractProjectKeyFromJiraKey(link.hazard?.key);
    if (!projKey) {
      if (!scope.projectKey) {
        authorizedLinks.push(link);
      }
      continue;
    }
    if (await hasProjectAccess(projKey)) {
      authorizedLinks.push(link);
    }
  }

  if (authorizedLinks.length === suite.traceLinks.length) {
    return suite;
  }

  return ComplianceEngine.generateComplianceReport(
    authorizedLinks,
    suite.datasetMode,
    scope.projectKey ? `${scope.projectKey} (${suite.projectName})` : suite.projectName,
    {
      storageFormat: suite.storageFormat,
      auditEntryCount: suite.auditEntryCount,
      auditHeadHash: suite.auditHeadHash,
      initialized: suite.initialized,
    }
  );
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
    options?: { suite?: ComplianceSummary }
  ): Promise<HazardLineageResponse> {
    const suite = options?.suite ?? (await SeederService.getActiveComplianceSuite());
    const initialized = suite.initialized ?? suite.traceLinks.length > 0;
    const rawIssueKey = typeof inputs?.issueKey === 'string' ? inputs.issueKey : '';
    const rawHazardKey = typeof inputs?.hazardKey === 'string' ? inputs.hazardKey : '';
    const lookupKey = (rawIssueKey || rawHazardKey).trim();

    if (lookupKey) {
      const lower = lookupKey.toLowerCase();
      const matches = suite.traceLinks.filter((l) => collectCanonicalLinkKeys(l).includes(lower));
      if (matches.length > 0) {
        const match = matches[0];
        return {
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
      }

      return {
        found: false,
        datasetMode: suite.datasetMode,
        initialized,
        queriedKey: lookupKey,
        message: `No trace link found for key "${lookupKey}" in project "${suite.projectName}".`,
        availableKeys: suite.traceLinks.map((l) => ({
          hazardKey: l.hazard.key,
          workKey: l.work.key,
          specId: l.spec.id,
          testKey: l.test.testKey,
        })),
      };
    }

    return {
      projectName: suite.projectName,
      datasetMode: suite.datasetMode,
      initialized,
      totalHazards: suite.totalHazards,
      verifiedPercentage: `${suite.verifiedPercentage}%`,
      releaseBlocked: suite.releaseBlocked,
      traceLinks: suite.traceLinks.map((l) => ({
        id: l.id,
        hazardKey: l.hazard.key,
        riskClass: l.hazard.riskClass,
        severity: l.hazard.severity,
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
   * Fails closed on uninitialized suites, restricts infusion-pump keyword fallbacks strictly to DEMO mode,
   * matches explicit keys + word-boundary tokens, and runs multi-trigger BFS blast-radius traversal.
   */
  public static async verifyIecCompliance(
    inputs?: {
      prDiff?: string;
      componentName?: string;
      issueKey?: string;
    },
    options?: { suite?: ComplianceSummary }
  ): Promise<IecComplianceVerificationResponse> {
    const suite = options?.suite ?? (await SeederService.getActiveComplianceSuite());
    const initialized = suite.initialized ?? suite.traceLinks.length > 0;

    if (!initialized || suite.traceLinks.length === 0) {
      return {
        standards: suite.standards,
        datasetMode: suite.datasetMode,
        initialized: false,
        canShipToClinicalProduction: false,
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
          'Run Live Jira + Confluence sync before verifying IEC 62304 compliance.',
        ],
        graphBlastRadius: undefined,
      };
    }

    const prDiff = typeof inputs?.prDiff === 'string' ? inputs.prDiff : '';
    const componentName = typeof inputs?.componentName === 'string' ? inputs.componentName : '';
    const issueKey = typeof inputs?.issueKey === 'string' ? inputs.issueKey : '';
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

    // 2. Dynamic word-boundary token matching + DEMO-only infusion-pump fallback keywords
    let triggerKeys: string[] = keyMatches;
    let tokenMatchedLinks: TraceLink[] = [];
    if (triggerKeys.length === 0) {
      tokenMatchedLinks = findLinksMatchingTextTokens(fullText, suite.traceLinks);
      if (tokenMatchedLinks.length > 0) {
        triggerKeys = Array.from(
          new Set(tokenMatchedLinks.map((l) => l.spec?.id || l.hazard.key).filter(Boolean))
        );
      } else if (suite.datasetMode === 'DEMO') {
        const inputWordSet = new Set(fullText.toLowerCase().match(/\b[a-z0-9]+\b/g) || []);
        triggerKeys = DEMO_KEYWORD_FALLBACKS.filter(
          (entry) =>
            entry.keywords.some((kw) => inputWordSet.has(kw)) &&
            suite.traceLinks.some((l) => l.spec?.id?.toLowerCase() === entry.specId)
        ).map((entry) => entry.specId);
      }
    }

    // 3. Execute deterministic BFS blast-radius traversal across all matched trigger keys
    const blastRadius =
      triggerKeys.length > 0
        ? ComplianceEngine.computeMultiBlastRadius(triggerKeys, suite)
        : undefined;

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
    const matchedLinks = suite.traceLinks.filter(
      (l) =>
        collectCanonicalLinkKeys(l).some((k) => triggerKeySet.has(k)) ||
        tokenMatchedLinks.includes(l)
    );

    const affectedHazardKeySet = new Set(
      (blastRadius?.affectedHazardKeys || []).map((k) => k.toUpperCase())
    );
    const traversedLinks =
      affectedHazardKeySet.size > 0
        ? suite.traceLinks.filter((l) => affectedHazardKeySet.has(l.hazard.key.toUpperCase()))
        : matchedLinks;

    const isTargeted = affectedHazards.length > 0 || matchedLinks.length > 0;
    const hasBlastRadiusGaps = Boolean(
      blastRadius &&
        (blastRadius.blockedWorkItemKeys.length > 0 ||
          blastRadius.invalidatedTestKeys.length > 0 ||
          blastRadius.invalidatedSignatureIds.length > 0)
    );
    const hasUnverifiedGaps = isTargeted
      ? matchedLinks.some((l) => l.complianceState !== 'VERIFIED') ||
        traversedLinks.some((l) => l.complianceState !== 'VERIFIED') ||
        hasBlastRadiusGaps
      : suite.releaseBlocked;

    const canShip = !hasUnverifiedGaps;

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
      canShipToClinicalProduction: canShip,
      verifiedCoveragePercentage: `${suite.verifiedPercentage}%`,
      classCSummary: {
        totalClassC: suite.classCCount,
        status: suite.releaseBlocked ? 'BLOCKED_BY_SAFETY_GATE' : 'CONFIGURED_CHECKS_PASSED',
      },
      signatureDriftDetected: suite.signatureDriftCount > 0,
      touchesSafetyCriticalCode: Boolean(isTargeted),
      affectedHazards:
        affectedHazards.length > 0
          ? affectedHazards
          : ['None (No matched safety-critical artifacts in change scope)'],
      activeViolations: suite.blockingReasons,
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
export async function rovoActionHandler(
  payload?: RovoActionPayload | Record<string, unknown>,
  context?: RovoActionContext
): Promise<HazardLineageResponse | IecComplianceVerificationResponse | RovoActionErrorResponse> {
  const payloadObj = isPlainRecord(payload) ? payload : {};
  const payloadCtx = isPlainRecord(payloadObj.context) ? (payloadObj.context as RovoActionContext) : undefined;
  const ctx: RovoActionContext = context ?? payloadCtx ?? {};

  const actionKey = String(
    ctx.moduleKey || payloadCtx?.moduleKey || payloadObj.actionKey || payloadObj.key || ''
  ).trim();

  if (!ALLOWED_ROVO_ACTIONS.has(actionKey)) {
    return {
      error: `Unknown action: ${actionKey || '(missing)'}`,
      availableTools: ['get-hazard-lineage-action', 'verify-iec-compliance-action'],
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
    let scopedSuite: ComplianceSummary | undefined;
    if (isForgeRuntime()) {
      if (!accountId) {
        throw new RovoAuthError(
          'Unauthorized: Authenticated user accountId is required in Forge runtime.'
        );
      }
      const extensionScope = extractRovoExtensionScope(ctx, payloadCtx);
      await assertRovoUserReadAccess(accountId, extensionScope);
      const rawSuite = await SeederService.getActiveComplianceSuite();
      scopedSuite = await scopeSuiteForRovoCaller(rawSuite, sanitizedInputs, extensionScope);
    }

    if (actionKey === 'get-hazard-lineage-action' || actionKey === 'get-hazard-lineage') {
      return await McpToolService.getHazardLineage(
        {
          issueKey: sanitizedInputs.issueKey,
          hazardKey: sanitizedInputs.hazardKey,
        },
        scopedSuite ? { suite: scopedSuite } : undefined
      );
    }

    return await McpToolService.verifyIecCompliance(
      {
        prDiff: sanitizedInputs.prDiff,
        componentName: sanitizedInputs.componentName,
        issueKey: sanitizedInputs.issueKey,
      },
      scopedSuite ? { suite: scopedSuite } : undefined
    );
  } catch (err: unknown) {
    if (err instanceof RovoAuthError) {
      return { error: err.message };
    }
    const errMsg = err instanceof Error ? err.message : 'Unknown error';
    console.error('[MedTrace RovoAction] Execution failed:', errMsg);
    return { error: 'Unable to execute MedTrace Rovo action.' };
  }
}
