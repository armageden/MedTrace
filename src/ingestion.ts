import api, { route } from '@forge/api';
import { kvs } from '@forge/kvs';
import { ComplianceEngine } from './compliance-engine';
import { isKvsConflictError, sha256Hex } from './crypto-utils';
import { isForgeRuntime } from './runtime';
import { JIRA_ISSUE_KEY_RE } from './seeder-identity';
import {
  BaselineMutationRecord,
  commitSuiteMutation,
  mapJiraStatusToWorkStatus,
  SeederService,
  SignedSpecBaseline,
} from './seeder';
import { TeamworkGraphService } from './teamwork-graph';
import {
  ConfluenceSpec,
  GraphMetadata,
  IsoHazard,
  IssueGraphContextResult,
  JiraWorkItem,
  LiveSyncOptions,
  LiveSyncResult,
  Part11Signature,
  RiskClass,
  TraceLink,
  VerificationTest,
} from './types';

export const DEFAULT_SYNC_MAX_ISSUES = 250;
export const MAX_SYNC_MAX_ISSUES = 500;
export const LIVE_SYNC_BUDGET_MS = 15_000;
export const LIVE_SYNC_CONCURRENCY_BATCH_SIZE = 5;
const JIRA_PAGE_SIZE = 50;
const CONFLUENCE_PAGE_SIZE = 50;
const MAX_PAGINATION_PAGES = 100;
const MAX_CAS_RETRY_ATTEMPTS = 3;
export const SYNC_CURSOR_KEY_PREFIX = 'medtrace:ingestion:cursor:';

export function getSyncCursorKey(projectKey?: string): string {
  const clean = typeof projectKey === 'string' && projectKey.trim() !== '' ? projectKey.trim().toUpperCase() : '';
  return `${SYNC_CURSOR_KEY_PREFIX}${clean || 'GLOBAL'}`;
}

const PROJECT_KEY_RE = /^[A-Z][A-Z0-9_]{0,20}$/;

const DEFAULT_HAZARD_ISSUE_TYPES = new Set<string>([
  'hazard',
  'risk',
  'safety hazard',
  'safety-hazard',
]);

const DEFAULT_HAZARD_LABEL_PATTERNS = [
  'class-a',
  'class_a',
  'class-b',
  'class_b',
  'class-c',
  'class_c',
  'critical-safety',
  'iso-14971',
  'iec-62304',
  'medtrace-hazard',
];

export interface SyncFromAtlassianOptions extends LiveSyncOptions {
  hazardLabels?: string[];
  hazardIssueTypes?: string[];
  maxIssues?: number;
}

export interface SafetyTrackFilterOptions {
  existingByWorkKey?: Map<string, TraceLink[]>;
  hazardLabels?: string[];
  hazardIssueTypes?: string[];
  includeUntaggedIssues?: boolean;
  hasConfluenceLinks?: boolean;
}

export interface ConfluencePageUpdatedEvent {
  content?: { id?: string | number };
  page?: { id?: string | number };
  atlassianId?: string;
  context?: { accountId?: string };
  contentHash?: string;
  storageBody?: string;
}

export interface ConfluencePageUpdatedResult {
  processed: boolean;
  pageId?: string;
  affectedHazards: string[];
}

export interface JiraIssueUpdatedEvent {
  eventType?: string;
  issue?: { id?: string | number; key?: string };
  issueLink?: {
    sourceIssueId?: string | number;
    destinationIssueId?: string | number;
  };
  atlassianId?: string;
  context?: { accountId?: string };
}

export interface JiraIssueUpdatedResult {
  processed: boolean;
  issueKey?: string;
  affectedHazards: string[];
}

interface JiraIssueLinkEntry {
  id?: string;
  type?: { name?: string; inward?: string; outward?: string };
  inwardIssue?: JiraApiIssue;
  outwardIssue?: JiraApiIssue;
}

interface JiraApiIssue {
  id?: string | number;
  key?: string;
  self?: string;
  fields?: {
    summary?: string;
    status?: {
      name?: string;
      statusCategory?: { key?: string; name?: string };
    };
    assignee?: { displayName?: string } | null;
    labels?: unknown[];
    priority?: { name?: string };
    issuetype?: { name?: string };
    project?: { name?: string; key?: string };
    issuelinks?: unknown[];
  };
}

interface ConfluencePageData {
  id: string | number;
  title?: string;
  version?: { number?: number; createdAt?: string };
  body?: { storage?: { value?: string } };
}

type ForgeApiClient = ReturnType<typeof api.asApp> | ReturnType<typeof api.asUser>;

function stripStorageMarkup(storageHtml: string): string {
  return storageHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 220);
}

function inferRiskClass(labels: string[]): {
  riskClass: RiskClass;
  safetyClassAssigned?: boolean;
} {
  const lowerLabels = labels.map((l) => l.toLowerCase());

  if (lowerLabels.some((l) => l.includes('class-c') || l.includes('class_c') || l.includes('critical-safety'))) {
    return { riskClass: 'CLASS_C' };
  }
  if (lowerLabels.some((l) => l.includes('class-b') || l.includes('class_b'))) {
    return { riskClass: 'CLASS_B' };
  }
  if (lowerLabels.some((l) => l.includes('class-a') || l.includes('class_a'))) {
    return { riskClass: 'CLASS_A' };
  }
  return {
    riskClass: 'CLASS_C',
    safetyClassAssigned: false,
  };
}

const DEFAULT_TEST_ISSUE_TYPES = new Set<string>([
  'test',
  'verification',
  'verification test',
  'test case',
  'test execution',
  'qa test',
  'sub-test',
]);

function normalizeStringArray(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const out: string[] = [];
  for (const item of values) {
    if (typeof item === 'string') {
      const trimmed = item.trim();
      if (trimmed) out.push(trimmed);
    }
  }
  return out;
}

interface ResolvedJiraLinkedIssue {
  key: string;
  id: string;
  summary: string;
  statusName: string;
  statusObj?: NonNullable<JiraApiIssue['fields']>['status'];
  issueTypeName: string;
  labels: string[];
  linkTypeName: string;
  linkDirection: 'inward' | 'outward';
  relationshipLabel: string;
  self?: string;
}

function isPureHazardIssue(issue: { issueTypeName?: string; labels?: string[] }): boolean {
  const typeLower = (issue.issueTypeName || '').trim().toLowerCase();
  if (typeLower && DEFAULT_HAZARD_ISSUE_TYPES.has(typeLower)) {
    return true;
  }
  const labelsLower = (issue.labels || []).map((l) => l.toLowerCase());
  return labelsLower.some(
    (l) => l === 'medtrace-hazard' || l === 'hazard' || l === 'iso-14971-hazard'
  );
}

function isPureVerificationTestIssue(issue: { issueTypeName?: string; labels?: string[] }): boolean {
  const typeLower = (issue.issueTypeName || '').trim().toLowerCase();
  if (typeLower && DEFAULT_TEST_ISSUE_TYPES.has(typeLower)) {
    return true;
  }
  const labelsLower = (issue.labels || []).map((l) => l.toLowerCase());
  return labelsLower.some(
    (l) =>
      l === 'medtrace-test' ||
      l === 'verification-test' ||
      l === 'hil-test' ||
      l === 'medtrace-reverification'
  );
}

function extractLinkedIssueCandidates(
  rawLinks: unknown[],
  issueByKey: Map<string, JiraApiIssue>
): ResolvedJiraLinkedIssue[] {
  if (!Array.isArray(rawLinks) || rawLinks.length === 0) return [];
  const out: ResolvedJiraLinkedIssue[] = [];
  const seen = new Set<string>();

  for (const raw of rawLinks) {
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as JiraIssueLinkEntry;
    const linkTypeName = String(entry.type?.name || '').trim();
    const inwardLabel = String(entry.type?.inward || '').trim();
    const outwardLabel = String(entry.type?.outward || '').trim();

    const pairs: Array<{
      issue?: JiraApiIssue;
      direction: 'inward' | 'outward';
      relLabel: string;
    }> = [
      { issue: entry.inwardIssue, direction: 'inward', relLabel: inwardLabel || linkTypeName },
      { issue: entry.outwardIssue, direction: 'outward', relLabel: outwardLabel || linkTypeName },
    ];

    for (const pair of pairs) {
      const key = typeof pair.issue?.key === 'string' ? pair.issue.key.trim().toUpperCase() : '';
      if (!key || seen.has(`${key}:${pair.direction}`)) continue;
      seen.add(`${key}:${pair.direction}`);

      const enriched = issueByKey.get(key);
      const fields = pair.issue?.fields || {};
      const enrichedFields = enriched?.fields || {};
      const summary =
        (typeof enrichedFields.summary === 'string' && enrichedFields.summary) ||
        (typeof fields.summary === 'string' && fields.summary) ||
        key;
      const statusObj = enrichedFields.status || fields.status;
      const statusName = String(statusObj?.name || '').trim();
      const issueTypeName = String(
        enrichedFields.issuetype?.name || fields.issuetype?.name || ''
      ).trim();
      const labels = normalizeStringArray(enrichedFields.labels ?? fields.labels);
      const id = String(enriched?.id || pair.issue?.id || key.toLowerCase());
      const self = enriched?.self || pair.issue?.self;

      out.push({
        key,
        id,
        summary,
        statusName,
        statusObj,
        issueTypeName,
        labels,
        linkTypeName,
        linkDirection: pair.direction,
        relationshipLabel: pair.relLabel,
        ...(self ? { self } : {}),
      });
    }
  }

  return out;
}

function resolveLinkedHazardAndTest(
  linkedIssues: ResolvedJiraLinkedIssue[]
): {
  linkedHazard?: ResolvedJiraLinkedIssue;
  linkedTest?: ResolvedJiraLinkedIssue;
  linkedReverification?: ResolvedJiraLinkedIssue;
} {
  let linkedHazard: ResolvedJiraLinkedIssue | undefined;
  let linkedTest: ResolvedJiraLinkedIssue | undefined;
  let linkedReverification: ResolvedJiraLinkedIssue | undefined;

  for (const item of linkedIssues) {
    const rel = `${item.linkTypeName} ${item.relationshipLabel}`.toLowerCase();
    const isRev = item.labels.some((l) => l.toLowerCase() === 'medtrace-reverification');
    if (isRev && !linkedReverification) {
      linkedReverification = item;
    }

    const itemIsTest = isPureVerificationTestIssue(item);
    const itemIsHazard = isPureHazardIssue(item);

    if (
      !linkedHazard &&
      !itemIsTest &&
      (itemIsHazard || /\b(mitigat|hazard|risk)\b/i.test(rel))
    ) {
      linkedHazard = item;
      continue;
    }

    if (
      !linkedTest &&
      !itemIsHazard &&
      (itemIsTest || /\b(test(s|ed|ing)?|verif(y|ies|ied|ication))\b/i.test(rel))
    ) {
      linkedTest = item;
    }
  }

  return { linkedHazard, linkedTest, linkedReverification };
}

function inferTestTypeFromIssue(
  riskClass: RiskClass,
  labels: string[],
  issueTypeName?: string
): VerificationTest['testType'] {
  const combined = `${issueTypeName || ''} ${labels.join(' ')}`.toLowerCase();
  if (combined.includes('hil')) return 'Automated HIL (Hardware-in-Loop)';
  if (combined.includes('clinical')) return 'Clinical Validation';
  if (combined.includes('unit')) return 'Unit Test';
  return riskClass === 'CLASS_C' ? 'Automated HIL (Hardware-in-Loop)' : 'Integration Test';
}

function extractCloudIdFromSelfUrl(selfUrl?: string): string | undefined {
  if (typeof selfUrl !== 'string') return undefined;
  const match = selfUrl.match(/\/ex\/jira\/([0-9a-f-]{8,})/i);
  return match?.[1];
}

/**
 * Determines whether a Jira issue should be ingested into MedTrace compliance tracking.
 * Prevents fabricating `HAZ-*` entries for untagged everyday Jira tickets unless `includeUntaggedIssues: true`
 * or the issue is already tracked, carries a safety/risk label or hazard issue type, or links to Confluence SRS pages.
 */
export function isSafetyTrackedIssue(
  issue: JiraApiIssue,
  options: SafetyTrackFilterOptions = {}
): boolean {
  if (options.includeUntaggedIssues === true) {
    return true;
  }

  const issueKey = typeof issue?.key === 'string' ? issue.key.trim().toUpperCase() : '';
  if (!issueKey) {
    return false;
  }

  if (options.existingByWorkKey?.has(issueKey)) {
    return true;
  }

  if (options.hasConfluenceLinks === true) {
    return true;
  }

  const issueTypeName = String(issue?.fields?.issuetype?.name || '').trim().toLowerCase();
  const customIssueTypes = new Set<string>(
    normalizeStringArray(options.hazardIssueTypes).map((t) => t.toLowerCase())
  );
  if (
    issueTypeName &&
    (DEFAULT_HAZARD_ISSUE_TYPES.has(issueTypeName) || customIssueTypes.has(issueTypeName))
  ) {
    return true;
  }

  const labels = normalizeStringArray(issue?.fields?.labels).map((l) => l.toLowerCase());
  const customLabels = new Set<string>(
    normalizeStringArray(options.hazardLabels).map((l) => l.toLowerCase())
  );
  if (
    labels.some(
      (label) =>
        customLabels.has(label) ||
        DEFAULT_HAZARD_LABEL_PATTERNS.some((pattern) => label.includes(pattern))
    )
  ) {
    return true;
  }

  return false;
}

function extractCursorFromNextLink(nextLink: unknown): string | undefined {
  if (typeof nextLink !== 'string') return undefined;
  const trimmed = nextLink.trim();
  if (!trimmed) return undefined;
  try {
    const parsed = new URL(trimmed, 'https://confluence.invalid');
    const cursor = parsed.searchParams.get('cursor');
    if (cursor && cursor.trim() !== '') {
      return cursor.trim();
    }
  } catch {
    // Fall back to regex extraction
  }
  const match = trimmed.match(/[?&]cursor=([^&#]+)/i);
  if (match?.[1]) {
    try {
      return decodeURIComponent(match[1]);
    } catch {
      return match[1];
    }
  }
  return undefined;
}

function isBaselineInvalidated(baseline: SignedSpecBaseline | undefined): boolean {
  if (!baseline?.invalidatedAt) return false;
  const invMs = Date.parse(baseline.invalidatedAt);
  const signedMs = baseline.signedAt ? Date.parse(baseline.signedAt) : NaN;
  if (!Number.isFinite(invMs) || !Number.isFinite(signedMs)) return true;
  return signedMs <= invMs;
}

function isSignatureTimestampInvalidated(signature: Part11Signature | undefined): boolean {
  if (!signature?.invalidatedAt) return false;
  const invMs = Date.parse(signature.invalidatedAt);
  const signedMs = signature.signedAt ? Date.parse(signature.signedAt) : NaN;
  if (!Number.isFinite(invMs) || !Number.isFinite(signedMs)) return true;
  return signedMs <= invMs;
}

function isConcurrencyError(err: unknown): boolean {
  if (isKvsConflictError(err)) return true;
  const msg = err instanceof Error ? err.message : String(err ?? '');
  return /Concurrent modification|version lock conflict/i.test(msg);
}

function validateAndNormalizeOptions(options: SyncFromAtlassianOptions): {
  projectKey?: string;
  spaceId?: string;
  jql: string;
  hasCustomJql: boolean;
  includeUntaggedIssues: boolean;
  callerMode: 'USER' | 'APP';
  hazardLabels?: string[];
  hazardIssueTypes?: string[];
  maxIssues: number;
  resumeFromCursor: boolean;
  pageToken?: string;
} {
  let projectKey: string | undefined;
  if (typeof options.projectKey === 'string' && options.projectKey.trim() !== '') {
    projectKey = options.projectKey.trim().toUpperCase();
    if (!PROJECT_KEY_RE.test(projectKey)) {
      throw new Error(
        `Invalid Jira projectKey "${options.projectKey}". Expected 1-21 characters matching /^[A-Z][A-Z0-9_]{0,20}$/.`
      );
    }
  }

  let spaceId: string | undefined;
  if (typeof options.spaceId === 'string' && options.spaceId.trim() !== '') {
    spaceId = options.spaceId.trim();
    if (spaceId.includes('..') || /[\\/?#]/.test(spaceId)) {
      throw new Error(`Invalid Confluence spaceId "${options.spaceId}".`);
    }
  }

  let maxIssues = DEFAULT_SYNC_MAX_ISSUES;
  if (options.maxIssues !== undefined) {
    if (!Number.isFinite(options.maxIssues) || Math.floor(options.maxIssues) < 1) {
      throw new Error(`Invalid maxIssues "${options.maxIssues}". Must be between 1 and ${MAX_SYNC_MAX_ISSUES}.`);
    }
    maxIssues = Math.min(MAX_SYNC_MAX_ISSUES, Math.floor(options.maxIssues));
  }

  const defaultJql = projectKey
    ? `project = "${projectKey}" ORDER BY updated DESC`
    : 'ORDER BY updated DESC';
  const trimmedJql = options.jql?.trim();
  const jql = trimmedJql || defaultJql;
  const hasCustomJql = Boolean(trimmedJql && trimmedJql !== defaultJql);

  const pageToken =
    typeof options.pageToken === 'string' && options.pageToken.trim() !== ''
      ? options.pageToken.trim()
      : undefined;

  return {
    projectKey,
    spaceId,
    jql,
    hasCustomJql,
    includeUntaggedIssues: options.includeUntaggedIssues === true,
    callerMode: options.callerMode === 'APP' ? 'APP' : 'USER',
    hazardLabels: options.hazardLabels,
    hazardIssueTypes: options.hazardIssueTypes,
    maxIssues,
    resumeFromCursor: options.resumeFromCursor === true,
    ...(pageToken ? { pageToken } : {}),
  };
}

async function fetchAllJiraIssues(
  client: ForgeApiClient,
  jql: string,
  maxIssues: number,
  startedAt: number,
  warnings: string[],
  initialPageToken?: string
): Promise<{ issues: JiraApiIssue[]; truncated: boolean; nextPageToken?: string }> {
  const issues: JiraApiIssue[] = [];
  const seenTokens = new Set<string>();
  let nextPageToken: string | undefined = initialPageToken;
  if (initialPageToken) {
    seenTokens.add(initialPageToken);
  }
  let resumePageToken: string | undefined;
  let truncated = false;

  for (let page = 0; page < MAX_PAGINATION_PAGES; page++) {
    if (page > 0 && Date.now() - startedAt >= LIVE_SYNC_BUDGET_MS) {
      truncated = true;
      resumePageToken = nextPageToken;
      warnings.push(
        `Live sync exceeded ${LIVE_SYNC_BUDGET_MS}ms fetch budget during Jira pagination; results truncated.`
      );
      break;
    }

    const jiraRoute = nextPageToken
      ? route`/rest/api/3/search/jql?jql=${jql}&maxResults=${JIRA_PAGE_SIZE}&fields=summary,status,assignee,labels,issuetype,project,issuelinks&nextPageToken=${nextPageToken}`
      : route`/rest/api/3/search/jql?jql=${jql}&maxResults=${JIRA_PAGE_SIZE}&fields=summary,status,assignee,labels,issuetype,project,issuelinks`;

    const jiraResp = await client.requestJira(jiraRoute);
    if (jiraResp.status !== 200) {
      const errText = await jiraResp.text();
      throw new Error(`Jira search failed (HTTP ${jiraResp.status}): ${errText.slice(0, 200)}`);
    }

    const jiraJson = (await jiraResp.json()) as {
      issues?: JiraApiIssue[];
      nextPageToken?: string;
      isLast?: boolean;
    };
    const pageIssues = Array.isArray(jiraJson?.issues) ? jiraJson.issues : [];
    issues.push(...pageIssues);

    if (issues.length >= maxIssues) {
      const candidateToken =
        typeof jiraJson?.nextPageToken === 'string' && jiraJson.nextPageToken.trim() !== ''
          ? jiraJson.nextPageToken.trim()
          : undefined;
      const hadMore =
        issues.length > maxIssues || (Boolean(candidateToken) && jiraJson?.isLast !== true);
      if (hadMore) {
        truncated = true;
        if (issues.length === maxIssues && candidateToken && jiraJson?.isLast !== true) {
          resumePageToken = candidateToken;
        }
        warnings.push(`Jira issue scan reached maxIssues cap (${maxIssues}); results truncated.`);
      }
      break;
    }

    const candidateToken =
      typeof jiraJson?.nextPageToken === 'string' && jiraJson.nextPageToken.trim() !== ''
        ? jiraJson.nextPageToken.trim()
        : undefined;
    if (!candidateToken || jiraJson?.isLast === true || pageIssues.length === 0) {
      break;
    }
    if (seenTokens.has(candidateToken)) {
      truncated = true;
      warnings.push('Jira pagination returned a duplicate nextPageToken; stopping pagination.');
      break;
    }
    seenTokens.add(candidateToken);
    nextPageToken = candidateToken;
  }

  return {
    issues: issues.length > maxIssues ? issues.slice(0, maxIssues) : issues,
    truncated,
    ...(truncated && resumePageToken ? { nextPageToken: resumePageToken } : {}),
  };
}

async function fetchJiraIssuesByKeys(
  client: ForgeApiClient,
  keys: string[],
  startedAt: number,
  warnings: string[]
): Promise<{ issues: JiraApiIssue[]; remainingKeys: string[]; truncated: boolean }> {
  const cleanKeys = Array.from(
    new Set(
      keys
        .map((k) => (typeof k === 'string' ? k.trim().toUpperCase() : ''))
        .filter((k) => JIRA_ISSUE_KEY_RE.test(k))
    )
  );
  const issues: JiraApiIssue[] = [];
  for (let i = 0; i < cleanKeys.length; i += JIRA_PAGE_SIZE) {
    if (i > 0 && Date.now() - startedAt >= LIVE_SYNC_BUDGET_MS) {
      warnings.push(
        `Live sync exceeded ${LIVE_SYNC_BUDGET_MS}ms fetch budget while resuming pending issues; results truncated.`
      );
      return { issues, remainingKeys: cleanKeys.slice(i), truncated: true };
    }
    const batchKeys = cleanKeys.slice(i, i + JIRA_PAGE_SIZE);
    const jql = `key in (${batchKeys.map((k) => `"${k}"`).join(', ')})`;
    const jiraResp = await client.requestJira(
      route`/rest/api/3/search/jql?jql=${jql}&maxResults=${JIRA_PAGE_SIZE}&fields=summary,status,assignee,labels,issuetype,project,issuelinks`
    );
    if (jiraResp.status !== 200) {
      const errText = await jiraResp.text();
      throw new Error(`Jira resume search failed (HTTP ${jiraResp.status}): ${errText.slice(0, 200)}`);
    }
    const jiraJson = (await jiraResp.json()) as { issues?: JiraApiIssue[] };
    if (Array.isArray(jiraJson?.issues)) {
      issues.push(...jiraJson.issues);
    }
  }
  return { issues, remainingKeys: [], truncated: false };
}

async function fetchAllConfluencePages(
  client: ForgeApiClient,
  spaceId: string | undefined,
  startedAt: number,
  warnings: string[]
): Promise<{ pages: ConfluencePageData[]; truncated: boolean }> {
  const pages: ConfluencePageData[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  let truncated = false;

  for (let page = 0; page < MAX_PAGINATION_PAGES; page++) {
    if (page > 0 && Date.now() - startedAt >= LIVE_SYNC_BUDGET_MS) {
      truncated = true;
      warnings.push(
        `Live sync exceeded ${LIVE_SYNC_BUDGET_MS}ms fetch budget during Confluence pagination; results truncated.`
      );
      break;
    }

    const pageRoute = spaceId
      ? cursor
        ? route`/wiki/api/v2/spaces/${spaceId}/pages?body-format=storage&limit=${CONFLUENCE_PAGE_SIZE}&cursor=${cursor}`
        : route`/wiki/api/v2/spaces/${spaceId}/pages?body-format=storage&limit=${CONFLUENCE_PAGE_SIZE}`
      : cursor
        ? route`/wiki/api/v2/pages?body-format=storage&limit=${CONFLUENCE_PAGE_SIZE}&cursor=${cursor}`
        : route`/wiki/api/v2/pages?body-format=storage&limit=${CONFLUENCE_PAGE_SIZE}`;

    const confResp = await client.requestConfluence(pageRoute);
    if (confResp.status !== 200) {
      if (page === 0) {
        warnings.push(
          `Confluence pages query returned HTTP ${confResp.status}; proceeding with Jira remote links only.`
        );
      } else {
        truncated = true;
        warnings.push(
          `Confluence pagination page returned HTTP ${confResp.status}; proceeding with partial page set.`
        );
      }
      break;
    }

    const confJson = (await confResp.json()) as {
      results?: ConfluencePageData[];
      _links?: { next?: string };
    };
    const results = Array.isArray(confJson?.results) ? confJson.results : [];
    pages.push(...results);

    const nextCursor = extractCursorFromNextLink(confJson?._links?.next);
    if (!nextCursor || results.length === 0) {
      break;
    }
    if (seenCursors.has(nextCursor)) {
      truncated = true;
      warnings.push('Confluence pagination returned a duplicate cursor; stopping pagination.');
      break;
    }
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  }

  return { pages, truncated };
}

function buildBaselineMutationForInvalidation(
  hazardKey: string,
  specId: string,
  pageId: string | undefined,
  newHash: string,
  invalidatedAt: string,
  reason: string
): BaselineMutationRecord {
  return {
    action: 'INVALIDATE',
    invalidation: {
      hazardKey,
      specId,
      ...(pageId ? { pageId } : {}),
      newHash,
      invalidatedAt,
      reason,
    },
  };
}

function cloneTraceLink(link: TraceLink): TraceLink {
  return JSON.parse(JSON.stringify(link)) as TraceLink;
}

export class LiveIngestionService {
  /**
   * Synchronizes real Jira issues + Confluence SRS pages (with SHA-256 hashing over `body.storage.value`)
   * into an active LIVE compliance suite persisted in sharded Forge KVS.
   */
  public static async syncFromAtlassian(
    options: SyncFromAtlassianOptions = {},
    actorAccountId: string = 'system:live-sync'
  ): Promise<LiveSyncResult> {
    if (!isForgeRuntime()) {
      throw new Error('LiveIngestionService.syncFromAtlassian requires an active Atlassian Forge runtime.');
    }

    const startedAt = Date.now();
    const warnings: string[] = [];
    const normalized = validateAndNormalizeOptions(options);
    const client: ForgeApiClient = normalized.callerMode === 'APP' ? api.asApp() : api.asUser();
    const part11Secret = (process.env.MEDTRACE_PART11_SECRET || '').trim();
    const cursorKey = getSyncCursorKey(normalized.projectKey);

    let initialPageToken = normalized.pageToken;
    let pendingIssueKeys: string[] = [];
    let pendingCoversInitialPage = false;
    let resumedFromCursor = Boolean(initialPageToken);
    if (!initialPageToken && normalized.resumeFromCursor) {
      try {
        const storedCursor = await kvs.get<{
          nextPageToken?: string;
          pendingIssueKeys?: string[];
          pendingCoversInitialPage?: boolean;
          jql?: string;
        }>(cursorKey);
        if (
          storedCursor &&
          (!storedCursor.jql || storedCursor.jql === normalized.jql)
        ) {
          if (typeof storedCursor.nextPageToken === 'string' && storedCursor.nextPageToken.trim() !== '') {
            initialPageToken = storedCursor.nextPageToken.trim();
          }
          if (Array.isArray(storedCursor.pendingIssueKeys)) {
            pendingIssueKeys = storedCursor.pendingIssueKeys
              .map((k) => (typeof k === 'string' ? k.trim().toUpperCase() : ''))
              .filter((k) => JIRA_ISSUE_KEY_RE.test(k));
          }
          pendingCoversInitialPage = storedCursor.pendingCoversInitialPage === true;
          resumedFromCursor = Boolean(initialPageToken || pendingIssueKeys.length > 0);
        }
      } catch {
        // Ignore missing/unreadable cursor and start cleanly from page 1.
      }
    }

    // 1. Fetch pending unprocessed issues (if resuming from mid-enrichment timeout) and/or paginate Jira issues
    let pendingIssues: JiraApiIssue[] = [];
    let remainingFetchKeys: string[] = [];
    let pendingTruncated = false;
    if (pendingIssueKeys.length > 0) {
      const pendingRes = await fetchJiraIssuesByKeys(client, pendingIssueKeys, startedAt, warnings);
      pendingIssues = pendingRes.issues;
      remainingFetchKeys = pendingRes.remainingKeys;
      pendingTruncated = pendingRes.truncated;
    }

    const tokenForNextJiraPage = pendingCoversInitialPage ? undefined : initialPageToken;
    const shouldFetchJiraPages = !resumedFromCursor || Boolean(tokenForNextJiraPage);
    const jiraResult =
      shouldFetchJiraPages && !pendingTruncated
        ? await fetchAllJiraIssues(
            client,
            normalized.jql,
            normalized.maxIssues,
            startedAt,
            warnings,
            tokenForNextJiraPage
          )
        : {
            issues: [] as JiraApiIssue[],
            truncated: pendingTruncated || Boolean(tokenForNextJiraPage),
            ...(tokenForNextJiraPage ? { nextPageToken: tokenForNextJiraPage } : {}),
          };
    const issues = [...pendingIssues, ...jiraResult.issues];
    let truncated = pendingTruncated || jiraResult.truncated;

    // 2. Paginate Confluence pages ONLY when spaceId is explicitly scoped; otherwise fetch linked pageIds
    // on demand and lazily fall back to bounded space/first-page lookup only for SRS-\d+ heuristic summaries.
    let pages: ConfluencePageData[] = [];
    if (normalized.spaceId) {
      const confResult = await fetchAllConfluencePages(
        client,
        normalized.spaceId,
        startedAt,
        warnings
      );
      pages = confResult.pages;
      if (confResult.truncated) {
        truncated = true;
      }
    }

    const pageCache = new Map<string, ConfluencePageData | null>();
    for (const p of pages) {
      if (p?.id !== undefined && p?.id !== null) {
        pageCache.set(String(p.id), p);
      }
    }
    const pageFetchInflight = new Map<string, Promise<ConfluencePageData | null>>();
    let heuristicPagesPromise: Promise<ConfluencePageData[]> | null = null;

    const getHeuristicCandidatePages = async (): Promise<ConfluencePageData[]> => {
      if (normalized.spaceId) {
        return pages;
      }
      if (!heuristicPagesPromise) {
        heuristicPagesPromise = (async (): Promise<ConfluencePageData[]> => {
          const collected: ConfluencePageData[] = [];
          try {
            if (normalized.projectKey) {
              const spaceResp = await client.requestConfluence(
                route`/wiki/api/v2/spaces?keys=${normalized.projectKey}&limit=5`
              );
              if (spaceResp.status === 200) {
                const spaceJson = (await spaceResp.json()) as {
                  results?: Array<{ id?: string | number }>;
                };
                const matchedSpaceId =
                  Array.isArray(spaceJson?.results) && spaceJson.results[0]?.id !== undefined
                    ? String(spaceJson.results[0].id).trim()
                    : '';
                if (matchedSpaceId) {
                  const spacePages = await fetchAllConfluencePages(
                    client,
                    matchedSpaceId,
                    startedAt,
                    warnings
                  );
                  if (spacePages.truncated) {
                    truncated = true;
                  }
                  collected.push(...spacePages.pages);
                  for (const p of collected) {
                    if (p?.id !== undefined && p?.id !== null) {
                      pageCache.set(String(p.id), p);
                    }
                  }
                  return collected;
                }
              }
            }

            const confResp = await client.requestConfluence(
              route`/wiki/api/v2/pages?body-format=storage&limit=${CONFLUENCE_PAGE_SIZE}`
            );
            if (confResp.status !== 200) {
              warnings.push(
                `Confluence heuristic pages query returned HTTP ${confResp.status}; proceeding with Jira remote links only.`
              );
              return collected;
            }
            const confJson = (await confResp.json()) as {
              results?: ConfluencePageData[];
              _links?: { next?: string };
            };
            const results = Array.isArray(confJson?.results) ? confJson.results : [];
            collected.push(...results);
            for (const p of collected) {
              if (p?.id !== undefined && p?.id !== null) {
                pageCache.set(String(p.id), p);
              }
            }
            if (extractCursorFromNextLink(confJson?._links?.next)) {
              warnings.push(
                `Confluence heuristic title fallback scanned only the first ${CONFLUENCE_PAGE_SIZE} pages (pass spaceId or link Confluence pages via Jira remote links for full coverage).`
              );
            }
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            warnings.push(`Confluence heuristic pages fallback failed: ${msg}`);
          }
          return collected;
        })();
      }
      return await heuristicPagesPromise;
    };

    const getConfluencePagesScanned = (): number => {
      let count = 0;
      for (const page of pageCache.values()) {
        if (page !== null) count++;
      }
      return count;
    };

    const getConfluencePageCached = async (
      pageId: string,
      referencingIssueKey: string
    ): Promise<ConfluencePageData | null> => {
      if (pageCache.has(pageId)) {
        return pageCache.get(pageId) ?? null;
      }
      const existingInflight = pageFetchInflight.get(pageId);
      if (existingInflight) {
        return await existingInflight;
      }

      const fetchPromise = (async (): Promise<ConfluencePageData | null> => {
        try {
          const singlePageResp = await client.requestConfluence(
            route`/wiki/api/v2/pages/${pageId}?body-format=storage`
          );
          if (singlePageResp.status === 200) {
            const pageJson = (await singlePageResp.json()) as ConfluencePageData;
            pageCache.set(pageId, pageJson);
            return pageJson;
          }
          warnings.push(
            `Confluence page ${pageId} linked from ${referencingIssueKey} returned HTTP ${singlePageResp.status}.`
          );
          pageCache.set(pageId, null);
          return null;
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          warnings.push(
            `Failed to fetch Confluence page ${pageId} linked from ${referencingIssueKey}: ${msg}`
          );
          pageCache.set(pageId, null);
          return null;
        } finally {
          pageFetchInflight.delete(pageId);
        }
      })();

      pageFetchInflight.set(pageId, fetchPromise);
      return await fetchPromise;
    };

    const { summary: existingSuite, version: existingVersion } = await SeederService.getSuiteWithVersion();
    const existingByWorkKey = new Map<string, TraceLink[]>();
    const existingByWorkAndSpec = new Map<string, TraceLink>();
    const existingByTestKey = new Map<string, VerificationTest>();
    if (existingSuite.datasetMode === 'LIVE' && existingSuite.initialized !== false) {
      for (const link of existingSuite.traceLinks) {
        const workKeyUpper = (link.work?.key || '').trim().toUpperCase();
        if (workKeyUpper) {
          const arr = existingByWorkKey.get(workKeyUpper) || [];
          arr.push(link);
          existingByWorkKey.set(workKeyUpper, arr);
          if (link.spec?.id) {
            existingByWorkAndSpec.set(`${workKeyUpper}::${link.spec.id.toLowerCase()}`, link);
          }
          if (link.spec?.pageId) {
            existingByWorkAndSpec.set(`${workKeyUpper}::${link.spec.pageId.toLowerCase()}`, link);
          }
        }
        const testKeyUpper = (link.test?.testKey || '').trim().toUpperCase();
        if (testKeyUpper && !existingByTestKey.has(testKeyUpper)) {
          existingByTestKey.set(testKeyUpper, link.test);
        }
      }
    }

    const issueByKey = new Map<string, JiraApiIssue>();
    for (const iss of issues) {
      const k = typeof iss?.key === 'string' ? iss.key.trim().toUpperCase() : '';
      if (k) issueByKey.set(k, iss);
    }

    // Identify Hazard/Test Jira issues already linked via `issuelinks` to a Work issue in this scan
    // so we don't fabricate duplicate standalone `HAZ-<testKey>` trace links for them.
    const linkedRoleOwners = new Set<string>();
    for (const iss of issues) {
      const k = typeof iss?.key === 'string' ? iss.key.trim().toUpperCase() : '';
      if (!k) continue;
      const issTypeName = String(iss.fields?.issuetype?.name || '').trim();
      const issLabels = normalizeStringArray(iss.fields?.labels);
      if (isPureHazardIssue({ issueTypeName: issTypeName, labels: issLabels }) || isPureVerificationTestIssue({ issueTypeName: issTypeName, labels: issLabels })) {
        continue;
      }
      const candidates = extractLinkedIssueCandidates(iss.fields?.issuelinks || [], issueByKey);
      const { linkedHazard, linkedTest, linkedReverification } = resolveLinkedHazardAndTest(candidates);
      if (linkedHazard) linkedRoleOwners.add(linkedHazard.key.toUpperCase());
      if (linkedTest) linkedRoleOwners.add(linkedTest.key.toUpperCase());
      if (linkedReverification) linkedRoleOwners.add(linkedReverification.key.toUpperCase());
    }

    const baselineCache = new Map<string, SignedSpecBaseline | undefined>();
    const readCachedBaseline = async (
      specOrPageId: string,
      hazardKey?: string
    ): Promise<SignedSpecBaseline | undefined> => {
      const cacheKey = hazardKey ? `${hazardKey}::${specOrPageId}` : `__unscoped__::${specOrPageId}`;
      if (baselineCache.has(cacheKey)) {
        return baselineCache.get(cacheKey);
      }
      const val = await SeederService.getSignedSpecBaseline(specOrPageId, hazardKey);
      baselineCache.set(cacheKey, val);
      return val;
    };

    const getBaselineForHazardSpec = async (
      hazardKey: string,
      specId: string,
      pageId?: string
    ): Promise<SignedSpecBaseline | undefined> => {
      const scopedSpec = await readCachedBaseline(specId, hazardKey);
      if (scopedSpec) return scopedSpec;
      if (pageId) {
        const scopedPage = await readCachedBaseline(pageId, hazardKey);
        if (scopedPage) return scopedPage;
        const legacyPage = await readCachedBaseline(pageId);
        if (legacyPage && (!legacyPage.hazardKey || legacyPage.hazardKey === hazardKey)) {
          return legacyPage;
        }
      }
      const legacySpec = await readCachedBaseline(specId);
      if (legacySpec && (!legacySpec.hazardKey || legacySpec.hazardKey === hazardKey)) {
        return legacySpec;
      }
      return undefined;
    };

    type ProcessedIssueResult = {
      skipped: boolean;
      links: TraceLink[];
      linkedPairs: number;
      drifts: number;
      baselineUpdates: BaselineMutationRecord[];
    };

    const processIssue = async (issue: JiraApiIssue): Promise<ProcessedIssueResult | null> => {
      const issueKey = typeof issue?.key === 'string' ? issue.key.trim() : '';
      if (!issueKey) return null;

      const fields = issue.fields || {};
      const labels = normalizeStringArray(fields.labels);
      const hasStaticTrack = isSafetyTrackedIssue(issue, {
        existingByWorkKey,
        hazardLabels: normalized.hazardLabels,
        hazardIssueTypes: normalized.hazardIssueTypes,
        includeUntaggedIssues: normalized.includeUntaggedIssues,
      });

      const graphCtx: IssueGraphContextResult | null = await TeamworkGraphService.queryIssueGraphContext(
        issueKey,
        {
          callerMode: normalized.callerMode,
          requireConfluenceLinkToEnrich: !hasStaticTrack,
        }
      );

      const shouldTrack =
        hasStaticTrack ||
        isSafetyTrackedIssue(issue, {
          existingByWorkKey,
          hazardLabels: normalized.hazardLabels,
          hazardIssueTypes: normalized.hazardIssueTypes,
          includeUntaggedIssues: normalized.includeUntaggedIssues,
          hasConfluenceLinks: Boolean(graphCtx?.confluenceLinks && graphCtx.confluenceLinks.length > 0),
        });

      if (!shouldTrack) {
        return {
          skipped: true,
          links: [],
          linkedPairs: 0,
          drifts: 0,
          baselineUpdates: [],
        };
      }

      const issueTypeName = String(fields.issuetype?.name || '').trim();
      const isSelfReverificationTask = labels.some((l) => l.toLowerCase() === 'medtrace-reverification');
      if (
        (isSelfReverificationTask ||
          isPureVerificationTestIssue({ issueTypeName, labels }) ||
          isPureHazardIssue({ issueTypeName, labels })) &&
        linkedRoleOwners.has(issueKey.toUpperCase())
      ) {
        return {
          skipped: true,
          links: [],
          linkedPairs: 0,
          drifts: 0,
          baselineUpdates: [],
        };
      }

      const rawIssueLinks =
        Array.isArray(graphCtx?.issuelinks) && graphCtx.issuelinks.length > 0
          ? graphCtx.issuelinks
          : Array.isArray(fields.issuelinks)
            ? fields.issuelinks
            : [];
      const linkedIssues = extractLinkedIssueCandidates(rawIssueLinks, issueByKey);
      const { linkedHazard, linkedTest, linkedReverification } =
        resolveLinkedHazardAndTest(linkedIssues);

      const hazardRisk = (() => {
        const workRisk = inferRiskClass(labels);
        if (linkedHazard && linkedHazard.labels.length > 0) {
          const hazRisk = inferRiskClass(linkedHazard.labels);
          if (hazRisk.safetyClassAssigned !== false) {
            return hazRisk;
          }
        }
        return workRisk;
      })();
      const { riskClass, safetyClassAssigned } = hazardRisk;
      const prevWorkLinks = existingByWorkKey.get(issueKey.toUpperCase()) || [];
      const defaultHazardKey = linkedHazard?.key || prevWorkLinks[0]?.hazard?.key || `HAZ-${issueKey}`;

      const work: JiraWorkItem = {
        id: String(issue.id || issueKey.toLowerCase()),
        key: issueKey,
        title: fields.summary || issueKey,
        status: mapJiraStatusToWorkStatus(fields.status),
        assignee: fields.assignee?.displayName || 'Unassigned',
      };

      const aggTraversalStatus =
        linkedHazard || linkedTest
          ? `LIVE (JIRA_ISSUELINK + ${graphCtx ? graphCtx.source : 'JIRA_REST'})`
          : graphCtx
            ? `LIVE (${graphCtx.source})`
            : 'LIVE (JIRA_REST)';
      const entityAri = graphCtx?.issueAri || `jira:issue:${issueKey}`;
      const jiraCloudId = extractCloudIdFromSelfUrl(issue.self) || extractCloudIdFromSelfUrl(linkedHazard?.self);

      const buildResolvedHazard = (
        hazardKey: string,
        mitigationRequirementId: string,
        fallbackTitle?: string
      ): IsoHazard => ({
        id: linkedHazard ? linkedHazard.id : hazardKey.toLowerCase(),
        key: hazardKey,
        title: linkedHazard?.summary || fields.summary || fallbackTitle || `Hazard for ${issueKey}`,
        riskClass,
        ...(safetyClassAssigned === false ? { safetyClassAssigned: false } : {}),
        mitigationRequirementId,
        status: 'UNVERIFIED_RISK',
        source: linkedHazard ? 'JIRA_ISSUE' : 'APP_MANAGED',
      });

      const buildResolvedTest = (prevTest?: VerificationTest): VerificationTest => {
        if (linkedTest) {
          const prior =
            (prevTest && prevTest.testKey.toUpperCase() === linkedTest.key.toUpperCase()
              ? prevTest
              : existingByTestKey.get(linkedTest.key.toUpperCase())) || prevTest;
          const preservedStatus =
            prior && prior.testKey.toUpperCase() === linkedTest.key.toUpperCase()
              ? prior.status
              : 'UNTESTED';
          return {
            ...(prior && prior.testKey.toUpperCase() === linkedTest.key.toUpperCase() ? prior : {}),
            id: linkedTest.id,
            testKey: linkedTest.key,
            title: linkedTest.summary || prior?.title || `Verification Test ${linkedTest.key}`,
            testType: inferTestTypeFromIssue(riskClass, linkedTest.labels, linkedTest.issueTypeName),
            status: preservedStatus,
            source: 'JIRA_ISSUE',
          };
        }
        if (prevTest) {
          return { ...prevTest, source: prevTest.source || 'APP_MANAGED' };
        }
        return {
          id: `test-${issueKey.toLowerCase()}`,
          testKey: `TEST-${issueKey}`,
          title: `Verification Test for ${issueKey}`,
          testType: riskClass === 'CLASS_C' ? 'Automated HIL (Hardware-in-Loop)' : 'Integration Test',
          status: 'UNTESTED',
          source: 'APP_MANAGED',
        };
      };

      const buildHazardAri = (hazardKey: string): string =>
        linkedHazard && jiraCloudId
          ? `ari:cloud:jira:${jiraCloudId}:issue/${linkedHazard.id}`
          : `ari:cloud:medtrace::iso14971-hazard/${hazardKey}`;

      // Collect all linked Confluence pages (M:N) from remote links, falling back to SRS-\d+ summary title heuristic
      const matchedPages: Array<{
        page: ConfluencePageData;
        edgeType: 'REST:jira-remotelink' | 'HEURISTIC:summary-srs-title';
      }> = [];
      const seenPageIds = new Set<string>();

      for (const remoteLink of graphCtx?.confluenceLinks || []) {
        if (!remoteLink.pageId) continue;
        const pid = String(remoteLink.pageId).trim();
        if (!pid || seenPageIds.has(pid)) continue;
        const page = await getConfluencePageCached(pid, issueKey);
        if (page && page.id !== undefined && page.id !== null) {
          const resolvedId = String(page.id);
          if (!seenPageIds.has(resolvedId)) {
            seenPageIds.add(resolvedId);
            matchedPages.push({ page, edgeType: 'REST:jira-remotelink' });
          }
        }
      }

      if (matchedPages.length === 0) {
        const srsTokens = Array.from(
          new Set((String(fields.summary || '').match(/\bSRS-\d+\b/gi) || []).map((t) => t.toLowerCase()))
        );
        if (srsTokens.length > 0) {
          const candidatePages = await getHeuristicCandidatePages();
          for (const token of srsTokens) {
            for (const candidate of candidatePages) {
              const candidateId = candidate?.id !== undefined && candidate?.id !== null ? String(candidate.id) : '';
              if (!candidateId || seenPageIds.has(candidateId)) continue;
              if (String(candidate.title || '').toLowerCase().includes(token)) {
                seenPageIds.add(candidateId);
                matchedPages.push({ page: candidate, edgeType: 'HEURISTIC:summary-srs-title' });
              }
            }
          }
        }
      }

      // Unlinked sentinel path
      if (matchedPages.length === 0) {
        const specId = `unlinked-${issueKey.toLowerCase()}`;
        const prevExact =
          existingByWorkAndSpec.get(`${issueKey.toUpperCase()}::${specId}`) || prevWorkLinks[0];
        const hazardKey = linkedHazard?.key || prevExact?.hazard?.key || defaultHazardKey;

        const spec: ConfluenceSpec = {
          id: specId,
          title: '',
          version: 0,
          sha256Hash: '',
          lastSignedHash: '',
          isSignatureInvalidated: true,
          isMissingSentinel: true,
          contentSnippet: 'No linked Confluence SRS specification found on Jira issue remote links.',
          lastUpdated: new Date().toISOString(),
        };

        const hazard = buildResolvedHazard(hazardKey, spec.id, prevExact?.hazard?.title);
        const test = buildResolvedTest(prevExact?.test);

        const signature: Part11Signature = {
          id: `sig-${spec.id}`,
          signedBy: prevExact?.signature?.signedBy || '',
          ...(prevExact?.signature?.signedByAccountId
            ? { signedByAccountId: prevExact.signature.signedByAccountId }
            : {}),
          signedAt: prevExact?.signature?.signedAt || '',
          ...(prevExact?.signature?.invalidatedAt
            ? { invalidatedAt: prevExact.signature.invalidatedAt }
            : {}),
          role: prevExact?.signature?.role || 'Regulatory Authority',
          meaning: prevExact?.signature?.meaning || 'Pending 21 CFR Part 11 Sign-off',
          artifactSha256: prevExact?.signature?.artifactSha256 || '',
          isValid: false,
          invalidationReason: 'No 21 CFR Part 11 sign-off recorded for unlinked Confluence SRS.',
        };

        const graphMetadata: GraphMetadata = {
          entityAri,
          hazardAri: buildHazardAri(hazard.key),
          linkedSpecAri: 'unlinked',
          edgeType: linkedHazard || linkedTest ? 'JIRA:issuelink+NONE:unlinked' : 'NONE:unlinked',
          aggTraversalStatus,
        };

        const evaluated = ComplianceEngine.evaluateTraceLink(
          hazard,
          spec,
          work,
          test,
          signature,
          graphMetadata,
          {
            linkId: ComplianceEngine.buildTraceLinkId(hazard.key, spec.id, work.key),
            part11Secret,
            requireCryptographicSeal: true,
            requireTestEvidence: true,
            reverificationTaskKey: linkedReverification?.key || prevExact?.reverificationTaskKey,
          }
        );
        evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);

        return {
          skipped: false,
          links: [evaluated],
          linkedPairs: 0,
          drifts: 0,
          baselineUpdates: [],
        };
      }

      // Multi-spec linked path (1 or M:N Confluence pages)
      const builtLinks: TraceLink[] = [];
      const localBaselineUpdates: BaselineMutationRecord[] = [];
      let localDrifts = 0;

      for (const { page, edgeType } of matchedPages) {
        const pageIdStr = String(page.id);
        const specId = `srs-${pageIdStr}`;
        const prevExact =
          existingByWorkAndSpec.get(`${issueKey.toUpperCase()}::${specId.toLowerCase()}`) ||
          existingByWorkAndSpec.get(`${issueKey.toUpperCase()}::${pageIdStr.toLowerCase()}`);
        const hazardKey = linkedHazard?.key || prevExact?.hazard?.key || defaultHazardKey;

        const storageBody = typeof page?.body?.storage?.value === 'string' ? page.body.storage.value : '';
        const currentHash = sha256Hex(storageBody);
        const baseline = await getBaselineForHazardSpec(hazardKey, specId, pageIdStr);

        const hashMismatch = baseline ? baseline.sha256Hash !== currentHash : false;
        const baselineInv = isBaselineInvalidated(baseline);
        const signedMs = baseline?.signedAt ? Date.parse(baseline.signedAt) : NaN;
        const prevInvMs = prevExact?.signature?.invalidatedAt
          ? Date.parse(prevExact.signature.invalidatedAt)
          : NaN;
        const prevLinkInv = Boolean(
          prevExact &&
            (!baseline ||
              (Number.isFinite(prevInvMs) && (!Number.isFinite(signedMs) || signedMs <= prevInvMs))) &&
            (prevExact.spec.isSignatureInvalidated ||
              !prevExact.signature.isValid ||
              Boolean(prevExact.signature.invalidatedAt))
        );

        const isDriftedOrInvalidated = Boolean(baseline && (hashMismatch || baselineInv)) || prevLinkInv;
        if (baseline && (hashMismatch || baselineInv)) {
          localDrifts++;
        }

        const nowIso = new Date().toISOString();
        let effectiveInvalidatedAt: string | undefined =
          baseline?.invalidatedAt || prevExact?.signature?.invalidatedAt;
        let effectiveReason: string | undefined =
          baseline?.invalidationReason || prevExact?.signature?.invalidationReason;

        if (baseline && hashMismatch && !baselineInv) {
          const driftAt =
            Number.isFinite(signedMs) && Date.now() <= signedMs
              ? new Date(signedMs + 1).toISOString()
              : nowIso;
          effectiveInvalidatedAt = driftAt;
          effectiveReason = `Confluence SRS content hash changed since Part 11 sign-off (${baseline.sha256Hash.slice(0, 12)}... -> ${currentHash.slice(0, 12)}...).`;
          localBaselineUpdates.push(
            buildBaselineMutationForInvalidation(
              hazardKey,
              specId,
              pageIdStr,
              currentHash,
              driftAt,
              effectiveReason
            )
          );
        } else if (baseline && baselineInv && !hashMismatch) {
          effectiveReason =
            effectiveReason ||
            `Part 11 signature previously invalidated (${baseline.invalidatedAt}); Confluence revert to prior hash does not re-validate without fresh sign-off.`;
        }

        const spec: ConfluenceSpec = {
          id: specId,
          pageId: pageIdStr,
          title: page.title || `Confluence Page ${pageIdStr}`,
          version: Number(page?.version?.number || 1),
          sha256Hash: currentHash,
          lastSignedHash: baseline?.sha256Hash || prevExact?.spec?.lastSignedHash || '',
          isSignatureInvalidated: baseline
            ? isDriftedOrInvalidated
            : Boolean(prevExact?.spec?.isSignatureInvalidated && prevExact?.signature?.artifactSha256),
          isMissingSentinel: false,
          contentSnippet: stripStorageMarkup(storageBody) || page.title || '',
          lastUpdated: page?.version?.createdAt || nowIso,
        };

        const hazard = buildResolvedHazard(hazardKey, spec.id, prevExact?.hazard?.title);

        const testSource = prevExact?.test || prevWorkLinks[0]?.test;
        const test = buildResolvedTest(testSource);

        let signatureValid = false;
        let signature: Part11Signature;

        if (baseline) {
          const candidateSig: Part11Signature = {
            id: `sig-${spec.id}`,
            signedBy: baseline.signedBy,
            ...(baseline.signedByAccountId ? { signedByAccountId: baseline.signedByAccountId } : {}),
            signedAt: baseline.signedAt,
            role: baseline.role,
            meaning: baseline.meaning,
            artifactSha256: baseline.sha256Hash,
            isValid: true,
            authMethod: baseline.authMethod,
            ...(baseline.signatureAlgorithm ? { signatureAlgorithm: baseline.signatureAlgorithm } : {}),
            ...(baseline.signatureSeal ? { signatureSeal: baseline.signatureSeal } : {}),
            ...(baseline.sealKeyId ? { sealKeyId: baseline.sealKeyId } : {}),
            ...(baseline.clientPublicKeySpki
              ? { clientPublicKeySpki: baseline.clientPublicKeySpki }
              : {}),
            ...(baseline.clientSignatureBase64
              ? { clientSignatureBase64: baseline.clientSignatureBase64 }
              : {}),
            ...(baseline.clientKeyFingerprint
              ? { clientKeyFingerprint: baseline.clientKeyFingerprint }
              : {}),
          };

          const sealOk = ComplianceEngine.verifyPart11Seal(
            hazardKey,
            spec.id,
            candidateSig,
            part11Secret
          );

          signatureValid = !isDriftedOrInvalidated && sealOk;
          if (!isDriftedOrInvalidated && !sealOk) {
            effectiveReason =
              'FDA 21 CFR Part 11 Cryptographic Seal Violation: Signed baseline failed HMAC-SHA256 verification.';
          }

          signature = {
            ...candidateSig,
            isValid: signatureValid,
            ...(effectiveInvalidatedAt ? { invalidatedAt: effectiveInvalidatedAt } : {}),
            ...(!signatureValid
              ? {
                  invalidationReason:
                    effectiveReason || 'Confluence SRS content hash changed since Part 11 sign-off.',
                }
              : {}),
          };
        } else {
          signature = {
            id: `sig-${spec.id}`,
            signedBy: prevExact?.signature?.signedBy || '',
            ...(prevExact?.signature?.signedByAccountId
              ? { signedByAccountId: prevExact.signature.signedByAccountId }
              : {}),
            signedAt: prevExact?.signature?.signedAt || '',
            ...(prevExact?.signature?.invalidatedAt
              ? { invalidatedAt: prevExact.signature.invalidatedAt }
              : {}),
            role: prevExact?.signature?.role || 'Regulatory Authority',
            meaning: prevExact?.signature?.meaning || 'Pending 21 CFR Part 11 Sign-off',
            artifactSha256: prevExact?.signature?.artifactSha256 || '',
            isValid: false,
            invalidationReason:
              prevExact?.signature?.invalidationReason ||
              'No 21 CFR Part 11 sign-off recorded for this Confluence SRS version.',
          };
        }

        const graphMetadata: GraphMetadata = {
          entityAri,
          hazardAri: buildHazardAri(hazard.key),
          linkedSpecAri: `confluence:page:${pageIdStr}`,
          edgeType: linkedHazard || linkedTest ? `JIRA:issuelink+${edgeType}` : edgeType,
          aggTraversalStatus,
        };

        const evaluated = ComplianceEngine.evaluateTraceLink(
          hazard,
          spec,
          { ...work },
          test,
          signature,
          graphMetadata,
          {
            linkId: ComplianceEngine.buildTraceLinkId(hazard.key, spec.id, work.key),
            part11Secret,
            requireCryptographicSeal: true,
            requireTestEvidence: true,
            reverificationTaskKey: linkedReverification?.key || prevExact?.reverificationTaskKey,
          }
        );
        evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
        builtLinks.push(evaluated);
      }

      return {
        skipped: false,
        links: builtLinks,
        linkedPairs: matchedPages.length,
        drifts: localDrifts,
        baselineUpdates: localBaselineUpdates,
      };
    };

    const traceLinks: TraceLink[] = [];
    const baselineUpdates: BaselineMutationRecord[] = [];
    const processedWorkKeys = new Set<string>();
    const unprocessedKeys: string[] = [];
    let linkedPairsFound = 0;
    let driftDetectedCount = 0;
    let skippedUntaggedCount = 0;

    for (let i = 0; i < issues.length; i += LIVE_SYNC_CONCURRENCY_BATCH_SIZE) {
      if (Date.now() - startedAt >= LIVE_SYNC_BUDGET_MS) {
        truncated = true;
        for (const rem of issues.slice(i)) {
          const rk = typeof rem?.key === 'string' ? rem.key.trim().toUpperCase() : '';
          if (rk) unprocessedKeys.push(rk);
        }
        warnings.push(
          `Live sync exceeded ${LIVE_SYNC_BUDGET_MS}ms fetch budget during issue enrichment; partial results saved.`
        );
        break;
      }

      const batch = issues.slice(i, i + LIVE_SYNC_CONCURRENCY_BATCH_SIZE);
      const batchResults = await Promise.all(batch.map((issue) => processIssue(issue)));
      for (const issue of batch) {
        const keyUpper = typeof issue?.key === 'string' ? issue.key.trim().toUpperCase() : '';
        if (keyUpper) {
          processedWorkKeys.add(keyUpper);
        }
      }
      for (const result of batchResults) {
        if (!result) continue;
        if (result.skipped) {
          skippedUntaggedCount++;
          continue;
        }
        traceLinks.push(...result.links);
        linkedPairsFound += result.linkedPairs;
        driftDetectedCount += result.drifts;
        baselineUpdates.push(...result.baselineUpdates);
      }
    }

    if (
      existingSuite.datasetMode === 'LIVE' &&
      existingSuite.initialized !== false &&
      existingSuite.traceLinks.length > 0 &&
      traceLinks.length > 0
    ) {
      const syncedProjectPrefix = normalized.projectKey
        ? `${normalized.projectKey.trim().toUpperCase()}-`
        : undefined;
      const seenLinkIds = new Set(traceLinks.map((l) => l.id));
      let preservedTruncatedCount = 0;
      let preservedOtherProjectCount = 0;
      let preservedFilteredJqlCount = 0;

      for (const existingLink of existingSuite.traceLinks) {
        const workKeyUpper = (existingLink.work?.key || '').trim().toUpperCase();
        const hasStandardPrefix = /^[A-Z][A-Z0-9_]*-\d+$/.test(workKeyUpper);
        const isOtherProject = Boolean(
          syncedProjectPrefix && hasStandardPrefix && !workKeyUpper.startsWith(syncedProjectPrefix)
        );
        const isUnprocessedTruncated = Boolean(
          (truncated || resumedFromCursor) && workKeyUpper && !processedWorkKeys.has(workKeyUpper)
        );
        const isExcludedByFilteredJql = Boolean(
          normalized.hasCustomJql &&
            !isOtherProject &&
            !isUnprocessedTruncated &&
            (!workKeyUpper || !processedWorkKeys.has(workKeyUpper))
        );

        if (
          (isOtherProject || isUnprocessedTruncated || isExcludedByFilteredJql) &&
          !seenLinkIds.has(existingLink.id)
        ) {
          traceLinks.push(cloneTraceLink(existingLink));
          seenLinkIds.add(existingLink.id);
          if (isOtherProject) {
            preservedOtherProjectCount++;
          } else if (isUnprocessedTruncated) {
            preservedTruncatedCount++;
          } else {
            preservedFilteredJqlCount++;
          }
        }
      }

      if (preservedTruncatedCount > 0) {
        warnings.push(
          truncated
            ? `Preserved ${preservedTruncatedCount} existing trace link(s) not reached before sync truncation.`
            : `Preserved ${preservedTruncatedCount} existing trace link(s) from prior sync page(s).`
        );
      }
      if (preservedOtherProjectCount > 0) {
        warnings.push(
          `Preserved ${preservedOtherProjectCount} existing trace link(s) belonging to other Jira project(s).`
        );
      }
      if (preservedFilteredJqlCount > 0) {
        warnings.push(
          `Preserved ${preservedFilteredJqlCount} existing trace link(s) outside the filtered JQL query scope.`
        );
      }
    }

    const nextPendingKeys = Array.from(new Set([...unprocessedKeys, ...remainingFetchKeys]));
    const retainedInitialToken =
      truncated && !jiraResult.truncated && resumedFromCursor ? initialPageToken : undefined;
    const nextResumeToken = jiraResult.nextPageToken || retainedInitialToken;
    const savedPendingCoversInitialPage = Boolean(retainedInitialToken && !jiraResult.nextPageToken);
    const hasPendingCursor = truncated && Boolean(nextResumeToken || nextPendingKeys.length > 0);

    const persistOrClearCursor = async (): Promise<void> => {
      try {
        if (hasPendingCursor) {
          await kvs.set(cursorKey, {
            ...(nextResumeToken ? { nextPageToken: nextResumeToken } : {}),
            ...(nextPendingKeys.length > 0 ? { pendingIssueKeys: nextPendingKeys } : {}),
            ...(savedPendingCoversInitialPage ? { pendingCoversInitialPage: true } : {}),
            jql: normalized.jql,
            projectKey: normalized.projectKey || 'GLOBAL',
            updatedAt: new Date().toISOString(),
          });
        } else {
          await kvs.delete(cursorKey);
        }
      } catch {
        // Non-fatal: nextPageToken is still returned to caller.
      }
    };

    const confluencePagesScanned = getConfluencePagesScanned();

    if (traceLinks.length === 0) {
      await persistOrClearCursor();
      let summaryToReturn = existingSuite;
      if (
        truncated &&
        existingSuite.datasetMode === 'LIVE' &&
        existingSuite.initialized !== false &&
        existingSuite.traceLinks.length > 0
      ) {
        const incompleteSummary = ComplianceEngine.generateComplianceReport(
          existingSuite.traceLinks,
          'LIVE',
          existingSuite.projectName,
          {
            initialized: true,
            lastSyncedAt: existingSuite.lastSyncedAt,
            syncIncomplete: true,
          }
        );
        summaryToReturn = await commitSuiteMutation({
          summary: incompleteSummary,
          expectedVersion: existingVersion ?? 0,
          auditEntry: {
            actorAccountId,
            action: 'SYNC_LIVE',
            targetKey: existingSuite.projectName,
            details: {
              projectKey: normalized.projectKey || null,
              truncated: true,
              syncIncomplete: true,
              ...(nextResumeToken ? { nextPageToken: nextResumeToken } : {}),
              ...(nextPendingKeys.length > 0 ? { pendingIssueKeysCount: nextPendingKeys.length } : {}),
            },
            authMethod: 'FORGE_USER_SESSION',
          },
        });
      }
      warnings.push(
        'No safety-tracked Jira issues matched the live sync query; keeping existing compliance suite unchanged.'
      );
      return {
        success: false,
        datasetMode: summaryToReturn.datasetMode,
        jiraIssuesScanned: issues.length,
        confluencePagesScanned,
        linkedPairsFound,
        driftDetectedCount,
        truncated,
        ...(nextResumeToken ? { nextPageToken: nextResumeToken } : {}),
        ...(resumedFromCursor ? { resumedFromCursor: true } : {}),
        skippedUntaggedCount,
        warnings,
        summary: summaryToReturn,
      };
    }

    const projectLabel =
      normalized.projectKey ||
      issues[0]?.fields?.project?.name ||
      'Atlassian Cloud Live Medical Project';

    const syncCompletedAt = new Date().toISOString();
    const summary = ComplianceEngine.generateComplianceReport(traceLinks, 'LIVE', projectLabel, {
      initialized: true,
      lastSyncedAt: syncCompletedAt,
      syncIncomplete: truncated,
    });

    const syncedWorkKeys = Array.from(processedWorkKeys);
    const syncedProjectKeys = Array.from(
      new Set(
        [
          ...(normalized.projectKey ? [normalized.projectKey] : []),
          ...syncedWorkKeys.map((k) => k.split('-')[0]).filter(Boolean),
        ]
      )
    );

    const saved = await commitSuiteMutation({
      summary,
      expectedVersion: existingVersion ?? 0,
      baselineUpdates,
      auditEntry: {
        actorAccountId,
        action: 'SYNC_LIVE',
        targetKey: projectLabel,
        details: {
          projectKey: normalized.projectKey || null,
          projectKeys: syncedProjectKeys,
          jiraIssuesScanned: issues.length,
          confluencePagesScanned,
          linkedPairsFound,
          driftDetectedCount,
          skippedUntaggedCount,
          truncated,
          lastSyncedAt: syncCompletedAt,
          ...(jiraResult.nextPageToken ? { nextPageToken: jiraResult.nextPageToken } : {}),
          ...(resumedFromCursor ? { resumedFromCursor: true } : {}),
        },
        authMethod: 'FORGE_USER_SESSION',
      },
    });

    await persistOrClearCursor();

    return {
      success: true,
      datasetMode: 'LIVE',
      jiraIssuesScanned: issues.length,
      confluencePagesScanned,
      linkedPairsFound,
      driftDetectedCount,
      truncated,
      ...(jiraResult.nextPageToken ? { nextPageToken: jiraResult.nextPageToken } : {}),
      ...(resumedFromCursor ? { resumedFromCursor: true } : {}),
      skippedUntaggedCount,
      warnings,
      summary: saved,
    };
  }

  /**
   * Forge product trigger handler for `avi:confluence:updated:page`.
   * Re-computes SHA-256 of updated Confluence SRS pages, invalidates drifted Part 11 signatures
   * (without resurrecting previously invalidated signatures on page revert), and commits with 3-attempt CAS retry.
   */
  public static async handleConfluencePageUpdated(
    event: ConfluencePageUpdatedEvent
  ): Promise<ConfluencePageUpdatedResult> {
    const pageId = String(event?.content?.id || event?.page?.id || '').trim();
    if (!pageId) {
      return { processed: false, affectedHazards: [] };
    }

    let fetchedPageContent:
      | {
          newHash: string;
          newVersion?: number;
          newTitle?: string;
          newSnippet?: string;
        }
      | undefined;

    for (let attempt = 1; attempt <= MAX_CAS_RETRY_ATTEMPTS; attempt++) {
      const { summary: suite, version } = await SeederService.getSuiteWithVersion();
      const matchingIndices: number[] = [];
      suite.traceLinks.forEach((link, idx) => {
        if (link.spec.pageId === pageId || link.spec.id === pageId || link.spec.id === `srs-${pageId}`) {
          matchingIndices.push(idx);
        }
      });

      if (matchingIndices.length === 0) {
        return { processed: false, pageId, affectedHazards: [] };
      }

      if (!fetchedPageContent) {
        if (isForgeRuntime()) {
          const resp = await api
            .asApp()
            .requestConfluence(route`/wiki/api/v2/pages/${pageId}?body-format=storage`);
          if (resp.status !== 200) {
            throw new Error(`Confluence trigger failed to fetch page ${pageId} (HTTP ${resp.status}).`);
          }
          const pageData = (await resp.json()) as ConfluencePageData;
          const bodyValue = typeof pageData?.body?.storage?.value === 'string' ? pageData.body.storage.value : '';
          fetchedPageContent = {
            newHash: sha256Hex(bodyValue),
            newVersion: Number(pageData?.version?.number || 1),
            newTitle: pageData?.title,
            newSnippet: stripStorageMarkup(bodyValue),
          };
        } else if (typeof event?.contentHash === 'string') {
          fetchedPageContent = { newHash: event.contentHash };
        } else if (typeof event?.storageBody === 'string') {
          fetchedPageContent = {
            newHash: sha256Hex(event.storageBody),
            newSnippet: stripStorageMarkup(event.storageBody),
          };
        } else {
          return { processed: false, pageId, affectedHazards: [] };
        }
      }

      const { newHash, newVersion, newTitle, newSnippet } = fetchedPageContent;
      const updatedLinks = suite.traceLinks.map(cloneTraceLink);
      const affectedHazards: string[] = [];
      const baselineUpdates: BaselineMutationRecord[] = [];
      const part11Secret = (process.env.MEDTRACE_PART11_SECRET || '').trim();
      const eventNowIso = new Date().toISOString();

      for (const idx of matchingIndices) {
        const link = updatedLinks[idx];

        const compositeSpecBaseline = await SeederService.getSignedSpecBaseline(link.spec.id, link.hazard.key);
        const compositePageBaseline =
          !compositeSpecBaseline && link.spec.pageId
            ? await SeederService.getSignedSpecBaseline(link.spec.pageId, link.hazard.key)
            : undefined;
        const unscopedCandidate =
          compositeSpecBaseline || compositePageBaseline
            ? undefined
            : (await SeederService.getSignedSpecBaseline(pageId)) ||
              (await SeederService.getSignedSpecBaseline(link.spec.id));
        const existingBaseline =
          compositeSpecBaseline ||
          compositePageBaseline ||
          (unscopedCandidate && (!unscopedCandidate.hazardKey || unscopedCandidate.hazardKey === link.hazard.key)
            ? unscopedCandidate
            : undefined);

        const baselineInvalidated = isBaselineInvalidated(existingBaseline);
        const wasAlreadyInvalidated =
          Boolean(link.spec.isSignatureInvalidated) ||
          !link.signature.isValid ||
          isSignatureTimestampInvalidated(link.signature) ||
          baselineInvalidated;

        const hashMismatch = newHash !== link.signature.artifactSha256;
        const shouldInvalidate = wasAlreadyInvalidated || hashMismatch;

        link.spec.sha256Hash = newHash;
        link.spec.isMissingSentinel = false;
        if (newVersion) link.spec.version = newVersion;
        if (newTitle) link.spec.title = newTitle;
        if (newSnippet !== undefined) link.spec.contentSnippet = newSnippet;
        link.spec.lastUpdated = eventNowIso;

        if (shouldInvalidate) {
          link.spec.isSignatureInvalidated = true;
          link.signature.isValid = false;

          const signedMs = link.signature.signedAt ? Date.parse(link.signature.signedAt) : NaN;
          let invalidatedAt =
            existingBaseline?.invalidatedAt || link.signature.invalidatedAt || eventNowIso;

          if (hashMismatch) {
            const safeMs =
              Number.isFinite(signedMs) && Date.now() <= signedMs ? signedMs + 1 : Date.now();
            invalidatedAt = new Date(safeMs).toISOString();
          }

          const hasPriorSignature = Boolean(link.signature.artifactSha256 || link.signature.signedAt);
          if (hasPriorSignature) {
            link.signature.invalidatedAt = invalidatedAt;
            if (hashMismatch) {
              link.signature.invalidationReason =
                `AUTOMATIC REVOCATION: Confluence page ${pageId} updated (SHA-256 ${newHash.slice(0, 12)}... != signed ${link.signature.artifactSha256.slice(0, 12)}...).`;
            } else {
              link.signature.invalidationReason =
                link.signature.invalidationReason ||
                existingBaseline?.invalidationReason ||
                `AUTOMATIC REVOCATION PERSISTED: Confluence page ${pageId} reverted to ${newHash.slice(0, 12)}... after prior invalidation; fresh Part 11 re-signature required.`;
            }

            if (hashMismatch || (existingBaseline && !baselineInvalidated)) {
              baselineUpdates.push(
                buildBaselineMutationForInvalidation(
                  link.hazard.key,
                  link.spec.id,
                  pageId,
                  newHash,
                  invalidatedAt,
                  link.signature.invalidationReason
                )
              );
            }
          }
        }

        const evaluated = ComplianceEngine.evaluateTraceLink(
          link.hazard,
          link.spec,
          link.work,
          link.test,
          link.signature,
          link.graphMetadata,
          {
            linkId: link.id,
            part11Secret,
            requireCryptographicSeal: true,
            requireTestEvidence: suite.datasetMode === 'LIVE',
            reverificationTaskKey: link.reverificationTaskKey,
          }
        );
        evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
        updatedLinks[idx] = evaluated;
        if (!affectedHazards.includes(evaluated.hazard.key)) {
          affectedHazards.push(evaluated.hazard.key);
        }
      }

      const affectedWorkKeys = Array.from(
        new Set(
          matchingIndices
            .map((i) => updatedLinks[i]?.work?.key?.trim().toUpperCase())
            .filter((k): k is string => Boolean(k))
        )
      );
      const affectedProjectKeys = Array.from(
        new Set(
          affectedWorkKeys
            .map((k) => k.split('-')[0])
            .filter(Boolean)
        )
      );

      const updated = ComplianceEngine.generateComplianceReport(
        updatedLinks,
        suite.datasetMode,
        suite.projectName,
        { initialized: suite.initialized ?? true, lastSyncedAt: suite.lastSyncedAt }
      );

      try {
        await commitSuiteMutation({
          summary: updated,
          expectedVersion: version ?? 0,
          baselineUpdates,
          auditEntry: {
            actorAccountId: String(
              event?.atlassianId || event?.context?.accountId || 'confluence-event-trigger'
            ),
            action: 'CONFLUENCE_PAGE_DRIFT',
            targetKey: `page:${pageId}`,
            details: {
              pageId,
              newSha256: newHash,
              affectedHazards,
              affectedWorkKeys,
              projectKeys: affectedProjectKeys,
            },
            authMethod: 'CONFLUENCE_EVENT_TRIGGER',
          },
        });
        return { processed: true, pageId, affectedHazards };
      } catch (err: unknown) {
        if (isConcurrencyError(err) && attempt < MAX_CAS_RETRY_ATTEMPTS) {
          continue;
        }
        throw err;
      }
    }

    throw new Error(`Failed to persist Confluence page drift for ${pageId} after ${MAX_CAS_RETRY_ATTEMPTS} attempts.`);
  }

  /**
   * Forge product trigger handler for `avi:jira:updated:issue`, `avi:jira:created:issuelink`,
   * and `avi:jira:deleted:issuelink`. Refreshes tracked LIVE Jira issues automatically so status,
   * title, assignee, labels, and linked Hazard/Test `issuelinks` stay current without manual re-sync.
   */
  public static async handleJiraIssueUpdated(
    event: JiraIssueUpdatedEvent
  ): Promise<JiraIssueUpdatedResult> {
    if (!isForgeRuntime()) {
      return { processed: false, affectedHazards: [] };
    }

    const candidateIssueRefs: string[] = [];
    if (typeof event?.issue?.key === 'string' && event.issue.key.trim()) {
      candidateIssueRefs.push(event.issue.key.trim().toUpperCase());
    } else if (event?.issue?.id !== undefined && event?.issue?.id !== null) {
      candidateIssueRefs.push(String(event.issue.id).trim());
    }
    if (event?.issueLink?.sourceIssueId !== undefined && event?.issueLink?.sourceIssueId !== null) {
      candidateIssueRefs.push(String(event.issueLink.sourceIssueId).trim());
    }
    if (event?.issueLink?.destinationIssueId !== undefined && event?.issueLink?.destinationIssueId !== null) {
      candidateIssueRefs.push(String(event.issueLink.destinationIssueId).trim());
    }

    const uniqueRefs = Array.from(new Set(candidateIssueRefs.filter(Boolean)));
    if (uniqueRefs.length === 0) {
      return { processed: false, affectedHazards: [] };
    }

    const client = api.asApp();
    const fetchedByKey = new Map<string, JiraApiIssue>();
    const fetchedIds = new Set<string>();
    let primaryResolvedKey: string | undefined;

    const fetchJiraIssueIntoMap = async (ref: string): Promise<JiraApiIssue | undefined> => {
      try {
        const resp = await client.requestJira(
          route`/rest/api/3/issue/${ref}?fields=summary,status,assignee,labels,issuetype,project,issuelinks`
        );
        if (resp.status === 200) {
          const parsed = (await resp.json()) as JiraApiIssue;
          if (typeof parsed?.key === 'string' && parsed.key.trim()) {
            const upperKey = parsed.key.trim().toUpperCase();
            fetchedByKey.set(upperKey, parsed);
            fetchedIds.add(upperKey);
            if (parsed.id !== undefined && parsed.id !== null) {
              fetchedIds.add(String(parsed.id).trim());
            }
            if (!primaryResolvedKey) {
              primaryResolvedKey = upperKey;
            }
            return parsed;
          }
        }
      } catch {
        // Ignore transient or deleted-issue 404 refs and continue resolving siblings
      }
      return undefined;
    };

    for (const ref of uniqueRefs) {
      await fetchJiraIssueIntoMap(ref);
    }

    if (!primaryResolvedKey || fetchedByKey.size === 0) {
      return { processed: false, affectedHazards: [] };
    }

    const collectRawIssueLinkKeys = (issuelinks: unknown): Set<string> => {
      const keys = new Set<string>();
      if (!Array.isArray(issuelinks)) return keys;
      for (const raw of issuelinks) {
        if (!raw || typeof raw !== 'object') continue;
        const entry = raw as JiraIssueLinkEntry;
        for (const side of [entry.inwardIssue, entry.outwardIssue]) {
          if (typeof side?.key === 'string' && side.key.trim()) {
            keys.add(side.key.trim().toUpperCase());
          }
        }
      }
      return keys;
    };

    const isDeletedLinkEvent = event?.eventType === 'avi:jira:deleted:issuelink';

    for (let attempt = 1; attempt <= MAX_CAS_RETRY_ATTEMPTS; attempt++) {
      const { summary: suite, version } = await SeederService.getSuiteWithVersion();
      if (suite.datasetMode !== 'LIVE' || suite.initialized === false || suite.traceLinks.length === 0) {
        return { processed: false, issueKey: primaryResolvedKey, affectedHazards: [] };
      }

      const matchingIndices: number[] = [];
      suite.traceLinks.forEach((link, idx) => {
        const workKey = (link.work?.key || '').trim().toUpperCase();
        const hazKey = (link.hazard?.key || '').trim().toUpperCase();
        const testKey = (link.test?.testKey || '').trim().toUpperCase();
        const revKey = (link.reverificationTaskKey || '').trim().toUpperCase();
        if (
          (workKey && fetchedByKey.has(workKey)) ||
          (hazKey && fetchedByKey.has(hazKey)) ||
          (testKey && fetchedByKey.has(testKey)) ||
          (revKey && fetchedByKey.has(revKey)) ||
          (link.work?.id && fetchedIds.has(String(link.work.id).trim())) ||
          (link.hazard?.id && fetchedIds.has(String(link.hazard.id).trim())) ||
          (link.test?.id && fetchedIds.has(String(link.test.id).trim()))
        ) {
          matchingIndices.push(idx);
        }
      });

      if (matchingIndices.length === 0) {
        return { processed: false, issueKey: primaryResolvedKey, affectedHazards: [] };
      }

      // Ensure every affected link's anchoring Jira work item is fetched so issuelinks reconciliation has current truth.
      for (const idx of matchingIndices) {
        const wk = (suite.traceLinks[idx].work?.key || '').trim().toUpperCase();
        if (wk && JIRA_ISSUE_KEY_RE.test(wk) && !fetchedByKey.has(wk)) {
          await fetchJiraIssueIntoMap(wk);
        }
      }

      const updatedLinks = suite.traceLinks.map(cloneTraceLink);
      const affectedHazards: string[] = [];
      const part11Secret = (process.env.MEDTRACE_PART11_SECRET || '').trim();

      for (const idx of matchingIndices) {
        const link = updatedLinks[idx];
        const workKeyUpper = (link.work?.key || '').trim().toUpperCase();
        const hazKeyUpper = (link.hazard?.key || '').trim().toUpperCase();
        const testKeyUpper = (link.test?.testKey || '').trim().toUpperCase();

        const workIssue = workKeyUpper ? fetchedByKey.get(workKeyUpper) : undefined;
        let hazDowngraded = false;
        let testDowngraded = false;

        if (workIssue) {
          const workFields = workIssue.fields || {};
          const workLabels = normalizeStringArray(workFields.labels);
          link.work.title = workFields.summary || link.work.title;
          link.work.status = mapJiraStatusToWorkStatus(workFields.status);
          link.work.assignee = workFields.assignee?.displayName || 'Unassigned';

          const rawLinks = Array.isArray(workFields.issuelinks) ? workFields.issuelinks : [];
          const rawLinkedKeys = collectRawIssueLinkKeys(rawLinks);
          const linked = resolveLinkedHazardAndTest(
            extractLinkedIssueCandidates(rawLinks, fetchedByKey)
          );

          if (linked.linkedHazard) {
            link.hazard.id = linked.linkedHazard.id;
            link.hazard.key = linked.linkedHazard.key;
            link.hazard.title = linked.linkedHazard.summary || link.hazard.title;
            link.hazard.source = 'JIRA_ISSUE';
            if (link.graphMetadata) {
              link.graphMetadata.hazardAri = `ari:cloud:jira::issue/${linked.linkedHazard.key}`;
              link.graphMetadata.edgeType = linked.linkedHazard.relationshipLabel || link.graphMetadata.edgeType;
            }
          } else if (link.hazard.source === 'JIRA_ISSUE' && Array.isArray(workFields.issuelinks)) {
            const fallbackHazKey = `HAZ-${workKeyUpper}`;
            link.hazard.id = fallbackHazKey.toLowerCase();
            link.hazard.key = fallbackHazKey;
            link.hazard.title = workFields.summary || `Hazard for ${workKeyUpper}`;
            link.hazard.source = 'APP_MANAGED';
            hazDowngraded = true;
            if (link.graphMetadata) {
              link.graphMetadata.hazardAri = `ari:cloud:medtrace::iso14971-hazard/${fallbackHazKey}`;
            }
          }

          if (linked.linkedTest) {
            const changedTest =
              link.test.testKey.toUpperCase() !== linked.linkedTest.key.toUpperCase();
            link.test.id = linked.linkedTest.id;
            link.test.testKey = linked.linkedTest.key;
            link.test.title = linked.linkedTest.summary || link.test.title;
            link.test.source = 'JIRA_ISSUE';
            if (changedTest) {
              link.test.status = 'UNTESTED';
              delete link.test.evidenceUrl;
              delete link.test.executionDate;
              delete link.test.recordedBy;
              delete link.test.notes;
            }
          } else if (link.test.source === 'JIRA_ISSUE' && Array.isArray(workFields.issuelinks)) {
            const fallbackTestKey = `TEST-${workKeyUpper}`;
            link.test.id = fallbackTestKey.toLowerCase();
            link.test.testKey = fallbackTestKey;
            link.test.title = `Verification Test for ${workKeyUpper}`;
            link.test.source = 'APP_MANAGED';
            link.test.status = 'UNTESTED';
            delete link.test.evidenceUrl;
            delete link.test.executionDate;
            delete link.test.recordedBy;
            delete link.test.notes;
            testDowngraded = true;
          }

          if (linked.linkedReverification) {
            link.reverificationTaskKey = linked.linkedReverification.key;
          } else if (
            link.reverificationTaskKey &&
            Array.isArray(workFields.issuelinks) &&
            !rawLinkedKeys.has(link.reverificationTaskKey.trim().toUpperCase())
          ) {
            delete link.reverificationTaskKey;
          }

          if (workLabels.length > 0 && !linked.linkedHazard) {
            const inferred = inferRiskClass(workLabels);
            link.hazard.riskClass = inferred.riskClass;
            delete link.hazard.severity;
            delete link.hazard.probability;
            if (inferred.safetyClassAssigned === false) {
              link.hazard.safetyClassAssigned = false;
            } else {
              delete link.hazard.safetyClassAssigned;
            }
          }
        }

        const currentHazKey = (link.hazard?.key || '').trim().toUpperCase();
        const hazIssue = !hazDowngraded
          ? fetchedByKey.get(currentHazKey) || (hazKeyUpper ? fetchedByKey.get(hazKeyUpper) : undefined)
          : undefined;
        if (hazIssue && !hazDowngraded && (!link.hazard.source || link.hazard.source === 'JIRA_ISSUE' || hazIssue.key?.toUpperCase() === currentHazKey)) {
          const hazFields = hazIssue.fields || {};
          const hazLabels = normalizeStringArray(hazFields.labels);
          link.hazard.title = hazFields.summary || link.hazard.title;
          link.hazard.source = 'JIRA_ISSUE';
          if (hazLabels.length > 0) {
            const inferred = inferRiskClass(hazLabels);
            if (inferred.safetyClassAssigned !== false) {
              link.hazard.riskClass = inferred.riskClass;
              delete link.hazard.severity;
              delete link.hazard.probability;
              delete link.hazard.safetyClassAssigned;
            }
          }
        }

        const currentTestKey = (link.test?.testKey || '').trim().toUpperCase();
        const testIssue = !testDowngraded
          ? fetchedByKey.get(currentTestKey) || (testKeyUpper ? fetchedByKey.get(testKeyUpper) : undefined)
          : undefined;
        if (testIssue && !testDowngraded) {
          const testFields = testIssue.fields || {};
          link.test.title = testFields.summary || link.test.title;
          link.test.source = 'JIRA_ISSUE';
        }

        if (isDeletedLinkEvent && link.reverificationTaskKey) {
          const revUpper = link.reverificationTaskKey.trim().toUpperCase();
          const revIssue = fetchedByKey.get(revUpper);
          if (revIssue && Array.isArray(revIssue.fields?.issuelinks)) {
            const revLinkedKeys = collectRawIssueLinkKeys(revIssue.fields.issuelinks);
            if (workKeyUpper && !revLinkedKeys.has(workKeyUpper)) {
              delete link.reverificationTaskKey;
            }
          }
        }

        const evaluated = ComplianceEngine.evaluateTraceLink(
          link.hazard,
          link.spec,
          link.work,
          link.test,
          link.signature,
          link.graphMetadata,
          {
            linkId: link.id,
            part11Secret,
            requireCryptographicSeal: true,
            requireTestEvidence: true,
            reverificationTaskKey: link.reverificationTaskKey,
          }
        );
        evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
        updatedLinks[idx] = evaluated;
        if (!affectedHazards.includes(evaluated.hazard.key)) {
          affectedHazards.push(evaluated.hazard.key);
        }
      }

      const eventNowIso = new Date().toISOString();
      const updated = ComplianceEngine.generateComplianceReport(
        updatedLinks,
        suite.datasetMode,
        suite.projectName,
        { initialized: true, lastSyncedAt: eventNowIso }
      );

      const affectedWorkProject = updatedLinks[matchingIndices[0]]?.work?.key?.split('-')[0];
      const projectKey = affectedWorkProject || primaryResolvedKey.split('-')[0];

      try {
        await commitSuiteMutation({
          summary: updated,
          expectedVersion: version ?? 0,
          auditEntry: {
            actorAccountId: String(
              event?.atlassianId || event?.context?.accountId || 'jira-event-trigger'
            ),
            action: 'SYNC_LIVE',
            targetKey: primaryResolvedKey,
            details: {
              projectKey,
              issueKey: primaryResolvedKey,
              eventType: event?.eventType || 'avi:jira:updated:issue',
              affectedHazards,
              lastSyncedAt: eventNowIso,
            },
            authMethod: 'JIRA_EVENT_TRIGGER',
          },
        });
        return { processed: true, issueKey: primaryResolvedKey, affectedHazards };
      } catch (err: unknown) {
        if (isConcurrencyError(err) && attempt < MAX_CAS_RETRY_ATTEMPTS) {
          continue;
        }
        throw err;
      }
    }

    throw new Error(
      `Failed to persist Jira issue trigger sync for ${primaryResolvedKey} after ${MAX_CAS_RETRY_ATTEMPTS} attempts.`
    );
  }
}
