import api, { route } from '@forge/api';
import { kvs } from '@forge/kvs';
import { ComplianceEngine } from './compliance-engine';
import { isKvsConflictError, sha256Hex } from './crypto-utils';
import { isForgeRuntime } from './runtime';
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

interface JiraApiIssue {
  id?: string | number;
  key?: string;
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

function inferRiskClass(labels: string[], priorityName?: string): {
  riskClass: RiskClass;
  severity: IsoHazard['severity'];
  probability: IsoHazard['probability'];
} {
  const lowerLabels = labels.map((l) => l.toLowerCase());
  const lowerPriority = (priorityName || '').toLowerCase();

  if (
    lowerLabels.some((l) => l.includes('class-c') || l.includes('class_c') || l.includes('critical-safety')) ||
    lowerPriority === 'highest'
  ) {
    return { riskClass: 'CLASS_C', severity: 'CATASTROPHIC', probability: 'OCCASIONAL' };
  }
  if (lowerLabels.some((l) => l.includes('class-b') || l.includes('class_b')) || lowerPriority === 'high') {
    return { riskClass: 'CLASS_B', severity: 'CRITICAL', probability: 'REMOTE' };
  }
  return { riskClass: 'CLASS_A', severity: 'MINOR', probability: 'IMPROBABLE' };
}

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

  const jql =
    options.jql?.trim() ||
    (projectKey ? `project = "${projectKey}" ORDER BY updated DESC` : 'ORDER BY updated DESC');

  const pageToken =
    typeof options.pageToken === 'string' && options.pageToken.trim() !== ''
      ? options.pageToken.trim()
      : undefined;

  return {
    projectKey,
    spaceId,
    jql,
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
      ? route`/rest/api/3/search/jql?jql=${jql}&maxResults=${JIRA_PAGE_SIZE}&fields=summary,status,assignee,labels,priority,issuetype,project&nextPageToken=${nextPageToken}`
      : route`/rest/api/3/search/jql?jql=${jql}&maxResults=${JIRA_PAGE_SIZE}&fields=summary,status,assignee,labels,priority,issuetype,project`;

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
    let resumedFromCursor = Boolean(initialPageToken);
    if (!initialPageToken && normalized.resumeFromCursor) {
      try {
        const storedCursor = await kvs.get<{ nextPageToken?: string; jql?: string }>(cursorKey);
        if (
          storedCursor &&
          typeof storedCursor.nextPageToken === 'string' &&
          storedCursor.nextPageToken.trim() !== '' &&
          (!storedCursor.jql || storedCursor.jql === normalized.jql)
        ) {
          initialPageToken = storedCursor.nextPageToken.trim();
          resumedFromCursor = true;
        }
      } catch {
        // Ignore missing/unreadable cursor and start cleanly from page 1.
      }
    }

    // 1. Paginate Jira issues via Jira REST v3 /search/jql (nextPageToken)
    const jiraResult = await fetchAllJiraIssues(
      client,
      normalized.jql,
      normalized.maxIssues,
      startedAt,
      warnings,
      initialPageToken
    );
    const issues = jiraResult.issues;
    let truncated = jiraResult.truncated;

    // 2. Paginate Confluence pages via v2 _links.next cursor
    const confResult = await fetchAllConfluencePages(
      client,
      normalized.spaceId,
      startedAt,
      warnings
    );
    const pages = confResult.pages;
    if (confResult.truncated) {
      truncated = true;
    }

    const pageCache = new Map<string, ConfluencePageData | null>();
    for (const p of pages) {
      if (p?.id !== undefined && p?.id !== null) {
        pageCache.set(String(p.id), p);
      }
    }
    const pageFetchInflight = new Map<string, Promise<ConfluencePageData | null>>();

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
    for (const link of existingSuite.traceLinks) {
      const workKeyUpper = (link.work?.key || '').trim().toUpperCase();
      if (!workKeyUpper) continue;
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

      const { riskClass, severity, probability } = inferRiskClass(labels, fields.priority?.name);
      const prevWorkLinks = existingByWorkKey.get(issueKey.toUpperCase()) || [];
      const defaultHazardKey = prevWorkLinks[0]?.hazard?.key || `HAZ-${issueKey}`;

      const work: JiraWorkItem = {
        id: String(issue.id || issueKey.toLowerCase()),
        key: issueKey,
        title: fields.summary || issueKey,
        status: mapJiraStatusToWorkStatus(fields.status),
        assignee: fields.assignee?.displayName || 'Unassigned',
      };

      const aggTraversalStatus = graphCtx ? `LIVE (${graphCtx.source})` : 'LIVE (JIRA_REST)';
      const entityAri = graphCtx?.issueAri || `jira:issue:${issueKey}`;

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
        for (const token of srsTokens) {
          for (const candidate of pages) {
            const candidateId = candidate?.id !== undefined && candidate?.id !== null ? String(candidate.id) : '';
            if (!candidateId || seenPageIds.has(candidateId)) continue;
            if (String(candidate.title || '').toLowerCase().includes(token)) {
              seenPageIds.add(candidateId);
              matchedPages.push({ page: candidate, edgeType: 'HEURISTIC:summary-srs-title' });
            }
          }
        }
      }

      // Unlinked sentinel path
      if (matchedPages.length === 0) {
        const specId = `unlinked-${issueKey.toLowerCase()}`;
        const prevExact =
          existingByWorkAndSpec.get(`${issueKey.toUpperCase()}::${specId}`) || prevWorkLinks[0];
        const hazardKey = prevExact?.hazard?.key || defaultHazardKey;

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

        const hazard: IsoHazard = {
          id: hazardKey.toLowerCase(),
          key: hazardKey,
          title: fields.summary || prevExact?.hazard?.title || `Hazard for ${issueKey}`,
          riskClass,
          severity,
          probability,
          mitigationRequirementId: spec.id,
          status: 'UNVERIFIED_RISK',
        };

        const test: VerificationTest = prevExact?.test
          ? { ...prevExact.test }
          : {
              id: `test-${issueKey.toLowerCase()}`,
              testKey: `TEST-${issueKey}`,
              title: `Verification Test for ${issueKey}`,
              testType: riskClass === 'CLASS_C' ? 'Automated HIL (Hardware-in-Loop)' : 'Integration Test',
              status: 'UNTESTED',
            };

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
          hazardAri: `ari:cloud:medtrace::iso14971-hazard/${hazard.key}`,
          linkedSpecAri: 'unlinked',
          edgeType: 'NONE:unlinked',
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
        const hazardKey = prevExact?.hazard?.key || defaultHazardKey;

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

        const hazard: IsoHazard = {
          id: hazardKey.toLowerCase(),
          key: hazardKey,
          title: fields.summary || prevExact?.hazard?.title || `Hazard for ${issueKey}`,
          riskClass,
          severity,
          probability,
          mitigationRequirementId: spec.id,
          status: 'UNVERIFIED_RISK',
        };

        const testSource = prevExact?.test || prevWorkLinks[0]?.test;
        const test: VerificationTest = testSource
          ? { ...testSource }
          : {
              id: `test-${issueKey.toLowerCase()}`,
              testKey: `TEST-${issueKey}`,
              title: `Verification Test for ${issueKey}`,
              testType: riskClass === 'CLASS_C' ? 'Automated HIL (Hardware-in-Loop)' : 'Integration Test',
              status: 'UNTESTED',
            };

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
          hazardAri: `ari:cloud:medtrace::iso14971-hazard/${hazard.key}`,
          linkedSpecAri: `confluence:page:${pageIdStr}`,
          edgeType,
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
    let linkedPairsFound = 0;
    let driftDetectedCount = 0;
    let skippedUntaggedCount = 0;

    for (let i = 0; i < issues.length; i += LIVE_SYNC_CONCURRENCY_BATCH_SIZE) {
      if (Date.now() - startedAt >= LIVE_SYNC_BUDGET_MS) {
        truncated = true;
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

      for (const existingLink of existingSuite.traceLinks) {
        const workKeyUpper = (existingLink.work?.key || '').trim().toUpperCase();
        const hasStandardPrefix = /^[A-Z][A-Z0-9_]*-\d+$/.test(workKeyUpper);
        const isOtherProject = Boolean(
          syncedProjectPrefix && hasStandardPrefix && !workKeyUpper.startsWith(syncedProjectPrefix)
        );
        const isUnprocessedTruncated = Boolean(
          (truncated || resumedFromCursor) && workKeyUpper && !processedWorkKeys.has(workKeyUpper)
        );

        if ((isOtherProject || isUnprocessedTruncated) && !seenLinkIds.has(existingLink.id)) {
          traceLinks.push(cloneTraceLink(existingLink));
          seenLinkIds.add(existingLink.id);
          if (isOtherProject) {
            preservedOtherProjectCount++;
          } else {
            preservedTruncatedCount++;
          }
        }
      }

      if (preservedTruncatedCount > 0) {
        warnings.push(
          `Preserved ${preservedTruncatedCount} existing trace link(s) not reached before sync truncation.`
        );
      }
      if (preservedOtherProjectCount > 0) {
        warnings.push(
          `Preserved ${preservedOtherProjectCount} existing trace link(s) belonging to other Jira project(s).`
        );
      }
    }

    const persistOrClearCursor = async (): Promise<void> => {
      try {
        if (jiraResult.truncated && jiraResult.nextPageToken) {
          await kvs.set(cursorKey, {
            nextPageToken: jiraResult.nextPageToken,
            jql: normalized.jql,
            projectKey: normalized.projectKey || 'GLOBAL',
            updatedAt: new Date().toISOString(),
          });
        } else if (!jiraResult.truncated) {
          await kvs.delete(cursorKey);
        }
      } catch {
        // Non-fatal: nextPageToken is still returned to caller.
      }
    };

    if (traceLinks.length === 0) {
      await persistOrClearCursor();
      warnings.push(
        'No safety-tracked Jira issues matched the live sync query; keeping existing compliance suite unchanged.'
      );
      return {
        success: false,
        datasetMode: existingSuite.datasetMode,
        jiraIssuesScanned: issues.length,
        confluencePagesScanned: pages.length,
        linkedPairsFound,
        driftDetectedCount,
        truncated,
        ...(jiraResult.nextPageToken ? { nextPageToken: jiraResult.nextPageToken } : {}),
        ...(resumedFromCursor ? { resumedFromCursor: true } : {}),
        skippedUntaggedCount,
        warnings,
        summary: existingSuite,
      };
    }

    const projectLabel =
      normalized.projectKey ||
      issues[0]?.fields?.project?.name ||
      'Atlassian Cloud Live Medical Project';

    const summary = ComplianceEngine.generateComplianceReport(traceLinks, 'LIVE', projectLabel, {
      initialized: true,
    });

    const saved = await commitSuiteMutation({
      summary,
      expectedVersion: existingVersion ?? 0,
      baselineUpdates,
      auditEntry: {
        actorAccountId,
        action: 'SYNC_LIVE',
        targetKey: projectLabel,
        details: {
          jiraIssuesScanned: issues.length,
          confluencePagesScanned: pages.length,
          linkedPairsFound,
          driftDetectedCount,
          skippedUntaggedCount,
          truncated,
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
      confluencePagesScanned: pages.length,
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
          { linkId: link.id, part11Secret }
        );
        evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
        updatedLinks[idx] = evaluated;
        if (!affectedHazards.includes(evaluated.hazard.key)) {
          affectedHazards.push(evaluated.hazard.key);
        }
      }

      const updated = ComplianceEngine.generateComplianceReport(
        updatedLinks,
        suite.datasetMode,
        suite.projectName,
        { initialized: suite.initialized ?? true }
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
}
