import api, { route } from '@forge/api';
import { kvs } from '@forge/kvs';
import { ComplianceEngine } from './compliance-engine';
import {
  cloneJsonValue,
  isHttpOk,
  JIRA_ISSUE_KEY_RE,
  JIRA_PROJECT_KEY_RE,
  safeParseJson,
  sanitizeKvsKeySegment,
  sha256Hex,
} from './crypto-utils';
import { isForgeRuntime } from './runtime';
import {
  BaselineMutationRecord,
  commitSuiteMutation,
  mapJiraStatusToWorkStatus,
  SeederService,
  SignedSpecBaseline,
} from './seeder';
import {
  extractAllJiraProjectKeysFromLink,
  hasJiraBrowsePermissionForCaller,
} from './seeder-identity';
import { resolveCloudId, TeamworkGraphService } from './teamwork-graph';
import {
  buildBaselineMutationForInvalidation,
  ConfluencePageData,
  ConfluencePageUpdatedEvent,
  ConfluencePageUpdatedResult,
  DEFAULT_HAZARD_ISSUE_TYPES,
  DEFAULT_HAZARD_LABEL_PATTERNS,
  extractLinkedIssueCandidates,
  handleConfluencePageUpdatedTrigger,
  handleJiraIssueUpdatedTrigger,
  inferRiskClass,
  isBaselineInvalidated,
  isPureHazardIssue,
  isPureVerificationTestIssue,
  JiraApiIssue,
  JiraIssueUpdatedEvent,
  JiraIssueUpdatedResult,
  normalizeStringArray,
  reconcileConfluenceSpecsTrigger,
  resolveLinkedHazardAndTest,
  stripStorageMarkup,
} from './triggers';
import {
  ComplianceSummary,
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

export type {
  ConfluencePageUpdatedEvent,
  ConfluencePageUpdatedResult,
  JiraIssueUpdatedEvent,
  JiraIssueUpdatedResult,
} from './triggers';

export const DEFAULT_SYNC_MAX_ISSUES = 250;
export const MAX_SYNC_MAX_ISSUES = 500;
export const LIVE_SYNC_BUDGET_MS = 11_000;
export const LIVE_SYNC_CONCURRENCY_BATCH_SIZE = 5;
const JIRA_PAGE_SIZE = 50;
const CONFLUENCE_PAGE_SIZE = 50;
const MAX_PAGINATION_PAGES = 100;
export const SYNC_CURSOR_KEY_PREFIX = 'medtrace:ingestion:cursor:';

export function getSyncCursorKey(projectKey?: string): string {
  const clean = typeof projectKey === 'string' && projectKey.trim() !== '' ? projectKey.trim().toUpperCase() : '';
  return `${SYNC_CURSOR_KEY_PREFIX}${clean || 'GLOBAL'}`;
}

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

type ForgeApiClient = ReturnType<typeof api.asApp> | ReturnType<typeof api.asUser>;

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
    if (!JIRA_PROJECT_KEY_RE.test(projectKey)) {
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
): Promise<{ issues: JiraApiIssue[]; overflowKeys: string[]; truncated: boolean; nextPageToken?: string }> {
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

    const jiraJson = await safeParseJson<{
      issues?: JiraApiIssue[];
      nextPageToken?: string;
      isLast?: boolean;
    }>(jiraResp);
    if (!jiraJson) {
      throw new Error('Jira search returned malformed JSON response.');
    }
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
        if (candidateToken && jiraJson?.isLast !== true) {
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

  const slicedIssues = issues.length > maxIssues ? issues.slice(0, maxIssues) : issues;
  const overflowKeys =
    issues.length > maxIssues
      ? issues
          .slice(maxIssues)
          .map((i) => (typeof i?.key === 'string' ? i.key.trim().toUpperCase() : ''))
          .filter((k) => JIRA_ISSUE_KEY_RE.test(k))
      : [];

  return {
    issues: slicedIssues,
    overflowKeys,
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
    const jiraJson = await safeParseJson<{ issues?: JiraApiIssue[] }>(jiraResp);
    if (!jiraJson) {
      throw new Error('Jira resume search returned malformed JSON response.');
    }
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

    const confJson = await safeParseJson<{
      results?: ConfluencePageData[];
      _links?: { next?: string };
    }>(confResp);
    if (!confJson) {
      truncated = true;
      warnings.push('Confluence pages query returned malformed JSON; proceeding with partial pages.');
      break;
    }
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
            overflowKeys: [] as string[],
            truncated: pendingTruncated || Boolean(tokenForNextJiraPage),
            ...(tokenForNextJiraPage ? { nextPageToken: tokenForNextJiraPage } : {}),
          };
    const seenIssueKeys = new Set<string>();
    const issues: JiraApiIssue[] = [];
    for (const candidateIssue of [...pendingIssues, ...jiraResult.issues]) {
      const keyUpper = typeof candidateIssue?.key === 'string' ? candidateIssue.key.trim().toUpperCase() : '';
      if (keyUpper && seenIssueKeys.has(keyUpper)) {
        continue;
      }
      if (keyUpper) {
        seenIssueKeys.add(keyUpper);
      }
      issues.push(candidateIssue);
    }
    const overflowKeys = jiraResult.overflowKeys ?? [];
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
    const pageFetchFailures = new Map<string, 'FORBIDDEN' | 'TRANSIENT' | 'NOT_FOUND'>();
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
                const spaceJson = await safeParseJson<{
                  results?: Array<{ id?: string | number }>;
                }>(spaceResp);
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
            const confJson = await safeParseJson<{
              results?: ConfluencePageData[];
              _links?: { next?: string };
            }>(confResp);
            if (!confJson) {
              warnings.push('Confluence heuristic pages query returned malformed JSON; proceeding with Jira remote links only.');
              return collected;
            }
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
            const pageJson = await safeParseJson<ConfluencePageData>(singlePageResp);
            if (!pageJson) {
              pageFetchFailures.set(pageId, 'TRANSIENT');
              warnings.push(
                `Confluence page ${pageId} linked from ${referencingIssueKey} returned malformed JSON.`
              );
              pageCache.set(pageId, null);
              return null;
            }
            pageCache.set(pageId, pageJson);
            return pageJson;
          }
          pageFetchFailures.set(
            pageId,
            singlePageResp.status === 404
              ? 'NOT_FOUND'
              : singlePageResp.status === 401 || singlePageResp.status === 403
                ? 'FORBIDDEN'
                : 'TRANSIENT'
          );
          warnings.push(
            `Confluence page ${pageId} linked from ${referencingIssueKey} returned HTTP ${singlePageResp.status}.`
          );
          pageCache.set(pageId, null);
          return null;
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          pageFetchFailures.set(pageId, 'TRANSIENT');
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
    if (resumedFromCursor && existingSuite.datasetMode === 'LIVE' && existingSuite.initialized !== false) {
      for (const link of existingSuite.traceLinks) {
        if (link.hazard?.source === 'JIRA_ISSUE' && link.hazard.key) {
          linkedRoleOwners.add(link.hazard.key.trim().toUpperCase());
        }
        if (link.test?.source === 'JIRA_ISSUE' && link.test.testKey) {
          linkedRoleOwners.add(link.test.testKey.trim().toUpperCase());
        }
        if (link.reverificationTaskKey) {
          linkedRoleOwners.add(link.reverificationTaskKey.trim().toUpperCase());
        }
      }
    }
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
      hazardKey: string
    ): Promise<SignedSpecBaseline | undefined> => {
      const cacheKey = `${hazardKey}::${specOrPageId}`;
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
          skipIssueMetadataFetch: true,
          preloadedIssue: {
            id: issue.id,
            self: issue.self,
            summary: fields.summary,
            issuelinks: fields.issuelinks,
          },
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
      const jiraCloudId = resolveCloudId(issue.self) || resolveCloudId(linkedHazard?.self);

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

      // Unlinked sentinel path (preserve existing non-sentinel specs when Confluence access is denied or transiently unavailable)
      if (matchedPages.length === 0) {
        const protectedPrevLinks = prevWorkLinks.filter((pl) => {
          const pid = typeof pl.spec?.pageId === 'string' ? pl.spec.pageId.trim() : '';
          if (!pid || pl.spec?.isMissingSentinel === true) return false;
          const failure = pageFetchFailures.get(pid);
          return failure === 'FORBIDDEN' || failure === 'TRANSIENT';
        });
        if (protectedPrevLinks.length > 0) {
          return {
            skipped: false,
            links: protectedPrevLinks.map((pl) => {
              const preserved = cloneJsonValue(pl);
              preserved.work = {
                ...preserved.work,
                title: fields.summary || preserved.work.title,
                status: work.status,
                assignee: fields.assignee?.displayName || 'Unassigned',
              };
              if (linkedReverification?.key) {
                preserved.reverificationTaskKey = linkedReverification.key;
              }
              return preserved;
            }),
            linkedPairs: protectedPrevLinks.length,
            drifts: 0,
            baselineUpdates: [],
          };
        }

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
          isSignatureInvalidated: false,
          isMissingSentinel: true,
          contentSnippet: 'No linked Confluence SRS specification found on Jira issue remote links.',
          lastUpdated: new Date().toISOString(),
        };

        const hazard = buildResolvedHazard(hazardKey, spec.id, prevExact?.hazard?.title);
        const test = buildResolvedTest(prevExact?.test);

        const signature: Part11Signature = {
          id: `sig-${sanitizeKvsKeySegment(`${hazardKey}--${spec.id}`)}`,
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
            id: `sig-${sanitizeKvsKeySegment(`${hazardKey}--${spec.id}`)}`,
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
            id: `sig-${sanitizeKvsKeySegment(`${hazardKey}--${spec.id}`)}`,
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
    const seenBuiltLinkIds = new Set<string>();
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
        for (const built of result.links) {
          if (!seenBuiltLinkIds.has(built.id)) {
            seenBuiltLinkIds.add(built.id);
            traceLinks.push(built);
          }
        }
        linkedPairsFound += result.linkedPairs;
        driftDetectedCount += result.drifts;
        baselineUpdates.push(...result.baselineUpdates);
      }
    }

    let preservedOtherProjectCount = 0;

    if (
      existingSuite.datasetMode === 'LIVE' &&
      existingSuite.initialized !== false &&
      existingSuite.traceLinks.length > 0 &&
      (traceLinks.length > 0 || resumedFromCursor || (!truncated && !normalized.hasCustomJql))
    ) {
      const syncedProjectPrefix = normalized.projectKey
        ? `${normalized.projectKey.trim().toUpperCase()}-`
        : undefined;
      const seenLinkIds = new Set(traceLinks.map((l) => l.id));
      let preservedTruncatedCount = 0;
      let preservedFilteredJqlCount = 0;
      const browsePermCache = new Map<string, boolean>();

      const isLinkInUnbrowsableProject = async (link: TraceLink): Promise<boolean> => {
        if (syncedProjectPrefix || normalized.callerMode !== 'USER' || !isForgeRuntime()) {
          return false;
        }
        const linkProjects = extractAllJiraProjectKeysFromLink(link);
        for (const projKey of linkProjects) {
          let allowed = browsePermCache.get(projKey);
          if (allowed === undefined) {
            if (options.preserveReadOnlyProjects) {
              try {
                const permResp = await api
                  .asUser()
                  .requestJira(
                    route`/rest/api/3/mypermissions?projectKey=${projKey}&permissions=BROWSE_PROJECTS,EDIT_ISSUES,ADMINISTER_PROJECTS`
                  );
                if (!isHttpOk(permResp)) {
                  allowed = false;
                } else {
                  const pData = (await permResp.json().catch(() => ({}))) as {
                    active?: unknown;
                    permissions?: Record<string, { havePermission?: boolean } | undefined>;
                  };
                  const canBrowse =
                    pData.permissions?.BROWSE_PROJECTS?.havePermission === true ||
                    (pData.permissions?.BROWSE_PROJECTS === undefined &&
                      (pData.permissions?.EDIT_ISSUES?.havePermission === true ||
                        pData.permissions?.ADMINISTER_PROJECTS?.havePermission === true));
                  const canEdit =
                    pData.permissions?.EDIT_ISSUES?.havePermission === true ||
                    pData.permissions?.ADMINISTER_PROJECTS?.havePermission === true;
                  allowed = pData.active !== false && canBrowse && canEdit;
                }
              } catch {
                allowed = false;
              }
            } else {
              allowed = await hasJiraBrowsePermissionForCaller({ projectKey: projKey });
            }
            browsePermCache.set(projKey, allowed);
          }
          if (!allowed) {
            return true;
          }
        }
        return false;
      };

      for (const existingLink of existingSuite.traceLinks) {
        const workKeyUpper = (existingLink.work?.key || '').trim().toUpperCase();
        const hasStandardPrefix = /^[A-Z][A-Z0-9_]*-\d+$/.test(workKeyUpper);
        const isOtherProject =
          Boolean(
            syncedProjectPrefix && hasStandardPrefix && !workKeyUpper.startsWith(syncedProjectPrefix)
          ) || (await isLinkInUnbrowsableProject(existingLink));
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
          traceLinks.push(cloneJsonValue(existingLink));
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

    const nextPendingKeys = Array.from(
      new Set([...overflowKeys, ...unprocessedKeys, ...remainingFetchKeys])
    );
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

    const prevIncompleteProjects = Array.isArray(existingSuite.incompleteProjectKeys)
      ? existingSuite.incompleteProjectKeys.map((p) => p.trim().toUpperCase()).filter(Boolean)
      : [];
    const mergeIncompleteProjects = (syncedProjects: string[]): string[] => {
      if (truncated) {
        const additions = normalized.projectKey ? [normalized.projectKey] : syncedProjects;
        return Array.from(new Set([...prevIncompleteProjects, ...additions].filter(Boolean)));
      }
      if (normalized.projectKey) {
        return prevIncompleteProjects.filter((p) => p !== normalized.projectKey);
      }
      return [];
    };

    if (traceLinks.length === 0) {
      await persistOrClearCursor();
      let summaryToReturn = existingSuite;
      const incompleteProjectsOnEmpty = mergeIncompleteProjects([]);
      const incompleteOnEmpty = truncated || incompleteProjectsOnEmpty.length > 0;
      const isLiveWithStaleLinks =
        existingSuite.datasetMode === 'LIVE' &&
        existingSuite.initialized !== false &&
        existingSuite.traceLinks.length > 0;
      const isSyntheticDemo = existingSuite.datasetMode === 'DEMO';
      const shouldResetToUninitializedLive =
        !truncated &&
        !normalized.hasCustomJql &&
        !resumedFromCursor &&
        (isLiveWithStaleLinks || isSyntheticDemo);

      if (shouldResetToUninitializedLive) {
        const prunedAt = new Date().toISOString();
        const nextProjectName = isSyntheticDemo
          ? normalized.projectKey || 'Atlassian Cloud Live Medical Project'
          : existingSuite.projectName;
        const prunedSummary = ComplianceEngine.generateComplianceReport([], 'LIVE', nextProjectName, {
          initialized: false,
          lastSyncedAt: prunedAt,
          syncIncomplete: incompleteOnEmpty,
          incompleteProjectKeys: incompleteProjectsOnEmpty,
        });
        summaryToReturn = await commitSuiteMutation({
          summary: prunedSummary,
          expectedVersion: existingVersion ?? 0,
          previousSuite: existingSuite,
          auditEntry: {
            actorAccountId,
            action: 'SYNC_LIVE',
            targetKey: normalized.projectKey || nextProjectName,
            details: {
              projectKey: normalized.projectKey || null,
              prunedToUninitialized: true,
              clearedDemoMode: isSyntheticDemo,
              previousTraceLinkCount: existingSuite.traceLinks.length,
              jiraIssuesScanned: issues.length,
              confluencePagesScanned,
              lastSyncedAt: prunedAt,
            },
            authMethod: normalized.callerMode === 'APP' ? 'SYSTEM_INIT' : 'FORGE_USER_SESSION',
          },
        });
        warnings.push(
          isSyntheticDemo
            ? `Cleared synthetic DEMO dataset into uninitialized LIVE mode (${issues.length} Jira issue(s) scanned, 0 safety-tracked); click Create Live Proof Chain or label a Jira issue with class-a / class-b / class-c or medtrace-hazard.`
            : `No safety-tracked Jira issues remain in ${normalized.projectKey ? `project ${normalized.projectKey}` : 'the synced scope'}; pruned stale trace link(s) from KVS.`
        );
        return {
          success: true,
          datasetMode: 'LIVE',
          jiraIssuesScanned: issues.length,
          confluencePagesScanned,
          linkedPairsFound: 0,
          driftDetectedCount: 0,
          truncated: false,
          skippedUntaggedCount,
          warnings,
          summary: summaryToReturn,
        };
      }

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
            syncIncomplete: incompleteOnEmpty,
            incompleteProjectKeys: incompleteProjectsOnEmpty,
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
              syncIncomplete: incompleteOnEmpty,
              incompleteProjectKeys: incompleteProjectsOnEmpty,
              ...(nextResumeToken ? { nextPageToken: nextResumeToken } : {}),
              ...(nextPendingKeys.length > 0 ? { pendingIssueKeysCount: nextPendingKeys.length } : {}),
            },
            authMethod: normalized.callerMode === 'APP' ? 'SYSTEM_INIT' : 'FORGE_USER_SESSION',
          },
        });
      } else if (truncated) {
        summaryToReturn = {
          ...summaryToReturn,
          syncIncomplete: true,
          ...(incompleteProjectsOnEmpty.length > 0
            ? { incompleteProjectKeys: incompleteProjectsOnEmpty }
            : {}),
        };
      }
      warnings.push(
        'No safety-tracked Jira issues matched the live sync query (label a Jira issue with class-a / class-b / class-c or medtrace-hazard, or create a Hazard issue type); keeping existing compliance suite unchanged.'
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
      (preservedOtherProjectCount > 0 && existingSuite.initialized && existingSuite.projectName
        ? existingSuite.projectName
        : issues[0]?.fields?.project?.name ||
          (existingSuite.initialized ? existingSuite.projectName : undefined) ||
          'Atlassian Cloud Live Medical Project');

    const syncedWorkKeys = Array.from(processedWorkKeys);
    const syncedProjectKeys = Array.from(
      new Set(
        [
          ...(normalized.projectKey ? [normalized.projectKey] : []),
          ...syncedWorkKeys.map((k) => k.split('-')[0]).filter(Boolean),
        ]
      )
    );
    const nextIncompleteProjectKeys = mergeIncompleteProjects(syncedProjectKeys);
    const effectiveSyncIncomplete = truncated || nextIncompleteProjectKeys.length > 0;

    const syncCompletedAt = new Date().toISOString();
    const summary = ComplianceEngine.generateComplianceReport(traceLinks, 'LIVE', projectLabel, {
      initialized: true,
      lastSyncedAt: syncCompletedAt,
      syncIncomplete: effectiveSyncIncomplete,
      incompleteProjectKeys: nextIncompleteProjectKeys,
    });

    const saved = await commitSuiteMutation({
      summary,
      expectedVersion: existingVersion ?? 0,
      baselineUpdates,
      previousSuite: existingSuite,
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
        authMethod: normalized.callerMode === 'APP' ? 'SYSTEM_INIT' : 'FORGE_USER_SESSION',
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
   */
  public static async handleConfluencePageUpdated(
    event: ConfluencePageUpdatedEvent
  ): Promise<ConfluencePageUpdatedResult> {
    return handleConfluencePageUpdatedTrigger(event);
  }

  /**
   * Reconciles live Confluence SRS hashes in the current product's KVS partition on read/gate paths.
   */
  public static async reconcileConfluenceSpecs(
    suite: ComplianceSummary,
    options?: {
      targetPageIds?: string[];
      actorAccountId?: string;
      projectKey?: string;
      issueKeyFilter?: string;
      allowAppFallback?: boolean;
      failClosedOnBudget?: boolean;
      userPageAccessCache?: Map<string, boolean>;
    }
  ): Promise<ComplianceSummary> {
    return reconcileConfluenceSpecsTrigger(suite, {
      ...options,
      onDriftDetected: (ev) => this.handleConfluencePageUpdated(ev),
    });
  }

  /**
   * Forge product trigger handler for `avi:jira:updated:issue`, `avi:jira:created:issuelink`,
   * and `avi:jira:deleted:issuelink`.
   */
  public static async handleJiraIssueUpdated(
    event: JiraIssueUpdatedEvent
  ): Promise<JiraIssueUpdatedResult> {
    return handleJiraIssueUpdatedTrigger(event);
  }
}
