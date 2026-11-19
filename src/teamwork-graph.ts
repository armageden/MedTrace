import api, { getAppContext, route } from '@forge/api';
import { ConfluenceRemoteLinkRef, IssueGraphContextResult, SpecOwnerRef } from './types';

export type { ConfluenceRemoteLinkRef, IssueGraphContextResult, SpecOwnerRef };

export interface QueryIssueGraphContextOptions {
  callerMode?: 'USER' | 'APP';
  /**
   * When true, checks Jira `/remotelink` first and returns `null` immediately if no Confluence links exist,
   * avoiding extra Jira issue REST calls for untagged non-safety issues.
   */
  requireConfluenceLinkToEnrich?: boolean;
  /**
   * When true and callerMode is USER, queries the Teamwork Graph `confluencePageOwners`
   * curated query for the linked Confluence pages and attaches `specOwners`.
   * Skipped in APP mode (Teamwork Graph is user-context only) and when no pageIds exist.
   */
  includeSpecOwners?: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asNonEmptyString(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? trimmed : undefined;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  return undefined;
}

function formatErrorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function extractConfluencePageId(url?: string, globalId?: string): string | undefined {
  const fromGlobal = globalId?.match(/pageId=(\d+)/i)?.[1];
  if (fromGlobal) return fromGlobal;
  if (!url) return undefined;
  return url.match(/\/pages\/(\d+)/i)?.[1] || url.match(/[?&]pageId=(\d+)/i)?.[1];
}

function extractJiraCloudIdFromSelfUrl(issueSelfUrl?: string): string | undefined {
  if (typeof issueSelfUrl !== 'string') return undefined;
  const trimmed = issueSelfUrl.trim();
  if (!trimmed) return undefined;

  let pathToCheck = trimmed;
  if (/^https?:\/\//i.test(trimmed)) {
    try {
      pathToCheck = new URL(trimmed).pathname;
    } catch {
      return undefined;
    }
  } else if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) {
    // Reject non-HTTP schemes (e.g. javascript:, file:)
    return undefined;
  }

  const match = pathToCheck.match(
    /^\/ex\/jira\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{4,}(?:-[0-9a-f]{4,})+)(?:\/|$)/i
  );
  return match?.[1];
}

/**
 * Resolves the Jira Cloud ID, prioritizing `/ex/jira/<uuid>` in the issue `self` URL
 * (ignoring non-Jira URLs such as Confluence endpoints), then a Jira installation context
 * from `getAppContext()`, and finally an untyped `{ cloudId }` fallback for test mocks.
 */
export function resolveCloudId(issueSelfUrl?: string): string | undefined {
  const fromSelfUrl = extractJiraCloudIdFromSelfUrl(issueSelfUrl);
  if (fromSelfUrl) return fromSelfUrl;

  try {
    const ctx = getAppContext();
    const contexts = ctx?.installation?.contexts;
    if (Array.isArray(contexts)) {
      const jiraContext = contexts.find(
        (c) => Boolean(c?.cloudId) && String(c.toString?.() ?? '').includes(':jira:')
      );
      if (jiraContext?.cloudId) return jiraContext.cloudId;

      const untypedContext = contexts.find((c) => {
        if (!c?.cloudId) return false;
        const repr = String(c.toString?.() ?? '');
        return !repr.startsWith('ari:cloud:') || repr.includes(':jira:');
      });
      if (untypedContext?.cloudId) return untypedContext.cloudId;
    }
  } catch {
    // Outside Forge runtime or appContext unavailable
  }

  return undefined;
}

function parseStatus(raw: unknown): { name?: string; category?: string } | undefined {
  if (!isRecord(raw)) return undefined;
  const name = typeof raw.name === 'string' && raw.name ? raw.name : undefined;
  const category =
    typeof raw.category === 'string' && raw.category
      ? raw.category
      : isRecord(raw.statusCategory) && typeof raw.statusCategory.name === 'string' && raw.statusCategory.name
        ? raw.statusCategory.name
        : undefined;
  if (name === undefined && category === undefined) return undefined;
  return {
    ...(name !== undefined ? { name } : {}),
    ...(category !== undefined ? { category } : {}),
  };
}

type ForgeClient = ReturnType<typeof api.asApp> | ReturnType<typeof api.asUser>;

const SPEC_OWNERS_MAX_PAGES = 5;

const SPEC_OWNERS_TWG_QUERY = `query medtrace_specPageOwners($id: ID!) {
  confluencePageOwners(id: $id, first: 25) {
    edges { node { __typename ... on AtlassianUser { accountId name } } }
  }
}`;

export type SpecOwnersStatus = 'OK' | 'EMPTY' | 'ERROR';

/**
 * Queries the Teamwork Graph `confluencePageOwners` curated query for up to 5 unique
 * Confluence pageIds (sequential calls, user-context client required). Extracts any valid
 * `AtlassianUser` edges even when GraphQL `errors` includes partial/app-owner errors;
 * non-200 responses, thrown errors, or GraphQL errors with zero valid owners on a page yield
 * status `ERROR` while keeping owners already collected; zero owners with all calls OK yields `EMPTY`.
 */
export async function fetchSpecOwnersFromTeamworkGraph(
  client: ReturnType<typeof api.asUser>,
  cloudId: string,
  pageIds: string[]
): Promise<{ owners: SpecOwnerRef[]; status: SpecOwnersStatus }> {
  const uniquePageIds = [...new Set(pageIds.filter((id) => typeof id === 'string' && id))].slice(
    0,
    SPEC_OWNERS_MAX_PAGES
  );
  const owners: SpecOwnerRef[] = [];
  let status: SpecOwnersStatus = 'OK';

  for (const pageId of uniquePageIds) {
    const pageAri = `ari:cloud:confluence:${cloudId}:page/${pageId}`;
    try {
      const resp = await client.requestTeamworkGraph(
        SPEC_OWNERS_TWG_QUERY,
        { id: pageAri },
        'medtrace_specPageOwners'
      );
      if (resp.status !== 200) {
        status = 'ERROR';
        console.warn(
          `[TeamworkGraph] specOwners query failed (status=${resp.status}): non-200 response`
        );
        continue;
      }
      const json: unknown = await resp.json();
      const graphErrors = isRecord(json) && Array.isArray(json.errors) ? json.errors : undefined;
      const edges =
        isRecord(json) &&
        isRecord(json.data) &&
        isRecord(json.data.confluencePageOwners) &&
        Array.isArray(json.data.confluencePageOwners.edges)
          ? json.data.confluencePageOwners.edges
          : [];
      const seenOnPage = new Set<string>();
      for (const edge of edges) {
        const node = isRecord(edge) && isRecord(edge.node) ? edge.node : undefined;
        if (!node) continue;
        if (typeof node.__typename === 'string' && node.__typename !== 'AtlassianUser') continue;
        if (typeof node.name !== 'string' || !node.name) continue;
        const accountId = typeof node.accountId === 'string' && node.accountId ? node.accountId : undefined;
        const dedupeKey = accountId || node.name;
        if (seenOnPage.has(dedupeKey)) continue;
        seenOnPage.add(dedupeKey);
        owners.push({ pageId, ...(accountId !== undefined ? { accountId } : {}), name: node.name });
      }
      if (graphErrors && graphErrors.length > 0) {
        const messages = graphErrors
          .map((e) => (isRecord(e) && typeof e.message === 'string' ? e.message : ''))
          .filter(Boolean);
        if (seenOnPage.size === 0) {
          status = 'ERROR';
          console.warn(
            `[TeamworkGraph] specOwners query failed (status=${resp.status}):`,
            messages.join('; ') || 'GraphQL errors'
          );
        } else {
          console.warn(
            `[TeamworkGraph] specOwners query returned partial GraphQL error(s) for page ${pageId}; kept ${seenOnPage.size} AtlassianUser owner(s):`,
            messages.join('; ') || 'GraphQL partial error'
          );
        }
      }
    } catch (err: unknown) {
      status = 'ERROR';
      console.warn('[TeamworkGraph] specOwners query error:', formatErrorMessage(err));
    }
  }

  if (status === 'OK' && owners.length === 0) status = 'EMPTY';
  console.log(
    `[TeamworkGraph] specOwners ${uniquePageIds.join(',')}: ${owners.length} owner(s) from ${uniquePageIds.length} page(s), status=${status}`
  );
  return { owners, status };
}

interface JiraIssueRestMetadata {
  issueId?: string;
  issueSelf?: string;
  summary?: string;
  status?: { name?: string; category?: string };
  issuelinks: unknown[];
}

async function fetchJiraIssueRestMetadata(
  client: ForgeClient,
  cleanKey: string
): Promise<JiraIssueRestMetadata> {
  const result: JiraIssueRestMetadata = { issuelinks: [] };
  try {
    const restResp = await client.requestJira(
      route`/rest/api/3/issue/${cleanKey}?fields=summary,status,issuelinks`
    );
    if (restResp && restResp.status === 200) {
      const issueJson: unknown = await restResp.json();
      if (isRecord(issueJson)) {
        result.issueId = asNonEmptyString(issueJson.id);
        result.issueSelf = typeof issueJson.self === 'string' ? issueJson.self : undefined;
        const fields = isRecord(issueJson.fields) ? issueJson.fields : undefined;
        if (fields) {
          result.summary = typeof fields.summary === 'string' ? fields.summary : undefined;
          result.status = parseStatus(fields.status);
          result.issuelinks = Array.isArray(fields.issuelinks) ? fields.issuelinks : [];
        }
      }
    }
  } catch (err: unknown) {
    console.warn(`[TeamworkGraph] Jira REST issue fetch notice for ${cleanKey}:`, formatErrorMessage(err));
  }
  return result;
}

async function fetchConfluenceRemoteLinks(
  client: ForgeClient,
  cleanKey: string
): Promise<ConfluenceRemoteLinkRef[]> {
  const confluenceLinks: ConfluenceRemoteLinkRef[] = [];
  try {
    const remoteResp = await client.requestJira(route`/rest/api/3/issue/${cleanKey}/remotelink`);
    if (remoteResp && remoteResp.status === 200) {
      const remoteList: unknown = await remoteResp.json();
      if (Array.isArray(remoteList)) {
        for (const item of remoteList) {
          if (!isRecord(item)) continue;
          const obj = isRecord(item.object) ? item.object : undefined;
          const app = isRecord(item.application) ? item.application : undefined;
          const url = typeof obj?.url === 'string' ? obj.url : '';
          const globalId = typeof item.globalId === 'string' ? item.globalId : '';
          const pageId = extractConfluencePageId(url, globalId);
          const appType = typeof app?.type === 'string' ? app.type : undefined;
          const isConfluence =
            Boolean(pageId) ||
            appType === 'com.atlassian.confluence' ||
            /confluence|\/wiki\//i.test(url);
          if (isConfluence) {
            const title =
              typeof obj?.title === 'string' && obj.title
                ? obj.title
                : pageId
                  ? `Confluence Page ${pageId}`
                  : url;
            const relationship = typeof item.relationship === 'string' ? item.relationship : undefined;
            confluenceLinks.push({
              ...(pageId !== undefined ? { pageId } : {}),
              title,
              url,
              ...(relationship !== undefined ? { relationship } : {}),
            });
          }
        }
      }
    }
  } catch (err: unknown) {
    console.warn(`[TeamworkGraph] Jira remotelink fetch notice for ${cleanKey}:`, formatErrorMessage(err));
  }
  return confluenceLinks;
}

/**
 * Jira REST issue + `/remotelink` Graph Context Service.
 * Queries Jira REST issue metadata and Jira `/remotelink` Confluence references
 * (`JIRA_REST` + `JIRA_REMOTELINK_REST`), with an optional Teamwork Graph
 * `confluencePageOwners` step for spec owners when `includeSpecOwners` is set.
 */
export class TeamworkGraphService {
  /**
   * Queries Jira REST issue metadata and Jira `/remotelink` Confluence references.
   * Defaults `callerMode` to `'USER'` (`api.asUser()`) for interactive UI authorization; background
   * app-level sync callers must explicitly pass `{ callerMode: 'APP' }`.
   */
  public static async queryIssueGraphContext(
    issueKey: string,
    options?: QueryIssueGraphContextOptions
  ): Promise<IssueGraphContextResult | null> {
    const cleanKey = typeof issueKey === 'string' ? issueKey.trim() : '';
    if (!cleanKey) return null;

    const callerMode: 'USER' | 'APP' = options?.callerMode === 'APP' ? 'APP' : 'USER';
    let client: ForgeClient;
    try {
      client = callerMode === 'APP' ? api.asApp() : api.asUser();
    } catch (err: unknown) {
      console.warn(
        `[TeamworkGraph] Failed to acquire ${callerMode} Forge client for ${cleanKey}:`,
        formatErrorMessage(err)
      );
      return null;
    }

    // Fetch /remotelink before /issue to short-circuit untagged issues without Confluence links
    // and keep <= 1 concurrent Jira REST request per ingestion worker (respecting batch concurrency <= 5).
    const confluenceLinks = await fetchConfluenceRemoteLinks(client, cleanKey);
    if (options?.requireConfluenceLinkToEnrich === true && confluenceLinks.length === 0) {
      return null;
    }

    const issueMeta = await fetchJiraIssueRestMetadata(client, cleanKey);

    const { issueId, issueSelf, summary, status, issuelinks } = issueMeta;

    // Construct a valid Jira issue ARI when cloudId + issueId are known
    const cloudId = resolveCloudId(issueSelf);
    const issueAri = cloudId && issueId ? `ari:cloud:jira:${cloudId}:issue/${issueId}` : undefined;

    if (!issueId && confluenceLinks.length === 0 && issuelinks.length === 0) {
      return null;
    }

    const result: IssueGraphContextResult = {
      source: 'JIRA_REST',
      confluenceSource: 'JIRA_REMOTELINK_REST',
      issueKey: cleanKey,
      issueId,
      issueAri,
      summary,
      status,
      issuelinks,
      confluenceLinks,
    };

    if (options?.includeSpecOwners === true) {
      if (callerMode === 'APP') {
        // Teamwork Graph is user-context only; asApp() cannot call it
        result.teamworkGraphStatus = 'SKIPPED_APP_MODE';
      } else {
        const pageIds = confluenceLinks
          .map((l) => l.pageId)
          .filter((id): id is string => typeof id === 'string' && Boolean(id));
        if (cloudId && pageIds.length > 0) {
          const { owners, status: twgStatus } = await fetchSpecOwnersFromTeamworkGraph(
            api.asUser(),
            cloudId,
            pageIds
          );
          result.specOwners = owners;
          result.teamworkGraphStatus = twgStatus;
        }
      }
    }

    return result;
  }
}
