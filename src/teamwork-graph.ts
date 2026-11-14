import api, { getAppContext, route } from '@forge/api';
import { AggIssueLinkRef, ConfluenceRemoteLinkRef, IssueGraphContextResult } from './types';

export type { AggIssueLinkRef, ConfluenceRemoteLinkRef, IssueGraphContextResult };

export interface QueryIssueGraphContextOptions {
  callerMode?: 'USER' | 'APP';
  /**
   * When true, checks Jira `/remotelink` first and returns `null` immediately if no Confluence links exist,
   * avoiding extra Jira issue REST and AGG GraphQL calls for untagged non-safety issues.
   */
  requireConfluenceLinkToEnrich?: boolean;
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

function parseAggIssueLinks(rawLinks: unknown): AggIssueLinkRef[] {
  if (!Array.isArray(rawLinks)) return [];
  const parsed: AggIssueLinkRef[] = [];
  for (const item of rawLinks) {
    if (!isRecord(item)) continue;
    const id = asNonEmptyString(item.id);
    if (!id) continue;

    const rawType = isRecord(item.type) ? item.type : undefined;
    const name = typeof rawType?.name === 'string' && rawType.name ? rawType.name : undefined;
    const inward = typeof rawType?.inward === 'string' && rawType.inward ? rawType.inward : undefined;
    const outward = typeof rawType?.outward === 'string' && rawType.outward ? rawType.outward : undefined;

    const linkRef: AggIssueLinkRef = { id };
    if (name !== undefined || inward !== undefined || outward !== undefined) {
      linkRef.type = {
        ...(name !== undefined ? { name } : {}),
        ...(inward !== undefined ? { inward } : {}),
        ...(outward !== undefined ? { outward } : {}),
      };
    }
    parsed.push(linkRef);
  }
  return parsed;
}

type ForgeClient = ReturnType<typeof api.asApp> | ReturnType<typeof api.asUser>;

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
 * Jira Atlassian GraphQL Gateway (AGG) + Jira/Confluence REST Graph Context Service.
 * Note: `@forge/api` provides `requestGraph` (AGG `/graphql`) rather than `requestTeamworkGraph`,
 * and this app declares no `read:graph:*` TWG scopes. This service queries AGG `jira.issue`
 * (`JIRA_AGG_AND_REST`) and enriches/falls back via Jira REST issue + `/remotelink` (`JIRA_REMOTELINK_REST`).
 */
export class TeamworkGraphService {
  /**
   * Queries Jira REST issue metadata, Jira `/remotelink` Confluence references, and AGG `jira.issue`.
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

    // 2. Construct valid Jira issue ARI when cloudId + issueId are known, and query AGG
    const cloudId = resolveCloudId(issueSelf);
    const issueAri = cloudId && issueId ? `ari:cloud:jira:${cloudId}:issue/${issueId}` : undefined;

    if (issueAri) {
      const graphQLQuery = `
        query GetIssueGraphContext($issueId: ID!) {
          jira {
            issue(id: $issueId) {
              id
              key
              summary
              status {
                name
                category
              }
              links {
                id
                type {
                  name
                  inward
                  outward
                }
              }
            }
          }
        }
      `;
      try {
        const response = await client.requestGraph(graphQLQuery, { issueId: issueAri });
        if (response && response.status === 200) {
          const json: unknown = await response.json();
          const errors = isRecord(json) && Array.isArray(json.errors) ? json.errors : undefined;
          const data = isRecord(json) && isRecord(json.data) ? json.data : undefined;
          const jiraData = data && isRecord(data.jira) ? data.jira : undefined;
          const jiraIssue = jiraData && isRecord(jiraData.issue) ? jiraData.issue : undefined;

          if ((!errors || errors.length === 0) && data && jiraIssue) {
            const aggSummary =
              typeof jiraIssue.summary === 'string' && jiraIssue.summary ? jiraIssue.summary : summary;
            const aggStatus = parseStatus(jiraIssue.status) || status;
            const aggIssueLinks = parseAggIssueLinks(jiraIssue.links);

            return {
              source: 'JIRA_AGG_AND_REST',
              confluenceSource: 'JIRA_REMOTELINK_REST',
              issueKey: cleanKey,
              issueId,
              issueAri,
              summary: aggSummary,
              status: aggStatus,
              issuelinks,
              aggIssueLinks,
              confluenceLinks,
              aggRaw: data,
            };
          }
        }
      } catch (err: unknown) {
        console.warn(`[TeamworkGraph] AGG query fallback to REST for ${cleanKey}:`, formatErrorMessage(err));
      }
    }

    if (!issueId && confluenceLinks.length === 0 && issuelinks.length === 0) {
      return null;
    }

    return {
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
  }
}
