import api, { getAppContext, route } from '@forge/api';

export interface ConfluenceRemoteLinkRef {
  pageId?: string;
  title: string;
  url: string;
  relationship?: string;
}

export interface IssueGraphContextResult {
  source: 'AGG' | 'JIRA_REST';
  issueKey: string;
  issueId?: string;
  issueAri?: string;
  summary?: string;
  status?: { name?: string; category?: string };
  issuelinks: unknown[];
  confluenceLinks: ConfluenceRemoteLinkRef[];
  aggRaw?: unknown;
}

function extractConfluencePageId(url?: string, globalId?: string): string | undefined {
  const fromGlobal = globalId?.match(/pageId=(\d+)/i)?.[1];
  if (fromGlobal) return fromGlobal;
  if (!url) return undefined;
  const fromPath = url.match(/\/pages\/(\d+)/i)?.[1] || url.match(/[?&]pageId=(\d+)/i)?.[1];
  return fromPath;
}

function resolveCloudId(issueSelfUrl?: string): string | undefined {
  try {
    const ctx = getAppContext();
    const jiraContext = ctx.installation?.contexts?.find((c) => c.cloudId);
    if (jiraContext?.cloudId) return jiraContext.cloudId;
  } catch {
    // Outside Forge runtime or appContext unavailable
  }
  const match = issueSelfUrl?.match(/\/ex\/jira\/([0-9a-f-]+)/i);
  return match?.[1];
}

/**
 * Teamwork Graph (TWG) + Jira/Confluence Remote Link Graph Service.
 * Resolves Jira issue ARIs for Atlassian GraphQL Gateway (AGG) traversal and
 * enriches with Jira REST issuelinks + /remotelink Confluence SRS references.
 */
export class TeamworkGraphService {
  public static async queryIssueGraphContext(issueKey: string): Promise<IssueGraphContextResult | null> {
    const cleanKey = (issueKey || '').trim();
    if (!cleanKey) return null;

    let issueId: string | undefined;
    let issueSelf: string | undefined;
    let summary: string | undefined;
    let status: { name?: string; category?: string } | undefined;
    let issuelinks: unknown[] = [];
    const confluenceLinks: ConfluenceRemoteLinkRef[] = [];

    // 1. Fetch Jira REST issue details + remote links (which store Confluence page links)
    try {
      const restResp = await api
        .asApp()
        .requestJira(route`/rest/api/3/issue/${cleanKey}?fields=summary,status,issuelinks`);
      if (restResp.status === 200) {
        const issueJson = await restResp.json();
        issueId = issueJson?.id;
        issueSelf = issueJson?.self;
        summary = issueJson?.fields?.summary;
        status = {
          name: issueJson?.fields?.status?.name,
          category: issueJson?.fields?.status?.statusCategory?.name,
        };
        issuelinks = Array.isArray(issueJson?.fields?.issuelinks) ? issueJson.fields.issuelinks : [];
      }
    } catch (err) {
      console.warn(`[TeamworkGraph] Jira REST issue fetch notice for ${cleanKey}:`, err);
    }

    try {
      const remoteResp = await api.asApp().requestJira(route`/rest/api/3/issue/${cleanKey}/remotelink`);
      if (remoteResp.status === 200) {
        const remoteList = await remoteResp.json();
        if (Array.isArray(remoteList)) {
          for (const item of remoteList) {
            const url: string = item?.object?.url || '';
            const globalId: string = item?.globalId || '';
            const pageId = extractConfluencePageId(url, globalId);
            const isConfluence =
              Boolean(pageId) ||
              item?.application?.type === 'com.atlassian.confluence' ||
              /confluence|\/wiki\//i.test(url);
            if (isConfluence) {
              confluenceLinks.push({
                pageId,
                title: item?.object?.title || (pageId ? `Confluence Page ${pageId}` : url),
                url,
                relationship: item?.relationship,
              });
            }
          }
        }
      }
    } catch (err) {
      console.warn(`[TeamworkGraph] Jira remotelink fetch notice for ${cleanKey}:`, err);
    }

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
        const response = await api.asApp().requestGraph(graphQLQuery, { issueId: issueAri });
        if (response && response.status === 200) {
          const json = await response.json();
          if (!json.errors?.length && json.data) {
            return {
              source: 'AGG',
              issueKey: cleanKey,
              issueId,
              issueAri,
              summary: json.data?.jira?.issue?.summary || summary,
              status: json.data?.jira?.issue?.status || status,
              issuelinks,
              confluenceLinks,
              aggRaw: json.data,
            };
          }
        }
      } catch (err: any) {
        console.warn(`[TeamworkGraph] AGG query fallback to REST for ${cleanKey}:`, err?.message || err);
      }
    }

    if (!issueId && confluenceLinks.length === 0 && issuelinks.length === 0) {
      return null;
    }

    return {
      source: 'JIRA_REST',
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
