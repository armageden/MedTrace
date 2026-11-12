import api, { route } from '@forge/api';

/**
 * Real Teamwork Graph (TWG) integration module.
 * Queries Atlassian GraphQL Gateway (AGG) at api.atlassian.com/graphql
 * to traverse native Jira issues, Confluence pages, and remote links.
 */
export class TeamworkGraphService {
  /**
   * Traverse issue relations and remote links via Atlassian GraphQL
   */
  public static async queryIssueGraphContext(issueKey: string): Promise<any> {
    const graphQLQuery = {
      query: `
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
      `,
      variables: {
        issueId: issueKey,
      },
    };

    try {
      const response = await api.asApp().requestGraph(graphQLQuery.query, graphQLQuery.variables);
      if (response && response.status === 200) {
        const json = await response.json();
        if (json.errors && json.errors.length > 0) {
          throw new Error(`GraphQL Error: ${json.errors[0]?.message || 'AGG query failed'}`);
        }
        if (json.data) {
          return json.data;
        }
      }
    } catch (err: any) {
      console.warn(`[TeamworkGraph] AGG Query notice for ${issueKey}: ${err?.message || err}. Falling back to Jira REST API.`);
    }

    // Direct fallback using Atlassian Jira REST API
    try {
      const restResp = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}?fields=summary,status,issuelinks,remotelinks`);
      if (restResp.status === 200) {
        return await restResp.json();
      }
    } catch (err) {
      console.error(`[TeamworkGraph] Failed to fetch context for ${issueKey}:`, err);
    }

    return null;
  }
}