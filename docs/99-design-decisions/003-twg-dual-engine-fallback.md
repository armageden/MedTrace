[<- Design Decisions Overview](./00-overview.md)

# ADR-003: Dual-Engine Atlassian Graph & Jira REST Fallback

## Status
Accepted

## Context
Atlassian Teamwork Graph / Atlassian Graph Gateway (AGG) exposes typed cross-product issue-to-Confluence lineage via GraphQL/Cypher (`requestGraph`). However, tenant environments without enabled graph relationships, newly created links, or permission-constrained sandboxes can return empty AGG edges even when Jira `issuelinks` or Confluence remote links exist.

## Decision
`TeamworkGraphService.queryIssueGraphContext(issueKey)` in [src/teamwork-graph.ts](../../src/teamwork-graph.ts) implements a dual-engine lookup (`source: 'AGG' | 'JIRA_REST'`):
1. Always fetches Jira REST issue details (`/rest/api/3/issue/${cleanKey}?fields=summary,status,issuelinks`) and Confluence remote links (`/rest/api/3/issue/${cleanKey}/remotelink`) to extract linked issue keys and Confluence `pageId` values.
2. Resolves `cloudId` dynamically from `@forge/api` `getAppContext()` to construct the tenant-accurate ARI `ari:cloud:jira:${cloudId}:issue/${issueId}`.
3. Queries `api.asApp().requestGraph` (`AGG`) for upstream/downstream nodes and merges or falls back cleanly to the `JIRA_REST` dataset if AGG returns no edges or errors.

## Consequences
- Live ingestion ([src/ingestion.ts](../../src/ingestion.ts)) and Custom UI inspection (`queryGraphContext`) continue working across both AGG-enabled sites and standard Jira/Confluence Cloud sandboxes without hardcoded demo tenant IDs.
