[<- Design Decisions Overview](./00-overview.md)

# ADR-003: Dual-Engine Atlassian Graph & Jira REST Fallback

## Status
Accepted (Clarified AGG GraphQL Scope & Caller-Mode Authorization)

## Context
Atlassian Graph Gateway (AGG) exposes typed cross-product issue context via GraphQL (`/graphql`). In Atlassian Forge `@forge/api`, the client method is `requestGraph` (NOT `requestTeamworkGraph`), and [manifest.yml](../../manifest.yml) declares only Jira/Confluence/storage scopes with **no** `read:graph:*` scopes. Furthermore, tenant sandboxes or newly created Jira/Confluence links can return empty AGG edges even when Jira `issuelinks` or Confluence remote links exist.

## Decision
`TeamworkGraphService.queryIssueGraphContext(issueKey, { callerMode })` in [src/teamwork-graph.ts](../../src/teamwork-graph.ts) implements a caller-scoped dual-engine lookup returning explicit `source: 'JIRA_AGG_AND_REST' | 'JIRA_REST'` and `confluenceSource: 'JIRA_REMOTELINK_REST'`:
1. **Explicit `callerMode: 'USER' | 'APP'`:** Defaults to `'USER'` (`api.asUser()`) for interactive Custom UI queries (`queryGraphContext`, `bindIssueToHazard`) so user Jira permissions are respected, while background `LiveIngestionService.syncFromAtlassian()` passes `{ callerMode: 'APP' }` (`api.asApp()`).
2. **Always-On Jira REST & RemoteLink Extraction (with Bulk Short-Circuit):** Fetches `/rest/api/3/issue/${cleanKey}/remotelink` to extract Confluence `pageId` references (`confluenceSource: 'JIRA_REMOTELINK_REST'`) alongside `/rest/api/3/issue/${cleanKey}?fields=summary,status,issuelinks`. During bulk live sync (`LiveIngestionService.syncFromAtlassian()`), issues are processed in concurrent batches of `LIVE_SYNC_CONCURRENCY_BATCH_SIZE = 5` with `requireConfluenceLinkToEnrich: true` (for unlabelled issues), returning `null` immediately when `/remotelink` contains no Confluence `pageId` so untagged non-safety issues skip redundant issue-detail REST and AGG GraphQL calls.
3. **Tenant-Accurate `cloudId` & `requestGraph` Enrichment:** `resolveCloudId(issueSelfUrl)` prioritizes the canonical `/ex/jira/<uuid>` path from Jira REST `self` URLs before checking Forge `getAppContext()` `:jira:` ARIs, then executes GraphQL `GetIssueGraphContext` against `ari:cloud:jira:${cloudId}:issue/${issueId}` via `client.requestGraph`.
4. **Deterministic Fallback:** When AGG returns graph links (`aggIssueLinks`), returns `source: 'JIRA_AGG_AND_REST'`; if AGG is unavailable, unpermitted, or returns empty links/errors, falls back seamlessly to `source: 'JIRA_REST'`.

## Consequences
- Diagnostic metadata (`source` and `confluenceSource`) accurately reflects what Forge APIs actually executed (`JIRA_AGG_AND_REST` / `JIRA_REST` / `JIRA_REMOTELINK_REST`) without pretending to invoke unpermissioned Teamwork Graph APIs.
- Interactive Custom UI callers cannot bypass Jira issue visibility via `api.asApp()`, while background live sync continues working across AGG-enabled and standard Jira/Confluence tenants alike.
