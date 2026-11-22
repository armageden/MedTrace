[<- Design Decisions Overview](./00-overview.md)

# ADR-003: Jira REST Graph Context Lookup (Superseded Dual-Engine AGG + Jira REST Fallback)

## Status
Superseded — the AGG `requestGraph` enrichment path was removed because the live AGG schema rejected the `jira.issue` query shape (`links`/`category` fields undefined), so production always fell back to REST; Jira REST issue + `/remotelink` is now the sole lookup path. A separate curated Teamwork Graph `confluencePageOwners` query was later added for interactive spec-owner lookup (opt-in `includeSpecOwners`, user-context only — unrelated to the removed AGG path).

## Context
Atlassian Graph Gateway (AGG) exposes typed cross-product issue context via GraphQL (`/graphql`). At decision time, the `@forge/api` client method was `requestGraph` and [manifest.yml](../../manifest.yml) declared only Jira/Confluence/storage scopes with no `read:graph:*` scopes. The AGG `jira.issue` query originally used here was invalid against the live tenant schema, so it could never return data. Furthermore, tenant sandboxes or newly created Jira/Confluence links can return empty AGG edges even when Jira `issuelinks` or Confluence remote links exist.

## Decision
`TeamworkGraphService.queryIssueGraphContext(issueKey, { callerMode })` in [src/teamwork-graph.ts](../../src/teamwork-graph.ts) implements a caller-scoped Jira REST lookup returning explicit `source: 'JIRA_REST'` and `confluenceSource: 'JIRA_REMOTELINK_REST'`:
1. **Explicit `callerMode: 'USER' | 'APP'`:** Defaults to `'USER'` (`api.asUser()`) for interactive Custom UI queries (`queryGraphContext`, `bindIssueToHazard`) so user Jira permissions are respected, while background `LiveIngestionService.syncFromAtlassian()` passes `{ callerMode: 'APP' }` (`api.asApp()`).
2. **Always-On Jira REST & RemoteLink Extraction (with Bulk Short-Circuit):** Fetches `/rest/api/3/issue/${cleanKey}/remotelink` to extract Confluence `pageId` references (`confluenceSource: 'JIRA_REMOTELINK_REST'`) alongside `/rest/api/3/issue/${cleanKey}?fields=summary,status,issuelinks`. During bulk live sync (`LiveIngestionService.syncFromAtlassian()`), issues are processed in concurrent batches of `LIVE_SYNC_CONCURRENCY_BATCH_SIZE = 5` with `requireConfluenceLinkToEnrich: true` (for unlabelled issues), returning `null` immediately when `/remotelink` contains no Confluence `pageId` so untagged non-safety issues skip redundant issue-detail REST calls.
3. **Tenant-Accurate `cloudId` & Issue/Page ARIs:** `resolveCloudId(issueSelfUrl)` prioritizes the canonical `/ex/jira/<uuid>` path from Jira REST `self` URLs before checking Forge `getAppContext()` `:jira:` ARIs (and constructs `ari:cloud:jira:${cloudId}:issue/${issueId}`), while `resolveConfluenceCloudId(confluenceUrl)` resolves Confluence `:confluence:` site UUIDs separately (falling back cleanly only when absent in single-UUID contexts) so `confluencePageOwners` queries target Confluence's real `cloudId`.
4. **Deterministic Source Attribution:** Always returns `source: 'JIRA_REST'`; no GraphQL fallback path remains.

## Consequences
- Diagnostic metadata (`source` and `confluenceSource`) accurately reflects what Forge APIs actually executed (`JIRA_REST` / `JIRA_REMOTELINK_REST`) without pretending to invoke unpermissioned graph APIs; the later `confluencePageOwners` spec-owner step reports its own `teamworkGraphStatus` (`'OK' | 'EMPTY' | 'ERROR' | 'SKIPPED_APP_MODE'`) separately from `source`.
- Interactive Custom UI callers cannot bypass Jira issue visibility via `api.asApp()`, while background live sync continues working across standard Jira/Confluence tenants alike.
