[<- Design Decisions Overview](./00-overview.md)

# ADR-001: Sharded Forge KVS + Atlassian Graph Hybrid

## Status
Accepted (Updated for `SHARDED_V2` KVS, `vlock` Optimistic Locking, and Cold-Start `LIVE` Safety)

## Context
MedTrace supports configurable traceability checks associated with IEC 62304, ISO 14971, and 21 CFR Part 11 across Jira issues, Confluence Software Requirement Specifications (SRS), test evidence, and electronic signatures inside Atlassian Cloud without declaring `permissions.external.fetch.backend` (while authenticated MCP/CI webtrigger responses return requested compliance data to configured callers).

Relying solely on live Jira/Confluence REST queries during every Jira workflow transition (`jira:workflowValidator`) adds network latency, cannot persist Part 11 electronic signature baselines or cryptographic seals, and cannot store append-only audit logs. Conversely, auto-seeding synthetic `DEMO` records into an empty production tenant on cold start would mask uninitialized `LIVE` workspaces and risk passing release checks against fake data.

## Decision
1. **No External Backend-Fetch Hybrid:** Keep live relationship discovery in [src/teamwork-graph.ts](../../src/teamwork-graph.ts) (`JIRA_REST` + `JIRA_REMOTELINK_REST`, plus an opt-in user-context Teamwork Graph `confluencePageOwners` curated query for interactive spec-owner lookup) and [src/ingestion.ts](../../src/ingestion.ts), while persisting evaluated trace links, signed Confluence SHA-256 baselines, and hash-chained audit logs in Forge KVS (`@forge/kvs`) via [src/seeder.ts](../../src/seeder.ts) and [src/audit-log.ts](../../src/audit-log.ts).
2. **Cold-Start `LIVE` Default:** When Forge KVS holds no persisted suite, `SeederService.getActiveComplianceSuite()` returns an uninitialized empty `LIVE` suite (`initialized: false`, 0 links) without writing synthetic `DEMO` records on read; release gates fail closed until explicit initialization.
3. **Sharded Storage (`SHARDED_V2`) & Optimistic Locking:** Store suite metadata under `medtrace:compliance:suite_meta` (`ShardedSuiteMetaV2`, protected by optimistic `vlock` versioning), index issue keys in `issueKeyIndex` (overflow-sharded into `medtrace:compliance:meta_index:` via `issueKeyIndexShardKeys` when metadata approaches `MAX_KVS_META_BYTES`) for O(1) workflow/release-gate lookups via `getActiveComplianceSuite({ issueKeyFilter, projectKey })`, track `incompleteProjectKeys` per Jira project, use `kvs.transact()` for batches of `<= 25` operations, and stage larger mutations (`> 25` ops) across `v<version>:` link and meta shard keys with garbage collection of stale shards.
4. **Composite Signed Spec Baselines:** Persist `SignedSpecBaseline` records keyed by composite `(hazardKey, specId)` (`SIGNED_SPEC_PREFIX`, with legacy `medtrace:compliance:signed_spec:<id>` read fallback) so multi-hazard shared specs isolate drift and re-syncing enforces revert non-resurrection when invalidated.

## Consequences
- Workflow transitions (`workflowValidatorHandler`) and CI release gates (`verify-release-gate`) evaluate deterministic local KVS state in O(1) shard lookups (when `issueKey` is supplied) without external network egress.
- Sharded storage, `issueKeyIndex` / `meta_index` overflow sharding, and content-hash unchanged link reuse keep metadata within `MAX_KVS_META_BYTES` (`128 * 1024` bytes) as suites scale, while preventing concurrent overwrites via `vlock`.
- Operators must explicitly run `syncLiveSuite` (`Sync Live Atlassian Data`) on new installations before `LIVE` release gates can pass.
