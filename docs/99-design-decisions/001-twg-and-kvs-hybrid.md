[<- Design Decisions Overview](./00-overview.md)

# ADR-001: Sharded Forge KVS + Atlassian Graph Hybrid

## Status
Accepted (Updated for `SHARDED_V2` KVS & Live Ingestion)

## Context
MedTrace enforces IEC 62304, ISO 14971, and 21 CFR Part 11 traceability across Jira issues, Confluence Software Requirement Specifications (SRS), test evidence, and electronic signatures without exfiltrating data outside Atlassian Cloud.

Relying solely on live Atlassian Graph Gateway (AGG) queries during every Jira workflow transition (`jira:workflowValidator`) adds network latency, cannot persist Part 11 electronic signature baselines, and cannot store append-only audit logs. Conversely, relying solely on static hardcoded seed data cannot reflect live Jira and Confluence workspaces.

## Decision
1. **Zero-Egress Hybrid:** Keep live relationship discovery in [src/teamwork-graph.ts](../../src/teamwork-graph.ts) and [src/ingestion.ts](../../src/ingestion.ts), while persisting evaluated trace links, signed Confluence SHA-256 baselines, and hash-chained audit logs in Atlassian Forge Key-Value Store (`@forge/kvs`) via [src/seeder.ts](../../src/seeder.ts) and [src/audit-log.ts](../../src/audit-log.ts).
2. **Sharded Storage (`SHARDED_V2`):** Store suite metadata under `medtrace:compliance:suite_meta` and shard individual `TraceLink` documents across `medtrace:compliance:link:<id>` keys (written and fetched in batches of 25), transparently migrating any legacy `medtrace:compliance:active_suite` (`SINGLE_KEY_V1`) payloads.
3. **Signed Spec Baselines:** Persist `medtrace:compliance:signed_spec:<id>` separately so re-syncing live Confluence pages detects content drift whenever SHA-256 hashes diverge from the signed baseline.

## Consequences
- Workflow transitions (`workflowValidatorHandler`) evaluate deterministic local KVS state in milliseconds without external network egress.
- Sharded storage avoids Forge KVS per-key payload limits as hazard/requirement suites grow.
- Requires an explicit `syncLiveSuite` run or `avi:confluence:updated:page` trigger to refresh `LIVE` KVS state from Jira/Confluence edits.
