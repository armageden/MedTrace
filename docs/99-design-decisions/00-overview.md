# Design Decisions (ADRs)

Architecture Decision Records documenting MedTrace's storage layout, zero-egress boundaries, cryptographic authentication, live ingestion, and audit integrity trade-offs.

## Files

- [001-twg-and-kvs-hybrid.md](./001-twg-and-kvs-hybrid.md) — Why MedTrace stores computed compliance state and signed baselines in sharded Forge KVS alongside Atlassian Graph Gateway (AGG) discovery.
- [002-webtrigger-hmac-authentication.md](./002-webtrigger-hmac-authentication.md) — Why the MCP bridge uses HMAC-SHA256 signatures over raw JSON payloads with SHA-256 hashed KVS TTL nonces and fail-closed `STORAGE_ERROR` handling.
- [003-twg-dual-engine-fallback.md](./003-twg-dual-engine-fallback.md) — Why `TeamworkGraphService` pairs Atlassian Graph Gateway (AGG) Cypher queries with Jira REST (`issuelinks` + `remotelink`) fallback.
- [004-artifact-node-bfs-blast-radius.md](./004-artifact-node-bfs-blast-radius.md) — Why blast-radius computation uses a 5-stage artifact graph and BFS traversal.
- [005-hash-chained-audit-log-and-sharded-kvs.md](./005-hash-chained-audit-log-and-sharded-kvs.md) — Why MedTrace shards trace links (`SHARDED_V2`) and records every mutation in a SHA-256 hash-chained, `FAIL_IF_EXISTS` KVS audit ledger.
