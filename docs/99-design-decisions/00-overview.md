# Design Decisions (ADRs)

Architecture Decision Records documenting MedTrace's storage layout, Forge network/MCP data-return boundaries, cryptographic authentication, live ingestion, and audit tamper-evidence trade-offs.

## Files

- [001-twg-and-kvs-hybrid.md](./001-twg-and-kvs-hybrid.md) — Why MedTrace persists evaluated compliance state, `issueKeyIndex` / `meta_index` O(1) lookups, composite `(hazardKey, specId)` baselines, `incompleteProjectKeys` scoping, and cold-start `LIVE` suites in sharded Forge KVS alongside Jira REST discovery.
- [002-webtrigger-hmac-authentication.md](./002-webtrigger-hmac-authentication.md) — Why `mcp-sync-webtrigger` enforces HMAC-SHA256 over raw JSON, `405` pre-nonce checks, asymmetric `[-300_000, +30_000]` ms replay windows with 7-minute hashed KVS TTL nonces, `LIVE`-mode guards, and `vlock` optimistic locking.
- [003-twg-dual-engine-fallback.md](./003-twg-dual-engine-fallback.md) — Why `TeamworkGraphService` uses Jira REST (`'JIRA_REST'`) paired with Jira `issuelinks` and `'JIRA_REMOTELINK_REST'`, scoped by `callerMode: 'USER' | 'APP'` and bulk `requireConfluenceLinkToEnrich` short-circuiting (`LIVE_SYNC_CONCURRENCY_BATCH_SIZE = 5`); supersedes the removed AGG `requestGraph` path.
- [004-artifact-node-bfs-blast-radius.md](./004-artifact-node-bfs-blast-radius.md) — Why `computeBlastRadius` and `computeMultiBlastRadius` run component BFS over artifact nodes with strict key guards and per-hazard/per-spec isolation.
- [005-hash-chained-audit-log-and-sharded-kvs.md](./005-hash-chained-audit-log-and-sharded-kvs.md) — Why MedTrace pairs sharded `SHARDED_V2` KVS (`vlock`, `kvs.transact()`, staged chunking, `issueKeyIndex` / `meta_index`, `incompleteProjectKeys`) with a canonical SHA-256 hash-chained audit ledger (bounded `verifyAuditChain` windows, `HMAC-SHA256-SEAL-V1` + `MEDTRACE_PART11_PREVIOUS_SECRETS` key rotation) and Forge KVS tamper-evidence limits (not hardware WORM/HSM/PKI).
- [006-live-proof-bootstrap.md](./006-live-proof-bootstrap.md) — Why live judge proof uses an explicit user-initiated native-artifact bootstrap without automatic evidence, attestation, cleanup, or synthetic compliance.
