[<- Design Decisions Overview](./00-overview.md)

# ADR-005: Hash-Chained Audit Ledger & Sharded KVS Persistence

## Status
Accepted

## Context
Medical device quality systems subject to 21 CFR Part 11 and IEC 62304 require tamper-evident audit trails attributing every record mutation (live ingestion, Confluence spec drift, issue binding, test evidence recording, and electronic sign-off) to a verified actor and timestamp. Storing an unbounded audit array inside a single KVS compliance document would risk silent truncation, race conditions under concurrent updates, and exceeding Forge KVS item limits.

## Decision
1. **Immutable Hash-Chained Ledger ([src/audit-log.ts](../../src/audit-log.ts)):**
   - Persist a chain head pointer at `medtrace:audit:head` and individual entries at `medtrace:audit:entry:<seq>`.
   - Chain each entry from `AUDIT_GENESIS_HASH` (`'0'.repeat(64)`) using `computeAuditEntryHash` (canonical sorted-key JSON SHA-256 over `seq`, `timestamp`, `action`, `actorAccountId`, `authMethod`, `prevHash`, target metadata, and suite digests).
   - Write each entry using `kvs.set(..., { keyPolicy: 'FAIL_IF_EXISTS' })` with up to 12 optimistic concurrency retries (`resolveChainTail()`), preventing silent overwrites.
   - Provide `verifyAuditChain()` to recompute every hash from sequence `1` to `head.seq` and surface tampering or gaps to the Custom UI ([static/frontend/src/components/AuditLogModal.tsx](../../static/frontend/src/components/AuditLogModal.tsx)).
2. **Sharded Compliance Suite ([src/seeder.ts](../../src/seeder.ts)):**
   - Store suite metadata (`medtrace:compliance:suite_meta`, `storageFormat: 'SHARDED_V2'`) separately from individual links (`medtrace:compliance:link:<id>`) using `kvs.batchSet` / `kvs.batchGet` in chunks of 25.
   - Isolate Forge runtime vs local Node test adapters via `isForgeRuntime()` ([src/runtime.ts](../../src/runtime.ts)).
3. **Live Ingestion & Confluence Drift Detection ([src/ingestion.ts](../../src/ingestion.ts)):**
   - `LiveIngestionService` fetches Jira issues (`/rest/api/3/search/jql`) and Confluence pages (`/wiki/api/v2/pages?body-format=storage`), computes SHA-256 digests of storage XML, invalidates Part 11 signatures on hash drift against `medtrace:compliance:signed_spec:<id>`, and reacts automatically to `avi:confluence:updated:page` triggers.

## Consequences
- Concurrent mutations cannot overwrite prior audit sequence entries, and any post-hoc KVS modification breaks `verifyAuditChain()`.
- Separate link shards scale cleanly without breaking single-key Forge KVS limits.
- Demo-only simulation (`remediateClassCGap`) is strictly gated to `datasetMode === 'DEMO'` and logged distinctly as `'DEMO_SIMULATION'`.
