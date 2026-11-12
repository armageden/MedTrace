# Compliance Engine

Evaluates IEC 62304, ISO 14971, and 21 CFR Part 11 traceability across the 5-stage graph (`HAZARD ↔ SPEC ↔ WORK ↔ TEST ↔ SIGNATURE`), computes deterministic blast radius, manages sharded KVS persistence, ingests live Atlassian artifacts, and maintains a SHA-256 hash-chained audit ledger.

## Files

- [evaluation-rules.md](./evaluation-rules.md) — Deterministic 5-stage status checks, `evaluateIssueReleaseGate`, `computeBlastRadius` BFS, sharded KVS (`SHARDED_V2`), `LiveIngestionService`, `AuditLogService`, RBAC/Part 11 mutations, and test suite coverage (`tests/compliance-engine.test.cjs`).
