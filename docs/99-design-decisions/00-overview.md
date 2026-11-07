**Back:** [Repository Root](../../README.md)

# Architecture Decision Records (ADRs)

**Covers:** `src/teamwork-graph.ts`, `src/seeder.ts`, `src/index.ts`, `mcp-server/index.mjs`  
**Read this when:** reviewing architectural choices, regulatory trade-offs, and rejected design alternatives.

MedTrace maintains Architecture Decision Records (ADRs) for all foundational infrastructure choices, including persistence tiering, external authentication protocols, and resilient API traversal.

## Contents

| File | Description |
|---|---|
| [001-twg-and-kvs-hybrid.md](./001-twg-and-kvs-hybrid.md) | Teamwork Graph AGG GraphQL and @forge/kvs hybrid persistence architecture. |
| [002-webtrigger-hmac-authentication.md](./002-webtrigger-hmac-authentication.md) | Webtrigger HMAC-SHA256 authentication and replay window protection. |
| [003-twg-dual-engine-fallback.md](./003-twg-dual-engine-fallback.md) | Teamwork Graph dual-engine architecture (AGG GraphQL and REST API v3). |
