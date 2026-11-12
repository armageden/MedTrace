[<- How-To Overview](./00-overview.md)

# Docs Sync Runbook

Run this checklist after **any** change to source code, manifest, workflows, or scripts.

## 1. Source-to-Docs Mapping

| Changed File | Doc(s) to Check / Update |
|---|---|
| [manifest.yml](../../manifest.yml) | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [README.md](../../README.md) |
| [src/index.ts](../../src/index.ts) | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [docs/03-mcp-integration/live-sync.md](../03-mcp-integration/live-sync.md) |
| [src/runtime.ts](../../src/runtime.ts) | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md) |
| [src/compliance-engine.ts](../../src/compliance-engine.ts), [src/types.ts](../../src/types.ts) | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/99-design-decisions/004-artifact-node-bfs-blast-radius.md](../99-design-decisions/004-artifact-node-bfs-blast-radius.md) |
| [src/seeder.ts](../../src/seeder.ts) | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/99-design-decisions/001-twg-and-kvs-hybrid.md](../99-design-decisions/001-twg-and-kvs-hybrid.md), [docs/99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md](../99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md) |
| [src/ingestion.ts](../../src/ingestion.ts) | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [docs/99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md](../99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md) |
| [src/audit-log.ts](../../src/audit-log.ts) | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md](../99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md) |
| [src/teamwork-graph.ts](../../src/teamwork-graph.ts) | [docs/99-design-decisions/003-twg-dual-engine-fallback.md](../99-design-decisions/003-twg-dual-engine-fallback.md) |
| [src/workflow-validator.ts](../../src/workflow-validator.ts) | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md) |
| [src/mcp-server.ts](../../src/mcp-server.ts), [src/nonce-store.ts](../../src/nonce-store.ts), [mcp-server/index.mjs](../../mcp-server/index.mjs) | [docs/03-mcp-integration/live-sync.md](../03-mcp-integration/live-sync.md), [mcp-server/README.md](../../mcp-server/README.md), [docs/99-design-decisions/002-webtrigger-hmac-authentication.md](../99-design-decisions/002-webtrigger-hmac-authentication.md) |
| [static/frontend/src/App.tsx](../../static/frontend/src/App.tsx), [static/frontend/src/bridge.ts](../../static/frontend/src/bridge.ts), [static/frontend/src/components/AuditLogModal.tsx](../../static/frontend/src/components/AuditLogModal.tsx), [static/frontend/src/components/FdaExportModal.tsx](../../static/frontend/src/components/FdaExportModal.tsx) | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [README.md](../../README.md) |
| [scripts/rotate-mcp-secret.sh](../../scripts/rotate-mcp-secret.sh), `.github/workflows/*.yml` | [docs/00-how-to/03-deploy-production.md](./03-deploy-production.md), [SECURITY.md](../../SECURITY.md) |
| [tests/compliance-engine.test.cjs](../../tests/compliance-engine.test.cjs) | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [README.md](../../README.md) |

## 2. Verification Commands

Run the mechanical doc verifier after updates:

```bash
npm run docs:check
```

Then confirm full build, typechecks, and test health:

```bash
npm run build && cd static/frontend && npm run build && cd ../..
npm test
```

## 3. Output Format

Always conclude any coding or docs task with:
`Docs checked/updated: <files or "none required (reason)">`
