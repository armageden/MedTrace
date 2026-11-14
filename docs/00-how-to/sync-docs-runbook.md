[<- How-To Overview](./00-overview.md)

# Docs Sync Runbook

Run this checklist after **any** change to source code, manifest, workflows, tests, or operational scripts. Every tracked entry point matched by `CONFIG.entryGlobs` in `scripts/docs-check.mjs` must remain documented and cross-linked.

## 0. Six-Step Checklist

1. **Inspect the working tree** — `git status`, `git diff`, `git diff --cached` (read-only; never stage or commit).
2. **Map changed paths to subjects** — use the `Changed File(s) -> Doc(s) to Check / Update` tables below.
3. **Update affected docs** — reflect new, changed, or removed symbols, paths, configs, and behaviors. Cite only what you have read in source.
4. **Reverse coverage** — any newly created public entry point (`src/*.ts`, `mcp-server/index.mjs`, `scripts/*`, `static/frontend/src/**/*.ts*`, `tests/*.test.*`, workflows, `manifest.yml`) must be referenced in at least one doc, or `npm run docs:check` fails with `reverse-coverage`.
5. **ADR logging** — if the change involved a significant architectural, dependency, or storage decision, add `docs/99-design-decisions/NNN-<slug>.md` (Title, Context, Decision, Status, Consequences), number sequentially, never reuse a number, and link it from [docs/99-design-decisions/00-overview.md](../99-design-decisions/00-overview.md).
6. **Run the validator** — `npm run docs:check` must exit `0` with zero errors and zero warnings. Resolve every error before finishing.

Validator flags (verified against `scripts/docs-check.mjs`):

```bash
npm run docs:check                              # strict: exit 1 on any error
node scripts/docs-check.mjs --json              # machine-readable result for CI
node scripts/docs-check.mjs --warn-only         # advisory (always exit 0) for hooks
node scripts/docs-check.mjs --strict-listing    # pre-Marketplace placeholder gate
```

## 1. Tracked File Inventory & Source-to-Docs Mapping

### Root Configuration, CI, MCP Server & Scripts

| Changed File(s) | Doc(s) to Check / Update |
|---|---|
| `manifest.yml` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [README.md](../../README.md) |
| `package.json`, `static/frontend/package.json`, `static/frontend/vite.config.ts`, `static/frontend/vitest.config.ts` | [docs/00-how-to/00-overview.md](./00-overview.md), [README.md](../../README.md) |
| `.github/workflows/ci.yml`, `.github/workflows/medtrace-release-gate.yml` | [docs/00-how-to/03-deploy-production.md](./03-deploy-production.md), [SECURITY.md](../../SECURITY.md) |
| `scripts/validate-manifest.mjs`, `scripts/docs-check.mjs`, `scripts/rotate-mcp-secret.sh` | [docs/00-how-to/03-deploy-production.md](./03-deploy-production.md), [SECURITY.md](../../SECURITY.md) |
| `mcp-server/index.mjs` | [docs/03-mcp-integration/live-sync.md](../03-mcp-integration/live-sync.md), [docs/00-how-to/02-add-mcp-tool.md](./02-add-mcp-tool.md), [mcp-server/README.md](../../mcp-server/README.md) |

### Backend Forge Runtime (`src/*.ts`)

| Changed File(s) | Doc(s) to Check / Update |
|---|---|
| `src/index.ts` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [docs/03-mcp-integration/live-sync.md](../03-mcp-integration/live-sync.md) |
| `src/runtime.ts` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md) |
| `src/compliance-engine.ts`, `src/types.ts` | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/99-design-decisions/004-artifact-node-bfs-blast-radius.md](../99-design-decisions/004-artifact-node-bfs-blast-radius.md) |
| `src/seeder.ts` | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/99-design-decisions/001-twg-and-kvs-hybrid.md](../99-design-decisions/001-twg-and-kvs-hybrid.md), [docs/99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md](../99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md) |
| `src/ingestion.ts` | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [docs/99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md](../99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md) |
| `src/audit-log.ts`, `src/crypto-utils.ts` | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md](../99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md), [SECURITY.md](../../SECURITY.md) |
| `src/teamwork-graph.ts` | [docs/99-design-decisions/003-twg-dual-engine-fallback.md](../99-design-decisions/003-twg-dual-engine-fallback.md) |
| `src/workflow-validator.ts` | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/00-how-to/03-deploy-production.md](./03-deploy-production.md) |
| `src/mcp-server.ts`, `src/nonce-store.ts` | [docs/03-mcp-integration/live-sync.md](../03-mcp-integration/live-sync.md), [docs/00-how-to/02-add-mcp-tool.md](./02-add-mcp-tool.md), [docs/99-design-decisions/002-webtrigger-hmac-authentication.md](../99-design-decisions/002-webtrigger-hmac-authentication.md) |

### Custom UI Frontend & Frontend Tests (`static/frontend/src/**/*.ts*`)

| Changed File(s) | Doc(s) to Check / Update |
|---|---|
| `static/frontend/src/main.tsx`, `static/frontend/src/App.tsx`, `static/frontend/src/bridge.ts`, `static/frontend/src/auditVerify.ts`, `static/frontend/src/types.ts`, `static/frontend/src/hooks/useDialogA11y.ts` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [README.md](../../README.md) |
| `static/frontend/src/components/AuditHeader.tsx`, `static/frontend/src/components/AuditLogModal.tsx`, `static/frontend/src/components/ConfirmSeedModal.tsx`, `static/frontend/src/components/CustomNodes.tsx`, `static/frontend/src/components/FdaExportModal.tsx` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [README.md](../../README.md) |
| `static/frontend/src/components/InspectionDrawer.tsx`, `static/frontend/src/components/LineageGraph.tsx`, `static/frontend/src/components/TraceMatrixTable.tsx`, `static/frontend/src/components/TransitionModal.tsx` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [README.md](../../README.md) |
| `static/frontend/src/test/setup.ts`, `static/frontend/src/__tests__/App.races.test.tsx`, `static/frontend/src/__tests__/AuditLogModal.test.tsx`, `static/frontend/src/__tests__/FdaExportModal.test.tsx` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [docs/00-how-to/00-overview.md](./00-overview.md) |
| `static/frontend/src/__tests__/InspectionDrawer.test.tsx`, `static/frontend/src/__tests__/TransitionModal.test.tsx`, `static/frontend/src/__tests__/a11yAndGraph.test.tsx`, `static/frontend/src/__tests__/bridge.test.ts` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [docs/00-how-to/00-overview.md](./00-overview.md) |

### Backend, MCP & Script Test Suites (`tests/*.test.*`)

| Changed File(s) | Doc(s) to Check / Update |
|---|---|
| `tests/audit-log.test.cjs`, `tests/seeder-storage.test.cjs` | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md](../99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md) |
| `tests/compliance-engine.test.cjs` | [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md), [docs/00-how-to/01-add-iso-hazard.md](./01-add-iso-hazard.md) |
| `tests/index-rbac-webtrigger.test.cjs`, `tests/nonce-store.test.cjs` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [docs/03-mcp-integration/live-sync.md](../03-mcp-integration/live-sync.md), [docs/99-design-decisions/002-webtrigger-hmac-authentication.md](../99-design-decisions/002-webtrigger-hmac-authentication.md) |
| `tests/ingestion.test.cjs` | [docs/01-architecture/forge-modules.md](../01-architecture/forge-modules.md), [docs/02-compliance-engine/evaluation-rules.md](../02-compliance-engine/evaluation-rules.md) |
| `tests/mcp-server.test.mjs`, `tests/workflow-validator-and-mcp.test.cjs` | [docs/03-mcp-integration/live-sync.md](../03-mcp-integration/live-sync.md), [docs/00-how-to/02-add-mcp-tool.md](./02-add-mcp-tool.md) |
| `npm run test:scripts` (`scripts/*.mjs` and `scripts/*.sh` tests) | [docs/00-how-to/00-overview.md](./00-overview.md), [docs/00-how-to/03-deploy-production.md](./03-deploy-production.md) |

## 2. Verification Commands

Run the mechanical doc verifier after updates (validates relative links, `#anchor` heading slugs, backticked disk paths, folder `00-overview.md` links, backlinks, and `reverse-coverage`):

```bash
npm run docs:check
```

Before Atlassian Marketplace submission, also verify zero unconfigured listing placeholders remain across `SECURITY.md` and `marketplace/` markdown files:

```bash
node scripts/docs-check.mjs --strict-listing
```

Then confirm typechecks, builds, tests, script syntax, and offline manifest validation:

```bash
npm run typecheck
npm run build:all
npm run test:all
npm run lint:manifest
node --check mcp-server/index.mjs && node --check scripts/validate-manifest.mjs && node --check scripts/docs-check.mjs && bash -n scripts/rotate-mcp-secret.sh
```

## 3. Output Format

Always conclude any coding or docs task with:
`Docs checked/updated: <files or "none required (reason)">`
