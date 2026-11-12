# MedTrace — Zero-Egress IEC 62304, ISO 14971 & 21 CFR Part 11 Compliance Engine

**MedTrace** is an Atlassian Forge application (`nodejs22.x`) and Model Context Protocol (MCP) compliance platform for medical-device engineering teams on Jira Cloud and Confluence Cloud. It tracks end-to-end safety traceability across a deterministic 5-stage graph:

`HAZARD <-> SPEC <-> WORK <-> TEST <-> SIGNATURE`

Every evaluation, live ingestion sync, Confluence drift check, and hash-chained audit entry executes inside Atlassian Cloud with **zero external network egress**.

## Key Capabilities

- **Jira & Confluence UI Parity ([manifest.yml](manifest.yml)):**
  - **Jira:** Project Safety Matrix (`jira:projectPage`), Issue Compliance Panel (`jira:issuePanel`), and transition-blocking Workflow Validator (`jira:workflowValidator`).
  - **Confluence:** Content Byline Item (`confluence:contentBylineItem`), Global Compliance Workspace (`confluence:globalPage`, route `medtrace-compliance`), and automatic `avi:confluence:updated:page` trigger (`confluence-trigger-fn`).
- **Live Atlassian Ingestion & Drift Detection ([src/ingestion.ts](src/ingestion.ts)):**
  - `syncLiveSuite` (`LiveIngestionService.syncFromAtlassian`) ingests Jira issues (`/rest/api/3/search/jql`) and Confluence pages (`/wiki/api/v2/pages`), enriches links via Atlassian Graph Gateway (AGG) + Jira `issuelinks` / `remotelink` fallback ([src/teamwork-graph.ts](src/teamwork-graph.ts)), and hashes Confluence storage XML with SHA-256.
  - Editing a Confluence Software Requirement Specification (SRS) fires `avi:confluence:updated:page`, recomputes the SHA-256 content hash against the signed baseline, invalidates drifted Part 11 signatures, and switches affected links to `SIGNATURE_DRIFT`.
  - Supports both `LIVE` tenant ingestion and `DEMO` synthetic datasets (`datasetMode: 'LIVE' | 'DEMO'`).
- **Sharded Forge KVS & Tamper-Evident Audit Ledger ([src/seeder.ts](src/seeder.ts), [src/audit-log.ts](src/audit-log.ts)):**
  - Stores suite metadata (`medtrace:compliance:suite_meta`, `SHARDED_V2`), individual sharded trace links (`medtrace:compliance:link:<id>` in batches of 25), and signed spec baselines (`medtrace:compliance:signed_spec:<id>`).
  - Records every mutation in a SHA-256 hash-chained append-only ledger (`medtrace:audit:head`, `medtrace:audit:entry:<seq>`) written with `keyPolicy: 'FAIL_IF_EXISTS'` and verifiable end-to-end via `verifyAuditChain` in [static/frontend/src/components/AuditLogModal.tsx](static/frontend/src/components/AuditLogModal.tsx).
- **RBAC & 21 CFR Part 11 Electronic Attestation ([src/index.ts](src/index.ts)):**
  - Mutating Custom UI resolvers enforce `assertAuthorizedOperator` (`ADMINISTER_PROJECTS` or `EDIT_ISSUES` in Jira; space read check in Confluence).
  - Supports explicit Jira issue binding (`bindIssueToHazard`), test evidence logging (`recordTestResult`), and 21 CFR Part 11 electronic sign-off (`signOffPart11` requiring explicit confirmation and meaning). Demo gap simulation (`remediateGap`) is strictly restricted to `DEMO` mode.
- **5-Stage Blast Radius & FDA Dossier Export ([src/compliance-engine.ts](src/compliance-engine.ts), [static/frontend/src/components/FdaExportModal.tsx](static/frontend/src/components/FdaExportModal.tsx)):**
  - Exact-key BFS blast radius (`computeBlastRadius`) across `HAZARD`, `SPEC`, `WORK`, `TEST`, and `SIGNATURE` nodes using `@xyflow/react`.
  - Exports submission dossiers as JSON, CSV, or printable report (`#fda-export-printable`).
- **Rovo AI & Hardened MCP Bridge ([src/mcp-server.ts](src/mcp-server.ts), [mcp-server/index.mjs](mcp-server/index.mjs)):**
  - In-cloud Rovo Agent (`medtrace-regulatory-auditor`) and Rovo MCP (`medtrace-mcp-server`) exposing `get-hazard-lineage-action` and `verify-iec-compliance-action`.
  - Standalone local MCP stdio server (`SERVER_VERSION = '1.1.0'`) communicating over HMAC-SHA256 (`x-medtrace-timestamp`, `x-medtrace-nonce`, `x-medtrace-signature`) with SHA-256 hashed KVS TTL nonces ([src/nonce-store.ts](src/nonce-store.ts)) and fail-closed `MEDTRACE_MCP_SECRET` enforcement.

## Architecture Overview

```
Local IDE / CI Runner                     Atlassian Cloud (Forge nodejs22.x — Zero Egress)
+------------------------+                +----------------------------------------------------+
| mcp-server/index.mjs   |  HTTPS + HMAC  | mcp-sync-webtrigger (src/index.ts)                 |
| or release-gate action +--------------->|  - Timing-safe SHA-256 signature + KVS TTL nonce   |
+------------------------+                |  - Shared evaluateIssueReleaseGate                 |
                                          +-------------------------+--------------------------+
Jira / Confluence Custom UI                                         |
+------------------------+  @forge/bridge                           v
| React 18 + @xyflow     +---------------> 12 Resolvers (assertAuthorizedOperator RBAC)
| (static/frontend/)     |                 |
+------------------------+                 +--> ComplianceEngine (src/compliance-engine.ts)
                                           +--> TeamworkGraphService (AGG + REST fallback)
Confluence Page Update Trigger ----------> +--> LiveIngestionService (src/ingestion.ts)
Jira Workflow Transition Validator ------> +--> SeederService SHARDED_V2 KVS (src/seeder.ts)
Rovo Agent & Actions --------------------> +--> AuditLogService SHA-256 Chain (src/audit-log.ts)
```

## Quick Start & Verification

### 1. Install & Build

```bash
npm install && cd static/frontend && npm install && cd ../..
npm run build && cd static/frontend && npm run build && cd ../..
```

### 2. Typecheck, Test & Docs Verification

```bash
npx tsc --noEmit && cd static/frontend && npx tsc --noEmit && cd ../..
npm test
npm run docs:check
node --check mcp-server/index.mjs
forge lint
```

- Test suite: [tests/compliance-engine.test.cjs](tests/compliance-engine.test.cjs) (**57 tests across 14 suites**).
- Documentation check: [scripts/docs-check.mjs](scripts/docs-check.mjs).

### 3. Deploy & Rotate Secrets

See [docs/00-how-to/03-deploy-production.md](docs/00-how-to/03-deploy-production.md) for setting encrypted `MEDTRACE_MCP_SECRET`, deploying to Jira and Confluence, binding `medtrace-safety-validator`, configuring [.github/workflows/ci.yml](.github/workflows/ci.yml) and [.github/workflows/medtrace-release-gate.yml](.github/workflows/medtrace-release-gate.yml), and rotating secrets via [scripts/rotate-mcp-secret.sh](scripts/rotate-mcp-secret.sh).

## Documentation Map

- [AGENTS.md](AGENTS.md) — Repository rules and verification workflow.
- [docs/00-how-to/00-overview.md](docs/00-how-to/00-overview.md) — Task guides (adding hazards, adding MCP tools, production deployment, docs sync).
- [docs/01-architecture/00-overview.md](docs/01-architecture/00-overview.md) — Forge manifest modules, RBAC, resolvers, and zero-egress boundary.
- [docs/02-compliance-engine/00-overview.md](docs/02-compliance-engine/00-overview.md) — Evaluation rules, blast radius, sharded KVS, live ingestion, and hash-chained audit ledger.
- [docs/03-mcp-integration/00-overview.md](docs/03-mcp-integration/00-overview.md) — Rovo MCP, local stdio server (`mcp-server/README.md`), HMAC nonces, and tool contracts.
- [docs/99-design-decisions/00-overview.md](docs/99-design-decisions/00-overview.md) — Architecture Decision Records (ADRs 001-005).
- [SECURITY.md](SECURITY.md) — Secret handling, vulnerability reporting, and rotation.
- [marketplace/PRIVACY_POLICY.md](marketplace/PRIVACY_POLICY.md), [marketplace/TERMS_OF_SERVICE.md](marketplace/TERMS_OF_SERVICE.md), [marketplace/SUPPORT.md](marketplace/SUPPORT.md) — Atlassian Marketplace documentation.

## License

See [LICENSE](LICENSE).
