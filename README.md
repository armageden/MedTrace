# MedTrace — Zero-Egress IEC 62304, ISO 14971 & 21 CFR Part 11 Compliance Engine

**MedTrace** is an Atlassian Forge application (`nodejs22.x`) and Model Context Protocol (MCP) compliance platform for medical-device engineering teams on Jira Cloud and Confluence Cloud. It tracks end-to-end safety traceability across a deterministic 5-stage graph:

`HAZARD <-> SPEC <-> WORK <-> TEST <-> SIGNATURE`

Every evaluation, live ingestion sync, Confluence drift check, and hash-chained audit entry executes inside Atlassian Cloud with **zero external network egress**.

## Key Capabilities

- **Jira & Confluence UI Parity ([manifest.yml](manifest.yml)):**
  - **Jira:** Project Safety Matrix (`jira:projectPage`, `medtrace-matrix-page`), Issue Compliance Panel (`jira:issuePanel`, `medtrace-issue-panel` with bundled local icon `resource:icons;medtrace-icon.svg` from [static/icons/medtrace-icon.svg](static/icons/medtrace-icon.svg)), and transition-blocking Workflow Validator (`jira:workflowValidator`, `medtrace-safety-validator`).
  - **Confluence:** Content Byline Item (`confluence:contentBylineItem`, `medtrace-confluence-byline`, `resource:icons;medtrace-icon.svg`), Global Compliance Workspace (`confluence:globalPage`, `medtrace-confluence-page`, route `medtrace-compliance`), and automatic `avi:confluence:updated:page` trigger (`confluence-trigger-fn`).
  - **Jira REST / Bulk Transition Limitation (`ECO-624`):** Forge `jira:workflowValidator` enforces interactive Jira UI transitions only and does **not** intercept Jira REST API or bulk issue transitions (`ECO-624`, documented in [src/workflow-validator.ts](src/workflow-validator.ts)); CI pipelines must invoke `action=verify-release-gate` via `mcp-sync-webtrigger`.
- **Live Atlassian Ingestion & Drift Detection ([src/ingestion.ts](src/ingestion.ts)):**
  - `syncLiveSuite` (`LiveIngestionService.syncFromAtlassian`) paginates Jira issues (`/rest/api/3/search/jql`, `DEFAULT_SYNC_MAX_ISSUES = 250`, persisting a resumable `nextPageToken` KVS cursor at `medtrace:ingestion:cursor:*` via `resumeFromCursor` / `pageToken` and returning `nextPageToken` + `resumedFromCursor` when truncated) and Confluence pages (`/wiki/api/v2/pages`). In concurrent batches of `LIVE_SYNC_CONCURRENCY_BATCH_SIZE = 5`, it enriches links via Atlassian Graph Gateway (`requestGraph`, `JIRA_AGG_AND_REST`) + Jira `issuelinks` / `remotelink` (`JIRA_REST`, `JIRA_REMOTELINK_REST`) fallback ([src/teamwork-graph.ts](src/teamwork-graph.ts)) with explicit `callerMode: 'USER' | 'APP'` (short-circuiting untagged non-safety Jira issues via `requireConfluenceLinkToEnrich: true` when `/remotelink` contains no Confluence links), hashes Confluence storage XML (`sha256Hash`), builds M:N trace links while preserving unreached/other-project links on scoped or paginated re-syncs, and enforces `requireTestEvidence: true` and `requireCryptographicSeal: true` in `LIVE`.
  - Editing a Confluence Software Requirement Specification (SRS) triggers `avi:confluence:updated:page` with optimistic 3-attempt CAS retry (`MAX_CAS_RETRY_ATTEMPTS = 3`), recomputes `sha256Hash` against composite `(hazardKey, specId)` baselines, invalidates drifted Part 11 signatures (enforcing revert non-resurrection if content reverts to an older invalidated hash), and switches affected links to `SIGNATURE_DRIFT`.
  - Cold-start installations return an uninitialized empty `LIVE` suite (`initialized: false`, 0 trace links, failing release gates closed until explicit initialization) without auto-seeding synthetic `DEMO` data.
- **Sharded Forge KVS & Tamper-Evident Audit Ledger ([src/seeder.ts](src/seeder.ts), [src/audit-log.ts](src/audit-log.ts)):**
  - Persists suite metadata (`medtrace:compliance:suite_meta`, `SHARDED_V2`, bounded by `MAX_KVS_META_BYTES = 128 * 1024`), an `issueKeyIndex` (overflow-sharded into `medtrace:compliance:meta_index:<version>:<chunk>` via `issueKeyIndexShardKeys` when metadata approaches `128 KiB`) for O(1) issue-scoped release-gate lookups (`getActiveComplianceSuite({ issueKeyFilter, projectKey })`), individual trace links (`medtrace:compliance:link:<id>` / `v<version>:` chunks with canonical content-hash reuse for unchanged shards), and composite `(hazardKey, specId)` `SignedSpecBaseline` records with optimistic `vlock` versioning, `kvs.transact()` for `<= 25` ops, staged chunking + GC for `> 25` ops, and `commitSuiteMutation` save-before-audit rollback.
  - Records every mutation in a SHA-256 hash-chained ledger (`medtrace:audit:head`, `medtrace:audit:entry:<seq>`) hashed canonically ([src/crypto-utils.ts](src/crypto-utils.ts)) over `seq`, `timestamp`, `actorAccountId`, `action`, `targetKey`, `details`, `prevHash`, and `authMethod`, written with `keyPolicy: 'FAIL_IF_EXISTS'`, paginated via `beforeSeq`, and verified across bounded windows (`fromSeq`, `maxEntries` defaulting to `500` in service / `200` in resolver, `expectedPrevHash`, returning `truncated` + `nextFromSeq`) via `verifyAuditChainBounded` ([static/frontend/src/auditVerify.ts](static/frontend/src/auditVerify.ts)) in [static/frontend/src/components/AuditLogModal.tsx](static/frontend/src/components/AuditLogModal.tsx) and [static/frontend/src/components/FdaExportModal.tsx](static/frontend/src/components/FdaExportModal.tsx).
  - **Honest Platform Scope:** SHA-256 hash chaining + `FAIL_IF_EXISTS` + `HMAC-SHA256-SEAL-V1` (with `MEDTRACE_PART11_PREVIOUS_SECRETS` key-ring rotation) / optional `ECDSA-P256-SHA256+HMAC-SEAL-V1` hybrid asymmetric Part 11 seals provide **software tamper-evidence** inside the customer's Atlassian tenant. Forge KVS (`@forge/kvs`) is **not** hardware WORM, does **not** use an app-controlled HSM, and does **not** issue third-party X.509/PKI non-repudiation certificates ([SECURITY.md](SECURITY.md), [ADR-005](docs/99-design-decisions/005-hash-chained-audit-log-and-sharded-kvs.md)).
- **RBAC & 21 CFR Part 11 Electronic Attestation ([src/index.ts](src/index.ts)):**
  - All 6 read resolvers enforce `assertAuthorizedReader` (Jira `BROWSE_PROJECTS`; Confluence page/space read), all 6 mutating resolvers enforce `assertAuthorizedOperator` (Jira project/issue-scoped `EDIT_ISSUES` / `ADMINISTER_PROJECTS`; Confluence page/space `/operations` and global-space probing), and Rovo actions enforce `assertRovoUserReadAccess`.
  - Supports Jira issue binding (`bindIssueToHazard`), test evidence logging (`recordTestResult` supporting `PASSED | FAILED | UNTESTED | IN_PROGRESS` and HTTPS `evidenceUrl`), and 21 CFR Part 11 sign-off (`signOffPart11` requiring `passwordConfirmed: true`, `PART11_ATTESTATION_PHRASE`, `UserIdentityResolver`, `MEDTRACE_PART11_SECRET` `HMAC-SHA256-SEAL-V1` sealing with zero-downtime `MEDTRACE_PART11_PREVIOUS_SECRETS` key rotation, and optional `ECDSA-P256-SHA256+HMAC-SEAL-V1` client `prime256v1` non-repudiation verification via `clientPublicKeySpki` and `clientSignatureBase64`). Demo gap simulation (`remediateGap`) is strictly restricted to `DEMO` mode (and guarded in the UI by [static/frontend/src/components/ConfirmSeedModal.tsx](static/frontend/src/components/ConfirmSeedModal.tsx) when overwriting `LIVE`).
- **5-Stage Blast Radius & FDA Dossier Export ([src/compliance-engine.ts](src/compliance-engine.ts), [static/frontend/src/components/FdaExportModal.tsx](static/frontend/src/components/FdaExportModal.tsx)):**
  - `ComplianceEngine.computeBlastRadius` and `computeMultiBlastRadius` run deterministic artifact-node component BFS in [src/compliance-engine.ts](src/compliance-engine.ts) across `HAZARD`, `SPEC`, `WORK`, `TEST`, and `SIGNATURE` stages along `SIGNS`, `MITIGATES`, `IMPLEMENTS`, and `VERIFIES` edges with per-hazard/per-spec drift isolation; `@xyflow/react` renders the interactive UI graph in [static/frontend/src/components/LineageGraph.tsx](static/frontend/src/components/LineageGraph.tsx) alongside [static/frontend/src/components/TraceMatrixTable.tsx](static/frontend/src/components/TraceMatrixTable.tsx).
  - Exports submission dossiers as JSON, CWE-1236 formula-safe CSV, or printable report (`#fda-export-printable`).
- **Rovo AI & Hardened MCP Bridge ([src/mcp-server.ts](src/mcp-server.ts), [mcp-server/index.mjs](mcp-server/index.mjs)):**
  - In-cloud Rovo Agent (`medtrace-regulatory-auditor`) and Rovo MCP (`medtrace-mcp-server`) exposing `get-hazard-lineage-action` and `verify-iec-compliance-action`.
  - Standalone local MCP stdio server (`SERVER_VERSION = '1.1.0'`) communicating over HMAC-SHA256 (`x-medtrace-timestamp`, `x-medtrace-nonce`, `x-medtrace-signature`) with an asymmetric `[-300_000, +30_000]` ms replay window, 7-minute (`NONCE_TTL_MS = 390_000`) SHA-256 hashed KVS nonces ([src/nonce-store.ts](src/nonce-store.ts)), `405` (`Allow: GET, POST`) pre-nonce method guards, and fail-closed `MEDTRACE_MCP_SECRET` enforcement.

## Architecture Overview

```text
+------------------------+            +---------------------------------------------------+
| Cursor / Claude / CI   |  HMAC-SHA  | Atlassian Forge Cloud (nodejs22.x, Zero Egress)   |
| mcp-server/index.mjs   +----------->+ mcp-webtrigger-fn (src/index.ts, nonce-store.ts)  |
+------------------------+   HTTPS    +-------------------------+-------------------------+
                                                                |
+------------------------+  @forge/bridge                       v
| Custom UI (React 18)   +---------------> 12 Resolvers (assertAuthorizedReader / Operator)
| Table + @xyflow/react  |  invokeResolver                      |
+------------------------+                                      v
                                          +-----------------------------------------------+
+------------------------+  Rovo Actions  | ComplianceEngine / SeederService (vlock KVS)  |
| Jira / Confluence UI   +--------------->+ LiveIngestionService + AuditLogService        |
| Workflow Gate (ECO-624)|                | TeamworkGraphService (AGG GraphQL + Jira REST)|
+------------------------+                +-----------------------------------------------+
```

## Quick Start & Verification

### 1. Install & Build

```bash
npm install && cd static/frontend && npm install && cd ../..
npm run build:all
```

### 2. Typecheck, Tests, Manifest & Docs Verification

```bash
npm run typecheck
npm test
npm run test:frontend
npm run lint:manifest
npm run docs:check
node --check mcp-server/index.mjs
forge lint
```

- **Backend & MCP Tests (`npm test`):** Executes pre-test TypeScript build and `node --test "tests/*.test.*"` across [tests/compliance-engine.test.cjs](tests/compliance-engine.test.cjs), [tests/audit-log.test.cjs](tests/audit-log.test.cjs), [tests/seeder-storage.test.cjs](tests/seeder-storage.test.cjs), [tests/ingestion.test.cjs](tests/ingestion.test.cjs), [tests/nonce-store.test.cjs](tests/nonce-store.test.cjs), [tests/workflow-validator-and-mcp.test.cjs](tests/workflow-validator-and-mcp.test.cjs), [tests/index-rbac-webtrigger.test.cjs](tests/index-rbac-webtrigger.test.cjs), [tests/mcp-server.test.mjs](tests/mcp-server.test.mjs), and [tests/scripts.test.mjs](tests/scripts.test.mjs).
- **Frontend Build & Tests (`npm run test:frontend`):** [static/frontend/vite.config.ts](static/frontend/vite.config.ts) splits vendor chunks (`vendor-xyflow`, `vendor-react`, `vendor-forge`) to keep built bundle sizes bounded; Vitest (`vitest run`) verifies UI race conditions, bounded audit verification, bridge loading, accessibility, blast-radius rendering, and CSV/export components under [static/frontend/src/__tests__/](static/frontend/src/__tests__/).
- **`forge lint` prerequisites:** requires an authenticated Forge CLI (`forge login`, or `FORGE_EMAIL` / `FORGE_API_TOKEN`). Without credentials it exits with `Error: Not logged in`; `npm run lint:manifest` is the offline substitute and does not replace it. Forge CLI v15 supports Node.js 22.x or 24.x only; other versions print an unsupported-version warning.
- **Manifest & Docs Checks:** [scripts/validate-manifest.mjs](scripts/validate-manifest.mjs) validates [manifest.yml](manifest.yml) offline against `@forge/manifest` plus compiled handler exports and bundled icons; [scripts/docs-check.mjs](scripts/docs-check.mjs) validates relative links, `#anchor` heading slugs, overview/backlink rules, and source-to-doc coverage.

### 3. Deploy & Rotate Secrets

See [docs/00-how-to/03-deploy-production.md](docs/00-how-to/03-deploy-production.md) for setting encrypted `MEDTRACE_MCP_SECRET` and `MEDTRACE_PART11_SECRET`, deploying to Jira and Confluence, binding `medtrace-safety-validator`, configuring [.github/workflows/ci.yml](.github/workflows/ci.yml) and [.github/workflows/medtrace-release-gate.yml](.github/workflows/medtrace-release-gate.yml), and rotating secrets via [scripts/rotate-mcp-secret.sh](scripts/rotate-mcp-secret.sh).

## Documentation Map

- **Guides & Runbooks:** [docs/00-how-to/00-overview.md](docs/00-how-to/00-overview.md) (including [Production Deploy](docs/00-how-to/03-deploy-production.md) & [Docs Sync Runbook](docs/00-how-to/sync-docs-runbook.md))
- **Architecture & Forge Modules:** [docs/01-architecture/00-overview.md](docs/01-architecture/00-overview.md)
- **Compliance Rules, Storage & Audit:** [docs/02-compliance-engine/00-overview.md](docs/02-compliance-engine/00-overview.md)
- **MCP Integration & Live Sync:** [docs/03-mcp-integration/00-overview.md](docs/03-mcp-integration/00-overview.md) & [mcp-server/README.md](mcp-server/README.md)
- **Architecture Decision Records (ADRs):** [docs/99-design-decisions/00-overview.md](docs/99-design-decisions/00-overview.md)
- **Security Policy:** [SECURITY.md](SECURITY.md)

## License

Apache-2.0 — see [package.json](package.json) license metadata.
