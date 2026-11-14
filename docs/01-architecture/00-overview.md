# Architecture

MedTrace runs inside the Atlassian Forge `nodejs22.x` runtime with zero outbound network egress. Every compliance evaluation, sharded storage mutation, hash-chained audit entry, Jira/Confluence API call, and Rovo/MCP interaction executes inside Atlassian Cloud using Forge KVS (`@forge/kvs`), Jira/Confluence REST APIs, and the Atlassian Graph Gateway (AGG).

## Files

- [forge-modules.md](./forge-modules.md) — Forge manifest (`manifest.yml`) Jira & Confluence module parity, local icon resources, RBAC (`assertAuthorizedReader` / `assertAuthorizedOperator` / `assertRovoUserReadAccess`), 12 typed `MedTraceResolverMap` resolvers, `ECO-624` workflow validator boundary, `mcp-webtrigger-fn` hardening, Custom UI architecture, and zero-egress permissions.

## Configuration & Assets

- [manifest.yml](../../manifest.yml) — Forge `nodejs22.x` modules, `main` (`static/frontend/dist`) and `icons` (`static/icons`) resources, `storage:app` & read scopes, CSP `styles: ['unsafe-inline']`, and zero external egress.
- [package.json](../../package.json), [static/frontend/package.json](../../static/frontend/package.json), & [static/frontend/vite.config.ts](../../static/frontend/vite.config.ts) — Backend and frontend npm build (`manualChunks` vendor splitting for `vendor-xyflow`, `vendor-react`, `vendor-forge`), typecheck, manifest validation, docs check, and test scripts.
- [static/icons/medtrace-icon.svg](../../static/icons/medtrace-icon.svg) — Bundled SVG module icon referenced as `resource:icons;medtrace-icon.svg` by `jira:issuePanel` and `confluence:contentBylineItem`.

## Backend Modules (`src/`)

- [src/index.ts](../../src/index.ts) — Forge handlers (`resolver-fn`, `workflow-validator-fn`, `rovo-action-fn`, `mcp-webtrigger-fn`, `confluence-trigger-fn`), RBAC gates (`assertAuthorizedReader` / `assertAuthorizedOperator`), 12 Custom UI resolvers, and HMAC-SHA256 `mcpWebtriggerHandler`.
- [src/runtime.ts](../../src/runtime.ts) — `isForgeRuntime()` runtime boundary check.
- [src/types.ts](../../src/types.ts) — Browser-safe shared domain contracts, `PART11_ATTESTATION_PHRASE`, and `MedTraceResolverMap`.
- [src/crypto-utils.ts](../../src/crypto-utils.ts) — `sha256Hex`, `canonicalJsonStringify`, `isKvsConflictError`, `sanitizeKvsKeySegment`, `measureJsonBytes`, and `validateHttpsUrl`.
- [src/compliance-engine.ts](../../src/compliance-engine.ts) — 5-stage rule evaluator, `HMAC-SHA256-SEAL-V1` (`computePart11Seal` / `verifyPart11Seal` + `MEDTRACE_PART11_PREVIOUS_SECRETS` key rotation via `resolvePart11VerificationSecrets` / `computePart11KeyFingerprint`) & hybrid `ECDSA-P256-SHA256+HMAC-SEAL-V1` (`computePart11ClientChallenge` / `verifyPart11ClientSignature` / `computeClientKeyFingerprint`), `evaluateIssueReleaseGate`, `generateComplianceReport`, `computeBlastRadius`, and `computeMultiBlastRadius`.
- [src/seeder.ts](../../src/seeder.ts) — `SeederService` sharded `SHARDED_V2` persistence, `vlock` optimistic locking, `issueKeyIndex` / `medtrace:compliance:meta_index:` O(1) lookup (`GetSuiteOptions`), content-hash unchanged link reuse (`lastKvsShardState`), `kvs.transact()` / chunked staging, composite `(hazardKey, specId)` `SignedSpecBaseline`, and compliance mutations.
- [src/teamwork-graph.ts](../../src/teamwork-graph.ts) — `TeamworkGraphService` dual-engine `JIRA_AGG_AND_REST` / `JIRA_REST` + `JIRA_REMOTELINK_REST` lookup with `callerMode: 'USER' | 'APP'` and `requireConfluenceLinkToEnrich` `/remotelink` short-circuiting.
- [src/ingestion.ts](../../src/ingestion.ts) — `LiveIngestionService` paginated Jira/Confluence ingestion, `LIVE_SYNC_CONCURRENCY_BATCH_SIZE = 5` enrichment, resumable `nextPageToken` KVS cursors (`SYNC_CURSOR_KEY_PREFIX`), unreached/other-project link preservation, M:N linking, revert non-resurrection, and `avi:confluence:updated:page` drift handler.
- [src/audit-log.ts](../../src/audit-log.ts) — `AuditLogService` SHA-256 hash-chained audit ledger (`AUDIT_GENESIS_HASH`, monotonic `setHead`, `beforeSeq` pagination, bounded `verifyAuditChain` windows with `DEFAULT_VERIFY_MAX_ENTRIES = 500` / `MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES` and `nextFromSeq`).
- [src/workflow-validator.ts](../../src/workflow-validator.ts) — `workflowValidatorHandler` release gate using O(1) `getActiveComplianceSuite({ issueKeyFilter })` lookup and Atlassian `ECO-624` scope note.
- [src/mcp-server.ts](../../src/mcp-server.ts) — `McpToolService` & `rovoActionHandler` (`assertRovoUserReadAccess` + Rovo actions).
- [src/nonce-store.ts](../../src/nonce-store.ts) — SHA-256 hashed KVS TTL replay nonce store (`MAX_TIMESTAMP_AGE_MS`, `MAX_FUTURE_SKEW_MS`, `NONCE_TTL_MS`).

## Custom UI Frontend (`static/frontend/`)

- [static/frontend/src/main.tsx](../../static/frontend/src/main.tsx) & [static/frontend/src/App.tsx](../../static/frontend/src/App.tsx) — React 18 entrypoint and Custom UI shell adapting to `view.getContext()`, compact panel default table view, poll/focus/mutation race serialization, and `ConfirmSeedModal` overwrite guard.
- [static/frontend/src/types.ts](../../static/frontend/src/types.ts) — Re-exports shared backend types plus `ForgePanelContext`, `UiNotice`, and `ClientTransitionResult`.
- [static/frontend/src/bridge.ts](../../static/frontend/src/bridge.ts) — Lazy `loadForgeBridge()`, `BridgeUnavailableError`, `getForgeContext()`, `enableForgeTheme()`, `unwrapInvokeResponse`, and typed `invokeResolver`.
- [static/frontend/src/auditVerify.ts](../../static/frontend/src/auditVerify.ts) — `verifyAuditChainBounded` sequential multi-window audit hash-chain verification helper (`AUDIT_VERIFY_PAGE_SIZE = 200`, `nextFromSeq` + `expectedPrevHash`) shared by `AuditLogModal` and `FdaExportModal`.
- [static/frontend/src/index.css](../../static/frontend/src/index.css) — Atlassian Design Tokens (`--ds-*` mapped to `--mt-*`), `.mt-panel-compact` layout rules, and `.mt-node-test--alert` styling.
- [static/frontend/src/hooks/useDialogA11y.ts](../../static/frontend/src/hooks/useDialogA11y.ts) — Accessible dialog hook managing LIFO `activeDialogStack`, `Escape` handling, and focus trap/restoration.
- **UI Components:**
  - [static/frontend/src/components/AuditHeader.tsx](../../static/frontend/src/components/AuditHeader.tsx) — Toolbar actions, `isCompactPanel` collapsed menu, and uninitialized-suite prompt.
  - [static/frontend/src/components/ConfirmSeedModal.tsx](../../static/frontend/src/components/ConfirmSeedModal.tsx) — `role="alertdialog"` modal guarding against overwriting `LIVE` suites with synthetic `DEMO` data.
  - [static/frontend/src/components/LineageGraph.tsx](../../static/frontend/src/components/LineageGraph.tsx) & [static/frontend/src/components/CustomNodes.tsx](../../static/frontend/src/components/CustomNodes.tsx) — `@xyflow/react` 5-stage compliance graph visualization and keyboard-operable custom nodes.
  - [static/frontend/src/components/TraceMatrixTable.tsx](../../static/frontend/src/components/TraceMatrixTable.tsx) — Searchable traceability matrix table and cold-start empty state.
  - [static/frontend/src/components/InspectionDrawer.tsx](../../static/frontend/src/components/InspectionDrawer.tsx) — Detail drawer for blast radius, `queryGraphContext`, issue binding, test evidence recording, and 21 CFR Part 11 attestation.
  - [static/frontend/src/components/TransitionModal.tsx](../../static/frontend/src/components/TransitionModal.tsx) — Workflow release gate simulator.
  - [static/frontend/src/components/AuditLogModal.tsx](../../static/frontend/src/components/AuditLogModal.tsx) — Paginated `beforeSeq` audit trail viewer and `verifyAuditChain` UI trigger.
  - [static/frontend/src/components/FdaExportModal.tsx](../../static/frontend/src/components/FdaExportModal.tsx) — JSON, CWE-1236 formula-safe CSV (`escapeCsvCell`), safe HTTPS evidence links, and `#fda-export-printable` print view.
- **Frontend Test Setup & Specs:** [static/frontend/vitest.config.ts](../../static/frontend/vitest.config.ts), [static/frontend/src/test/setup.ts](../../static/frontend/src/test/setup.ts), [static/frontend/src/__tests__/App.races.test.tsx](../../static/frontend/src/__tests__/App.races.test.tsx), [static/frontend/src/__tests__/AuditLogModal.test.tsx](../../static/frontend/src/__tests__/AuditLogModal.test.tsx), [static/frontend/src/__tests__/FdaExportModal.test.tsx](../../static/frontend/src/__tests__/FdaExportModal.test.tsx), [static/frontend/src/__tests__/InspectionDrawer.test.tsx](../../static/frontend/src/__tests__/InspectionDrawer.test.tsx), [static/frontend/src/__tests__/TransitionModal.test.tsx](../../static/frontend/src/__tests__/TransitionModal.test.tsx), [static/frontend/src/__tests__/a11yAndGraph.test.tsx](../../static/frontend/src/__tests__/a11yAndGraph.test.tsx), and [static/frontend/src/__tests__/bridge.test.ts](../../static/frontend/src/__tests__/bridge.test.ts).
