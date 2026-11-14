[<- Architecture Overview](./00-overview.md)

# Forge Modules & Security Boundaries

MedTrace is defined in [manifest.yml](../../manifest.yml) under the Forge `nodejs22.x` runtime (App ID `ari:cloud:ecosystem::app/5e49c10e-696f-4984-9d00-4a47d0a5dd99`). Five Forge function keys dispatch backend handlers from [src/index.ts](../../src/index.ts), [src/workflow-validator.ts](../../src/workflow-validator.ts), [src/mcp-server.ts](../../src/mcp-server.ts), and [src/ingestion.ts](../../src/ingestion.ts).

## Declared Modules & Resources ([manifest.yml](../../manifest.yml))

| Module Type | Key | Handler / Resource | Purpose |
|---|---|---|---|
| `jira:projectPage` | `medtrace-matrix-page` | `resolver-fn` / `main` | Project-level Custom UI traceability matrix, blast-radius graph, audit log modal, and FDA dossier export. |
| `jira:issuePanel` | `medtrace-issue-panel` | `resolver-fn` / `main` / `resource:icons;medtrace-icon.svg` | Contextual issue-level compliance status, hazard binding, test recording, and Part 11 sign-off panel. |
| `jira:workflowValidator` | `medtrace-safety-validator` | `workflow-validator-fn` | Transition gate blocking Jira UI release transitions when an issue (loaded O(1) via `getActiveComplianceSuite({ issueKeyFilter: issueKey })`) or active suite violates IEC 62304 release rules (see `ECO-624` limit below). |
| `confluence:contentBylineItem` | `medtrace-confluence-byline` | `resolver-fn` / `main` / `resource:icons;medtrace-icon.svg` | Content byline item on Confluence pages surfacing linked requirements, signature validity, and drift state. |
| `confluence:globalPage` | `medtrace-confluence-page` | `resolver-fn` / `main` | Confluence global compliance workspace (route: `medtrace-compliance`) matching Jira workspace parity. |
| `trigger` | `medtrace-confluence-page-updated` | `confluence-trigger-fn` | Listens to `avi:confluence:updated:page`; runs `LiveIngestionService.handleConfluencePageUpdated()` with CAS retry for real-time spec drift detection. |
| `rovo:agent` | `medtrace-regulatory-auditor` | — | MedTrace Regulatory Auditor agent for IEC 62304 / ISO 14971 compliance review. |
| `action` | `get-hazard-lineage-action` | `rovo-action-fn` | Returns the 5-stage trace chain for a `hazardKey` or `issueKey` (or `found: false` when absent). |
| `action` | `verify-iec-compliance-action` | `rovo-action-fn` | Analyzes a diff or description for affected suite tokens/safety keywords and computes blast radius. |
| `rovo:mcp` | `medtrace-mcp-server` | — | Exposes `get-hazard-lineage-action` and `verify-iec-compliance-action` to Rovo / Atlassian Studio. |
| `webtrigger` | `mcp-sync-webtrigger` | `mcp-webtrigger-fn` | HMAC-SHA256 authenticated HTTPS bridge for local `mcp-server/index.mjs` and CI release gates. |

**Bundled Resources:**
- `main`: `static/frontend/dist` (built Vite/React 18 Custom UI bundle configured in [static/frontend/vite.config.ts](../../static/frontend/vite.config.ts) with `manualChunks` splitting into `vendor-xyflow`, `vendor-react`, and `vendor-forge`).
- `icons`: `static/icons` (local asset [static/icons/medtrace-icon.svg](../../static/icons/medtrace-icon.svg) referenced as `resource:icons;medtrace-icon.svg`, avoiding external icon CDN fetches).

### Jira & Confluence Parity and Platform Limit (`ECO-624`)

- Both Jira (`jira:projectPage`, `jira:issuePanel`) and Confluence (`confluence:globalPage`, `confluence:contentBylineItem`) share the same Custom UI bundle (`main`) and all 12 `MedTraceResolverMap` resolvers.
- **Jira REST / Bulk API Transition Limitation (`ECO-624`):** As documented in [src/workflow-validator.ts](../../src/workflow-validator.ts), Forge `jira:workflowValidator` does **not** intercept Jira REST API or bulk workflow transitions (`ECO-624`). CI pipelines and automated release workflows must call `action=verify-release-gate` via `mcp-sync-webtrigger` in addition to UI workflow validation.

## Runtime Detection, Custom UI Resolvers & Frontend Bridge

`isForgeRuntime()` in [src/runtime.ts](../../src/runtime.ts) inspects `globalThis.__forge_runtime__` so storage, nonce, audit, and live-ingestion adapters fail closed inside Forge while enabling isolated in-memory unit testing in Node.js.

The React 18 Custom UI ([static/frontend/src/App.tsx](../../static/frontend/src/App.tsx)) adapts its layout via `view.getContext()` (`compact` `.mt-panel-compact` mode defaulting to the table view on `jira:issuePanel` / `confluence:contentBylineItem`, full workspace on `jira:projectPage` / `confluence:globalPage`). Through [static/frontend/src/bridge.ts](../../static/frontend/src/bridge.ts), it lazy-loads `@forge/bridge` (`loadForgeBridge()`), fails cleanly with `BridgeUnavailableError` outside Forge, enables Atlassian theming (`enableForgeTheme()`, backed by `--ds-*` tokens in [static/frontend/src/index.css](../../static/frontend/src/index.css)), serializes polling/focus/mutation refreshes, steps across bounded `verifyAuditChain` windows via [static/frontend/src/auditVerify.ts](../../static/frontend/src/auditVerify.ts), gates `LIVE`-mode synthetic resets behind `ConfirmSeedModal`, enforces accessible dialog stacking via [static/frontend/src/hooks/useDialogA11y.ts](../../static/frontend/src/hooks/useDialogA11y.ts), and unwraps typed backend responses via `unwrapInvokeResponse` / `invokeResolver`:

| Resolver (`MedTraceResolverMap`) | RBAC Gate | Action |
|---|---|---|
| `getComplianceSuite` | `assertAuthorizedReader` | Loads active suite via `SeederService.getActiveComplianceSuite()` (returns uninitialized empty `LIVE` suite when KVS is cold/empty; no demo auto-seeding) + compliance report; workflow and release-gate callers pass `GetSuiteOptions` (`{ issueKeyFilter, projectKey }`) for O(1) shard lookups via `issueKeyIndex` / `meta_index`. |
| `queryGraphContext` | `assertAuthorizedReader` | Calls `TeamworkGraphService.queryIssueGraphContext(issueKey, { callerMode: 'USER' })` (AGG + Jira REST + `remotelink`). |
| `analyzeBlastRadius` | `assertAuthorizedReader` | Computes 5-stage BFS blast radius via `ComplianceEngine.computeBlastRadius()` (scoped reader check when `issueKey` is supplied). |
| `simulateTransition` | `assertAuthorizedReader` | Evaluates `workflowValidatorHandler()` release-gate readiness for an issue or suite. |
| `getAuditLog` | `assertAuthorizedReader` | Returns paginated hash-chained audit entries (`limit` clamped, optional `beforeSeq` cursor) via `AuditLogService.getAuditLog()`. |
| `verifyAuditChain` | `assertAuthorizedReader` | Recomputes canonical SHA-256 hashes over bounded windows (`fromSeq`, `maxEntries` defaulting to `200` / capped at `500`, `expectedPrevHash`) via `AuditLogService.verifyAuditChain()`, returning `{ valid, truncated, nextFromSeq, verifiedFromSeq, verifiedToSeq, windowEntryCount }` for multi-batch verification via `verifyAuditChainBounded()`. |
| `seedDemoSuite` | `assertAuthorizedOperator` | Resets storage to synthetic `DEMO` dataset and logs `'SEED_DEMO'` (guarded by UI `ConfirmSeedModal` when overwriting `LIVE`). |
| `syncLiveSuite` | `assertAuthorizedOperator` | Ingests paginated Jira issues & Confluence pages into `LIVE` mode via `LiveIngestionService.syncFromAtlassian()`, supporting resumable `nextPageToken` KVS cursors (`resumeFromCursor`, `pageToken`, returning `nextPageToken` and `resumedFromCursor`), `LIVE_SYNC_CONCURRENCY_BATCH_SIZE = 5` batching, and untagged `/remotelink` short-circuiting (`requireConfluenceLinkToEnrich`). |
| `bindIssueToHazard` | `assertAuthorizedOperator` | Binds a verified Jira issue (`/rest/api/3/issue/{key}`, `callerMode: 'USER'`) to a hazard link, clearing stale git/graph fields. |
| `recordTestResult` | `assertAuthorizedOperator` | Records `'PASSED' | 'FAILED' | 'UNTESTED' | 'IN_PROGRESS'` test evidence (`validateHttpsUrl` check; `""` clears URL) and logs `'RECORD_TEST_RESULT'`. |
| `signOffPart11` | `assertAuthorizedOperator` | Requires `attestationConfirmed: true`, `passwordConfirmed: true`, exact `PART11_ATTESTATION_PHRASE`, `meaning.trim().length >= 5`, `UserIdentityResolver`, and `HMAC-SHA256-SEAL-V1` seal (`MEDTRACE_PART11_SECRET`, verifiable across `MEDTRACE_PART11_PREVIOUS_SECRETS` key rotation) plus optional hybrid asymmetric `ECDSA-P256-SHA256+HMAC-SEAL-V1` client `prime256v1` signature fields (`clientPublicKeySpki`, `clientSignatureBase64`), storing composite `(hazardKey, specId)` `SignedSpecBaseline`. |
| `remediateGap` | `assertAuthorizedOperator` | Executes `DEMO`-only simulated Class C gap remediation (`simulate: true`, `attestationConfirmed: true`, non-empty `targetHazardKey`); rejected in `LIVE` mode. |

### RBAC Enforcement (`assertAuthorizedReader`, `assertAuthorizedOperator`, `assertRovoUserReadAccess`)

- **Custom UI Read Resolvers (`assertAuthorizedReader`):** Every read resolver verifies caller identity and read permissions in Forge runtime before reading KVS or querying APIs:
  - **Jira:** Calls `/rest/api/3/mypermissions` (`BROWSE_PROJECTS` scoped to `issueKey` / `projectKey` when available; `BROWSE_PROJECTS`, `EDIT_ISSUES`, or `ADMINISTER_PROJECTS` when unscoped).
  - **Confluence:** Verifies `/wiki/rest/api/user/current`, then checks `/wiki/api/v2/pages/{id}` (when `contentId` is present), `/wiki/api/v2/spaces/{id}` (when `spaceId` is present), or `/wiki/api/v2/spaces?limit=1` (global fallback).
- **Custom UI Write Resolvers (`assertAuthorizedOperator`):** Every mutating resolver enforces caller identity and operator privileges before mutating KVS:
  - **Jira:** Requires `EDIT_ISSUES` or `ADMINISTER_PROJECTS` (plus `BROWSE_PROJECTS` when scoped to `issueKey` / `projectKey`) via `/rest/api/3/mypermissions`, blocking cross-project write abuse.
  - **Confluence:** Verifies `/wiki/rest/api/user/current` and checks write/admin operations via `/wiki/api/v2/pages/{id}/operations`, `/wiki/api/v2/spaces/{id}/operations`, or `/wiki/api/v2/spaces?type=global&limit=25` (probing `/operations` across up to `CONFLUENCE_GLOBAL_SPACES_PROBE_LIMIT = 10` global spaces, preventing personal-space access from bypassing global operator RBAC).
- **Rovo Actions (`assertRovoUserReadAccess` in [src/mcp-server.ts](../../src/mcp-server.ts)):** Enforces caller-scoped user read access (`api.asUser()`) when invoked by a user inside Forge Rovo.

## Webtrigger Security & Hardening (`mcpWebtriggerHandler`)

1. **Method Validation Before Nonce Claim:** Rejects unsupported HTTP methods with HTTP `405` (`Allow: GET, POST`) before validating/consuming replay nonces.
2. **Fail-Closed Secret & Asymmetric Replay Window:** Returns HTTP `500` (`{ error, errorId }`) if `MEDTRACE_MCP_SECRET` is unset or empty. Requires `x-medtrace-timestamp` within `[-300_000, +30_000]` ms (`MAX_TIMESTAMP_AGE_MS = 300_000`, `MAX_FUTURE_SKEW_MS = 30_000`), `x-medtrace-nonce`, and `x-medtrace-signature` (`crypto.timingSafeEqual` over `${timestamp}.${nonce}.${rawBody}`).
3. **SHA-256 KVS Nonce Store ([src/nonce-store.ts](../../src/nonce-store.ts)):** Stores SHA-256 hashed nonce keys (`nonce:<sha256>`) with `NONCE_TTL_MS = 390_000` (7-minute Forge KVS TTL so future-skewed timestamps never outlive their nonce record). Returns HTTP `409` on `'REPLAY'` and HTTP `500` on `'STORAGE_ERROR'`.
4. **Strict JSON & Allowlisted Actions:** Malformed `POST` JSON returns HTTP `400` without falling back to `GET` parameters. `POST` actions are restricted to `ALLOWED_WEBTRIGGER_POST_ACTIONS`: `'status'`, `'seed'`, `'remediate'`, `'verify'`, `'verify-release-gate'`, `'validate'`, `'simulate_transition'` (unknown actions return `400`).
5. **Mode Guards & Sanitized Errors:**
   - `seed` and `remediate` return HTTP `403` when active mode is `LIVE` (`remediate` attributes actor `'service:mcp-webtrigger'` and returns HTTP `404` when target hazard is missing in `DEMO`).
   - `verify-release-gate`: Always enforces fail-closed `evaluateIssueReleaseGate(issueKey, suite)` (returning HTTP `200` on pass, HTTP `403` on block/uninitialized), and when `requireLiveMode: true` is supplied, additionally requires `datasetMode === 'LIVE'`, `initialized !== false`, and `totalHazards > 0` (returning HTTP `403` if `DEMO` or uninitialized).
   - Unexpected internal errors return sanitized HTTP `500` `{ error, errorId }` without stack-trace leakage.
   - Responses omit wildcard `Access-Control-Allow-Origin: *`.

## Permissions & Zero-Egress Boundary

- **Scopes ([manifest.yml](../../manifest.yml)):** `read:jira-work`, `read:jira-user`, `read:page:confluence`, `read:space:confluence`, `read:user:confluence`, `read:content.metadata:confluence`, and `storage:app` (note: declares **no** `read:graph:*` scopes).
- **Content Security Policy:** `permissions.content.styles: ['unsafe-inline']` (required by `@xyflow/react` runtime inline `transform` styles; no external scripts or network origins).
- **Zero External Egress:** `manifest.yml` declares **no** `permissions.external.fetch.backend` entries. All Jira/Confluence/AGG calls use Forge `api.asApp()` or `api.asUser()` inside Atlassian Cloud.
