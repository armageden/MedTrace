[<- Architecture Overview](./00-overview.md)

# Forge Modules & Security Boundaries

MedTrace is defined in [manifest.yml](../../manifest.yml) under the Forge `nodejs22.x` runtime (App ID `ari:cloud:ecosystem::app/5e49c10e-696f-4984-9d00-4a47d0a5dd99`). Five Forge functions dispatch backend handlers from [src/index.ts](../../src/index.ts), [src/workflow-validator.ts](../../src/workflow-validator.ts), [src/mcp-server.ts](../../src/mcp-server.ts), and [src/ingestion.ts](../../src/ingestion.ts).

## Declared Modules ([manifest.yml](../../manifest.yml))

| Module Type | Key | Function Handler | Purpose |
|---|---|---|---|
| `jira:projectPage` | `medtrace-matrix-page` | `resolver-fn` | Project-level Custom UI traceability matrix, blast-radius graph, audit log modal, and FDA dossier export. |
| `jira:issuePanel` | `medtrace-issue-panel` | `resolver-fn` | Contextual issue-level compliance status, hazard binding, test recording, and Part 11 sign-off panel. |
| `jira:workflowValidator` | `medtrace-safety-validator` | `workflow-validator-fn` | Transition gate blocking release transitions when an issue or active suite violates IEC 62304 release rules. |
| `confluence:contentBylineItem` | `medtrace-confluence-byline` | `resolver-fn` | Content byline item on Confluence pages surfacing linked requirements, signature validity, and drift state. |
| `confluence:globalPage` | `medtrace-confluence-page` | `resolver-fn` | Confluence global compliance workspace (route: `medtrace-compliance`) sharing the Custom UI bundle. |
| `trigger` | `medtrace-confluence-page-updated` | `confluence-trigger-fn` | Listens to `avi:confluence:updated:page`; triggers `LiveIngestionService.handleConfluencePageUpdated()` for real-time spec drift detection. |
| `rovo:agent` | `medtrace-regulatory-auditor` | — | MedTrace Regulatory Auditor agent for IEC 62304 / ISO 14971 compliance review. |
| `action` | `get-hazard-lineage-action` | `rovo-action-fn` | Returns the 5-stage trace chain for a `hazardKey` or `issueKey` (or `found: false` when absent). |
| `action` | `verify-iec-compliance-action` | `rovo-action-fn` | Analyzes a diff or description for affected suite tokens/safety keywords and computes blast radius. |
| `rovo:mcp` | `medtrace-mcp-server` | — | Exposes `get-hazard-lineage-action` and `verify-iec-compliance-action` to Rovo / Atlassian Studio. |
| `webtrigger` | `mcp-sync-webtrigger` | `webtrigger-fn` | HMAC-SHA256 authenticated HTTPS bridge for local `mcp-server/index.mjs` and CI release gates. |

## Runtime Detection & Custom UI Resolvers ([src/index.ts](../../src/index.ts))

`isForgeRuntime()` in [src/runtime.ts](../../src/runtime.ts) inspects `globalThis.__forge_runtime__` so storage, nonce, audit, and live-ingestion adapters fail closed inside Forge while permitting deterministic in-memory testing in Node.js.

The React 18 Custom UI ([static/frontend/src/App.tsx](../../static/frontend/src/App.tsx)) adapts its behavior using `view.getContext()` for Jira (`jira:projectPage`, `jira:issuePanel`) and Confluence (`confluence:contentBylineItem`, `confluence:globalPage`) and invokes backend resolvers through [static/frontend/src/bridge.ts](../../static/frontend/src/bridge.ts) (`invokeResolver`):

| Resolver | Access | Action |
|---|---|---|
| `getComplianceSuite` | Read | Loads the active suite (auto-seeding demo data only when empty) and compliance report. |
| `queryGraphContext` | Read | Calls `TeamworkGraphService.queryIssueGraphContext()` (AGG with Jira REST + `remotelink` fallback). |
| `analyzeBlastRadius` | Read | Computes 5-stage BFS blast radius via `ComplianceEngine.computeBlastRadius()`. |
| `simulateTransition` | Read | Evaluates `workflowValidatorHandler()` release-gate readiness for an issue or suite. |
| `getAuditLog` | Read | Returns hash-chained audit entries (`limit` clamped `1..200`, default `50`) via `AuditLogService.getAuditLog()`. |
| `verifyAuditChain` | Read | Recomputes canonical SHA-256 hashes from seq 1 to head via `AuditLogService.verifyAuditChain()`. |
| `seedDemoSuite` | RBAC (`assertAuthorizedOperator`) | Resets storage to the synthetic `DEMO` dataset and appends an audit entry. |
| `syncLiveSuite` | RBAC (`assertAuthorizedOperator`) | Ingests live Jira issues & Confluence pages into `LIVE` mode via `LiveIngestionService.syncFromAtlassian()`. |
| `bindIssueToHazard` | RBAC (`assertAuthorizedOperator`) | Binds an existing Jira issue (verified via `/rest/api/3/issue/{key}` in Forge runtime) to a hazard link. |
| `recordTestResult` | RBAC (`assertAuthorizedOperator`) | Records `PASSED`, `FAILED`, or `PENDING` test evidence with `actorAccountId` and notes. |
| `signOffPart11` | RBAC (`assertAuthorizedOperator`) | Executes an explicit 21 CFR Part 11 attestation (`attestationConfirmed: true`, `meaning.trim().length >= 5`) and stores a signed spec hash baseline. |
| `remediateGap` | RBAC (`assertAuthorizedOperator`) | Runs `DEMO`-mode-only simulated Class C gap remediation (`simulate: true`, `attestationConfirmed: true`); rejected in `LIVE` mode. |

### RBAC Enforcement (`assertAuthorizedOperator`)

All mutating Custom UI resolvers enforce caller authorization via `assertAuthorizedOperator(req)` before touching KVS:
- **Confluence context** (`context.extension?.type` starts with `confluence:`): verifies `api.asUser().requestConfluence('/wiki/api/v2/spaces?limit=1')` succeeds.
- **Jira context**: verifies `/rest/api/3/mypermissions?permissions=ADMINISTER_PROJECTS,EDIT_ISSUES` grants `ADMINISTER_PROJECTS` or `EDIT_ISSUES`.

## Webtrigger Security & Hardening (`mcpWebtriggerHandler`)

- **Fail-closed secret verification:** Returns HTTP `500` if `process.env.MEDTRACE_MCP_SECRET` is unset or empty.
- **HMAC-SHA256 & replay defense:** Requires `x-medtrace-timestamp` (digits within 300s), `x-medtrace-nonce`, and `x-medtrace-signature` verified via `crypto.timingSafeEqual` over `${timestamp}.${nonce}.${rawBody}`. Nonces are stored in KVS under SHA-256 hashed keys; `REPLAY` returns HTTP `409` and `STORAGE_ERROR` fails closed with HTTP `500`.
- **Strict JSON parsing:** Malformed JSON on `POST` returns HTTP `400` without falling back to `GET` parameters.
- **No wildcard CORS & non-spoofable actor:** Responses set `Content-Type: application/json` without `Access-Control-Allow-Origin: *`. `action=remediate` always attributes actor identity to `'service:mcp-webtrigger'` (ignoring any caller-supplied `accountId`).
- **Action routing:** `action=verify-release-gate` uses `ComplianceEngine.evaluateIssueReleaseGate()` (HTTP `200` on pass, `403` on block); `action=validate` / `simulate_transition` executes `workflowValidatorHandler()`.

## Permissions & Zero-Egress Boundary

- **Scopes:** `read:jira-work`, `read:jira-user`, `read:page:confluence`, `read:space:confluence`, `read:user:confluence`, `read:content.metadata:confluence`, and `storage:app`.
- **Content Security Policy:** `permissions.content.styles: ['unsafe-inline']` (no external script or network domains).
- **Zero External Egress:** `manifest.yml` declares **no** `permissions.external.fetch.backend` entries. All Jira/Confluence/AGG calls use Forge `api.asApp()` or `api.asUser()` inside Atlassian Cloud.
