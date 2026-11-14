[<- MCP Integration Overview](./00-overview.md)

# MCP Live Sync, Webtrigger Bridge & Tool Contracts

MedTrace exposes compliance inspection and CI gate verification through two synchronized entrypoints:
1. **Rovo MCP & Actions (In-Cloud):** Defined in [manifest.yml](../../manifest.yml) (`medtrace-mcp-server`, `medtrace-regulatory-auditor`, `get-hazard-lineage-action`, `verify-iec-compliance-action`) and handled by `rovoActionHandler` in [src/mcp-server.ts](../../src/mcp-server.ts).
2. **Local MCP Stdio Bridge:** Implemented in [mcp-server/index.mjs](../../mcp-server/index.mjs) (`SERVER_NAME = 'medtrace-mcp-server'`, `SERVER_VERSION = '1.1.0'`), communicating over JSON-RPC 2.0 NDJSON `stdio` and forwarding HMAC-authenticated requests to `mcpWebtriggerHandler` in [src/index.ts](../../src/index.ts).

For local client JSON configuration (`mcpServers`), see [mcp-server/README.md](../../mcp-server/README.md).

## Environment & Fail-Closed Startup

- [mcp-server/index.mjs](../../mcp-server/index.mjs) loads `.env` via `loadLocalEnv()` from `process.cwd()` first and falls back to the repository parent directory (`..`). Pre-existing `process.env` values always override `.env`.
- `parseEnvContent()` supports blank lines, `#` full-line comments, optional `export ` prefixes, single/double-quoted values containing `#` (unescaping `\"`, `\'`, and `\\`), and unquoted inline ` # comment` stripping.
- **Fail-closed startup:** When launched as CLI (`isMainModule`, overrideable with `MEDTRACE_MCP_NO_AUTOSTART=1` for ESM imports), startup exits with status `1` if `MEDTRACE_MCP_SECRET` is unset/empty or if `validateWebtriggerUrl()` rejects `MEDTRACE_WEBTRIGGER_URL`. `mcpWebtriggerHandler` likewise fails closed with HTTP `500` if `MEDTRACE_MCP_SECRET` is unset.
- **URL validation (`MEDTRACE_WEBTRIGGER_URL`):** Requires `https://` with no embedded `username:password` credentials or control characters. Retrieve or create the Forge URL using Forge CLI v15:
  ```bash
  forge webtrigger list -f mcp-sync-webtrigger -e production
  forge webtrigger create -f mcp-sync-webtrigger -e production
  ```
- **Optional environment flags:**
  - `MEDTRACE_ALLOW_INSECURE_LOCALHOST=true`: Permits `http://` **only** for loopback hosts (`localhost`, `127.0.0.1`, `::1`, `[::1]`) in local development or test harnesses. Remote `http://` and non-HTTP schemes are always rejected.
  - `MEDTRACE_REQUEST_TIMEOUT_MS`: Webtrigger HTTP request timeout in milliseconds (default `DEFAULT_REQUEST_TIMEOUT_MS = 15000`, clamped to `1000..60000`).
- **Separate signing secret:** `MEDTRACE_PART11_SECRET` (plus optional `MEDTRACE_PART11_PREVIOUS_SECRETS` key-ring rotation secrets) is provisioned solely inside Forge encrypted variables for `HMAC-SHA256-SEAL-V1` / `ECDSA-P256-SHA256+HMAC-SEAL-V1` Part 11 seals ([src/seeder.ts](../../src/seeder.ts), [src/compliance-engine.ts](../../src/compliance-engine.ts)) and must **never** be placed in local MCP `.env` files.

## JSON-RPC 2.0 Transport ([mcp-server/index.mjs](../../mcp-server/index.mjs))

- **Serialized FIFO `lineQueue`:** `createLineProcessor()` chains incoming `stdin` lines sequentially so async `signedCloudRequest()` responses flush to `stdout` in strict arrival order as NDJSON without frame interleaving.
- **Supported methods:** `initialize` (`protocolVersion: '2024-11-05'`), `ping` (returns `{}`), "tools/list", and "tools/call".
- **Notifications:** Messages omitting `id` (or with `id === undefined`, such as "notifications/initialized" or "notifications/cancelled") return `null` and emit zero `stdout` output.
- **Protocol error codes:**
  - `-32700` (`Parse error`, `id: null`): Invalid JSON syntax (evaluated before reading `id`).
  - `-32600` (`Invalid Request`): Batch arrays, non-object payloads, `jsonrpc !== '2.0'`, non-string/empty `method`, or invalid `id` types.
  - `-32601`: Unsupported method or unknown tool name.
  - `-32602` (`Invalid params`): Non-object `params` or `params.arguments`, missing tool `name`, or invalid local arguments on `medtrace_remediate_safety_gap`.

## Webtrigger HMAC-SHA256 & Nonce Replay Protection

Requests sent by `signedCloudRequest()` in [mcp-server/index.mjs](../../mcp-server/index.mjs) use `GET` (for `medtrace_get_hazard_lineage`) or `POST` (for `verify`, `remediate`, `verify-release-gate`, etc.) with:
- `x-medtrace-timestamp`: **Unix epoch milliseconds** (`Date.now().toString()`, digits only).
- `x-medtrace-nonce`: Unique random UUID/string (1–256 chars; `mcpWebtriggerHandler` also accepts fallback `x-medtrace-event-id`).
- `x-medtrace-signature`: `sha256=<hex>` HMAC-SHA256 over `${timestamp}.${nonce}.${rawBody}`, verified via `crypto.timingSafeEqual` in `verifyHmacSignature()` (fails closed on empty secrets or non-64-hex signatures).

### Asymmetric Timestamp Window & Nonce Store ([src/nonce-store.ts](../../src/nonce-store.ts))

- `mcpWebtriggerHandler` enforces an asymmetric replay window `[-300_000, +30_000]` ms:
  - `MAX_TIMESTAMP_AGE_MS = 300_000` (maximum past age: 300 seconds)
  - `MAX_FUTURE_SKEW_MS = 30_000` (maximum future clock skew: 30 seconds)
  - Requests outside `[now - 300_000, now + 30_000]` are rejected with HTTP `401` before consuming a nonce.
- `getNonceStore()` selects `kvsNonceStore` when `isForgeRuntime()` ([src/runtime.ts](../../src/runtime.ts)) is true, and `defaultInMemoryStore` in unit tests unless overridden via `setNonceStore()`.
- `toKvsNonceKey(key)` hashes `nonce:${cleanNonce}` once into ``nonce:${sha256Hex(key)}`` so KVS keys stay fixed-length and valid.
- `NONCE_TTL_MS` is `390_000` ms (`MAX_TIMESTAMP_AGE_MS + MAX_FUTURE_SKEW_MS + 60_000`). `kvsNonceStore.claimDetailed(key, val, ttlMs)` rounds up to `{ value: 7, unit: 'MINUTES' }` (`420` seconds, exceeding the `330`-second total accepted span so future-skewed nonces cannot expire early) and writes atomically with `keyPolicy: 'FAIL_IF_EXISTS'`:
  - `'CLAIMED'` -> request proceeds.
  - `'REPLAY'` (HTTP 409 / `EXISTS` / `CONFLICT`) -> webtrigger returns HTTP `409`.
  - `'STORAGE_ERROR'` (KVS outage) -> webtrigger fails closed with HTTP `500`.

### Webtrigger Validation Order & Error Classification

`mcpWebtriggerHandler` validates requests in strict order (before claiming a nonce whenever possible):
1. Missing/empty `MEDTRACE_MCP_SECRET` -> HTTP `500`.
2. Unsupported HTTP method (anything other than `GET` or `POST`) -> HTTP `405` (`Allow: GET, POST`).
3. Missing/malformed headers, non-digit/out-of-window timestamp (`[-300_000, +30_000]`), non-string body in Forge runtime, or HMAC mismatch -> HTTP `401`.
4. Duplicate nonce -> HTTP `409`; nonce store failure -> HTTP `500`.
5. `GET` with non-empty body or disallowed `?action=` (only omitted, `status`, or `get-suite` allowed) -> HTTP `400`.
6. `POST` with empty/malformed/non-object JSON or missing/unknown `action` (allowlist: `status`, `seed`, `remediate`, `verify`, `verify-release-gate`, `validate`, `simulate_transition`) -> HTTP `400`.
7. `action: 'seed'` or `action: 'remediate'` when active suite `datasetMode === 'LIVE'` -> HTTP `403`.
8. `action: 'remediate'` when `hazardKey` is not found in active `DEMO` suite -> HTTP `404`.
9. Unhandled runtime exceptions -> sanitized HTTP `500` (`{ error, errorId }`). Responses set `Content-Type: application/json` without wildcard CORS headers.

`cloudErrorResult()` in [mcp-server/index.mjs](../../mcp-server/index.mjs) classifies tool failures into structured MCP `{ isError: true }` payloads:

| Condition | `source` | `errorType` | `httpStatus` |
|---|---|---|---|
| Network failure / invalid local config / `AbortSignal.timeout` | `'UNAVAILABLE'` | `'NETWORK_ERROR'` / `'CONFIG_ERROR'` / `'TIMEOUT'` | `0` |
| Invalid HMAC, timestamp skew, or duplicate nonce | `'ATLASSIAN_CLOUD_REJECTED'` | `'AUTH_FAILED'` (`401`) / `'REPLAY_DETECTED'` (`409`) | `401` / `409` |
| Validation failure or policy block (e.g., `LIVE` `remediate`) | `'POLICY_OR_VALIDATION_ERROR'` | `'BACKEND_REJECTED'` | `400`, `403`, `404`, `405`, `422` |
| Forge internal error or malformed JSON response | `'BACKEND_ERROR'` | `'UPSTREAM_ERROR'` | `5xx` |

## Tool Contracts

| MCP Tool | Rovo Action | Parameters (Required / Optional) | Behavior & Contracts |
|---|---|---|---|
| `medtrace_get_hazard_lineage` | `get-hazard-lineage-action` | **Required:** none<br>**Optional:** `hazardKey`, `issueKey` | Matches case-insensitively across 9 canonical fields (`hazard.key`, `hazard.id`, `work.key`, `work.id`, `test.testKey`, `test.id`, `spec.id`, `spec.pageId`, `signature.id`). Returns `{ found: true, datasetMode, initialized, traceLink, matchedLinks?, regulatoryStatus, riskClass, safetyRequirement, testStatus, part11Valid, hazard, spec, work, test, signature, complianceState, violations }`, `{ found: false, datasetMode, initialized, queriedKey, message, availableKeys }`, or full project summary (`traceLinks`) when both keys are omitted. |
| `medtrace_verify_iec_compliance` | `verify-iec-compliance-action` | **Required:** none<br>**Optional:** `prDiff`, `componentName`, `issueKey` | Fails closed on uninitialized suites (`initialized: false`, `canShipToClinicalProduction: false`). Extracts explicit canonical suite keys (`/\b[A-Za-z]{2,10}-\d+\b/g`) and dynamic word-boundary tokens (`findLinksMatchingTextTokens`). `DEMO_KEYWORD_FALLBACKS` (`bolus`, `clamp`, `motor`, `flow`, `pwm`, `droplet`, `sensor`, `stall`, `photodiode`, `oled`, `battery`, `voltage`, `spi`) apply **only** when `datasetMode === 'DEMO'`. Computes BFS blast radius via `ComplianceEngine.computeMultiBlastRadius`. `rovoActionHandler` never logs raw `prDiff` content. |
| `medtrace_remediate_safety_gap` | — | **Required:** `hazardKey`, `simulate` (`true`), `attestationConfirmed` (`true`)<br>**Optional:** `meaning` | Local schema check rejects invalid args with `-32602` (0 HTTP calls). Calls `POST { action: 'remediate', ... }`. Hardcodes actor `'service:mcp-webtrigger'` (ignores any caller `accountId`). Demo-only: rejected with HTTP `403` when `datasetMode === 'LIVE'`. |

### Dynamic `source` Labels & Rovo Authorization

- `formatSourceLabel(datasetMode)` in [mcp-server/index.mjs](../../mcp-server/index.mjs) emits `'Atlassian Cloud (Forge KVS - LIVE)'` for `'LIVE'`, `'Atlassian Forge KVS (DEMO Dataset)'` for `'DEMO'`, and `'Atlassian Forge KVS (UNSPECIFIED)'` otherwise.
- `rovoActionHandler` in [src/mcp-server.ts](../../src/mcp-server.ts) restricts `actionKey` to `ALLOWED_ROVO_ACTIONS`, rejects empty `accountId` strings, and invokes `assertRovoUserReadAccess()` (`GET /wiki/rest/api/user/current` or `GET /rest/api/3/mypermissions?permissions=BROWSE_PROJECTS`) inside Forge when `accountId` is supplied.

### Webtrigger CI & Release Gate Actions

In addition to MCP tools, `mcpWebtriggerHandler` exposes CI/gate POST actions:
- `action: 'verify-release-gate'`: Accepts optional `issueKey` and `requireLiveMode` (`boolean`). When `issueKey` is provided, loads matching shards in O(1) via `SeederService.getActiveComplianceSuite({ issueKeyFilter: issueKey })` (`issueKeyIndex` / `meta_index`) before calling `ComplianceEngine.evaluateIssueReleaseGate(issueKey, suite)` ([src/compliance-engine.ts](../../src/compliance-engine.ts)), evaluating the Global Release Gate when `issueKey` is omitted. When `requireLiveMode: true`, returns HTTP `403` (`{ result: false, releaseBlocked: true, datasetMode, initialized, errorMessage }`) unless `datasetMode === 'LIVE'`, `initialized !== false`, and `totalHazards > 0`. Otherwise returns HTTP `200` on pass or `403` on block. Used by [.github/workflows/medtrace-release-gate.yml](../../.github/workflows/medtrace-release-gate.yml) (`"requireLiveMode": true`).
- `action: 'validate'` or `'simulate_transition'`: Accepts optional `issueKey` and `transitionName` (default `'Done'`), delegates to `workflowValidatorHandler` ([src/workflow-validator.ts](../../src/workflow-validator.ts)), and returns HTTP `200` with `{ ...outcome, evaluatedIssueKey }`.
