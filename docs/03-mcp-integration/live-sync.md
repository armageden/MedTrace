[<- MCP Integration Overview](./00-overview.md)

# MCP Live Sync, Webtrigger Bridge & Tool Contracts

MedTrace exposes compliance inspection and CI gate verification through two synchronized entrypoints:
1. **Rovo MCP & Actions (In-Cloud):** Defined in [manifest.yml](../../manifest.yml) (`medtrace-mcp-server`, `get-hazard-lineage-action`, `verify-iec-compliance-action`) and handled by `rovoActionHandler` in [src/mcp-server.ts](../../src/mcp-server.ts).
2. **Local MCP Stdio Bridge:** Implemented in [mcp-server/index.mjs](../../mcp-server/index.mjs) (`SERVER_VERSION = '1.1.0'`), communicating over JSON-RPC 2.0 `stdio` and forwarding authenticated requests to `mcpWebtriggerHandler` in [src/index.ts](../../src/index.ts).

## Environment & Startup Fail-Closed Behavior

- [mcp-server/index.mjs](../../mcp-server/index.mjs) loads `.env` from `process.cwd()` first and falls back to the module parent directory (`..`).
- `MEDTRACE_MCP_SECRET` is mandatory. If unset or empty, local MCP startup and `mcpWebtriggerHandler` (HTTP `500`) both fail closed.
- `MEDTRACE_WEBTRIGGER_URL` points to the deployed `mcp-sync-webtrigger` URL (`forge webtrigger -f mcp-sync-webtrigger`).

## Webtrigger HMAC-SHA256 & Nonce Replay Protection

Requests sent by `signedCloudRequest()` in [mcp-server/index.mjs](../../mcp-server/index.mjs) use a single `POST` call (no extra `GET` preflight) with:
- `x-medtrace-timestamp`: Unix epoch seconds (digits only, validated within a `±300` second window).
- `x-medtrace-nonce`: Unique random UUID/hex per request.
- `x-medtrace-signature`: Hex HMAC-SHA256 over `${timestamp}.${nonce}.${rawBody}`, verified with `crypto.timingSafeEqual`.

### Nonce Store ([src/nonce-store.ts](../../src/nonce-store.ts))

- `getNonceStore()` selects `kvsNonceStore` whenever `isForgeRuntime()` ([src/runtime.ts](../../src/runtime.ts)) is true, and `defaultInMemoryStore` in unit tests unless overridden via `setNonceStore()`.
- `toKvsNonceKey(key)` hashes raw nonce keys into ``nonce:${sha256(key)}`` so Forge KVS keys stay fixed-length and safe.
- `claimDetailed(key, ttlMs)` uses atomic `kvs.set(..., { keyPolicy: 'FAIL_IF_EXISTS', ttl: { value: Math.max(1, Math.ceil(ttlMs / 60000)), unit: 'MINUTES' } })` and returns a 3-state `NonceClaimResult`:
  - `'CLAIMED'` -> proceeds.
  - `'REPLAY'` (409 / EXISTS / CONFLICT) -> webtrigger returns HTTP `409`.
  - `'STORAGE_ERROR'` (KVS unavailability) -> webtrigger fails closed with HTTP `500`.

### Request Validation & Error Propagation

- Malformed JSON on `POST` returns HTTP `400` immediately without falling back to `GET` query parameters.
- Responses include `Content-Type: application/json` with no wildcard `Access-Control-Allow-Origin: *` header.
- `signedCloudRequest()` propagates non-2xx HTTP responses cleanly as MCP tool errors (`isError: true`, `{ httpStatus, error }`).

## Tool Contracts

| MCP Tool | Rovo Action | Required Parameters | Behavior & Contracts |
|---|---|---|---|
| `medtrace_get_hazard_lineage` | `get-hazard-lineage-action` | One of `hazardKey` or `issueKey` | Returns `{ found: true, ... }` with the 5-stage trace chain, or `{ found: false, queriedKey, message, availableKeys }` if no matching link exists. |
| `medtrace_verify_iec_compliance` | `verify-iec-compliance-action` | `prDiff` | Extracts suite keys plus dynamic meaningful tokens (`findLinksMatchingTextTokens`) and safety keywords (`pump`, `infusion`, `alarm`, `dose`, `sensor`, `watchdog`, `class c`, etc.), computes 5-stage blast radius (`ComplianceEngine.computeBlastRadius`), and never logs raw `prDiff` contents in `rovoActionHandler`. |
| `medtrace_remediate_safety_gap` | — | `hazardKey`, `simulate`, `attestationConfirmed` | Missing `hazardKey` fails JSON-RPC validation (`-32602`). Calls `action=remediate` on the webtrigger. Actor identity is hardcoded to `'service:mcp-webtrigger'` (any caller `accountId` is ignored). Demo-only: rejected in `LIVE` mode. |

In addition, `mcpWebtriggerHandler` exposes `action=verify-release-gate` (shared `ComplianceEngine.evaluateIssueReleaseGate`, returning HTTP `200` on pass or `403` on compliance block) and `action=validate` / `simulate_transition` (`workflowValidatorHandler`), used by [.github/workflows/medtrace-release-gate.yml](../../.github/workflows/medtrace-release-gate.yml).
