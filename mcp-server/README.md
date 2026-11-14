# MedTrace MCP Stdio Server

Standalone Model Context Protocol (`stdio`, JSON-RPC 2.0) bridge (`SERVER_VERSION = 1.1.0`) implemented in [mcp-server/index.mjs](./index.mjs), connecting local AI coding assistants (Cursor, Claude Desktop, VS Code, Windsurf) to your Atlassian Forge MedTrace instance.

Zero compliance state is persisted locally. All tool calls are signed with HMAC-SHA256, guarded by single-use nonces, and forwarded over `https://` to the deployed `mcp-sync-webtrigger` (`mcpWebtriggerHandler` in [src/index.ts](../src/index.ts)).

## Configuration & `.env` Rules

On CLI startup, [mcp-server/index.mjs](./index.mjs) loads `.env` from `process.cwd()` first, falling back to the repository root (`..`). Pre-set process environment variables always win over `.env`.

`.env` parsing supports:
- Blank lines and full-line `#` comments
- Optional leading `export ` prefixes (for example `export MEDTRACE_MCP_SECRET="..."`)
- Single-quoted and double-quoted values containing `#` characters, unescaping `\"`, `\'`, and `\\`, and discarding trailing `# ...` comments after the closing quote
- Unquoted values with trailing whitespace-delimited `# ...` inline comments stripped

### Required Environment Variables (Fail-Closed Startup)

The server **fails closed** (exits with status `1`) if either variable is missing, empty, or invalid:

```bash
# Forge CLI v15 webtrigger commands:
#   forge webtrigger list -f mcp-sync-webtrigger -e production
#   forge webtrigger create -f mcp-sync-webtrigger -e production
MEDTRACE_WEBTRIGGER_URL="https://<your-forge-webtrigger-url>"

# Must match: forge variables set MEDTRACE_MCP_SECRET "<secret>" --encrypt -e production
MEDTRACE_MCP_SECRET="<your-32-byte-hex-secret>"
```

- `MEDTRACE_WEBTRIGGER_URL` **must** use `https://` and **must not** contain embedded `username:password` credentials or control characters.

### Optional Environment Flags

- `MEDTRACE_ALLOW_INSECURE_LOCALHOST=true`: Permits `http://` **only** for loopback hosts (`localhost`, `127.0.0.1`, `::1`) during local development or automated testing. Remote `http://` URLs (such as `http://example.com`) and non-HTTP schemes are always rejected even when this flag is enabled.
- `MEDTRACE_REQUEST_TIMEOUT_MS`: Webtrigger HTTP request timeout in milliseconds (default `15000` ms to accommodate Forge cold starts; clamped to `1000`..`60000` ms).
- `MEDTRACE_MCP_NO_AUTOSTART=1`: Disables automatic stdio initialization when importing `mcp-server/index.mjs` programmatically as an ESM module.

## Client Setup (`mcpServers` JSON)

```json
{
  "mcpServers": {
    "medtrace-compliance": {
      "command": "node",
      "args": ["/ABS/PATH/TO/MedTrace/mcp-server/index.mjs"],
      "env": {
        "MEDTRACE_WEBTRIGGER_URL": "https://your-forge-webtrigger-url",
        "MEDTRACE_MCP_SECRET": "your-32-byte-hex-secret"
      }
    }
  }
}
```

## JSON-RPC 2.0 Transport Behavior

- **Serialized FIFO Line Queue:** Incoming NDJSON requests on `stdin` execute through a serialized FIFO queue so concurrent async webtrigger calls flush to `stdout` in strict arrival order without interleaved frames.
- **Protocol Methods:** Supports `initialize`, `ping` (returns `{}`), "tools/list", and "tools/call".
- **Notifications:** Requests omitting `id` (such as "notifications/initialized" and "notifications/cancelled") return zero `stdout` output.
- **Standard Error Codes:**
  - `-32700` (`Parse error`, `id: null`): Malformed JSON input (checked before reading `id`).
  - `-32600` (`Invalid Request`): Batch arrays, non-object payloads, non-`2.0` `jsonrpc` versions, invalid `id` types, or missing `method`.
  - `-32601`: Unknown JSON-RPC method or unknown MCP tool name.
  - `-32602` (`Invalid params`): Non-object `params` or `params.arguments`, missing tool `name`, or invalid arguments to `medtrace_remediate_safety_gap` (validated locally with zero HTTP calls).

## Available Tools

- `medtrace_get_hazard_lineage`: Queries the 5-stage trace chain (`HAZARD <-> SPEC <-> WORK <-> TEST <-> SIGNATURE`) via `GET`. Matches case-insensitively across 9 canonical identifiers (`hazard.key`, `hazard.id`, `work.key`, `work.id`, `test.testKey`, `test.id`, `spec.id`, `spec.pageId`, `signature.id`).
  - Returns the unified schema (`found: true`, `datasetMode`, `initialized`, `traceLink`, `regulatoryStatus`, `riskClass`, `safetyRequirement`, `testStatus`, `part11Valid`, and artifact fields) when matched, or `{ found: false, availableKeys }` when no link matches (including uninitialized empty `LIVE` suites).
  - Sets `source` dynamically via `formatSourceLabel`:
    - `'Atlassian Cloud (Forge KVS - LIVE)'` (`LIVE`)
    - `'Atlassian Forge KVS (DEMO Dataset)'` (`DEMO`)
    - `'Atlassian Forge KVS (UNSPECIFIED)'` (otherwise)
- `medtrace_verify_iec_compliance`: Sends `POST` (`action: 'verify'`) with `prDiff`, `componentName`, and `issueKey` to compute 5-stage blast radius and clinical release readiness (`McpToolService` in [src/mcp-server.ts](../src/mcp-server.ts)).
- `medtrace_remediate_safety_gap`: Demo-only simulated remediation (`DEMO` dataset only). Locally requires non-empty `hazardKey`, `simulate: true`, and `attestationConfirmed: true` (otherwise returns `-32602` with zero HTTP calls). Attributes audit entries to `'service:mcp-webtrigger'` and is rejected with HTTP `403` when the active suite is in `LIVE` mode.

## Error Classification Model

Tool-level webtrigger errors return MCP `{ isError: true }` with structured JSON:

| Condition | `source` | `errorType` | `httpStatus` |
|---|---|---|---|
| Network failure / config error / cold-start timeout | `'UNAVAILABLE'` | `'NETWORK_ERROR'` / `'CONFIG_ERROR'` / `'TIMEOUT'` | `0` |
| Invalid HMAC, timestamp skew, or nonce replay | `'ATLASSIAN_CLOUD_REJECTED'` | `'AUTH_FAILED'` (`401`) / `'REPLAY_DETECTED'` (`409`) | `401` / `409` |
| Policy block (e.g. `LIVE` remediate) or request validation failure | `'POLICY_OR_VALIDATION_ERROR'` | `'BACKEND_REJECTED'` | HTTP 4xx (`400`, `403`, `404`, `405`, `422`) |
| Upstream Forge error or malformed response | `'BACKEND_ERROR'` | `'UPSTREAM_ERROR'` | HTTP 5xx |

## Security Posture (HMAC-SHA256 & Forge KVS Honesty)

- Every request signs `${timestamp}.${nonce}.${rawBody}` with HMAC-SHA256 (`x-medtrace-timestamp` in epoch milliseconds bounded to `-300s`..`+30s`, `x-medtrace-nonce` claimed atomically in `@forge/kvs` with a 7-minute TTL, verified with `crypto.timingSafeEqual`).
- **Platform Boundary Disclosure:** `@forge/kvs` provides tenant-scoped storage with conditional `FAIL_IF_EXISTS` write protection and a SHA-256 hash-chained audit ledger (`tamper-evident`), **not** hardware WORM or HSM key storage. Electronic signatures under 21 CFR Part 11 combine Atlassian Cloud session identity with server-side `HMAC-SHA256-SEAL-V1` record sealing (`MEDTRACE_PART11_SECRET`, supporting zero-downtime rotation via `MEDTRACE_PART11_PREVIOUS_SECRETS`) and optional hybrid asymmetric `ECDSA-P256-SHA256+HMAC-SEAL-V1` client `prime256v1` non-repudiation signatures; customers must still maintain organizational SOPs and external archival exports for full regulatory compliance.

For full webtrigger and Rovo integration contracts, see [docs/03-mcp-integration/live-sync.md](../docs/03-mcp-integration/live-sync.md).
