[<- Design Decisions Overview](./00-overview.md)

# ADR-002: Webtrigger HMAC-SHA256 Authentication & SHA-256 KVS Nonces

## Status
Accepted (Hardened with Asymmetric Replay Windows, 7-Minute Nonce TTL, Method Guards & Optimistic Suite Locking)

## Context
Local MCP clients ([mcp-server/index.mjs](../../mcp-server/index.mjs)) and CI release gates ([.github/workflows/medtrace-release-gate.yml](../../.github/workflows/medtrace-release-gate.yml)) invoke `mcp-sync-webtrigger` (`mcp-webtrigger-fn`) over HTTPS. Because Forge webtriggers are public endpoints unguarded by Jira/Confluence user sessions, weak bearer headers, permissive HTTP method handling, or unguarded storage errors would expose compliance state and audit logs to spoofing, replay attacks, or race corruption.

## Decision
1. **Method Validation Before Nonce Consumption:** `mcpWebtriggerHandler` ([src/index.ts](../../src/index.ts)) rejects unsupported HTTP methods with HTTP `405` (`Allow: GET, POST`) before validating timestamps or claiming nonces.
2. **Fail-Closed Shared Secret & Sanitized Errors:** Both `mcpWebtriggerHandler` and [mcp-server/index.mjs](../../mcp-server/index.mjs) fail closed if `MEDTRACE_MCP_SECRET` is missing or empty. Unexpected backend exceptions return HTTP `500` with sanitized `{ error, errorId }` payloads instead of stack traces.
3. **Canonical HMAC-SHA256 & Asymmetric Replay Window:** Callers send `x-medtrace-timestamp`, `x-medtrace-nonce`, and `x-medtrace-signature` computed as HMAC-SHA256 over `${timestamp}.${nonce}.${rawBody}`, verified with `crypto.timingSafeEqual`. Timestamp checks enforce an asymmetric replay window of `MAX_TIMESTAMP_AGE_MS = 300_000` (5 minutes past) and `MAX_FUTURE_SKEW_MS = 30_000` (30 seconds future).
4. **SHA-256 Hashed Nonce Keys & 7-Minute KVS TTL ([src/nonce-store.ts](../../src/nonce-store.ts)):**
   - Raw nonces are hashed via `toKvsNonceKey(key)` (`nonce:<sha256>`) to avoid key-length or character issues in KVS.
   - `kvsNonceStore.claimDetailed(key, NONCE_TTL_MS)` uses `NONCE_TTL_MS = 390_000` (rounded up to a 7-minute KVS TTL with `keyPolicy: 'FAIL_IF_EXISTS'`) so future-skewed timestamps up to `+30s` never outlive their replay guard.
   - Outcomes distinguish `'CLAIMED'`, `'REPLAY'` (HTTP `409`), and `'STORAGE_ERROR'` (HTTP `500` fail-closed).
5. **Strict JSON, Action Allowlist, Mode Isolation & Optimistic `vlock` Concurrency:**
   - Malformed `POST` JSON returns HTTP `400` without falling back to `GET` parameters; `POST` actions are allowlisted by `ALLOWED_WEBTRIGGER_POST_ACTIONS` (`status`, `seed`, `remediate`, `verify`, `verify-release-gate`, `validate`, `simulate_transition`).
   - `seed` and `remediate` return HTTP `403` when the active suite is `LIVE` (`remediate` also returns HTTP `404` for unknown hazards in `DEMO` and pins actor attribution to `'service:mcp-webtrigger'`); `verify-release-gate` enforces fail-closed release checks and supports `requireLiveMode: true`.
   - Webtrigger suite mutations share [src/seeder.ts](../../src/seeder.ts) optimistic `vlock` locking, `kvs.transact()` / staged `v<version>:` sharding, and `commitSuiteMutation` rollback so concurrent calls cannot silently clobber suite state.
   - Responses omit wildcard CORS headers (`Access-Control-Allow-Origin: *`).

## Consequences
- Prevents replay attacks across stateless Forge invocations, avoids future-skewed nonce expiry gaps, and prevents Forge KVS failure modes from masquerading as valid nonces or replays.
- Operators must keep identical `MEDTRACE_MCP_SECRET` values in Forge encrypted variables (`forge variables set MEDTRACE_MCP_SECRET --encrypt`) and client/CI environments; see [SECURITY.md](../../SECURITY.md) and [scripts/rotate-mcp-secret.sh](../../scripts/rotate-mcp-secret.sh).
