[<- Design Decisions Overview](./00-overview.md)

# ADR-002: Webtrigger HMAC-SHA256 Authentication & SHA-256 KVS Nonces

## Status
Accepted (Hardened with SHA-256 Nonce Keys & Fail-Closed Storage Handling)

## Context
Local MCP clients ([mcp-server/index.mjs](../../mcp-server/index.mjs)) and CI release gates ([.github/workflows/medtrace-release-gate.yml](../../.github/workflows/medtrace-release-gate.yml)) must invoke `mcp-sync-webtrigger` over HTTPS. Because Forge webtriggers are public endpoints unguarded by Jira/Confluence session cookies, weak bearer headers or permissive error handling would expose compliance actions to spoofing or replay attacks.

## Decision
1. **Fail-Closed Shared Secret:** Both `mcpWebtriggerHandler` ([src/index.ts](../../src/index.ts)) and [mcp-server/index.mjs](../../mcp-server/index.mjs) fail closed if `MEDTRACE_MCP_SECRET` is missing or empty (returning HTTP `500` on the webtrigger).
2. **Canonical HMAC-SHA256 Verification:** Callers must send `x-medtrace-timestamp` (digits within `±300` seconds), `x-medtrace-nonce`, and `x-medtrace-signature` computed as hex HMAC-SHA256 over `${timestamp}.${nonce}.${rawBody}`, verified with `crypto.timingSafeEqual`.
3. **SHA-256 Hashed Nonce Keys & Native KVS TTL ([src/nonce-store.ts](../../src/nonce-store.ts)):**
   - Raw nonce identifiers are hashed with `toKvsNonceKey(key)` (`nonce:<sha256>`) to avoid key-length or character issues in KVS.
   - `kvsNonceStore.claimDetailed(key, ttlMs)` uses atomic `kvs.set(..., { keyPolicy: 'FAIL_IF_EXISTS', ttl: { value: Math.max(1, Math.ceil(ttlMs / 60000)), unit: 'MINUTES' } })` so Forge KVS enforces expiry natively without lazy `delete()` sweeps on access.
   - Nonce claim outcomes distinguish `'CLAIMED'`, `'REPLAY'` (HTTP `409`), and `'STORAGE_ERROR'` (HTTP `500` fail-closed).
4. **Strict Request Parsing & Actor Attribution:** Malformed `POST` JSON returns HTTP `400` immediately (no fallback to `GET` parameters), responses omit wildcard CORS headers, and `action=remediate` attributes audit entries to `'service:mcp-webtrigger'` (ignoring any caller-supplied `accountId`).

## Consequences
- Prevents replay attacks across stateless Forge invocations and avoids Forge KVS failure modes silently masquerading as valid nonces or replays.
- Operators must configure identical `MEDTRACE_MCP_SECRET` values in Forge encrypted variables (`forge variables set MEDTRACE_MCP_SECRET --encrypt`) and client/CI environments; rotation is automated via [scripts/rotate-mcp-secret.sh](../../scripts/rotate-mcp-secret.sh).
