**Back:** [00-overview](./00-overview.md)

# ADR 002: Webtrigger HMAC-SHA256 Authentication and Replay Window Protection

## Context
Atlassian Forge webtriggers are publicly accessible HTTP endpoints generated with unique hashed URLs. While unlisted, relying solely on URL secrecy or simple token headers leaves endpoints vulnerable to parameter tampering and replay attacks. An attacker intercepting a remediation payload could replay it indefinitely to alter compliance states.

## Decision
Implement a cryptographic signature protocol binding the payload and timestamp in `src/index.ts` and `mcp-server/index.mjs`:
1. The client derives an HMAC-SHA256 signature over `${timestamp}.${nonce}.${rawBody}` using a pre-shared secret (`MEDTRACE_MCP_SECRET`); `x-medtrace-nonce` is required on every request.
2. Transmit `x-medtrace-timestamp`, `x-medtrace-nonce`, and `x-medtrace-signature: sha256=<hex>`.
3. The server checks a 300-second maximum replay window against `Date.now()`.
4. Perform timing-safe signature comparison using `crypto.timingSafeEqual` in `verifyHmacSignature()`.

## Alternatives Considered
* **Static API Key Header (`x-api-key`):** Rejected because a static key does not bind to the HTTP request body. An attacker capturing the token could tamper with `hazardKey` or replay requests indefinitely.
* **OAuth 2.0 / Bearer Token Flow:** Rejected for local terminal MCP daemons due to user authentication friction during hackathon evaluations and lack of native Forge webtrigger OAuth interception hooks.

## Consequences
- Protects the production webtrigger against unauthorized modification, parameter tampering, and replay attacks.
- Eliminates timing side-channels during signature validation (`crypto.timingSafeEqual`).
- **Nonce claim is atomic:** `claimNonce()` uses a conditional write (`keyPolicy: 'FAIL_IF_EXISTS'`) against `@forge/kvs`, so concurrent replays cannot both claim the same nonce; expired records are pruned lazily on access.
- The CI-facing `verify-release-gate` action maps the validator verdict to HTTP 200/403 so pipeline gating needs no body parsing.
- Validated via automated test suite in `tests/compliance-engine.test.cjs`.

## Key Files

| Path | Role |
|---|---|
| `src/index.ts` | Webtrigger handler implementing `verifyHmacSignature()`. |
| `mcp-server/index.mjs` | Local MCP client generating HMAC-SHA256 headers. |
| `tests/compliance-engine.test.cjs` | Automated security tests for signature tampering and replay rejection. |

## Related

- [Live MCP Sync Architecture](../03-mcp-integration/live-sync.md)
- [How-To: Add an MCP Tool](../00-how-to/02-add-mcp-tool.md)
