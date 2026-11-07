**Back:** [00-overview](./00-overview.md)

# Live MCP Sync & Stdio Server

MedTrace provides dual Model Context Protocol support:
1. **Cloud-Native `rovo:mcp`:** Declared in `manifest.yml` and routed through `rovo-action-fn` (`src/mcp-server.ts`) for Atlassian Rovo conversational agents.
2. **Local Stdio JSON-RPC Server:** Standalone, zero-dependency Node.js script in `mcp-server/index.mjs` for local IDE coding environments (Cursor, Claude Desktop).

---

## Tool Registry Specifications

### 1. Local Stdio Tools (`mcp-server/index.mjs`)

| Tool Identifier | Input Schema | Return Payload | Purpose |
|---|---|---|---|
| `medtrace_get_hazard_lineage` | `{ hazardKey?: string }` | `{ found, traceLink, regulatoryStatus, riskClass, ... }` | Returns complete 5-stage trace lineage for a specific hazard or full project suite. |
| `medtrace_verify_iec_compliance` | `{ prDiff?: string }` | `{ standards, canShipToClinicalProduction, classCSummary, activeViolations, ... }` | Audits code diff against IEC 62304 Class C hazards and 21 CFR Part 11 signatures. |
| `medtrace_remediate_safety_gap` | `{ hazardKey: string }` | `{ success, remediatedHazard, updatedStatus, message }` | Triggers simulated HIL test execution and re-certifies electronic signatures live on Atlassian Cloud. |

### 2. Atlassian Rovo Action Modules (`manifest.yml` / `src/mcp-server.ts`)

| Action Key | Action Verb | Handler Method | Inputs |
|---|---|---|---|
| `get-hazard-lineage-action` | `GET` | `McpToolService.getHazardLineage` | `{ issueKey?: string }` |
| `verify-iec-compliance-action` | `GET` | `McpToolService.verifyIecCompliance` | `{ prDiff?: string, componentName?: string }` |

---

## 2-Way Cloud Synchronization Architecture

`mcp-server/index.mjs` communicates with Atlassian Cloud via an authenticated HTTPS webtrigger (`mcp-sync-webtrigger` in `src/index.ts`):

```mermaid
sequenceDiagram
    participant IDE as Cursor / Claude Desktop
    participant MCP as Local MCP Server (mcp-server/index.mjs)
    participant Cloud as Forge Webtrigger (src/index.ts)
    participant KVS as @forge/kvs Persistence

    IDE->>MCP: tools/call (medtrace_get_hazard_lineage)
    MCP->>Cloud: GET /x1/... (HMAC authenticated)
    Cloud->>KVS: Read medtrace:compliance:active_suite
    KVS-->>Cloud: ComplianceSummary JSON
    Cloud-->>MCP: 200 OK (Live Cloud State)
    MCP-->>IDE: Tool result JSON

    Note over IDE,KVS: Autonomous Remediation Flow
    IDE->>MCP: tools/call (medtrace_remediate_safety_gap, HAZ-101)
    MCP->>Cloud: POST /x1/... { action: 'remediate', hazardKey: 'HAZ-101' }
    Cloud->>KVS: Update TEST-88 -> PASSED & Re-hash Confluence SRS-104
    KVS-->>Cloud: Updated ComplianceSummary
    Cloud-->>MCP: 200 OK ({ success: true, updatedStatus: 'VERIFIED' })
    MCP-->>IDE: Tool result: Release gate unlocked!
```

* **Configuration Parameters:**
  * **Webtrigger URL:** Set via environment variable `MEDTRACE_WEBTRIGGER_URL` (points to your deployed Forge `mcp-sync-webtrigger`).
  * **Shared Secret:** Set via environment variable `MEDTRACE_MCP_SECRET`. Mandatory in production; the webtrigger and MCP server fail closed if unset.
* **Offline Fallback Guarantee:** If the cloud webtrigger is unreachable (network drop or 4-second timeout), the MCP server automatically falls back to an internal mock suite, guaranteeing that developer workflows never crash during offline editing.

---

## Cryptographic Security & Anti-Replay Defense

The webtrigger endpoint in `src/index.ts` verifies incoming requests using `verifyHmacSignature()`:
1. **Shared Key Requirement (`x-medtrace-key`):** Enforced on all requests (`GET` and `POST`) to protect confidential clinical safety hazards and audit trails from unauthenticated scrapers.
2. **HMAC-SHA256 Payload Signature:** For state mutations (`POST`), the client signs `${timestamp}.${nonce}.${rawBody}` using the shared secret and passes `x-medtrace-signature: sha256=<hex>`.
3. **Anti-Replay Window (300 Seconds):** The server verifies `x-medtrace-timestamp`. If `Math.abs(Date.now() - reqTime) > 300_000`, the request is rejected with HTTP 401.
4. **Timing-Safe Digest Comparison:** Verifies signatures using `crypto.timingSafeEqual` over pre-computed digest buffers, preventing timing side-channel attacks.
5. **In-Window Nonce Replay Defense (`x-medtrace-nonce`):** Rejects replayed requests within the 300-second window using persistent Forge app storage (`storage:app`), halting duplicate invocations with HTTP 409 Conflict across ephemeral serverless containers.
6. **Header-Only Authentication:** Rejects credentials passed via URL query parameters (`query.token`) to prevent secrets from leaking into server logs, proxies, and browser histories.

Automated verification tests are maintained in `tests/compliance-engine.test.cjs`.

---

## IDE Setup (Cursor Configuration)

```json
{
  "mcpServers": {
    "medtrace": {
      "command": "node",
      "args": ["/absolute/path/to/medtrace/mcp-server/index.mjs"],
      "env": {
        "MEDTRACE_MCP_SECRET": "<your-forge-mcp-secret>",
        "MEDTRACE_WEBTRIGGER_URL": "https://<forge-app-id>.hello.atlassian-dev.net/x1/..."
      }
    }
  }
}
```

---

## Key Files

| Path | Role |
|---|---|
| `mcp-server/index.mjs` | Local stdio JSON-RPC MCP server with live cloud sync and offline fallback. |
| `src/mcp-server.ts` | Handlers for manifest-declared `rovo:mcp` tools and Rovo chat actions. |
| `src/nonce-store.ts` | NonceStore interface and `@forge/kvs` persistent store with lazy pruning. |
| `src/index.ts` | Webtrigger handler verifying HMAC signatures and executing mutations. |
| `tests/compliance-engine.test.cjs` | Unit tests for HMAC generation, timing safety, and replay window expiration. |

---

## Related

- [Forge Modules & Manifest Extensions](../01-architecture/forge-modules.md)
- [Compliance Evaluation Rules](../02-compliance-engine/evaluation-rules.md)
- [ADR 002: Webtrigger HMAC Authentication](../99-design-decisions/002-webtrigger-hmac-authentication.md)
- [How-To: Add an MCP Tool](../00-how-to/02-add-mcp-tool.md)
