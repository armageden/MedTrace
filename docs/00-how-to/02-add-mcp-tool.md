**Back:** [00-overview](./00-overview.md)

# How-To: Add a Model Context Protocol (MCP) Tool

## Goal
Expose a new compliance tool so external coding agents (Cursor, Claude Desktop, VS Code) and Atlassian Rovo can execute it securely.

## Steps

1. **Declare Manifest Action (for Rovo):**
   Open [manifest.yml](../../manifest.yml) and add the action to `modules.action`:
   ```yaml
   action:
     - key: custom-audit-action
       name: Custom Audit Action
       description: Performs targeted verification checks.
       actionVerb: GET
       function: rovo-action-fn
       inputs:
         hazardKey:
           title: Hazard Key
           type: string
           required: false
           description: Optional hazard key to inspect.
   ```
   Also add `custom-audit-action` to `rovo:mcp` (`tools:`) and, if appropriate, `rovo:agent` (`actions:`) in [manifest.yml](../../manifest.yml).

2. **Implement Rovo & Service Handler ([src/mcp-server.ts](../../src/mcp-server.ts)):**
   - Add the new tool method on `McpToolService`.
   - Allowlist the action key in `ALLOWED_ROVO_ACTIONS` and dispatch it inside `rovoActionHandler()` (which executes `assertRovoUserReadAccess()` when `isForgeRuntime() && accountId` and returns sanitized error payloads).

3. **Expose Webtrigger Route if Called from Local Stdio MCP ([src/index.ts](../../src/index.ts)):**
   - Add any new `POST` action name to `ALLOWED_WEBTRIGGER_POST_ACTIONS` and the `switch (action)` block inside `mcpWebtriggerHandler()`.
   - Keep `LIVE`-mode protections intact (mutating demo helpers must return HTTP `403` when `datasetMode === 'LIVE'`).

4. **Implement Tool Handler in Local MCP Stdio Server ([mcp-server/index.mjs](../../mcp-server/index.mjs)):**
   - Register the tool metadata in `TOOLS` (omit optional fields from `required`).
   - Handle execution inside `handleMessage()` under `method === 'tools/call'`, validating inputs locally with JSON-RPC `-32602` when invalid, calling `signedCloudRequest()`, surfacing errors with `cloudErrorResult()`, and labeling `source` with `formatSourceLabel()`.

5. **Verify Syntax, Contracts, Manifest & Stdio Behavior:**
   Bare `node mcp-server/index.mjs` fails closed (exits `1`) unless `MEDTRACE_MCP_SECRET` and a valid `MEDTRACE_WEBTRIGGER_URL` are present. Verify with:
   ```bash
   node --check mcp-server/index.mjs
   npm run typecheck
   npm run build:all
   npm run test:mcp
   npm run test:backend
   npm run lint:manifest
   npm run docs:check
   ```
   To smoke-test over stdio with `.env` configured (or `MEDTRACE_ALLOW_INSECURE_LOCALHOST=true` for a local stub), pipe NDJSON `initialize`, `ping`, and "tools/list" requests into `node mcp-server/index.mjs`.

## Key Files

| Path | Role |
|---|---|
| `manifest.yml` | Declares `action`, `rovo:mcp`, `rovo:agent`, `webtrigger`, and `function` bindings. |
| `mcp-server/index.mjs` | Local JSON-RPC 2.0 NDJSON stdio server (`createLineProcessor`, `handleMessage`, `signedCloudRequest`). |
| `src/mcp-server.ts` | `McpToolService` compliance helpers and `rovoActionHandler` dispatch. |
| `src/index.ts` | `mcpWebtriggerHandler` HMAC-SHA256 verification, replay window, and `ALLOWED_WEBTRIGGER_POST_ACTIONS`. |
| `tests/mcp-server.test.mjs` | Authenticated stdio E2E and JSON-RPC protocol tests. |
| `tests/workflow-validator-and-mcp.test.cjs` | Unit tests for `McpToolService`, `rovoActionHandler`, and `workflowValidatorHandler`. |

## Related

- [Live MCP Sync Architecture](../03-mcp-integration/live-sync.md)
- [Local MCP Server Quickstart](../../mcp-server/README.md)
- [ADR 002: Webtrigger HMAC Authentication](../99-design-decisions/002-webtrigger-hmac-authentication.md)
- [How-To: Deploy to Production](./03-deploy-production.md)
