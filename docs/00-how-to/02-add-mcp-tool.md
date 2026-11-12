**Back:** [00-overview](./00-overview.md)

# How-To: Add a Model Context Protocol (MCP) Tool

## Goal
Expose a new compliance tool so external coding agents (Cursor, Claude Desktop) and Atlassian Rovo can execute it.

## Steps

1. **Declare Manifest Action:**
   Open `manifest.yml` and add the action to the `action:` section:
   ```yaml
   action:
     - key: custom-audit-action
       name: Custom Audit Action
       description: Performs targeted verification checks.
       actionVerb: GET
       function: rovo-action-fn
   ```

2. **Add to `rovo:mcp` Tools Array:**
   In `manifest.yml`, add `custom-audit-action` to the `tools` list under `rovo:mcp`.

3. **Implement Tool Handler in MCP Server:**
   Open `mcp-server/index.mjs` and register the tool in the `TOOLS` array:
   ```javascript
   {
     name: 'medtrace_custom_audit',
     description: 'Performs targeted verification checks.',
     inputSchema: { type: 'object', properties: {} }
   }
   ```
   Handle execution in `handleMessage()` under `method === 'tools/call'`.

4. **Verify Tool via Stdio:**
   Run:
   ```bash
   node mcp-server/index.mjs
   ```

## Key Files

| Path | Role |
|---|---|
| `manifest.yml` | Declares `action:` and `rovo:mcp` tool bindings. |
| `mcp-server/index.mjs` | Local stdio JSON-RPC MCP server. |
| `src/mcp-server.ts` | Handlers for Rovo chat actions and Forge MCP invocations. |

## Related

- [Live MCP Sync Architecture](../03-mcp-integration/live-sync.md)
- [ADR 002: Webtrigger HMAC Authentication](../99-design-decisions/002-webtrigger-hmac-authentication.md)
