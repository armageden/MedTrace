# MedTrace MCP Stdio Server

Standalone Model Context Protocol (`stdio`, JSON-RPC 2.0) bridge (`SERVER_VERSION = 1.1.0`) connecting local AI coding assistants (Cursor, Claude Desktop, VS Code, Windsurf) to your Atlassian Forge MedTrace instance.

Zero compliance state is persisted locally. All requests are HMAC-SHA256 signed, nonce-protected, and forwarded over HTTPS to the deployed `mcp-sync-webtrigger`.

## Configuration

Set the following environment variables in `.env` (checked in `process.cwd()` first, then the repository root):

```bash
MEDTRACE_WEBTRIGGER_URL="https://..." # Output of `forge webtrigger -f mcp-sync-webtrigger`
MEDTRACE_MCP_SECRET="..."             # Must match `forge variables set MEDTRACE_MCP_SECRET --encrypt`
```

Both variables are required; the server fails closed if `MEDTRACE_MCP_SECRET` is unset.

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

## Available Tools

- `medtrace_get_hazard_lineage`: Query the 5-stage trace chain (`HAZARD <-> SPEC <-> WORK <-> TEST <-> SIGNATURE`) by `hazardKey` or `issueKey`. Returns `found: false` with `availableKeys` when no link matches.
- `medtrace_verify_iec_compliance`: Analyze a `prDiff` against active suite tokens, dynamic component tokens, and safety keywords to compute 5-stage blast radius and release readiness.
- `medtrace_remediate_safety_gap`: Demo-only simulated remediation (`DEMO` dataset only). Requires `hazardKey`, `simulate: true`, and `attestationConfirmed: true`; attributes audit entries to `service:mcp-webtrigger`.

For protocol details, nonce replay defense, and HTTP error handling, see [docs/03-mcp-integration/live-sync.md](../docs/03-mcp-integration/live-sync.md).
