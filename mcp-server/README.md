# MedTrace MCP Server (Local Stdio)

Standalone Model Context Protocol server (`index.mjs`) that connects local AI coding
environments (Cursor, Claude Desktop, and other MCP clients) to the live MedTrace
compliance state running on Atlassian Forge.

The server speaks JSON-RPC 2.0 over stdio and signs every mutating request to the Forge
webtrigger with HMAC-SHA256.

---

## Tools

| Tool | Input | Effect |
|---|---|---|
| `medtrace_get_hazard_lineage` | `{ hazardKey?: string }` | Returns the 5-stage traceability chain for one hazard/issue/test, or the full project lineage. Read-only. |
| `medtrace_verify_iec_compliance` | `{ prDiff?: string, componentName?: string, issueKey?: string }` | Flags affected hazards via keyword matching against the live compliance state (full blast-radius traversal runs on the Forge backend via the Rovo action / `analyzeBlastRadius` resolver). Read-only. |
| `medtrace_remediate_safety_gap` | `{ hazardKey: string }` (required) | Marks the verification test PASSED and re-certifies the Part 11 signature **on the live Forge backend**. Mutating. |

**Honesty guarantees:** every tool reports its true data source. If the cloud fetch fails,
tools answer `UNAVAILABLE` and never fabricate compliance state or
remediation success.

---

## Configuration

| Environment variable | Required | Purpose |
|---|---|---|
| `MEDTRACE_MCP_SECRET` | Yes (fail-closed — the server refuses to start without it) | Shared HMAC/perimeter secret. Must match the Forge app environment value. |
| `MEDTRACE_WEBTRIGGER_URL` | Yes for live sync | Deployed Forge webtrigger URL (`forge webtrigger list`). |

## Adding to Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "medtrace": {
      "command": "node",
      "args": ["/absolute/path/to/medtrace/mcp-server/index.mjs"],
      "env": {
        "MEDTRACE_MCP_SECRET": "<your-mcp-secret>",
        "MEDTRACE_WEBTRIGGER_URL": "https://<forge-app-id>.hello.atlassian-dev.net/x1/<webtrigger-path>"
      }
    }
  }
}
```

## Adding to Claude Desktop (`claude_desktop_config.json`)

Same shape as Cursor under `mcpServers`.

---

## Wire protocol

* `x-medtrace-timestamp`: epoch milliseconds; requests outside a **300-second** window are rejected.
* `x-medtrace-nonce`: unique per request; consumed nonces are rejected (HTTP 409) via Forge KVS.
* `x-medtrace-signature`: `sha256=` hex HMAC-SHA256 over `${timestamp}.${nonce}.${rawBody}`,
  verified with `crypto.timingSafeEqual`.

## Example prompt for Cursor

> *"I am editing `dose_calc.py` to change the bolus rate to 5.5 mL/hr. Does this touch any
> IEC 62304 Class C hazard in Jira, and what tests are required?"*
