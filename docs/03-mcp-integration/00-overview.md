**Back:** [Repository Root](../../README.md)

# Model Context Protocol (MCP) Integration Overview

**Covers:** `mcp-server/index.mjs`, `src/mcp-server.ts`, `manifest.yml`  
**Read this when:** configuring or testing the Model Context Protocol tools for Cursor, Claude Desktop, or Atlassian Rovo.

MedTrace provides dual Model Context Protocol (MCP) integration:
1. **Local Developer Stdio MCP Server (`mcp-server/index.mjs`):** A standalone, zero-dependency Node.js JSON-RPC server enabling AI coding assistants (Cursor, Claude Desktop) to audit code changes and trigger remediation right from the IDE.
2. **Cloud-Native Atlassian Rovo MCP (`rovo:mcp`):** Manifest-declared tool modules enabling Rovo Chat agents within Jira and Confluence to inspect regulatory lineage and verify IEC 62304 compliance.

## Contents

| File | Description |
|---|---|
| [live-sync.md](./live-sync.md) | Tool schemas, JSON-RPC stdio protocol, HMAC-SHA256 cloud synchronization, and offline fallback. |
