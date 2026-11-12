# MCP Integration & Rovo Tools

Bridges local AI engineering assistants (via Model Context Protocol over `stdio`), Rovo Studio (`rovo:mcp`), and CI release pipelines directly to the Forge compliance engine without storing compliance data outside Atlassian Cloud.

## Files

- [live-sync.md](./live-sync.md) — MCP stdio server (`mcp-server/index.mjs` v1.1.0), Rovo actions (`src/mcp-server.ts`), HMAC-SHA256 webtrigger transport, SHA-256 nonce replay store (`src/nonce-store.ts`), tool input/error contracts, and IDE client setup.
- [mcp-server/README.md](../../mcp-server/README.md) — Standalone quickstart for running the local MCP stdio bridge.
