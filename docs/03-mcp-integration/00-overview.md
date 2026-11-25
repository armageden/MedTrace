**Back:** [Repository Root](../../README.md)

# MCP Integration & Rovo Tools

Bridges local AI engineering assistants (via Model Context Protocol JSON-RPC 2.0 over `stdio`), Atlassian Rovo (`rovo:mcp` and `rovo:agent`), and CI release pipelines to the Forge compliance engine. Configured MCP/CI clients receive requested response data outside Atlassian; client retention is outside MedTrace's control.

## Atlassian-hosted MCP (`rovo:mcp`)

The `rovo:mcp` module exposes the Rovo actions below to remote MCP clients through Atlassian's hosted server at `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` (the UUID after `ari:cloud:ecosystem::app/` in `manifest.yml`). External exposure is off by default: a site or org admin enables it per installation under Atlassian Administration → Apps → Sites → site → Connected apps → MedTrace. Clients connect via OAuth 2.1 consent and tools run under the invoking user's permissions. See [rovo:mcp manifest reference](https://developer.atlassian.com/platform/forge/manifest-reference/modules/rovo-mcp/) and [Configure tools for an external MCP server](https://support.atlassian.com/organization-administration/docs/configure-tools-for-an-external-mcp-server/). The `mcp-server/` stdio bridge is a separate optional HMAC-webtrigger path.

## Files

- [live-sync.md](./live-sync.md) — MCP stdio server (`mcp-server/index.mjs` v1.1.0), Rovo actions (`src/mcp-server.ts`), HMAC-SHA256 webtrigger transport (`src/index.ts`), SHA-256 nonce replay store (`src/nonce-store.ts`), tool input/error contracts, and IDE client setup.
- [mcp-server/README.md](../../mcp-server/README.md) — Standalone quickstart for running the local MCP stdio bridge.

## Tool & Action Surface

| MCP Stdio Tool (`mcp-server/index.mjs`) | Rovo Action (`manifest.yml` / `src/mcp-server.ts`) | Webtrigger Method / Action (`src/index.ts`) | Inputs & Behavior |
|---|---|---|---|
| `medtrace_get_hazard_lineage` | `get-hazard-lineage-action` | `POST` (`action: "get-hazard-lineage"`) | Optional `hazardKey` or `issueKey`. Returns a reduced project summary or a matching lineage, not the raw full suite. Inside Forge runtime, matched lineages with `spec.pageId` also fetch `specOwners` + `teamworkGraphStatus` via Teamwork Graph `confluencePageOwners`. |
| `medtrace_verify_iec_compliance` | `verify-iec-compliance-action` | `POST` (`action: "verify"`) | Optional `prDiff`, `componentName`, `issueKey`. Computes multi-trigger BFS blast radius (`ComplianceEngine.computeMultiBlastRadius`). |
| `medtrace_remediate_safety_gap` | — | `POST` (`action: "remediate"`) | Required `hazardKey`, `simulate: true`, `attestationConfirmed: true`; optional `meaning`. Demo-only (HTTP `403` in `LIVE` mode). |
| — | — | `POST` (`action: "verify-release-gate"`) | Optional `issueKey`, `requireLiveMode` (`boolean`), `transitionToDone` (`boolean`). Enforces `ComplianceEngine.evaluateIssueReleaseGate` for CI release gates ([medtrace-release-gate.yml](../../.github/workflows/medtrace-release-gate.yml)). |
| — | — | `POST` (`action: "validate"` or `"simulate_transition"`) | Optional `issueKey`, `transitionName` (default `"Done"`). Invokes `workflowValidatorHandler` ([src/workflow-validator.ts](../../src/workflow-validator.ts)). |
| — | — | `GET` or `POST` (`action: "status"`) | Returns suite metadata without `traceLinks`. `POST action: "seed"` resets to `DEMO` (blocked with HTTP `403` when `datasetMode === 'LIVE'`). |

Automated tests covering these contracts live in [tests/mcp-server.test.mjs](../../tests/mcp-server.test.mjs) and [tests/workflow-validator-and-mcp.test.cjs](../../tests/workflow-validator-and-mcp.test.cjs).
