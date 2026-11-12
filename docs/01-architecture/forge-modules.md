**Back:** [00-overview](./00-overview.md)

# Forge Modules & Extension Points

The application is declared in `manifest.yml` and targets Jira Cloud and Confluence Cloud using the `nodejs22.x` Forge runtime.

## Manifest Extension Modules

| Module Key | Manifest Type | Resource / Binding | Description |
|---|---|---|---|
| `medtrace-matrix-page` | `jira:projectPage` | `resource: main`<br/>`resolver: resolver-fn` | Primary Custom UI interactive lineage graph and trace matrix table (`static/frontend/src/App.tsx`). |
| `medtrace-issue-panel` | `jira:issuePanel` | `resource: main`<br/>`resolver: resolver-fn` | Jira Issue context panel displaying active regulatory safety badges and detailed inspection drawer. |
| `medtrace-safety-validator` | `jira:workflowValidator` | `function: workflow-validator-fn` | Physical transition gate blocking Jira releases when `suite.releaseBlocked === true`. |
| `medtrace-regulatory-auditor` | `rovo:agent` | `actions: [get-hazard-lineage-action, verify-iec-compliance-action]` | AI compliance officer enforcing IEC 62304 and ISO 14971 risk mitigations in Jira and Confluence. Combined, the two actions declare optional `inputs` schemas (`issueKey` on lineage; `issueKey`, `prDiff`, `componentName` on compliance) and dispatch on `context.moduleKey` per the Forge `rovo:action` payload contract. |
| `medtrace-mcp-server` | `rovo:mcp` | `tools: [get-hazard-lineage-action, verify-iec-compliance-action]` | Exposes compliance actions as native Model Context Protocol tools. |
| `mcp-sync-webtrigger` | `webtrigger` | `function: mcp-webtrigger-fn` | Authenticated public HTTP endpoint providing state synchronization with local IDE MCP clients. |

## Function Handlers & Entry Points

Declared under `function:` in `manifest.yml`:

| Function Key | Entry Handler | Implementation File | Role |
|---|---|---|---|
| `resolver-fn` | `index.resolverHandler` | `src/index.ts` | Bridge IPC handler dispatching Custom UI RPC methods. |
| `workflow-validator-fn` | `index.workflowValidatorHandler` | `src/workflow-validator.ts` | Synchronous transition validator executing fail-closed gate checks in <80ms. |
| `rovo-action-fn` | `index.rovoActionHandler` | `src/mcp-server.ts` | Invokes `McpToolService` to handle Rovo and Forge MCP tool requests. |
| `mcp-webtrigger-fn` | `index.mcpWebtriggerHandler` | `src/index.ts` | Authenticates HMAC-SHA256 signatures and processes external MCP sync requests. |

## Custom UI Resolver RPC Contracts (`src/index.ts`)

The Custom UI frontend (`static/frontend`) communicates with the backend via `@forge/bridge` using seven registered resolver methods:

| Method Name | Payload | Return Type | Purpose |
|---|---|---|---|
| `getComplianceSuite` | *None* | `ComplianceSummary` | Fetches active compliance suite from `@forge/kvs` (auto-seeds if uninitialized). |
| `seedDemoSuite` | *None* | `{ success, confluenceEnabled, summary, message }` | Provisions realistic Smart Infusion Pump hazards, specs, tasks, and tests. |
| `remediateGap` | `{ hazardKey?: string }` | `ComplianceSummary` | Simulates HIL test execution and re-certifies 21 CFR Part 11 signatures. |
| `queryGraphContext` | `{ issueKey?: string }` | Raw AGG GraphQL `data`, Jira REST issue JSON, or `null` | Traverses Teamwork Graph via AGG GraphQL with Jira REST fallback. |
| `bindIssueToHazard` | `{ hazardKey, issueKey? }` | `{ success, summary?, error? }` | Binds a real Jira issue key to a hazard trace link (makes the safety gate real). |
| `simulateTransition` | *None* | `{ result, errorMessage? }` | Directly evaluates the Jira workflow validator gate logic from the UI. |
| `analyzeBlastRadius` | `{ triggerKey?: string }` | `BlastRadiusReport` | Runs the deterministic BFS blast-radius traversal (powers the hero Blast Radius button). |

## Inbound Webtrigger & Security Architecture

The `mcp-sync-webtrigger` provides an HTTPS ingress point for local developer environments (Cursor / Claude Desktop):
* **Inbound Protocol:** Accepts `GET` (returns active `ComplianceSummary`) and `POST` with JSON actions: `seed`, `remediate`, `validate` / `simulate_transition` (HTTP 200 with the validator outcome in the body), and `verify-release-gate` (CI enforcement — **HTTP 200 when the gate is open, HTTP 403 when blocked**, so pipelines can gate on the status code alone).
* **Timing-Safe HMAC-SHA256 Authentication:** Incoming requests must provide `x-medtrace-timestamp`, `x-medtrace-nonce` (required), and `x-medtrace-signature: sha256=<hex>`. The signature binds `${timestamp}.${nonce}.${rawBody}` and is verified using `crypto.timingSafeEqual`.
* **Anti-Replay Window:** Enforces a 300-second maximum replay threshold (`Math.abs(Date.now() - timestamp) <= 300_000`).
* **Tenant Isolation Guarantee:** Outbound external network permissions (`permissions.external.fetch.backend`) are **completely omitted**. The Forge runtime makes zero outbound requests to external services; communication is strictly inbound request-response.

## Scopes & Permissions

| Permission / Directive | Manifest Declaration | Purpose & Justification |
|---|---|---|
| **Jira Issue Access** | `read:jira-work`, `read:jira-user` | Reading work items and traversing issue links (all Jira calls are reads; the transition gate evaluates state, it never writes). |
| **Confluence Page Access** | `read:page:confluence`, `read:space:confluence` | Reading SRS requirement pages and verifying SHA-256 hashes (no page writes). |
| **Persistence** | `storage:app` | Persisting compliance summaries and audit trail in `@forge/kvs`. |
| **Content Security Policy** | `permissions.content.styles: ['unsafe-inline']` | Required by `@xyflow/react` for SVG styling and animated node connections. |
| **Network Egress** | *Omitted (`fetch:backend` disabled)* | Guarantees zero clinical data egress to external servers. |

## Key Files

| Path | Role |
|---|---|
| `manifest.yml` | Top-level Atlassian Forge app manifest declaring modules, functions, and scopes. |
| `src/index.ts` | Main entry point defining resolver, validator, and webtrigger handlers. |
| `src/workflow-validator.ts` | Fail-closed Jira workflow validator implementation. |
| `src/mcp-server.ts` | Rovo action handler and Model Context Protocol service logic. |
| `static/frontend/dist` | Static bundle directory for Custom UI React application (`resource: main`). |

## Related

- [Evaluation Rules in Compliance Engine](../02-compliance-engine/evaluation-rules.md)
- [Live MCP Sync Architecture](../03-mcp-integration/live-sync.md)
- [ADR 002: Webtrigger HMAC Authentication](../99-design-decisions/002-webtrigger-hmac-authentication.md)
