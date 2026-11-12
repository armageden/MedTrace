# Architecture

MedTrace runs inside the Atlassian Forge `nodejs22.x` runtime with zero outbound network egress. Every data lookup, compliance evaluation, sharded storage mutation, hash-chained audit entry, and Rovo/MCP interaction executes within Atlassian Cloud using Forge storage, Jira/Confluence REST APIs, and the Atlassian Graph Gateway (AGG).

## Files

- [forge-modules.md](./forge-modules.md) — Forge manifest (`manifest.yml`) Jira & Confluence extension points, event triggers, RBAC, 12 Custom UI resolvers, Rovo actions, webtrigger hardening, and egress-free permission boundaries.

## Source Entrypoints

- [src/index.ts](../../src/index.ts) — Forge resolver definitions, `assertAuthorizedOperator` RBAC gate, webtrigger handler, and exported module functions (`resolver-fn`, `workflow-validator-fn`, `rovo-action-fn`, `webtrigger-fn`, `confluence-trigger-fn`).
- [src/runtime.ts](../../src/runtime.ts) — `isForgeRuntime()` marker helper distinguishing Forge invocation from local Node.js test/CLI execution.
- [src/teamwork-graph.ts](../../src/teamwork-graph.ts) — `TeamworkGraphService` dual-engine `AGG` + `JIRA_REST` context and Confluence `remotelink` resolver.
- [src/ingestion.ts](../../src/ingestion.ts) — `LiveIngestionService` live Jira/Confluence ingestion and Confluence page-update drift handling.
- [src/audit-log.ts](../../src/audit-log.ts) — `AuditLogService` SHA-256 hash-chained immutable audit ledger.
- [static/frontend/src/App.tsx](../../static/frontend/src/App.tsx) — Custom UI entry shell adapting to Jira and Confluence `view.getContext()` contexts.
- [static/frontend/src/bridge.ts](../../static/frontend/src/bridge.ts) — Typed `@forge/bridge` `invokeResolver` wrapper.
- [static/frontend/src/components/AuditLogModal.tsx](../../static/frontend/src/components/AuditLogModal.tsx) — Audit trail and chain verification modal (`getAuditLog` / `verifyAuditChain`).
- [static/frontend/src/components/FdaExportModal.tsx](../../static/frontend/src/components/FdaExportModal.tsx) — FDA submission dossier export modal (JSON, CSV, and `#fda-export-printable` print view).
