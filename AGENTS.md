# AGENTS.md

Single source of truth for any AI agent working in this repository. Read this file first.

## Project Snapshot

- **Stack:** TypeScript, Node.js (nodejs22.x Forge runtime), React 18, Vite, `@xyflow/react`, Atlassian Forge CLI v15
- **Package manager:** npm
- **Environment setup:** `npm install && cd static/frontend && npm install && cd ../..`
- **Run / dev:** `forge tunnel`
- **Verify:**
  - build: `npm run build && cd static/frontend && npm run build && cd ../..`
  - test: `npm test`
  - lint: `forge lint`
  - typecheck: `npx tsc --noEmit && cd static/frontend && npx tsc --noEmit && cd ../..`
  - docs: `npm run docs:check`

## Knowledge Base

Executing a common task? Start at [docs/00-how-to/](docs/00-how-to/00-overview.md).

| Folder | Covers | Read when |
|---|---|---|
| [docs/01-architecture/](docs/01-architecture/00-overview.md) | Forge manifest modules, endpoints, and permissions | modifying extension points or UI layout |
| [docs/02-compliance-engine/](docs/02-compliance-engine/00-overview.md) | IEC 62304, ISO 14971, and 21 CFR Part 11 rules | updating safety rules or audit state |
| [docs/03-mcp-integration/](docs/03-mcp-integration/00-overview.md) | Model Context Protocol stdio server and webtrigger sync | modifying MCP tools or IDE integration |
| [docs/99-design-decisions/](docs/99-design-decisions/00-overview.md) | Architecture Decision Records (ADRs) | reviewing storage and performance trade-offs |

## Working Rules

0. **Git is read-only.** Never run `git add`, `commit`, `push`, `stash`, `checkout`, `reset`, `branch`, `tag`, `rebase`, or `merge`. Read-only inspection only (`status`, `diff`, `log`, `show`, `ls-files`). User stages and commits manually.
1. **Docs stay in sync.** After ANY change to code, config, or scripts, run the docs-sync pass (`docs/00-how-to/sync-docs-runbook.md`) and end your response with:
   `Docs checked/updated: <files or "none required (reason)">`.
2. **Verify before claiming.** Run verification commands (`npm run build`, `forge lint`, `npm run docs:check`) after changes; never report success without output.
3. **Zero hallucination.** Read a file before citing its path, symbol, flag, or behavior.
4. **In place.** Upgrade existing files instead of creating parallel trees.
5. **Preserve production manifests.** Keep `manifest.yml` clean and synchronized across both `jira` and `confluence` contexts.
