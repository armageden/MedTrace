**Back:** [Repository Root](../../README.md)

# How-To Recipes Overview

**Covers:** `docs/00-how-to/`  
**Read this when:** executing common modification, operational deployment, CI/release verification, or documentation synchronization workflows.

Diátaxis-style operational guides and runbooks providing copy-pasteable execution procedures for MedTrace engineering and DevOps tasks.

## Contents

| File | Description |
|---|---|
| [01-add-iso-hazard.md](./01-add-iso-hazard.md) | How to define a new ISO 14971 clinical hazard and attach IEC 62304 verification. |
| [02-add-mcp-tool.md](./02-add-mcp-tool.md) | How to expose a new Model Context Protocol tool to local IDEs and Atlassian Rovo. |
| [03-deploy-production.md](./03-deploy-production.md) | How to deploy MedTrace, provision encrypted secrets, enforce CI gates (`ECO-624`), and run pre-Marketplace listing checks. |
| [sync-docs-runbook.md](./sync-docs-runbook.md) | Mandatory post-task documentation synchronization checklist and repository file inventory. |

## Standard Verification Scripts ([package.json](../../package.json))

```bash
npm run typecheck       # Backend + frontend TypeScript typecheck
npm run build:all       # Backend tsc + frontend Vite production build
npm run test:all        # pretest build + backend/MCP/script tests + frontend Vitest suite
npm run test:backend    # Backend unit/integration tests (tests/*.test.cjs)
npm run test:mcp        # Local MCP stdio server tests (tests/mcp-server.test.mjs)
npm run test:scripts    # Docs-check & rotation script tests (tests/scripts.test.mjs)
npm run test:frontend   # React Testing Library / Vitest suite (static/frontend)
npm run lint:manifest   # Offline @forge/manifest validation + dist/index.js export checks
npm run docs:check      # Mechanical links, headings, backtick paths, and reverse-coverage check
node scripts/docs-check.mjs --strict-listing  # Pre-Marketplace gate failing on [CONFIGURE BEFORE LISTING]
```
