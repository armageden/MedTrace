**Back:** [00-overview](./00-overview.md)

# Docs Sync Runbook

This runbook defines the mandatory post-task documentation synchronization procedure. Whenever code, configuration, or scripts change, follow these 6 steps in order.

## Source-to-Docs Mapping Table

| Modified Source Path | Mapped Reference Doc Folder |
|---|---|
| `manifest.yml` | `docs/01-architecture/` |
| `src/index.ts` | `docs/01-architecture/` |
| `src/types.ts` | `docs/02-compliance-engine/` |
| `src/compliance-engine.ts` | `docs/02-compliance-engine/` |
| `src/seeder.ts` | `docs/02-compliance-engine/` |
| `src/workflow-validator.ts` | `docs/01-architecture/` |
| `src/teamwork-graph.ts` | `docs/99-design-decisions/` |
| `src/mcp-server.ts` | `docs/03-mcp-integration/` |
| `mcp-server/index.mjs` | `docs/03-mcp-integration/` |
| `static/frontend/src/` | `docs/01-architecture/` |

## Six-Step Execution Procedure

1. **Inspect Working Tree (Read-only):**
   ```bash
   git status
   git diff
   ```
2. **Identify Impacted Docs:** Match each changed file against the mapping table above.
3. **Update Affected Reference Docs:** Update paths, symbols, functions, and behavioral contracts.
4. **Reverse Coverage Check:** Ensure any new entry point, tool, or module is cited in at least one doc.
5. **ADR-lite Check:** If an architectural change occurred, record an ADR entry under `docs/99-design-decisions/`.
6. **Run Mechanical Validator:**
   ```bash
   node scripts/docs-check.mjs
   ```
   Must exit with status `0`.

## Key Files

| Path | Role |
|---|---|
| `scripts/docs-check.mjs` | Zero-dependency documentation validator enforcing links, backticks, and coverage. |
| `AGENTS.md` | Top-level agent router directing LLMs to relevant doc domains. |

## Related

- [Repository Root Overview](../../README.md)
- [How-To: Deploy Production](./03-deploy-production.md)
