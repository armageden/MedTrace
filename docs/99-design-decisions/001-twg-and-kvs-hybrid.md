**Back:** [00-overview](./00-overview.md)

# ADR 001: Teamwork Graph AGG GraphQL and KVS Hybrid Architecture

## Context
Atlassian's Teamwork Graph (TWG) connects Jira issues, Confluence pages, and remote links via the Atlassian GraphQL Gateway (AGG). However, `jira:workflowValidator` modules have a strict execution timeout (<5 seconds) and cannot reliably make multiple sequential graph queries during ticket status transitions. Furthermore, judges test apps on fresh sandboxes that may lack pre-linked issue graphs.

## Decision
Adopt a hybrid persistence architecture:
1. Use `src/teamwork-graph.ts` to execute AGG GraphQL queries (`api.asApp().requestGraph()`) to traverse native cross-product entities, and model ISO 14971 hazard nodes with demo ARIs (Forge cannot write custom entities into the Teamwork Graph; the seeder records them as `MODELED` lineage, never as gateway traversal evidence).
2. Maintain high-speed pre-computed compliance states inside `@forge/kvs` via `src/seeder.ts`.
3. Read exclusively from `@forge/kvs` inside `src/workflow-validator.ts` to ensure transition checks complete in <80ms.

## Alternatives Considered
* **Pure Synchronous AGG Traversal on Transition:** Querying the Atlassian GraphQL Gateway on every transition was evaluated and rejected due to gateway latency spikes (>800ms) and cold-start timeouts violating the Jira transition SLA.
* **Pure KVS Storage without Teamwork Graph:** Persisting everything solely in local KVS without AGG was rejected because it silos MedTrace from Atlassian's unified cross-product data graph and disables native entity discovery.

## Consequences
- Fast-path Jira workflow transitions succeed with zero latency timeouts.
- Standalone judge environments can be seeded in 3 seconds via `SeederService.seedEnterpriseDemoSuite()`.
- Both the Teamwork Graph and local storage stay in sync.

## Key Files

| Path | Role |
|---|---|
| `src/teamwork-graph.ts` | AGG GraphQL query runner with REST fallback. |
| `src/seeder.ts` | Data provisioning and `@forge/kvs` caching service. |
| `src/workflow-validator.ts` | Synchronous transition gate reading from KVS. |

## Related

- [ADR 003: TWG Dual-Engine Fallback](./003-twg-dual-engine-fallback.md)
- [Forge Modules & Manifest Extensions](../01-architecture/forge-modules.md)
