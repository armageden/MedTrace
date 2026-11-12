**Back:** [00-overview](./00-overview.md)

# ADR 003: Teamwork Graph Dual-Engine Architecture (AGG GraphQL and REST API v3)

## Context
The Atlassian Teamwork Graph (TWG) via the Atlassian GraphQL Gateway (AGG) is currently in Developer Preview. During hackathon judging and multi-tenant testing, tenant configurations, permissions, or transient gateway issues can result in GraphQL errors or schema drift. Crashing during graph evaluation would fail the entire compliance scan.

## Decision
Implement a dual-engine architecture in `src/teamwork-graph.ts`:
1. First attempt native AGG GraphQL queries (`api.asApp().requestGraph()`) to retrieve cross-product graph context and node links.
2. Check both HTTP status and GraphQL errors (`json.errors`). If errors occur, catch and log the notice.
3. Automatically fall back to standard Jira Cloud REST API v3 endpoints (`/rest/api/3/issue/...`) to fetch issue metadata and issue links.

## Alternatives Considered
* **Fail-Hard on GraphQL Errors:** Rejected because transient gateway outages or unlinked sandbox projects would completely disable the compliance view for hospital release teams.
* **Pure Jira REST API v3 Only:** Rejected because REST cannot query cross-product Confluence link graphs or register custom ISO 14971 entity ARIs in the Atlassian Teamwork Graph.

## Consequences
- Guaranteed zero runtime crashes when querying graph context across diverse Atlassian tenant environments.
- Fully exercises the modern Teamwork Graph GraphQL API while maintaining robust fallback reliability.
- Seamlessly surfaces Atlassian Resource Identifiers (ARIs) in the Custom UI drawer (`static/frontend/src/components/InspectionDrawer.tsx`).

## Key Files

| Path | Role |
|---|---|
| `src/teamwork-graph.ts` | Teamwork Graph AGG GraphQL query runner with REST fallback. |
| `src/types.ts` | Type definitions for `GraphMetadata` (AGG context is returned as raw GraphQL data, REST JSON, or `null`). |
| `static/frontend/src/components/InspectionDrawer.tsx` | UI component displaying graph entity details. |

## Related

- [ADR 001: TWG & KVS Hybrid Architecture](./001-twg-and-kvs-hybrid.md)
- [Forge Modules & Manifest Extensions](../01-architecture/forge-modules.md)
