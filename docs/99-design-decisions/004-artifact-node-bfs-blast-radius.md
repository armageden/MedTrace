**Back:** [00-overview](./00-overview.md)

# ADR 004: Artifact-Node BFS for Blast Radius Traversal

## Context
The original `computeBlastRadius` implementation filtered trace links matching the trigger key and walked each matching link's fixed 4-hop chain. That meant "BFS graph traversal" overstated the behavior: a spec drift never propagated *transitively* into sibling links that share only a hazard node (e.g., two SRS requirements mitigating the same hazard), and the 500-node benchmark measured an O(n) filter rather than graph traversal.

## Decision
Rebuild `ComplianceEngine.computeBlastRadius` (`src/compliance-engine.ts`) as a real breadth-first traversal:
1. Index every trace link under five artifact-node keys (`spec:`, `haz:`, `work:`, `test:`, `sig:`) in a `nodeKey -> links[]` adjacency map.
2. Seed the FIFO queue with the trigger-matching links; process links in order, emitting per-link hops in the fixed `SIGNS -> MITIGATES -> IMPLEMENTS -> VERIFIES` sequence (skipping already-visited nodes/relations).
3. After processing a link, enqueue every sibling link that shares any of its artifact nodes, so drift propagates transitively across shared hazards, specs, work items, tests, and signatures.
4. Keep visited node/relation sets as the cycle guard, preserving deterministic termination on circular trace links.

## Alternatives Considered
* **Keep the per-link fixed walk and reword the docs:** Rejected — the transitive case (one hazard mitigated by multiple specs) is exactly the regulatory scenario blast radius exists for, and it costs ~40 lines.
* **Adjacency list of typed edges only (no link-level expansion):** Rejected — hop semantics (`SIGNS`, `MITIGATES`, `IMPLEMENTS`, `VERIFIES`) and effect strings are properties of the link that owns the edge; expanding link-by-link preserves deterministic hop ordering and keeps the existing report contract stable for all consumers (`src/index.ts`, `src/mcp-server.ts`, Custom UI).

## Consequences
- Drift on one spec now invalidates sibling requirements, tasks, and tests that share a hazard node — previously invisible.
- Existing report consumers are unchanged; the seeded single-link case emits the identical 4-hop cascade as before.
- Performance: the 500-node synthetic benchmark remains under the test-enforced 20ms ceiling (adjacency build is O(n)).
- Behavior covered by new tests: transitive sibling propagation, plus all pre-existing cascade, multi-signature, disconnected-node, and circular-link cases.

## Key Files

| Path | Role |
|---|---|
| `src/compliance-engine.ts` | `computeBlastRadius` BFS implementation and node-key adjacency. |
| `tests/compliance-engine.test.cjs` | Traversal, cycle-safety, disconnected-node, and 500-node benchmark assertions. |
| `src/index.ts`, `src/mcp-server.ts` | Unchanged consumers (resolver and Rovo/MCP tool). |

## Related

- [ADR 001: TWG + KVS Hybrid](./001-twg-and-kvs-hybrid.md)
- [Evaluation Rules](../02-compliance-engine/evaluation-rules.md)
