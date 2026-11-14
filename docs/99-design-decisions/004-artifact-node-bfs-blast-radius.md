**Back:** [00-overview](./00-overview.md)

# ADR 004: Artifact-Node BFS for Blast Radius Traversal

## Context
The original `computeBlastRadius` implementation filtered trace links matching the trigger key and walked each matching link's fixed 4-hop chain. That meant "BFS graph traversal" overstated the behavior: a spec drift never propagated *transitively* into sibling links that share only a hazard node (e.g., two SRS requirements mitigating the same hazard), and the 500-node benchmark measured an O(n) filter rather than graph traversal.

## Decision
Rebuild `ComplianceEngine.computeBlastRadius` and `computeMultiBlastRadius` ([src/compliance-engine.ts](../../src/compliance-engine.ts)) as a real component breadth-first traversal:
1. **Empty Trigger & Spec-Key Guards:** Empty/whitespace trigger keys return immediately (`No Trigger Artifact Specified`, `impactedCount: 0`); `matchesLinkByKey` applies `/^[a-z]{2,10}-\d+$/i` to `specShortKey` matching so prose words never collide with short spec tokens.
2. **Artifact-Node Adjacency Index:** Index every trace link under five artifact-node keys (`spec:`, `haz:`, `work:`, `test:`, `sig:`) in a `nodeKey -> links[]` adjacency map.
3. **BFS & Fixed Edge Vocabulary:** Seed the FIFO queue with trigger-matching links; process links in order, emitting per-link hops in the fixed `SIGNS -> MITIGATES -> IMPLEMENTS -> VERIFIES` sequence (including clean `SIGNS` hops accurately while skipping already-visited nodes/relations).
4. **Transitive Component Traversal with Drift Isolation:** Enqueue sibling links sharing artifact nodes within the connected component while isolating drift effects per hazard and per spec so unrelated links sharing a `work.key` are not falsely marked drifted.
5. **Cycle Guard:** Visited node and relation sets guarantee deterministic termination on circular trace links.

## Alternatives Considered
* **Keep the per-link fixed walk and reword the docs:** Rejected — the transitive case (one hazard mitigated by multiple specs) is exactly the regulatory scenario blast radius exists for, and it costs ~40 lines.
* **Adjacency list of typed edges only (no link-level expansion):** Rejected — hop semantics (`SIGNS`, `MITIGATES`, `IMPLEMENTS`, `VERIFIES`) and effect strings are properties of the link that owns the edge; expanding link-by-link preserves deterministic hop ordering and keeps the existing report contract stable for all consumers (`src/index.ts`, `src/mcp-server.ts`, Custom UI).

## Consequences
- Drift on one spec invalidates sibling requirements, tasks, and tests connected through shared hazard/spec components without tainting unrelated requirements on shared Jira work keys.
- `computeMultiBlastRadius` supports multi-artifact queries from diff/Rovo analysis cleanly.
- Performance: the 500-node synthetic benchmark stays under the test-enforced 20ms ceiling (adjacency build is O(n)).
- Behavior covered in [tests/compliance-engine.test.cjs](../../tests/compliance-engine.test.cjs): transitive sibling propagation, empty trigger guards, multi-artifact traversal, per-spec drift isolation, disconnected-node checks, circular links, and the 500-node benchmark.

## Key Files

| Path | Role |
|---|---|
| `src/compliance-engine.ts` | `computeBlastRadius` and `computeMultiBlastRadius` BFS implementation and node-key adjacency. |
| `tests/compliance-engine.test.cjs` | Traversal, cycle-safety, drift-isolation, disconnected-node, and 500-node benchmark assertions. |
| `src/index.ts`, `src/mcp-server.ts` | Downstream consumers (Custom UI resolver, webtrigger, and Rovo/MCP tool). |

## Related

- [ADR-001: Sharded Forge KVS + Atlassian Graph Hybrid](./001-twg-and-kvs-hybrid.md)
- [Evaluation Rules](../02-compliance-engine/evaluation-rules.md)
