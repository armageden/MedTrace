# Goldfish Annotated Review Report

**Target:** `devpost_submission_draft.md` (`lines 1-144`)
**Status:** completed (open findings preserved for reference)

## Prioritized Findings & AI Suggestions

### [Issue 1] [`egm-codebase-details` / `egm-design` / `egm-comprehension`] - Severity: Blocker
* **Affected Scope:** [Lines 136, 138](devpost_submission_draft.md#L136-L138) (## Try it out)
* **Discrepancy Description:** Lines 136 and 138 contain unpopulated evaluation placeholders (`[TO BE INSERTED BEFORE SUBMISSION — ...]` and `https://youtu.be/YOUR_VIDEO_ID`).
* **Rationale:** A Devpost submission with placeholder URLs fails automated hackathon screening. Judges cannot install the app on their tenant or watch the required demonstration video.
* **AI Suggestion:** ESCALATE
* **Justification:** The exact YouTube video ID and Atlassian Developer Console distribution link must be provided by the human project owner. The document must clearly instruct the submitter and provide prominent callouts.
* **Proposed Edit:**
  * Location: Lines 136 and 138
  * Change: Add prominent pre-submission checklist warnings and clear instructions for pasting the video URL and distribution install link.

---

### [Issue 2] [`egm-codebase-details`] - Severity: Blocker
* **Affected Scope:** [Lines 32-34](devpost_submission_draft.md#L32-L34) (### 2. Cryptographic Approval Hash Drift Detection)
* **Discrepancy Description:** The draft claims: *"If an engineer modifies a Confluence page post-approval without clinical re-review, MedTrace dynamically computes the SHA-256 digest over the modified content, flags cryptographic approval hash drift, and marks the lineage as an unverified risk."*
* **Rationale:** MedTrace declares no Confluence event listeners in `manifest.yml`. Hashes and specifications are modeled in the seeder, and hash comparisons are evaluated on-demand during inspections, transitions, CI calls, and MCP queries—not via background push listeners.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Describing drift detection as an on-demand evaluation during workflow transitions, Custom UI inspections, CI webtriggers, and MCP queries matches the actual Forge serverless implementation and defends the zero-egress architecture.
* **Proposed Edit:**
  * Location: Lines 32-34
  * Change: Clarify that hash drift detection is evaluated on-demand across workflow transitions, in-app inspections, CI gates, and developer MCP queries, illustrated by the demo seeder's modeled specification revision.

---

### [Issue 3] [`egm-codebase-details`] - Severity: Blocker
* **Affected Scope:** [Line 37](devpost_submission_draft.md#L37) (### 3. IEC 62304 Safety Release Gate)
* **Discrepancy Description:** The draft claims: `* **Class A (No injury):** Requires documented requirements and baseline test coverage.`
* **Rationale:** In `src/compliance-engine.ts:35-49`, `test.status` is checked exclusively for `CLASS_C` and `CLASS_B`. For `CLASS_A`, test status is pass-through and only a requirement specification title is required.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Aligning the text with `compliance-engine.ts` prevents a technical judge from flagging an inconsistency between documentation and the rule engine.
* **Proposed Edit:**
  * Location: Line 37
  * Change: Replace with: `* **Class A (No injury):** Requires documented safety requirements (verification test execution is informational/non-blocking).`

---

### [Issue 4] [`egm-codebase-details`] - Severity: Blocker
* **Affected Scope:** [Lines 65, 77](devpost_submission_draft.md#L65) (Secure Webtrigger Gateway & Challenges)
* **Discrepancy Description:** The draft claims Forge KVS operates by *"lazily pruning expired tokens on access"*.
* **Rationale:** In production (`src/nonce-store.ts:24-31`), `kvsNonceStore.claim` uses `@forge/kvs` native atomic TTL and collision detection (`keyPolicy: 'FAIL_IF_EXISTS'`). Lazy pruning on access is only used in the in-memory test mock helper.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Highlighting Forge KVS's native atomic TTL and `FAIL_IF_EXISTS` is a much stronger technical proof of anti-replay concurrency defense.
* **Proposed Edit:**
  * Location: Lines 65, 77
  * Change: Clarify that production enforces atomic single-operation nonce claims via `@forge/kvs` (`FAIL_IF_EXISTS` with TTL), while in-memory test mocks use lazy TTL pruning.

---

### [Issue 5] [`egm-design`] - Severity: Major
* **Affected Scope:** [Lines 30, 99](devpost_submission_draft.md#L30) (1. Deterministic Regulatory Blast Radius Engine)
* **Discrepancy Description:** Asserting that the benchmark computes blast radius across a "500-node graph benchmark... in under 20ms of breadth-first traversal" is topologically imprecise, as the benchmark suite indexes 100 disconnected links (500 nodes) into the adjacency map and traverses the matching connected subgraph.
* **Rationale:** A technical reviewer looking at `tests/compliance-engine.test.cjs` will note that all 500 nodes are indexed into memory in O(n) time, while the BFS traversal operates on the connected subgraph.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Accurately describing the two phases (O(n) indexing of 500 artifact nodes followed by sub-20ms BFS traversal over connected subgraphs) is factually airtight and technically impressive.
* **Proposed Edit:**
  * Location: Lines 30 and 99
  * Change: Clarify that 500 artifact nodes across 100 trace links are indexed into the adjacency map in O(n) time, and BFS traversal over connected subgraphs terminates deterministically in under 20ms (single-digit ms on the seeded suite).

---

### [Issue 6] [`egm-design`] - Severity: Major
* **Affected Scope:** [Line 90](devpost_submission_draft.md#L90) (Honest Scope & System Limitations)
* **Discrepancy Description:** Claiming single-key Forge KVS is "sufficient for seeded and medium projects (~500 nodes)" ignores Forge KVS's strict 32 KB per-key limit.
* **Rationale:** 100 full trace links with serialized snippets and metadata require ~100 KB, which exceeds Forge KVS's 32 KB single-key quota. Single-key storage is sized for ~25-30 trace links (~120-150 nodes).
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Honest documentation of platform storage quotas demonstrates real production awareness to judges.
* **Proposed Edit:**
  * Location: Line 90
  * Change: Update the ceiling to ~25-30 trace links (~120-150 nodes / ~30 KB) per single KVS entity, and document entity sharding (`medtrace:link:{id}`) for larger enterprise architectures.

---

### [Issue 7] [`egm-codebase-details`] - Severity: Major
* **Affected Scope:** [Line 100](devpost_submission_draft.md#L100) (Accomplishments)
* **Discrepancy Description:** The draft cites *"Clauses 5.1.7, 5.3.3, 5.3.6 for SOUP verification records"*, but the codebase contains no SOUP data types or verification logic.
* **Rationale:** Citing regulatory clauses for features that do not exist undermines credibility with medical device judges.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Remove non-existent SOUP references and anchor the narrative strictly on IEC 62304 Clause 5.7 (Software System Testing), Clause 5.8 (Software Release), and ISO 14971 Risk Mitigations.
* **Proposed Edit:**
  * Location: Line 100
  * Change: Remove SOUP clauses and focus strictly on Clauses 5.7 and 5.8.

---

### [Issue 8] [`egm-codebase-details`] - Severity: Major
* **Affected Scope:** [Lines 38-39](devpost_submission_draft.md#L38-L39) (IEC 62304 Safety Release Gate)
* **Discrepancy Description:** The text implies only Class C strictly blocks Jira issue transitions.
* **Rationale:** In `src/workflow-validator.ts:22-28`, the release gate blocks transitions if *any* matching link is not `VERIFIED`. An untested Class B hazard results in `INCOMPLETE` and strictly halts the transition.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Accurately communicating that both Class B and Class C gaps block transitions highlights MedTrace's strict safety enforcement.
* **Proposed Edit:**
  * Location: Lines 38-39
  * Change: State clearly that both Class B and Class C unverified gaps block Jira issue transitions and global release.

---

### [Issue 9] [`egm-design`] - Severity: Major
* **Affected Scope:** Document Structure (Between "Inspiration" and "What it does")
* **Discrepancy Description:** Missing structured "Goals & Non-Goals" section mandated by the Feature Specification Standard.
* **Rationale:** Regulatory judges require explicit legal boundaries defining what the software does and does not do (e.g. not an active MDDS, does not connect directly to pump hardware, not a substitute for Notified Body audits).
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Transplanting the crisp Goals & Non-Goals section from `README.md:44-53` into `devpost_submission_draft.md` establishes defensible legal boundaries.
* **Proposed Edit:**
  * Location: After Line 20
  * Change: Insert a structured "Goals & Non-Goals" subsection.

---

### [Issue 10] [`egm-comprehension`] - Severity: Major
* **Affected Scope:** [Lines 14, 43, 89](devpost_submission_draft.md#L14) (Throughout)
* **Discrepancy Description:** Undefined acronyms and regulatory references: `eSTAR`, `FDA 21 CFR 807.92`, `AGG`, `TWG`.
* **Rationale:** Non-specialist hackathon judges may not know these acronyms without inline definitions.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Define each acronym inline upon first introduction.
* **Proposed Edit:**
  * Location: Lines 14, 43, 89
  * Change: Define eSTAR (*electronic Submission Template And Resource*), 21 CFR 807.92 (*510(k) summary regulations*), and AGG (*Atlassian GraphQL Gateway*).

---

### [Issue 11] [`egm-comprehension`] - Severity: Major
* **Affected Scope:** [Line 28](devpost_submission_draft.md#L28) (1. Deterministic Regulatory Blast Radius Engine)
* **Discrepancy Description:** Labeling the chain with `(MED)` and `(TEST)` causes confusion about whether these are generic entity types or Jira issue keys.
* **Rationale:** A fresh reader may wonder if MedTrace requires custom issue types or standard Jira issues.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Clarify that these represent standard Jira work items and verification test issues.
* **Proposed Edit:**
  * Location: Line 28
  * Change: Replace with: `ISO 14971 Clinical Hazard ↔ Safety Requirement (Confluence SRS) ↔ Jira Work Item (e.g., MED-42) ↔ Verification Test Issue (e.g., TEST-88) ↔ Clinical Approval Hash`

---

### [Issue 12] [`egm-comprehension`] - Severity: Major
* **Affected Scope:** [Lines 46-54](devpost_submission_draft.md#L46-L54) (5. Optional Developer Assistant)
* **Discrepancy Description:** The MCP assistant description lacks a concrete user interaction example showing what a developer asks in Cursor and what the tool returns.
* **Rationale:** Concrete developer interactions make the MCP bonus category tangible and compelling for technical judges.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Add a concrete example of an engineer asking Cursor if a bolus rate parameter change touches a safety-critical hazard.
* **Proposed Edit:**
  * Location: Line 54
  * Change: Add a 2-line interaction snippet illustrating Cursor calling `medtrace_verify_iec_compliance`.

---

### [Issue 13] [`egm-comprehension`] - Severity: Nit
* **Affected Scope:** [Lines 13-19](devpost_submission_draft.md#L13-L19) (Inspiration)
* **Discrepancy Description:** Omits the empirical time-savings metric found in `README.md` (*"saved us 120+ hours of forensic reconciliation"*).
* **Rationale:** Concrete metrics provide judges with measurable proof of value under the Heilmeier standard.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Add the 120+ hours quote to the Inspiration section.
* **Proposed Edit:**
  * Location: Line 19
  * Change: Include the team quote citing 120+ hours saved.

---

### [Issue 14] [`egm-design`] - Severity: Nit
* **Affected Scope:** [Lines 69-73](devpost_submission_draft.md#L69-L73) (Architectural Alternatives Considered)
* **Discrepancy Description:** Omission of ADR 004 (Artifact-Node BFS vs. per-link walk) from the Alternatives Considered list.
* **Rationale:** Documenting algorithmic trade-offs demonstrates technical depth.
* **AI Suggestion:** PROPOSE FIX
* **Justification:** Add ADR 004 as the fourth bullet in Architectural Alternatives Considered.
* **Proposed Edit:**
  * Location: Line 73
  * Change: Add bullet describing ADR 004.
