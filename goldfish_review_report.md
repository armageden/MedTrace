# Goldfish Review Report: Round 1

**Target:** [`medtrace/README.md`](file:///home/farhan/Downloads/codegeist2026.devpost/medtrace/README.md) (`Lines 1–128`)  
**Timestamp:** 2026-11-07  
**Orchestrator:** Elephant-Goldfish Model (EGM) Review Loop  

---

## Reviewer Status

| Reviewer | Lens | Status | Blockers | Major | Nit | Total |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `egm-codebase-details` | Technical Quality & Code Grounding | `completed` | 2 | 6 | 2 | 10 |
| `egm-structural` | Layout & Template Rigor | `completed` | 2 | 2 | 4 | 8 |
| `egm-comprehension` | Naive Reader & Clarity | `completed` | 2 | 3 | 1 | 6 |
| **Consolidated** | | | **5** | **11** | **7** | **23** | *(Deduplicated)*

---

## Prioritized Findings & Resolution Plan

### 🔴 Blockers

#### [BLK-01] Architecture Dataflow Contradicts Runtime Topology
* **Reviewers:** `egm-codebase-details` (F1), `egm-comprehension` (F2)
* **Affected Scope:** `medtrace/README.md` Lines 30–60 (Mermaid Diagram)
* **Discrepancy:** The diagram depicts `MCPServer <--> Engine` directly and `Rovo <--> Resolvers`. In reality, the local stdio MCP server runs outside Atlassian Cloud and connects to Forge via an HTTPS Webtrigger (`mcp-sync-webtrigger` in `index.ts`), while Rovo modules invoke `rovoActionHandler` in `src/mcp-server.ts`.
* **Resolution:** `PROPOSE FIX` — Update the Mermaid diagram to explicitly depict the HTTPS Webtrigger boundary (with HMAC-SHA256 signature verification) and the `rovoActionHandler` module boundary.

#### [BLK-02] Unstated HMAC-SHA256 Wire Protocol & 5-Minute Anti-Replay Guardrails
* **Reviewers:** `egm-codebase-details` (F2), `egm-comprehension` (F2)
* **Affected Scope:** `medtrace/README.md` Lines 96–118 (Section 4)
* **Discrepancy:** The Cursor MCP setup snippet omits mandatory authentication headers and environment variables (`x-medtrace-key`, `x-medtrace-timestamp`, `x-medtrace-signature`, `MEDTRACE_MCP_SECRET`, `MEDTRACE_WEBTRIGGER_URL`).
* **Resolution:** `PROPOSE FIX` — Document the environment variables, the 300,000ms replay window, and HMAC-SHA256 signature authentication in Section 4.

#### [BLK-03] Missing Mandatory "Risks & Limits" Section
* **Reviewers:** `egm-structural` (F2)
* **Affected Scope:** Document Structure
* **Discrepancy:** No explicit documentation of system limits (Forge KVS storage quota, AGG GraphQL rate limits, fail-closed validator execution timeouts, and 5-minute replay window).
* **Resolution:** `PROPOSE FIX` — Add a dedicated "System Limits & Architectural Safeguards" section.

#### [BLK-04] Missing "Alternatives Considered" Section
* **Reviewers:** `egm-structural` (F1)
* **Affected Scope:** Document Structure
* **Discrepancy:** Standard requires evaluating design alternatives.
* **Resolution:** `CONTEST & COMPACT` — The repository already contains dedicated Architecture Decision Records under `medtrace/docs/99-design-decisions/` (`001-twg-and-kvs-hybrid.md`, `002-webtrigger-hmac-authentication.md`, `003-twg-dual-engine-fallback.md`). We will add an "Architecture Decision Records & Alternatives Considered" section with concise summaries and direct links rather than inflating the README.

#### [BLK-05] Unstated Authentication & Access Prerequisites for Live Demo
* **Reviewers:** `egm-comprehension` (F1)
* **Affected Scope:** `medtrace/README.md` Lines 66–71
* **Discrepancy:** Directs judges to Atlassian Cloud without explaining authentication / access credentials.
* **Resolution:** `PROPOSE FIX` — Add guidance that judge access credentials and guest instructions are provided in the Devpost submission package and provide fallback testing instructions.

---

### 🟡 Major Findings

#### [MAJ-01] Missing "Goals & Non-Goals" Section
* **Reviewers:** `egm-structural` (F3)
* **Discrepancy:** Scope boundaries are undefined (e.g. MedTrace is a software traceability and governance engine, not an active Medical Device Data System [MDDS] or physical test execution runner).
* **Resolution:** `PROPOSE FIX` — Add explicit Goals & Non-Goals list under Executive Summary.

#### [MAJ-02] Incomplete MCP Tool Registry Documentation
* **Reviewers:** `egm-codebase-details` (F4)
* **Discrepancy:** Only `medtrace_verify_iec_compliance` was mentioned. Omitted `medtrace_get_hazard_lineage` and `medtrace_remediate_safety_gap`.
* **Resolution:** `PROPOSE FIX` — Document all 3 MCP tools with input arguments and descriptions.

#### [MAJ-03] Undefined Regulatory Standards & Risk Classes (Class A / B / C)
* **Reviewers:** `egm-comprehension` (F3, F4)
* **Discrepancy:** IEC 62304, FDA 21 CFR Part 11, ISO 14971, and Class A/B/C severity differences are assumed knowledge without definitions.
* **Resolution:** `PROPOSE FIX` — Add a concise "Regulatory Context & Compliance Standards" primer table.

#### [MAJ-04] Undocumented Fail-Safe (Fail-Closed) Mode in Jira Workflow Validator
* **Reviewers:** `egm-codebase-details` (F6)
* **Discrepancy:** Validator halts transitions (`result: false`) upon unhandled storage/network exceptions to prevent non-compliant releases.
* **Resolution:** `PROPOSE FIX` — Document the fail-closed safety invariant in Section 2 and in the safety safeguards.

#### [MAJ-05] Missing Public API Specification for Forge Resolvers & KVS Storage
* **Reviewers:** `egm-codebase-details` (F3, F7, F8)
* **Discrepancy:** Resolver endpoints (`getComplianceSuite`, `seedDemoSuite`, `remediateGap`, `queryGraphContext`, `simulateTransition`), KVS key (`medtrace:compliance:active_suite`), and AGG GraphQL fallback to REST are undocumented.
* **Resolution:** `PROPOSE FIX` — Document the resolver contracts and AGG-to-REST fallback mechanism.

---

### 🟢 Nits & Formatting Repairs

* **[NIT-01] Numbered Headings:** Remove rigid numeric prefixes (`## 1.`, `## 2.`) in favor of clean semantic markdown titles.
* **[NIT-02] Trailing Punctuation:** Remove trailing colon in heading `### Asking Cursor in your IDE:`.
* **[NIT-03] LaTeX Delimiters:** Replace raw LaTeX `$\rightarrow$` with clean Unicode arrows `→`.
* **[NIT-04] Clickable URLs:** Convert bare `https://one-atlas-feur.atlassian.net` to standard markdown links.
* **[NIT-05] Test Suite Checklist:** Add `npm test` verification command (`tests/compliance-engine.test.cjs`) to the Hackathon submission checklist.
