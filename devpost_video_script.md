# Codegeist 2026 — Devpost Video Script + Judge Rehearsal Plan

**Video constraints (official rules):** less than 5 minutes; show the app functioning on its
platform; public YouTube link.
**Target runtime: 3:10.** Record the real app; this script is not evidence of a completed demo.

---

## Part 1 — Video script (3:10)

### Shot 1 — Hook (0:00–0:25) · screen: dark slide with the 5-stage chain
> **NARRATION:** "A change to a medical-device software requirement can affect linked hazards,
> work items, test evidence, and approval records. MedTrace makes those trace relationships
> inspectable in Jira and Confluence. It supports traceability work; it does not determine
> regulatory compliance."

**On screen:** `HAZARD ↔ SRS ↔ JIRA TASK ↔ TEST ↔ SIGNATURE`, then the 5.0 → 5.5 diff.

### Shot 2 — Cold-start discipline & the demo dataset (0:25–0:48) · screen: Jira → MedTrace project page
**Action:** Start on empty uninitialized `LIVE` state (`0 hazards`), then click `⚡ Seed Demo Suite`. Wait for the graph to populate.
> **NARRATION:** "On an empty tenant, MedTrace starts fail-closed in clean LIVE mode — never
> auto-seeding fake data. One click seeds a modeled Smart Infusion Pump project, stamped
> with a persistent DEMO DATASET badge. Honest boundaries are the product."

**Overlay:** `DEMO DATASET — MODELED RECORDS` badge zoom.

### Shot 3 — The hero: blast radius (0:48–1:20) · screen: the live graph
**Action:** Point at HAZ-101 (Class C, flashing red TEST-88, invalidated signature).
Click `⚡ Blast Radius`.
> **NARRATION:** "SRS-104 drifted after its approval attestation. One click runs a breadth-first
> traversal over the trace graph and returns the blast radius: the signature invalidated,
> the Class C hazard compromised, Jira task MED-42 locked, TEST-88 invalidated — plus the
> exact re-audit checklist. When two requirements share one hazard, the traversal crosses
> that shared node — a dedicated test in our suite pins that propagation."

**Overlay:** hop-by-hop path highlight; `executionTimeMs` chip; then a 3-second overlay of the
test name `propagates blast radius transitively to sibling links sharing the hazard node` with
`✔ passing`.

### Shot 4 — The gate (1:20–1:48) · screen: same page
**Action:** Click `🔒 Test Human Gate` → blocked modal appears.
> **NARRATION:** "This in-app simulation invokes the validator handler. A Jira admin can attach
> the Forge validator to a workflow transition. Atlassian issue ECO-624 reports an Automation
> case but is marked Invalid; it does not establish REST behavior. Our separate release-gate
> workflow also checks the production suite on pull requests and pushes to main."

### Shot 5 — Demo remediation (1:48–2:02) · screen: inspection drawer
**Action:** Run the demo-only remediation simulation. Show the modeled graph state change and
the updated demo result.
> **NARRATION:** "This is a demo-only state change: it does not run hardware tests or certify a
> real device. In LIVE mode, remediation is blocked. Backend failures remain visible as errors."

### Shot 6 — The evidence export (2:02–2:12) · screen: export modal
**Action:** Click `📄 Audit Evidence Export` → print preview.
> **NARRATION:** "The printable traceability report includes linked artifacts and hashes. It is
> not an official FDA eSTAR form or 510(k) submission."

### Shot 7 — Architecture and data flow (2:12–2:44) · screen: architecture slide
> **NARRATION:** "The Forge manifest grants no external backend-fetch permission. Separately,
> authenticated MCP and CI requests receive their requested results, so data can leave the
> tenant through those configured clients. The webtrigger uses HMAC-SHA256 and single-use
> nonces. Automated tests cover replay handling; show production results only if freshly verified."

**Overlay:** Show a redacted live terminal capture only after rerunning the check against the
deployment being demonstrated. Never include secrets or signed URLs.

### Shot 8 — Rovo agent + MCP (2:44–3:00) · screen: Rovo chat + Cursor
**Action (pre-record the Cursor half separately — Rovo latency often exceeds 20s):**
In Rovo: "Audit current sprint for IEC 62304 compliance gaps" → agent calls
`verify-iec-compliance-action`, returns affected hazards + remediation (tighten to the agent's
answer card). In Cursor (pre-recorded 5s capture): paste the bolus-rate diff question →
`medtrace_verify_iec_compliance` answers from live cloud state.
> **NARRATION:** "The MedTrace Auditor Rovo agent runs the same deterministic engine from chat.
> And through our MCP server, Cursor asks the live compliance graph before you commit."

### Shot 9 — Close (3:00–3:10)
> **NARRATION:** "MedTrace — deterministic regulatory blast radius, a hard safety gate, and
> cryptographic evidence, inside the tools engineers already use. Built on Atlassian Forge."
> **Overlay:** repo URL.

**Recording notes:** 1080p minimum, zoom to 125% in Jira, cut all dead time, captions on
(YouTube auto-captions + manual fix of IEC/62304/14971 terms).

---

## Part 2 — 60-minute judge dress rehearsal (do this the day before recording)

1. **Fresh tenant install (10 min):** create a brand-new dev tenant → install using the
   judge-facing Jira and Confluence links →
   confirm the app appears in a project sidebar. Anything that breaks here is what judges hit first.
2. **Zero-state path (10 min):** open MedTrace on the empty tenant → confirm clean uninitialized
   `LIVE` state (no fabricated auto-seeded data, no console errors), then click `⚡ Seed Demo Suite`
   and confirm the graph + `DEMO DATASET: MODELED RECORDS` badge render cleanly.
3. **Full click-through + live Firefox gates (10 min):** every button in the header, drawer,
   table search, export print; also verify the three live production browser checks in Firefox:
   (a) native Jira workflow dropdown block on `MED-42` (confirm standalone `WorkflowValidator` log),
   (b) real Confluence SRS page edit (`avi:confluence:updated:page` drift trigger), and
   (c) Rovo prompt triggering `[MedTrace RovoAction] Dispatching action:` in `forge logs -e production`.
4. **Crypto replay proof (5 min):** run the README's replay check against the target deployment;
   retain dated, redacted output if you intend to claim a live result.
5. **CI gate (5 min):** POST `verify-release-gate` → expect HTTP 403 with the HAZ-101 violation.
6. **Rovo live test (10 min):** in the tenant's Rovo chat, ask:
   - "Audit current sprint for IEC 62304 compliance gaps" → expect affected hazards + guidance.
   - "Inspect ISO 14971 Class C hazards for Smart Infusion Pump" → expect HAZ-101 lineage.
   - **If the agent answers without calling an action**, open Developer logs
     (`forge logs -e production`) — look for `[MedTrace RovoAction] Dispatching action:`.
     Absent log = invocation didn't reach the handler: check the manifest deployed
     and that the agent's conversation starters are enabled.
7. **MCP in Cursor (10 min):** configure per `mcp-server/README.md`, ask the bolus question,
   confirm the response cites live cloud state; then kill the URL and confirm it says
   `LOCAL HEURISTIC ONLY` instead of pretending.

---

## Part 3 — Submission checklist (final 48 hours)

- [ ] Deploy HEAD (`npm run build:all && forge deploy -e production`) and verify production logs are free of old `KEY_NOT_FOUND` batch-read errors.
- [ ] Record the functioning app, publish it on YouTube, and add the public URL to `devpost_submission_draft.md` (currently a blocker, no URL present).
- [ ] Confirm separate judge-facing Jira and Confluence install links on a fresh site.
- [ ] Provide least-privilege demo accounts; never submit a production webtrigger secret.
- [ ] Verify the Marketplace status and include a review-ticket/listing link only if one exists.
- [ ] Re-run `npm run test:all` and verify the final test count (`191`: 158 backend + 33 frontend) matches the draft.
- [ ] Screenshot the `DEMO DATASET` badge + honest error banner — use one in the Devpost gallery
      images; it's a differentiator, not a weakness.
