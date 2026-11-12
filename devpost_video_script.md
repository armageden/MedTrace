# Codegeist 2026 — Devpost Video Script + Judge Rehearsal Plan

**Video constraints (official rules):** under 5 minutes; judges are not required to watch beyond
3 minutes; must show the app functioning on the platform it was built for; public YouTube link.
**Target runtime: 3:10.** Everything decisive happens in the first 100 seconds.

---

## Part 1 — Video script (3:10)

### Shot 1 — Hook (0:00–0:25) · screen: dark slide with the 5-stage chain
> **NARRATION:** "In medical device software, changing one firmware constant — a bolus clamp
> limit from 5.0 to 5.5 milliliters per hour — doesn't just change code. It invalidates a
> clinical hazard assessment, a safety requirement, a verification test, and an FDA
> electronic signature. IEC 62304 and ISO 14971 demand you prove that chain is intact.
> MedTrace does it live, inside Jira and Confluence — with zero data leaving Atlassian."

**On screen:** `HAZARD ↔ SRS ↔ JIRA TASK ↔ TEST ↔ SIGNATURE`, then the 5.0 → 5.5 diff.

### Shot 2 — The demo dataset (0:25–0:40) · screen: Jira → MedTrace project page
**Action:** Click `⚡ Seed Demo Suite`. Wait for the graph to populate.
> **NARRATION:** "One click seeds a Smart Infusion Pump project. Note the badge — every record
> is clearly labeled as modeled demo data. We never fake tenant evidence — that discipline is
> the product."

**Overlay:** `DEMO DATASET — MODELED RECORDS` badge zoom.

### Shot 3 — The hero: blast radius (0:40–1:15) · screen: the live graph
**Action:** Point at HAZ-101 (Class C, flashing red TEST-88, invalidated signature).
Click `⚡ Blast Radius`.
> **NARRATION:** "SRS-104 drifted after its Part 11 signature. One click runs a breadth-first
> traversal over the trace graph and returns the blast radius: the signature invalidated,
> the Class C hazard compromised, Jira task MED-42 locked, TEST-88 invalidated — plus the
> exact re-audit checklist. When two requirements share one hazard, the traversal crosses
> that shared node — a dedicated test in our suite pins that propagation."

**Overlay:** hop-by-hop path highlight; `executionTimeMs` chip; then a 3-second overlay of the
test name `propagates blast radius transitively to sibling links sharing the hazard node` with
`✔ passing`.

### Shot 4 — The gate (1:15–1:35) · screen: same page
**Action:** Click `🔒 Test Human Gate` → blocked modal appears.
> **NARRATION:** "This button invokes the exact validator handler that Jira runs natively —
> attach it to a workflow transition with site-admin, and Jira itself blocks the move to Done
> while a Class C hazard is unverified. It fails closed. Because Jira Automation can bypass
> transition validators — platform issue ECO-624 — an identical gate also runs in CI via an
> authenticated webtrigger; a working GitHub Actions workflow ships in the repo."

### Shot 5 — Remediation (1:35–1:55) · screen: inspection drawer
**Action:** Click `⚡ Remediate Class C Gap & Re-certify Gate`. Graph turns green, banner flips
to `✅ AUDIT READY`.
> **NARRATION:** "Verification runs, the electronic signature re-certifies against the current
> SHA-256, and the release gate unlocks. If the backend were unreachable, you'd get an honest
> error banner — never a simulated success."

### Shot 6 — The evidence dossier (1:55–2:15) · screen: FDA export modal
**Action:** Click `📄 Audit Evidence Export` → print preview.
> **NARRATION:** "Everything compiles into a printable 510(k) eSTAR-aligned traceability
> dossier — hashes, signatures, test evidence."

### Shot 7 — Architecture + zero egress (2:15–2:40) · screen: architecture slide
> **NARRATION:** "No external fetch permissions exist in the manifest — clinical data never
> leaves the Atlassian tenant. Mutations arrive through a webtrigger protected by HMAC-SHA256,
> a 300-second replay window, and persistent nonce consumption in Forge storage — replay
> returns 409, and our test suite proves it live: 200, 409, 409, 200."

**Overlay:** `200 → 409 → 409 → 200` terminal capture (run README's 4-step curl script).

### Shot 8 — Rovo agent + MCP (2:40–3:00) · screen: Rovo chat + Cursor
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

1. **Fresh tenant install (10 min):** create a brand-new dev tenant → install via the shared
   installation link → confirm the app appears in a project sidebar. Anything that breaks here
   is what judges will hit first.
2. **Zero-state path (10 min):** open MedTrace on the empty tenant → confirm the auto-seeded
   suite + `DEMO DATASET` badge render, no blank screen, no console errors.
3. **Full click-through (10 min):** every button in the header, drawer, table search, export
   print. Screenshot anything ugly — fix before recording.
4. **Crypto replay proof (5 min):** run the README's 4-step curl script against the live
   webtrigger; expect 200/409/409/200.
5. **CI gate (5 min):** POST `verify-release-gate` → expect HTTP 403 with the HAZ-101 violation.
6. **Rovo live test (10 min):** in the tenant's Rovo chat, ask:
   - "Audit current sprint for IEC 62304 compliance gaps" → expect affected hazards + guidance.
   - "Inspect ISO 14971 Class C hazards for Smart Infusion Pump" → expect HAZ-101 lineage.
   - **If the agent answers without calling an action**, open Developer logs
     (`forge logs --environment development`) — look for `[MedTrace RovoAction] Received action
     invocation:`. Absent log = invocation didn't reach the handler: check the manifest deployed
     and that the agent's conversation starters are enabled.
7. **MCP in Cursor (10 min):** configure per `mcp-server/README.md`, ask the bolus question,
   confirm the response cites live cloud state; then kill the URL and confirm it says
   `LOCAL HEURISTIC ONLY` instead of pretending.

---

## Part 3 — Submission checklist (final 48 hours)

- [ ] Replace `YOUR_VIDEO_ID` in `devpost_submission_draft.md` with the YouTube URL.
- [ ] Generate the judges' installation link (Developer Console → app → Distribute) and paste
      it into the "Try it out" section of the draft (a marked slot is waiting).
- [ ] Put the rotated webtrigger secret + judge credentials into the Devpost private fields.
- [ ] Re-run `npm test` and paste the final count (40) if any code changed after this draft.
- [ ] Screenshot the `DEMO DATASET` badge + honest error banner — use one in the Devpost gallery
      images; it's a differentiator, not a weakness.
