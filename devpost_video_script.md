# Codegeist 2026 — Devpost Video Script + Judge Rehearsal Plan

**Video constraints (official rules):** less than 5 minutes; show the app functioning on its
platform; public YouTube link.
**Target runtime: 3:48.** Record the real app; this script is not evidence of a completed demo.

---

## Part 1 — Video script (3:48)

### Shot 1 — Hook (0:00–0:20) · screen: dark slide with the 5-stage chain
> **NARRATION:** "A change to a medical-device software requirement can affect linked hazards,
> work items, test evidence, and approval records. MedTrace makes those trace relationships
> inspectable on live Jira and Confluence data. It supports traceability work; it does not
> determine regulatory compliance."

**On screen:** `HAZARD ↔ SRS ↔ JIRA TASK ↔ TEST ↔ SIGNATURE`, then the 5.0 → 5.5 diff.

### Shot 2 — Real data: live sync (0:20–1:05) · screen: Jira project + Confluence space → MedTrace project page
**Action:** Flash the `MEDTRACE` Jira project (six issues) and the `MEDTRACE` Confluence space
(four SRS pages) — real tenant artifacts, synthetic content. Open the MedTrace project page in
`MEDTRACE`: empty uninitialized `LIVE` state. Click `Sync Live Atlassian`; watch links populate.
Point out the SRS-201…204 links, MEDTRACE-5 flagged with no linked SRS, MEDTRACE-6 skipped as
untagged, and the `RELEASE BLOCKED` state.
> **NARRATION:** "This is a real Jira project and a real Confluence space — the specifications
> are synthetic, but they are live tenant artifacts. MedTrace opens empty: LIVE mode starts
> fail-closed with zero hazards. One click on Sync Live Atlassian ingests the project's labelled
> issues. Four tracked tasks link to their SRS pages through Jira remote links. MEDTRACE-5 is
> safety-labelled but has no linked specification — flagged as a gap. MEDTRACE-6 is untagged and
> skipped. Every test starts UNTESTED and unsigned, so the release is BLOCKED."

**Overlay:** `LIVE ATLASSIAN DATA` dataset badge; zoom on the MEDTRACE-5 no-linked-SRS flag and the
`RELEASE BLOCKED` chip.

### Shot 3 — Closing the loop on MEDTRACE-1 (1:05–1:35) · screen: inspection drawer
**Action:** On the MEDTRACE-1 link, open `Record Test Result`, submit `PASSED` with an
`https://` evidence URL, then `Execute Electronic Attestation Sign-Off`. The link flips to verified.
> **NARRATION:** "Closing the loop on MEDTRACE-1: record a PASSED verification result with a
> real evidence URL, then execute the electronic attestation sign-off — a cryptographic approval
> over the spec's content hash. The trace link turns verified."

### Shot 4 — Drift + blast radius (1:35–2:05) · screen: Confluence SRS-201 edit → MedTrace graph
**Action:** Edit `SRS-201 Bolus Rate Hard Limit` in Confluence, changing `5.0` to `5.5` mL/hr,
and publish. Return to MedTrace: the approval signature is revoked; click `Blast Radius`.
> **NARRATION:** "Now the requirement drifts: in Confluence, SRS-201 changes from 5.0 to 5.5
> millilitres per hour. The page-update trigger fires, the approval signature is revoked, and one
> click shows the transitive blast radius — the spec, its hazard, the Jira task, the test, and the
> re-audit checklist."

**Overlay:** hop-by-hop path highlight; the revoked-signature marker on the spec node.

### Shot 5 — The gate (2:05–2:30) · screen: same page
**Action:** Click `Test Human Gate` → blocked modal appears on the Class C issue.
> **NARRATION:** "The Test Human Gate button invokes the same validator handler a Jira workflow
> calls on transition. With a Class C hazard unverified, the transition is blocked — fail-closed.
> A site admin can attach this validator to a live workflow."

### Shot 6 — Rovo agent (2:30–2:55) · screen: Rovo chat
**Action (pre-record if Rovo latency runs long):** In Rovo, choose MedTrace Auditor and ask
"Show me the hazard lineage for MEDTRACE-1" → the agent calls `get-hazard-lineage-action` and
returns the lineage card; follow with "verify IEC 62304 compliance" → `verify-iec-compliance-action`.
> **NARRATION:** "The MedTrace Auditor runs the same deterministic engine inside Rovo chat. Asked
> about MEDTRACE-1, it calls the hazard-lineage action and returns the trace chain and the release
> verdict — under the invoking user's own permissions."

### Shot 7 — Atlassian MCP (2:55–3:20) · screen: MCP client (Claude Desktop / VS Code / Cursor — whichever supports remote MCP with OAuth)
**Action:** Show the client connected to
`https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99`; run
`verify-iec-compliance-action` with `issueKey: "MEDTRACE-1"` (or a diff referencing `SRS-201`) → response: `configuredChecksPassed: false`.
> **NARRATION:** "The same two actions are exposed through the Atlassian MCP server at
> mcp.atlassian.com — a site admin enables external MCP exposure under Connected apps, and the
> client connects over OAuth. Here verify-iec-compliance answers for SRS-201 / MEDTRACE-1: configured checks failed, release
> blocked." *(Optional extra: the local stdio MCP bridge in `mcp-server/` — not part of this demo.)*

### Shot 8 — Evidence & boundaries (3:20–3:38) · screen: `Export Dossier` + audit log
**Action:** Click `Export Dossier` → printable report; flash the audit log hash chain.
> **NARRATION:** "Evidence exports and the hash-chained audit trail verify independently.
> Evaluators with no tenant data can seed a labelled DEMO dataset instead. MedTrace is assistive
> traceability tooling — not a regulatory determination, not a validated QMS, and not for patient
> data."

### Shot 9 — Close (3:38–3:48)
> **NARRATION:** "MedTrace — deterministic blast radius, a hard safety gate, and cryptographic
> evidence, on live Atlassian data. Built on Forge."
> **Overlay:** repo URL.

**Recording notes:** 1080p minimum, zoom to 125% in Jira, cut all dead time, captions on
(YouTube auto-captions + manual fix of IEC/62304/14971 terms).

---

## Part 2 — 60-minute judge dress rehearsal (do this the day before recording)

1. **Confirm the live dataset on MEDTRACE (10 min):** open the `MEDTRACE` Jira project (six
   issues, correct labels) and the `MEDTRACE` Confluence space (four SRS pages, status current).
   Open the MedTrace project page in `MEDTRACE` → confirm clean uninitialized `LIVE` state →
   click `Sync Live Atlassian` → confirm hazards, tests, and the four SRS links populate,
   MEDTRACE-5 shows the missing-SRS flag, and MEDTRACE-6 is skipped.
2. **Close-the-loop path (10 min):** on MEDTRACE-1 use `Record Test Result` (`PASSED` + an
   `https://` evidence URL) → `Execute Electronic Attestation Sign-Off` → link verified and the release
   state updates.
3. **Confluence drift trigger (10 min):** edit SRS-201 (`5.0` → `5.5` mL/hr) and publish →
   confirm `avi:confluence:updated:page` fires and the signature is revoked → run `Blast Radius`.
   Check `forge logs -e production` for the trigger event if nothing changes.
4. **Gate + Rovo (10 min):** `Test Human Gate` → blocked modal on a Class C issue. In Rovo chat,
   choose MedTrace Auditor → "Show me the hazard lineage for MEDTRACE-1" → expect the action
   response. If the agent answers without calling an action, check `forge logs -e production` for
   `[MedTrace RovoAction] Dispatching action:` — absent log means the invocation never reached the
   handler.
5. **Atlassian MCP (10 min):** a site or org admin enables external MCP exposure (Atlassian
   Administration → Apps → Sites → site → Connected apps → MedTrace → turn on tools). Connect an
   MCP client to `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` via the
   OAuth consent screen, then run `verify-iec-compliance-action` referencing `MEDTRACE-1` / `SRS-201` → expect
   `configuredChecksPassed: false`.
6. **Demo fallback + install smoke (10 min):** on a scratch site, install via the judge-facing
   link → `Seed Demo Suite` → confirm the `DEMO DATASET` badge path still works for evaluators
   with no tenant data.
7. **Recording prep (5 min):** 1080p, zoom 125%, cut dead time; pre-record the Rovo shot if
   latency exceeds ~20 s.

---

## Part 3 — Submission checklist (final 48 hours)

- [ ] Deploy HEAD (`npm run build:all && forge deploy -e production` + `forge install --upgrade` on Jira and Confluence so `read:graph:*` scopes apply), initialize `Sync Live Atlassian` on the active production partition, and verify `production` logs are free of old errors.
- [ ] Verify `verify-iec-compliance-action` over `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` after production sync so it answers from live `MEDTRACE` records rather than an uninitialized storage partition.
- [ ] Record the functioning app, publish it on YouTube, and add the public URL to `devpost_submission_draft.md` (currently a blocker, no URL present).
- [ ] Confirm separate judge-facing Jira and Confluence install links on a fresh site.
- [ ] Provide least-privilege demo accounts; never submit a production webtrigger secret.
- [ ] Re-run `npm run test:all` and verify the final test count (`202`: `168` backend + `34` frontend) matches the draft.
- [ ] Screenshot the `DEMO DATASET` badge + honest error banner — use one in the Devpost gallery
      images; it's a differentiator, not a weakness.
