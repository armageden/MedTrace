# Codegeist 2026 — Devpost Video Script + Judge Rehearsal Plan

**Video constraints (official rules):** less than 5 minutes; show the app functioning on its
platform; public YouTube link.
**Target runtime: 3:50.** Record the real app; this script is not evidence of a completed demo.

---

## Part 1 — Video script (3:50)

### Shot 1 — Problem & Thesis (0:00–0:20) · screen: Confluence `5.0 → 5.5` edit + 5-stage chain
> **NARRATION:** "When a signed medical-device requirement changes—say an infusion limit moves
> from 5.0 to 5.5 mL/hr—teams must prove which hazards, Jira work, tests, and approvals are
> affected. MedTrace tracks that chain on live Atlassian data, revokes stale approvals, enforces
> the release gate, and creates linked re-verification tasks without leaving Atlassian."

### Shot 2 — Live Data & Sync (0:20–0:50) · screen: Jira project + Confluence space → MedTrace
**Action:** Show real `MEDTRACE` Jira issues (in `Under Review`, labeled `class-c`, linked via
Confluence remote links and native `issuelinks`) and Confluence SRS pages. Open MedTrace in
empty `LIVE` mode (`RELEASE BLOCKED`) and click `Sync Live Atlassian` to ingest live artifacts.
> **NARRATION:** "LIVE mode starts fail-closed with zero hazards. One click on Sync Live
> Atlassian ingests real Jira issues, Confluence remote links, and native issue links—with no
> fabricated risk metrics."

### Shot 3 — Compliant Path: `Under Review → Done` (0:50–1:30) · screen: Inspection Drawer → Jira board
**Action:** On a `MEDTRACE` issue in `Under Review`, record `PASSED` test evidence (`https://...`),
execute `Sign Off Spec (Attestation)`, then transition the issue in Jira from `Under Review → Done`
with the live `jira:workflowValidator` attached. Transition succeeds.
> **NARRATION:** "Recording passing test evidence and signing the Confluence spec's SHA-256 hash
> satisfies the release gate—so the real Jira workflow validator allows moving this compliant
> issue from Under Review to Done."

### Shot 4 — Confluence Drift & Blast Radius (1:30–2:10) · screen: Confluence edit → MedTrace graph
**Action:** Edit `SRS-201` in Confluence (`5.0` → `5.5` mL/hr) and publish. Return to MedTrace:
cross-partition Confluence hash reconciliation (complementing `avi:confluence:updated:page`)
automatically revokes the signature (`SIGNATURE_DRIFT`). Run
`Blast Radius` to highlight the full transitive impact path across shared hazards and work items.
> **NARRATION:** "Now SRS-201 changes from 5.0 to 5.5. Live Confluence hash reconciliation recomputes the digest,
> revokes the stale signature automatically, and traces the complete transitive blast radius."

### Shot 5 — Gate Enforcement Alongside Compliant Case (2:10–2:40) · screen: Jira transition blocked
**Action:** Attempt to transition an affected/incomplete Jira issue to `Done` using the real Jira
workflow validator—transition is blocked with the exact missing-evidence / signature-drift reason,
contrasted alongside the earlier `Done` issue.
> **NARRATION:** "With approval drifted or evidence missing, the same Jira workflow validator blocks
> the transition to Done—contrasted directly with our compliant issue."

### Shot 6 — Hosted Atlassian MCP Read + Write (2:40–3:20) · screen: MCP client over OAuth 2.1
**Action:** Show the MCP client connected to
`https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` over OAuth 2.1. Run
`verify-iec-compliance-action` (`configuredChecksPassed: false`), then invoke
`create-reverification-task-action` to create and link the Jira re-verification task under user permissions.
> **NARRATION:** "Through hosted Atlassian MCP over OAuth, verify-iec-compliance flags the drift,
> and create-reverification-task creates and links the Jira follow-up task—invoked by the user,
> never silently auto-created."

### Shot 7 — Evidence & Close (3:20–3:50) · screen: Jira link + Audit Log + Export Dossier
**Action:** Briefly show the linked re-verification task inside Jira, the hash-chained Audit Log,
and Export Dossier. Repeat the winning thesis.
> **NARRATION:** "The Jira issue link and hash-chained audit record close the loop. A Confluence
> requirement changes; MedTrace proves the impact, revokes stale approvals, and creates linked
> re-verification work without leaving Atlassian."

**Recording notes:** 1080p minimum, zoom to 125% in Jira, cut all dead time, captions on
(YouTube auto-captions + manual fix of IEC/62304/14971 terms).

---

## Part 2 — 60-minute judge dress rehearsal (do this the day before recording)

1. **Confirm the live dataset on MEDTRACE (10 min):** open the `MEDTRACE` Jira project (six
   issues, correct labels) and the `MEDTRACE` Confluence space (four SRS pages, status current).
   Open the MedTrace project page in `MEDTRACE` → confirm clean uninitialized `LIVE` state →
   click `Sync Live Atlassian` → confirm hazards, tests, and the four SRS links populate,
   MEDTRACE-5 shows the missing-SRS flag, and MEDTRACE-6 is skipped.
2. **Close-the-loop path + real Jira `Under Review → Done` (10 min):** on MEDTRACE-1 (in
   `Under Review`) use `Record Test Result` (`PASSED` + an `https://` evidence URL) →
   `Sign Off Spec (Attestation)` → link flips to `VERIFIED` (and any sibling work sharing the
   same `(hazardKey, specId)` baseline updates too), then transition MEDTRACE-1 to `Done` in Jira
   with `MedTrace Safety Gate` (`medtrace-safety-validator`) attached.
3. **Confluence drift trigger (10 min):** edit SRS-201 (`5.0` → `5.5` mL/hr) and publish →
   reload MedTrace (cross-partition `reconcileConfluenceSpecs`, complementing `avi:confluence:updated:page`) and confirm the signature is revoked → run `Blast Radius`.
   Check `forge logs -e production` for the trigger/reconciliation event if nothing changes.
4. **Negative gate check (5 min):** attempt to transition an affected/incomplete Jira issue to
   `Done` using the live Jira workflow validator and verify it blocks with the exact violation
   alongside the earlier `Done` issue.
5. **Atlassian MCP (10 min):** a site or org admin enables external MCP exposure (Atlassian
   Administration → Apps → Sites → site → Connected apps → MedTrace → turn on tools). Connect an
   MCP client to `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` via the
   OAuth consent screen, run `verify-iec-compliance-action` referencing `MEDTRACE-1` / `SRS-201` → expect
   `configuredChecksPassed: false`, and run `create-reverification-task-action` (confirming task creation,
   honest link reporting, and reuse of any open linked task).
6. **Demo fallback + install smoke (10 min):** on a scratch site, install via the judge-facing
   link → `Seed Demo Suite` → confirm the `DEMO DATASET` badge path still works for evaluators
   with no tenant data.
7. **Recording prep (5 min):** 1080p, zoom 125%, cut dead time, keep under 5:00.

---

## Part 3 — Submission checklist (final 48 hours)

- [ ] Commit, push, and tag the exact submission commit, then deploy HEAD (`npm run build:all && forge deploy -e production` + `forge install --upgrade` on Jira and Confluence so `write:jira-work`, `medtrace-jira-issue-updated`, and `create-reverification-task-action` apply, then refresh the shareable install URL in `devpost_submission_draft.md`), initialize `Sync Live Atlassian` (and `Resume Sync` if truncated) on the active production partition, and verify `production` logs are free of old errors.
- [ ] Verify `verify-iec-compliance-action` and `create-reverification-task-action` over `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` after production sync so they operate on initialized live `MEDTRACE` records.
- [ ] Capture actual current application screenshots (replacing generic AI/crypto artwork thumbnails) and obtain genuine domain feedback from at least one medical-device QA, regulatory, or systems engineer.
- [ ] Record the functioning app, publish it on YouTube, and add the public URL to `devpost_submission_draft.md` (currently a blocker, no URL present).
- [ ] Confirm separate judge-facing Jira and Confluence install links on a fresh site.
- [ ] Provide least-privilege demo accounts; never submit a production webtrigger secret.
- [ ] Re-run `npm run test:all && npm run docs:check && npm run lint:manifest && forge lint` from a clean checkout and verify all checks pass.
