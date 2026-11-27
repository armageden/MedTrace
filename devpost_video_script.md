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

### Shot 2 — Live Data & Proof Chain (`SMK` on `farhantanvir277.atlassian.net`) (0:20–0:50) · screen: Jira `SMK` → MedTrace
**Action:** Open MedTrace in `SMK` in empty `LIVE` mode (`RELEASE BLOCKED`) and show **Create Live Proof Chain** (creating Confluence SRS page `4620289` with `5.0 mL/hr`, native Hazard `SMK-1`, Verification Test `SMK-2`, and Work `SMK-3`) or the live synced `SMK` matrix.
> **NARRATION:** "LIVE mode starts fail-closed with zero hazards. Create Live Proof Chain creates real native Jira issues and a Confluence SRS page—with no fabricated test evidence or approvals."

### Shot 3 — Compliant Path: `SMK-3 → Done` (0:50–1:30) · screen: Inspection Drawer → Jira board
**Action:** Record `SMK-2` as `PASSED` (`https://...`), complete `Sign Off Spec (Attestation)`, then transition `SMK-3` to `Done` (`Mark as done`) in Jira with `MedTrace IEC 62304 Safety Gate` (`medtrace-safety-validator`) attached. Transition succeeds (`100% VERIFIED`).
> **NARRATION:** "Recording passing test evidence and signing the Confluence spec's SHA-256 hash satisfies the release gate—so the real Jira workflow validator allows moving SMK-3 to Done."

### Shot 4 — Confluence Drift & Blast Radius (1:30–2:10) · screen: Confluence `4620289` edit → MedTrace graph
**Action:** Edit page `4620289` in Confluence (`5.0` → `5.5` mL/hr, `v2`) and publish. Return to MedTrace: cross-partition Confluence hash reconciliation automatically revokes the signature (`INVALIDATED`). Run `Blast Radius` to highlight all 4 hops (`SMK-1`, `SMK-3`, `SMK-2`, revoked `PART11_ATTESTATION`).
> **NARRATION:** "Now the Confluence SRS changes from 5.0 to 5.5. Live hash reconciliation recomputes the SHA-256 digest, revokes the stale signature automatically, and traces the complete 4-hop blast radius."

### Shot 5 — Live Gate Block & Re-Verification Closeout (2:10–2:40) · screen: Jira `SMK-4` transition blocked → approved
**Action:** Create linked re-verification task `SMK-4` (`medtrace-reverification`), attempt `Mark as done` on `SMK-4` in Jira while drifted -> blocked live by the workflow validator. Re-record `SMK-2` `PASSED`, re-sign `SMK-1` (`v2`), and transition `SMK-4` to `Done` (`APPROVED`).
> **NARRATION:** "While drifted, the Jira workflow validator blocks SMK-4 from Done. Once re-tested and re-signed for v2, SMK-4 transitions cleanly to Done."

### Shot 6 — Ask Rovo (`MedTrace Auditor`) & Hosted Atlassian MCP (2:40–3:20) · screen: Jira Ask Rovo + Claude Code OAuth MCP
**Action:** In Jira **Ask Rovo** (`MedTrace Auditor`), run `get-hazard-lineage-action` and `verify-iec-compliance-action` (`MEDTRACE-4` verified, `MEDTRACE-1` flagged), and show Claude Code connected over OAuth 2.1 to `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` invoking live hosted MCP tools (failing closed on uninitialized partitions).
> **NARRATION:** "Inside Jira Ask Rovo and over hosted Atlassian MCP with OAuth 2.1, MedTrace Auditor verifies live lineage and fails closed whenever a product partition is uninitialized."

### Shot 7 — Evidence & Close (3:20–3:50) · screen: Jira link + Audit Log + Export Dossier
**Action:** Briefly show the linked re-verification task inside Jira, the hash-chained Audit Log, and Export Dossier. Repeat the winning thesis.
> **NARRATION:** "The Jira issue link and hash-chained audit record close the loop. A Confluence requirement changes; MedTrace proves the impact, revokes stale approvals, and gates unsafe releases without leaving Atlassian."

**Recording notes:** 1080p minimum, zoom to 125% in Jira, cut all dead time, captions on
(YouTube auto-captions + manual fix of IEC/62304/14971 terms).

---

## Part 2 — Rehearsal checklist (SMK on farhantanvir277 + Ask Rovo on MEDTRACE)

1. **Confirm live `SMK` proof chain (`farhantanvir277.atlassian.net`):** `SMK-1` (Hazard `CLASS C`), `SMK-2` (Test), `SMK-3` (Work), `SMK-4` (`medtrace-reverification`), and Confluence SRS `4620289` (`v2`, `5.5 mL/hr`).
2. **Confirm Jira workflow validator binding:** `MedTrace IEC 62304 Safety Gate` (`medtrace-safety-validator`) bound on `Mark as done` in `SMK`.
3. **Ask Rovo (`MedTrace Auditor` on `one-atlas-feur.atlassian.net`):** Query `MEDTRACE-4` (passes) and `MEDTRACE-1` (flagged).
4. **Hosted MCP (`rovo:mcp`):** `claude mcp` connected to `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` over OAuth 2.1 (`verify-iec-compliance-action`, `get-hazard-lineage-action`).
5. **Recording prep:** 1080p, zoom 125%, cut dead time, keep under 5:00.

---

## Part 3 — Submission checklist (final 48 hours)

- [ ] Commit, push, and tag the exact submission commit, then deploy HEAD (`npm run build:all && forge deploy -e production` + `forge install --upgrade` on Jira and Confluence so `write:jira-work`, `write:page:confluence`, `medtrace-jira-issue-updated`, `createLiveProofScenario`, and `create-reverification-task-action` apply, then refresh the shareable install URL in `devpost_submission_draft.md`), initialize `Sync Live Atlassian` (and `Resume Sync` if truncated) on the active production partition, and verify `production` logs are free of old errors. For the fastest native-artifact rehearsal path, use **Create Live Proof Chain** and [docs/00-how-to/04-live-judge-proof.md](docs/00-how-to/04-live-judge-proof.md) instead of manually assembling all five artifact relationships.
- [ ] Verify `verify-iec-compliance-action` and `create-reverification-task-action` over `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` after production sync so they operate on initialized live `MEDTRACE` records.
- [ ] Capture actual current application screenshots (replacing generic AI/crypto artwork thumbnails) and obtain genuine domain feedback from at least one medical-device QA, regulatory, or systems engineer.
- [ ] Record the functioning app, publish it on YouTube, and add the public URL to `devpost_submission_draft.md` (currently a blocker, no URL present).
- [ ] Confirm separate judge-facing Jira and Confluence install links on a fresh site.
- [ ] Provide least-privilege demo accounts; never submit a production webtrigger secret.
- [ ] Re-run `npm run test:all && npm run docs:check && npm run lint:manifest && forge lint --approve MAJOR_VERSION_RULE` from a clean checkout after reviewing the intentional `write:page:confluence` major-version consent change, and verify all checks pass.
