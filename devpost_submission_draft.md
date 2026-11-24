# MedTrace

## Tagline
When a signed medical-device requirement changes, MedTrace identifies the affected hazards and verification work, invalidates stale approval evidence, creates linked re-verification tasks, and enforces the configured release gate.

---

## Track & Category Nominations
* **Primary Category:** Apps for Specialized Industries (Medical Devices & Healthcare Engineering)
* **Bonus Prize Target:** **Best App with Atlassian MCP** (`rovo:mcp` server `medtrace-mcp-server` exposing `get-hazard-lineage-action`, `verify-iec-compliance-action`, and `create-reverification-task-action` at `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` over OAuth 2.1 when enabled by a site/org admin under Connected apps).

---

## The Problem
In medical-device software engineering (IEC 62304, ISO 14971, FDA 21 CFR Part 11), a single specification edit—such as changing an infusion pump bolus limit from `5.0 mL/hr` to `5.5 mL/hr`—invalidates prior clinical sign-offs and requires re-verifying downstream hazards, implementation work, and test evidence.

Teams managing specs in Confluence and work in Jira either reconcile those links manually in spreadsheets or replicate proprietary design history files into external eQMS tools.

---

## One Closed-Loop Workflow in Atlassian Cloud
1. **Live Atlassian Lineage (`read:jira-work` + Confluence REST v2):** MedTrace ingests safety-labeled Jira issues (`class-a`, `class-b`, `class-c`), Jira `/remotelink` Confluence SRS pages, and native Jira `issuelinks` (resolving linked Hazard and Verification Test issues directly while labeling any unlinked item `App-Managed` and avoiding fabricated ISO severity/probability fields). Incomplete multi-page or budget-truncated syncs persist `syncIncomplete: true` and keep the global release gate blocked until **Resume Sync** finishes.
2. **Content-Hashed Confluence Approval:** Engineers record verification test evidence (`https://` URL + execution timestamp) and execute a session-bound electronic attestation over the Confluence specification's SHA-256 content hash (`HMAC-SHA256-SEAL-V1`), updating every trace link sharing that `(hazardKey, specId)` approval baseline.
3. **Transition-Aware Release Gate (`jira:workflowValidator`):** Moving a compliant issue from `Under Review` into `Done` succeeds when spec linkage, passing test evidence, valid Part 11 signature, and software safety class are satisfied—while missing evidence, drifted signatures, or unclassified safety issues block the transition.
4. **Automatic Drift Invalidation & Transitive Blast Radius:** Editing the Confluence SRS (e.g., `5.0` → `5.5 mL/hr`) triggers `avi:confluence:updated:page`. MedTrace recomputes the SHA-256 digest, revokes the stale approval baseline (without resurrecting invalidated signatures if reverted), and traces transitive impact across shared hazards, Jira work items, and verification tests.
5. **User-Invoked Linked Re-Verification Task (`write:jira-work`):** Triggered explicitly by an authorized user from the Inspection Drawer, Rovo Agent (`medtrace-regulatory-auditor`), or hosted Atlassian MCP (`create-reverification-task-action`)—never auto-created by Confluence edits—MedTrace creates a Jira re-verification task, attempts Jira `issuelink` creation (honestly reporting any failed or missing links), and appends every event to the SHA-256 hash-chained audit ledger (`FAIL_IF_EXISTS`) for JSON, CWE-1236-safe CSV, or printable dossier export.

---

## What Differentiates MedTrace
* **Content-hashed Confluence approval baselines:** Signatures bind to the exact SHA-256 of Confluence storage markup, with automatic revocation on edit and revert non-resurrection.
* **Transitive artifact-node blast radius:** Traverses M:N shared hazards and specs across `SIGNS`, `MITIGATES`, `IMPLEMENTS`, and `VERIFIES` edges.
* **Dual-surface enforcement (UI + MCP + CI):** `rovo:mcp` exposes read and re-verification write actions under the invoking user's own Atlassian OAuth permissions, while `mcp-sync-webtrigger` enforces HMAC-SHA256 + KVS nonce replay protection for CI release gates.
* **Cross-project tenant isolation & honest failure states:** Read, mutation, blast-radius, audit-log, and export paths enforce Jira project-level isolation; cold starts fail closed (`UNINITIALIZED`); demo fixtures carry persistent `DEMO DATASET — MODELED RECORDS` badges.

---

## Architecture
* **Forge Runtime (`nodejs22.x`):** Custom UI (`React 18` + `@xyflow/react` + Matrix table defaulting to matrix on `>= 25` links), `jira:projectPage`, `jira:issuePanel`, `jira:workflowValidator`, `confluence:globalPage`, `confluence:contentBylineItem`, product triggers (`avi:confluence:updated:page`, `avi:jira:updated:issue`, `avi:jira:created:issuelink`, `avi:jira:deleted:issuelink`), `rovo:agent`, `rovo:mcp`, and `webtrigger`.
* **Storage:** Sharded Forge KVS (`SHARDED_V2` with `vlock` optimistic locking and save-before-audit rollback), composite `(hazardKey, specId)` `SignedSpecBaseline` records, and SHA-256 hash-chained audit entries.
* **Network Boundary:** `manifest.yml` declares no `permissions.external.fetch.backend`; Forge executes all Jira/Confluence reads and re-verification issue writes inside Atlassian Cloud. (Configured MCP/CI clients receive requested responses under their own retention policies.)

---

## Honest Scope & Limitations
* **Assistive tooling, not regulatory certification:** MedTrace enforces configured traceability and hash checks; it does not verify test execution authenticity, require independent second-person QA sign-off, or constitute a validated QMS, HIPAA/BAA control, or official FDA eSTAR submission.
* **Software tamper-evidence boundary:** Forge KVS is not hardware WORM, HSM-backed, or X.509/PKI; `attestationChecked` is a session confirmation checkbox rather than IdP password re-authentication.
* **Workflow validator attachment & boundary:** Attaching `jira:workflowValidator` to live Jira workflows requires Jira site-admin privileges (evaluators can also run the shared handler via `Test Human Gate` or CI `verify-release-gate`). See [ECO-624](https://jira.atlassian.com/browse/ECO-624) notes in `SECURITY.md` for workflow boundary context.
* **Fallback records:** Tracked Jira issues without native Hazard or Verification Test `issuelinks` fall back to app-managed hazard/test records labeled `App-Managed` in the UI.
* **No measured customer study yet:** The workflow models medical-device change-impact reconciliation; no customer field study or measured time-saving benchmark is claimed.

---

## Verification Appendix (Local Suite)
* Automated tests cover transition-aware `jira:workflowValidator` (`Under Review → Done` positive/negative paths), shared-baseline `signOffPart11`, honest partial-linking & `issuelinks` reuse checks in `createReverificationTask`, resumable multi-page/mid-enrichment `LiveIngestionService` sync, backend RBAC/two-project isolation, `SHARDED_V2` KVS rollback, hash-chained audit verification, Rovo/MCP contracts, manifest validation (`npm run lint:manifest`), and strict docs checks (`npm run docs:check`).

---

## Try It Out
* **Installation Link (Jira + Confluence):** Regenerate/verify after final production `forge deploy` (`App ID: 5e49c10e-696f-4984-9d00-4a47d0a5dd99`) — see [devpost_video_script.md](devpost_video_script.md).
* **Demo Video (< 5:00):** `[[YOUTUBE_URL]]`
* **GitHub Repository:** https://github.com/armageden/MedTrace (Apache-2.0)

### Judge Walkthrough (Fresh Install & Live Evaluation)
1. **Install on Jira + Confluence:** Install MedTrace on both Jira and Confluence on the same Atlassian Cloud site (or use `--upgrade` when updating scopes). Ensure the Confluence integration and Jira integration share the same target site, and if testing Atlassian MCP (`https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99`), run **Sync Live Atlassian** inside the same product partition enabled under **Atlassian Administration → Apps → Sites → Connected apps**.
2. **Prepare Jira & Confluence Artifacts:**
   - **Confluence:** Create an SRS page (e.g., `SRS-201: Bolus Rate Hard Limit` containing `5.0 mL/hr`).
   - **Jira Issue Types & Labels:** Create a `Story` or `Task` (e.g., `MEDTRACE-1`) in status `Under Review` with label `class-c` (or `class-b` / `class-a`; issues without a class label are flagged fail-closed as Class C unclassified). Optionally create a `Hazard` (or `Risk` / `Safety Hazard`, or label `medtrace-hazard`) and `Test` (or label `medtrace-test`) Jira issue.
   - **Confluence Remote Link:** On `MEDTRACE-1`, click **Link → Confluence page** (remote link) and attach `SRS-201`.
   - **Native Jira Issue Links (optional):** Link `MEDTRACE-1` to the `Hazard` issue (`mitigates` / `is mitigated by`) and `Test` issue (`tests` / `is verified by`).
   - **Workflow Validator (Jira Admin):** Under **Jira Project Settings → Workflows**, attach **MedTrace Safety Gate** (`medtrace-safety-validator`) to the release transition (e.g., `Under Review → Done`).
3. **Run the Closed-Loop Workflow:**
   - Open **Jira Project → Apps → MedTrace IEC 62304**. Cold start shows `UNINITIALIZED (NO DATA)` and `RELEASE BLOCKED` (fail-closed). Click **Sync Live Atlassian** (if a large workspace truncates, click **Resume Sync** until `SYNC INCOMPLETE` clears).
   - Select `MEDTRACE-1` in the Matrix/Graph, record `PASSED` test evidence (`https://...`), and execute **Sign Off Spec (Attestation)** with `"I CERTIFY THIS ELECTRONIC SIGNATURE"`. Expect the link state to flip to `VERIFIED` (along with any sibling work items sharing that `(hazardKey, specId)` baseline).
   - Transition `MEDTRACE-1` from `Under Review → Done` in Jira: **allowed**.
   - Edit `SRS-201` in Confluence from `5.0` to `5.5 mL/hr` and publish: `avi:confluence:updated:page` revokes the signature (`SIGNATURE_DRIFT`) and **Blast Radius** highlights the full chain. Transitioning an unverified/drifted issue to `Done` is **blocked**.
   - Click **Create Re-Verification Jira Task** (or invoke `verify-iec-compliance-action` + `create-reverification-task-action` via hosted Atlassian MCP): a linked Jira task is created under your user permissions and recorded in **Audit Log** / **Export Dossier**.
4. **Recovery (Uninitialized or Wrong Partition):** If `rovo:mcp` or `Test Human Gate` reports `uninitialized (0 hazards synced)`, confirm you opened MedTrace in the same product (Jira vs Confluence) exposed in Connected apps and click **Sync Live Atlassian** (or **Seed Demo Suite** on a scratch evaluation site for the labeled `DEMO DATASET` path).
