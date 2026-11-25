# Codegeist 2026 — Devpost Submission Draft

> Copy-ready sections for Devpost. Every feature, module, UI label, and test count below reflects the verified repository state.

## Project Title
**MedTrace**

## Elevator Pitch
When a medical-device requirement changes in Confluence (e.g., `5.0 -> 5.5 mL/hr`), MedTrace proves the downstream safety impact, automatically revokes stale approvals across Confluence and Jira, blocks unsafe transitions, and lets engineers create linked Jira re-verification tasks without leaving Atlassian.

## Category / Track
* **Primary Category:** Apps for Specialized Industries
* **Bonus Prize:** Best app with Atlassian MCP

## Inspiration
In regulated medical-device software engineering (IEC 62304, ISO 14971, FDA 21 CFR Part 11), editing a single clinical threshold in Confluence invalidates prior sign-offs and requires re-verifying downstream hazards, Jira work items, and verification tests. Yet engineering teams still maintain traceability matrices in static spreadsheets that drift out of date while developers transition Jira issues to **Done**. MedTrace turns Jira, Confluence, Rovo, and hosted/local MCP clients into a live traceability and release-gate system built natively on Atlassian Forge (`nodejs22.x`).

## What it does
1. **Living 5-Stage Traceability Graph & Matrix:** Connects `ISO 14971 Hazard <-> Confluence SRS <-> Jira Implementation <-> Verification Test <-> Electronic Approval` inside Jira (`jira:projectPage`, `jira:issuePanel`) and Confluence (`confluence:globalPage`, `confluence:contentBylineItem`), clearly distinguishing `UNSIGNED` records from `INVALIDATED` drifted signatures.
2. **Content-Hashed Confluence Sign-Off (`HMAC-SHA256-SEAL-V1`):** Engineers record verification test evidence (`https://` CI URL + timestamp, synced across all links sharing that `testKey`) and execute a session-bound electronic attestation over the Confluence specification's SHA-256 hash across sibling links sharing that `(hazardKey, specId)` baseline.
3. **Transition-Aware Release Gate (`jira:workflowValidator`):** Moving a compliant issue from `Under Review` into `Done` succeeds when SRS linkage, passing test evidence, valid Part 11 signature, and software safety class are satisfied—while missing evidence, drifted signatures, unclassified safety issues, or unverified `Test` issues block release.
4. **Automatic Drift Invalidation & Transitive Blast Radius:** Editing a Confluence SRS page triggers `avi:confluence:updated:page` in Confluence and on-demand cross-partition hash reconciliation in Jira (`reconcileConfluenceSpecs`, prioritizing signed specs across all unique pages in batches), revoking stale baselines without resurrecting invalidated signatures on revert and running deterministic BFS blast-radius analysis.
5. **Hosted Atlassian MCP (`rovo:mcp`), Rovo Agent & Stdio Bridge:** Exposes `get-hazard-lineage-action`, `verify-iec-compliance-action`, and `create-reverification-task-action` to AI tools over hosted Atlassian MCP / OAuth 2.1 (with Teamwork Graph spec owners and user-scoped RBAC), alongside an HMAC-SHA256 stdio MCP bridge (`mcp-server/index.mjs`) for local IDEs and CI pipelines.
6. **Hash-Chained Audit Log & FDA Dossier Export:** Records every sync, bind, test update, task creation, and sign-off in a canonical SHA-256 hash-chained Forge KVS ledger with bounded multi-window verification, Jira + Confluence permission filtering, printable reports, formula-safe CSV export, and JSON dossiers.

## How we built it
* **Backend (`src/`, Forge `nodejs22.x`):** TypeScript compliance engine ([src/compliance-engine.ts](src/compliance-engine.ts)), RBAC & target authorization ([src/rbac.ts](src/rbac.ts)), Forge resolver & trigger wiring ([src/index.ts](src/index.ts)), HMAC-SHA256 CI/MCP webtrigger ([src/webtrigger.ts](src/webtrigger.ts)), sharded `SHARDED_V2` Forge KVS with `vlock` optimistic locking and O(1) `issueKeyIndex` / `meta_index` lookups ([src/seeder.ts](src/seeder.ts), [src/seeder-storage.ts](src/seeder-storage.ts)), per-page Confluence & Jira permission checks ([src/seeder-identity.ts](src/seeder-identity.ts)), paginated live sync (`LIVE_SYNC_BUDGET_MS = 11_000`) & event triggers ([src/ingestion.ts](src/ingestion.ts), [src/triggers.ts](src/triggers.ts)), Teamwork Graph queries ([src/teamwork-graph.ts](src/teamwork-graph.ts)), strictly read-only `GET` Rovo actions ([src/mcp-server.ts](src/mcp-server.ts)), and monotonic SHA-256 audit log ([src/audit-log.ts](src/audit-log.ts)).
* **Frontend (`static/frontend/`):** React 18 Custom UI built with Vite (`@xyflow/react`, Atlassian Design Tokens `--ds-*`, guided 4-step `LIVE` empty-state onboarding via `LiveOnboardingCard`, accessible modal stack, modular `BlastRadiusCard` + `InspectionActionForms`, 30s cache-only polling via `{ skipReconcile: true }`, and Jira/Confluence parity).
* **No External Backend-Fetch Permission (`manifest.yml`):** Declares **no** `permissions.external.fetch.backend` entries—Jira, Confluence, Rovo, and Forge KVS operations run inside Atlassian Cloud (`npm run lint:manifest` and `forge lint -e production` clean). Note: MedTrace is not enrolled in Runs on Atlassian because `mcp-sync-webtrigger` can return requested compliance data to configured callers.

## Honest Scope & Boundaries
* **Assistive tooling, not formal QMS certification:** MedTrace enforces configured traceability and SHA-256 checks; it does not verify test execution authenticity, enforce dual-person QA sign-off, or replace a validated QMS or official FDA eSTAR submission.
* **Software tamper-evidence & Forge KVS boundaries:** Hash chaining + `HMAC-SHA256-SEAL-V1` provide software tamper-evidence in Atlassian Cloud (not hardware WORM, HSM, or third-party PKI); Forge `jira:workflowValidator` also requires calling `verify-release-gate` via `mcp-sync-webtrigger` in CI for automated/REST checks, and Confluence triggers keep per-product KVS partitions fresh on read/gate via `reconcileConfluenceSpecs`.
* **Fallback records:** Tracked Jira issues without native Hazard or Verification Test `issuelinks` use app-managed records labeled `App-Managed` in the UI until native Jira links are added.

## Verification & Quality Bar
* **236 automated tests pass (`0` failures):** **195** backend/MCP/script tests + **41** React/Vitest frontend tests across 7 files, covering RBAC/IDOR isolation, live sync pagination & cursor resume, cross-partition gate reconciliation, `SHARDED_V2` rollback recovery, CAS retry idempotency, and hash-chain verification.
* Strict verification gates (`npm run typecheck`, `npm run build:all`, `npm run test:coverage:all`, `npm run lint:manifest`, `npm run docs:check -- --strict-listing`, and `forge lint -e production`) pass cleanly.

## Judge Evaluation Guide
MedTrace starts fail-closed in `LIVE` mode (`UNINITIALIZED (NO DATA)`, `0 hazards`, blocking release gates) and renders a 4-step guided onboarding card (`Connect Your Live Jira & Confluence Artifacts`) without polluting real workspaces. Choose either walkthrough:

### Option A: 30-Second Zero-Setup Demo Walkthrough
1. Open **MedTrace IEC 62304** on any Jira project (`Apps → MedTrace IEC 62304`), click **Explore Demo Suite** (or **Seed Demo Suite** in the header; confirm overwrite via **Confirm Overwrite & Seed Demo** if an initialized `LIVE` suite already exists) to load the **3-hazard** (`HAZ-101`–`HAZ-103`) Smart Infusion Pump safety scenario.
2. Inspect the live drift on `HAZ-101` / `MED-42` (`5.0 mL/hr -> 5.5 mL/hr`), run **Blast Radius**, test **Test Human Gate**, inspect the hash-chained **Audit Log**, and export the printable **Export Dossier**.

### Option B: Live Jira & Confluence End-to-End Drift Walkthrough
1. **Create linked artifacts:** Create a Confluence SRS page containing `Bolus limit: 5.0 mL/hr`. In Jira, create a Task (e.g. `MED-1`) in **Under Review**, add label `class-c`, and attach the Confluence page via **Link -> Confluence Page** (optional: create Jira `Hazard` / `Test` issues and link via Jira **Link issue**; otherwise MedTrace manages them as `App-Managed`).
2. **Bind the workflow validator:** In **Jira Project Settings -> Workflows**, edit the workflow transition into **Done** and add validator **MedTrace IEC 62304 Safety Gate**.
3. **Sync, verify, and sign off:** Open **Apps -> MedTrace IEC 62304**, click **Sync Live Atlassian**, inspect the row, record `PASSED` test evidence (`https://...`), and complete **Sign Off Spec (Attestation)** with `"I CERTIFY THIS ELECTRONIC SIGNATURE"` -> status turns `VERIFIED` and transitioning `MED-1` to **Done** succeeds.
4. **Trigger drift & Atlassian MCP:** Edit the Confluence page from `5.0` to `5.5 mL/hr` -> MedTrace automatically revokes the signature across Confluence & Jira, blocks **Done** transitions, and traces impact in **Blast Radius**. Enable **MedTrace MCP Server** under Atlassian Admin **Connected apps** (note: Forge stores Jira and Confluence KVS separately, so initialize live sync in whichever product hosts the MCP context) and invoke `verify-iec-compliance-action` + `create-reverification-task-action` to create a linked Jira re-verification task.

## Built With
TypeScript, Node.js (`nodejs22.x`), React 18, Vite, `@xyflow/react`, Atlassian Forge (`@forge/kvs`, Jira REST v3, Confluence REST v2, Teamwork Graph, Rovo Agent & MCP), Model Context Protocol (`@modelcontextprotocol/sdk`).
