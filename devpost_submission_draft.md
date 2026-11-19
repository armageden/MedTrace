# MedTrace: IEC 62304 Traceability & Blast Radius Engine

## Tagline
Deterministic IEC 62304 & ISO 14971 traceability for Jira, Rovo, and MCP, with a synthetic 500-node graph test enforcing a 20 ms traversal ceiling.

---

## Track & Category Nominations
* **Primary Category:** Apps for Specialized Industries (Medical Devices & Healthcare Engineering)
* **Target Bonus Prize (select 1 per official rules; do NOT enter Best Marketplace Published App on this same App ID, as Marketplace listing disables shareable installation links):**
  * Best Agents — Rovo / Assignable agents (`rovo:agent` MedTrace Regulatory Auditor + `get-hazard-lineage-action` / `verify-iec-compliance-action`)
  * Best App with Atlassian MCP (`rovo:mcp` server exposing both actions through the Atlassian-hosted MCP endpoint)
  * Best Apps with Teamwork Graph Integration (`confluencePageOwners` curated query via `api.asUser().requestTeamworkGraph`, surfacing Confluence spec owners for review in the Inspection Drawer and Rovo hazard lineage)
  * *Per the rules, a submission can win at most one bonus prize (and one main-category prize).*

---

## Inspiration
Medical device software engineering is governed by strict life-safety standards: IEC 62304 (Medical Device Software Lifecycle Processes), ISO 14971 (Application of Risk Management to Medical Devices), and FDA 21 CFR 807.92 (Premarket Notification 510(k) Summary Documentation). In medical device R&D, a code change is never just a code change: if an engineer modifies an infusion pump flow-rate constant from 5.0 mL/hr to 5.5 mL/hr, that single parameter update cascades across clinical hazard assessments, software requirement specifications (SRS), electronic approval hashes, and verification test runs.

Historically, engineering teams manage this burden through external Application Lifecycle Management (ALM) or electronic Quality Management Systems (eQMS) that require syncing sensitive design history files, proprietary device specifications, and architectural documentation to third-party cloud infrastructure.

MedTrace targets the reconciliation work of linking hazards, specifications, Jira tasks, verification evidence, and approval records. The demo models this workflow; it is not customer research or evidence of measured time savings.

### Goals & Non-Goals
* **Goals:**
  * Automate bidirectional traceability verification directly within Jira and Confluence.
  * Enforce hard release gate transitions using fast-path workflow validation.
  * Provide optional developer-facing IDE assistance via Model Context Protocol (MCP), with query results returned to the configured client.
  * Maintain tamper-evident cryptographic audit logs for electronic signatures.
* **Non-Goals:**
  * MedTrace is **not** an active Medical Device Data System (MDDS) and does not directly connect to infusion pump physical hardware or patient telemetry.
  * MedTrace does not replace formal notified body / FDA auditor evaluations or produce an official FDA eSTAR submission.

---

## What it does
MedTrace provides deterministic regulatory traceability and safety release gating for medical device software in Atlassian Cloud:

### 1. Deterministic Regulatory Blast Radius Engine
When a specification, hazard mitigation, or test run changes, MedTrace traverses the entire 5-stage transitive traceability chain:

`ISO 14971 Clinical Hazard ↔ Safety Requirement (Confluence SRS) ↔ Jira Work Item (e.g., MED-42) ↔ Verification Test Issue (e.g., TEST-88) ↔ Clinical Approval Hash`

On a synthetic 500-node graph benchmark (100 five-stage trace links), MedTrace computes the blast radius using deterministic breadth-first traversal with cycle detection. The automated test enforces a **20 ms ceiling** on this synthetic case; this is not a production latency guarantee.

### 2. Cryptographic Approval Hash Drift Detection
MedTrace records an approval attestation and SHA-256 content digest for a Confluence specification. On evaluation, it compares the current digest with the stored baseline and flags detected drift. These software controls are not a claim that MedTrace conforms to 21 CFR Part 11 or has been validated for use in a regulated quality system.

### 3. IEC 62304 Safety Release Gate (Jira Workflow Validator)
MedTrace implements configurable Class A/B/C release rules intended to support traceability work associated with IEC 62304 and ISO 14971. The rules are not a standards-conformance determination:
* **Class A (No injury):** Requires documented safety requirements, passing verification tests (`PASSED`), and valid Part 11 approval hashes. Unverified coverage or failing tests result in `INCOMPLETE` status and **block release transitions** via the shared release gate.
* **Class B (Non-serious injury):** Requires passing verification tests, active requirement links, and valid approval hashes. Unverified gaps result in `INCOMPLETE` status and **block transitions**.
* **Class C:** Requires the configured verification evidence and matching approval hash before related tracked Jira issues can pass MedTrace's gate. Unverified gaps or signature drift trigger **`SAFETY_VIOLATION`**.

*Deployment Architecture & Evaluator Testing:* The release gate is implemented as a Forge `jira:workflowValidator` module declared in `manifest.yml` (`src/workflow-validator.ts`). Because attaching Forge validators to live workflows requires Jira site-admin privileges, MedTrace provides two direct evaluator verification paths: (1) an in-app "Test Human Gate" button in the Custom UI header and issue panel running the live backend validator handler, and (2) an authenticated webtrigger action (`simulate_transition` or `verify-release-gate`) runnable via curl.

### 4. Traceability Evidence Export
Provides JSON, CSV, and printable traceability reports with linked artifacts, status, and hashes. These are supporting records, not an official FDA eSTAR form, 510(k) submission, or assurance that a dossier is ready for regulatory review.

### 5. Optional Developer Assistant: Connected IDE Context (MCP) & Rovo Compliance Agent
*Optional, non-PHI, assistive tooling: does not affect the core regulatory engine.*

For developer convenience during implementation, MedTrace provides:
* **Atlassian Rovo Agent (`rovo:agent`):** An assistive agent that runs deterministic graph checks and returns affected hazards and blocked Jira items.
* **Atlassian-hosted MCP (`rovo:mcp`) — primary path:** The `medtrace-mcp-server` module exposes `get-hazard-lineage-action` and `verify-iec-compliance-action` through Atlassian's MCP server at `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99`. External MCP exposure is disabled by default; a site or org admin enables it per app installation in Atlassian Administration → Apps → Sites → site → Connected apps → MedTrace. MCP clients connect over OAuth 2.1 (the user picks the site and approves), and tools run subject to the invoking user's own permissions.
* **Local stdio MCP bridge (`mcp-server/`) — optional secondary:** A standalone stdio bridge for local IDE clients, forwarding signed requests to the app's HMAC-authenticated Forge webtrigger. Requested response data is returned to that client; the client may retain it under its own policies.

*Example IDE Interaction:*
> **Developer in Cursor:** *"I am modifying `pump_motor.c` to change bolus flow-rate threshold to 5.5 mL/hr. Does this touch any IEC 62304 hazard?"*  
> **MedTrace MCP Response:** *"⚠️ CRITICAL: Diff modifies bolus delivery logic governed by ISO 14971 Class C Hazard HAZ-101. IEC 62304 verification test TEST-88 is UNTESTED and Confluence spec SRS-104 has signature drift. Release is BLOCKED until remediated."*

*Data and Regulatory Boundary:* MedTrace is intended for non-PHI engineering metadata, but does not detect or redact PHI in source fields. Do not ingest patient information. MCP/CI responses may transmit requested tenant data to the configured client. The assistant is not connected to device runtime and does not make regulatory determinations.

---

## How we built it
MedTrace was built natively on the Atlassian Forge platform using TypeScript, React, and `@forge/kvs`:

* **Atlassian Forge Custom UI:** React frontend running inside Jira Cloud (issue panel + project page) providing interactive traceability graphs (`@xyflow/react`), real-time blast radius inspection, and safety gate status.
* **Deterministic BFS Traversal Engine (`src/compliance-engine.ts`):** In-memory adjacency-list graph engine engineered with cycle detection, pre-computed edge sets, and zero external database round-trips.
* **Jira Workflow Validator (`src/workflow-validator.ts`):** Native Forge workflow validator applying MedTrace's configured release rules and approval-hash checks to transitions where Jira invokes the validator.
* **Cross-Product Context Resolution (`src/teamwork-graph.ts`):** Resolves Jira issue links, remote links, and linked Confluence safety specifications through Jira REST API v3 and Confluence REST v2 (`JIRA_REST` + `JIRA_REMOTELINK_REST`), plus user-context Teamwork Graph `confluencePageOwners` curated queries (`api.asUser().requestTeamworkGraph` under `read:graph:page:confluence` and `read:graph:user:atlassian`) to surface Confluence spec owners for re-review in the Inspection Drawer and Rovo hazard lineage.
* **Secure Webtrigger Gateway (`src/index.ts`, `src/nonce-store.ts`):**
  * **HMAC-SHA256 Auth:** Cryptographic HMAC-SHA256 signature verification (`x-medtrace-signature`) over `${timestamp}.${nonce}.${rawBody}`, with a required nonce and 5-minute replay window. The shared secret is never transmitted.
  * **Anti-Replay Defense:** Enforces a 300-second timestamp validity window and atomic single-operation nonce reservation via `@forge/kvs` with `keyPolicy: 'FAIL_IF_EXISTS'` and TTL, eliminating race conditions across serverless micro-VMs.
* **Forge Network Boundary:** The manifest does not declare `permissions.external.fetch.backend`, so Forge cannot initiate those external backend fetches. Authenticated MCP/CI calls intentionally return requested compliance data to their configured clients; this is not a zero-data-egress guarantee.

### Architectural Alternatives Considered
* **Inbound Webtrigger vs. Outbound Event Webhooks / Polling:** The inbound webtrigger avoids granting Forge an external-fetch permission. Its authenticated responses still send requested results to the calling MCP/CI client.
* **In-Memory BFS Traversal vs. Live GraphQL Multi-Join:** Pre-indexing the trace graph into memory avoids multi-hop REST/GraphQL network calls during Jira workflow transitions, meeting Forge's serverless execution timeout limits without database round-trips.
* **Tenant-Scoped KVS vs. External eQMS Database:** MedTrace stores its persisted suite in Forge KVS; configured MCP/CI clients can receive requested results outside the tenant.
* **Artifact-Node BFS vs. Per-Link Fixed Walk (ADR 004):** A naive per-link walk was rejected because it never traversed into sibling requirements mitigating the same hazard. We built genuine artifact-node BFS traversal so drift propagates transitively across shared hazard nodes.

---

## Challenges we ran into
* **Serverless Nonce Persistence in Forge:** Forge webtriggers execute in ephemeral serverless micro-VMs where module-level in-memory caches do not persist between invocations. To prevent replay attacks across distinct runtime instances, we abstracted storage behind a `NonceStore` interface using `@forge/kvs` native atomic TTL and collision detection (`keyPolicy: 'FAIL_IF_EXISTS'`).
* **Circular Regulatory Traceability:** Real-world engineering requirements frequently contain circular references (e.g., Hazard -> Spec -> Sub-Hazard -> Spec). We implemented visited-set cycle prevention in our BFS engine to guarantee deterministic termination on circular trace links.
* **Workflow Validator Boundary:** Atlassian issue [ECO-624](https://jira.atlassian.com/browse/ECO-624) reports a Jira Automation case but is marked Invalid; it does not establish direct REST API behavior. The repository's release-gate workflow runs on pull requests and pushes to main when its secrets are configured, plus manual and published-release triggers.
* **Cryptographic Timing Defenses:** Ensuring HMAC validation was protected against timing side-channel attacks required validating signature buffer lengths prior to executing constant-time `crypto.timingSafeEqual`.
* **Prior Credential Exposure:** A previously committed MCP secret was rotated on 2026-11-15; the old value is rejected (HTTP 401) by the production and development webtrigger endpoints. Removal of the value from Git history is still pending.

---

## Honest Scope & System Limitations
To ensure transparent evaluation by technical judges, we explicitly document MedTrace's architectural boundaries:
* **Workflow Validator Attachment Requires Jira Site-Admin:** The release gate is implemented as a native Forge `jira:workflowValidator` declared in `manifest.yml`. Attaching it to a live Jira workflow transition requires Jira site-administration permissions; for non-admin evaluators, the app includes an interactive in-app simulation harness invoking the exact same validator handler.
* **Validator Scope:** Atlassian issue [ECO-624](https://jira.atlassian.com/browse/ECO-624) reports an Automation case but is marked Invalid and does not establish direct REST API behavior. The included release-gate workflow runs from CI on pull requests and pushes to main when its secrets are configured.
* **Cross-Product Context & Teamwork Graph Scope (`read:graph:*` Preview Fallback):** `manifest.yml` declares `read:graph:page:confluence` and `read:graph:user:atlassian` for the `confluencePageOwners` curated query (`api.asUser().requestTeamworkGraph`, `@forge/api` `8.5.0`). Jira REST v3 + Confluence v2 REST links remain primary; if Preview graph scopes are not granted by a tenant admin or return GraphQL errors, evaluations degrade gracefully (`teamworkGraphStatus: 'EMPTY' | 'ERROR'`) without blocking core traceability.
* **Forge KVS Storage & Sharded Persistence (`SHARDED_V2`):** Forge KVS enforces per-entity and transaction limits (`<= 25` ops per `kvs.transact()`). MedTrace ships `SHARDED_V2` entity-scoped sharding (`medtrace:compliance:link:...`) with content-hash shard reuse, bounded 128 KiB `ShardedSuiteMetaV2` metadata (`medtrace:compliance:suite_meta`), overflowing `meta_index` O(1) lookup shards (`issueKeyIndex`), and resumable `nextPageToken` live sync pagination (`MAX_SYNC_MAX_ISSUES = 500`, `LIVE_SYNC_BUDGET_MS = 15_000` per invocation).
* **Non-PHI Intended Use:** MedTrace is intended for engineering metadata and has no PHI detection or redaction. Customers must not put PHI in fields MedTrace ingests. This is not a HIPAA compliance or BAA determination.
* **Demo vs. Live:** A deterministic demo fixture is labeled `DEMO DATASET: MODELED RECORDS`. Demo records are not evidence about a real device or customer system.
* **Regulatory Framing:** MedTrace is an assistive traceability tool, not a regulatory authority, certified product, validated QMS, or official FDA submission generator.

---

## Accomplishments that we're proud of
* **Test-Enforced Deterministic Traversal:** Blast-radius BFS over the artifact-node graph completes the 500-node synthetic benchmark in under 20ms (a ceiling asserted by the automated test suite itself), delivering instant transitive impact analysis inside Jira.
* **Defensible Regulatory Framing:** Grounded MedTrace strictly in formal IEC 62304 software verification clauses (Clause 5.7 system testing and Clause 5.8 software release) and ISO 14971 risk classifications, avoiding ungrounded marketing claims.
* **Replay Defense Tests:** Automated tests cover HMAC validation and nonce replay behavior. They do not establish a current production deployment result.
* **Automated Test Suite:** 200 automated tests (166 backend/MCP/script tests across 29 suites + 34 React/Vitest frontend tests), covering `verify-release-gate` CI semantics (HTTP 403-on-block), cross-project RBAC, Confluence-to-Jira `LIVE` read isolation, unbound-hazard operator guards and target-issue IDOR guards, `SHARDED_V2` storage + rollback, Forge `rovo:action` payload contracts, fail-closed `safetyClassAssigned: false` hazard classification, Teamwork Graph `confluencePageOwners` parsing (including partial GraphQL error tolerance), Part 11 cryptographic seals, and transitive blast-radius propagation, accompanied by zero-warning docs-sync checks.
* **Honest-Failure UX as a Feature:** Every backend failure path renders an explicit error banner or a "no verdict rendered" state: the UI and MCP tools never fabricate compliance evidence, remediation success, or Teamwork Graph traversals, and demo records carry a persistent `DEMO DATASET: MODELED RECORDS` badge.

---

## What we learned
* How to query Atlassian Forge context while making the MCP/CI data-return boundary explicit.
* The nuances of building resilient idempotency and replay guards in serverless Atlassian environments using `@forge/kvs`.
* How to bridge developer IDEs via local MCP to Atlassian Cloud while keeping demo data distinct from live records and disclosing returned data.
* That "honest or it didn't happen" applies to algorithms too: our original "BFS" was really a per-link walk, so we rebuilt it as a genuine artifact-node breadth-first traversal (ADR 004) rather than rewording the claim.

---

## What's next for MedTrace
* **Atlassian Teamwork Graph API Expansion:** Extending beyond `confluencePageOwners` to additional `read:graph:*` curated queries (page contributors, cross-product issue/deployment edges) as Atlassian promotes Teamwork Graph schemas out of preview.
* **Jira Service Management Clinical Change Requests:** Connecting customer-reported medical device post-market surveillance issues directly into ISO 14971 risk mitigations.

---

## Built with
* Atlassian Forge
* TypeScript
* React 18 & @xyflow/react
* Forge KVS
* Jira Cloud
* Confluence Cloud
* Model Context Protocol (MCP)
* Crypto HMAC-SHA256
* Node.js Test Runner

---

## Try it out
* **Installation Link:** `[[INSTALL_LINK — paste from Developer Console → Distribution]]`
* **Demo Video (< 5:00):** `[[YOUTUBE_URL]]`
* **GitHub Repository:** [https://github.com/armageden/MedTrace](https://github.com/armageden/MedTrace) (Public, Apache-2.0, with automated test suite)

### Judge walkthrough

1. **Install** the app on your Jira + Confluence site using the installation link above.
2. **Open a Jira project** → **Apps** → **MedTrace IEC 62304** project page.
3. **Load data** — pick one:
   * **(i) Demo dataset:** click `Seed Demo Suite` to load the labelled modeled dataset (`DEMO DATASET` badge).
   * **(ii) Live sync:** label issues `iec-62304` plus a risk class (`class-a`, `class-b`, or `class-c`), add a Confluence page as a Jira remote link (`Wiki Page`), then click `Sync Live Atlassian`. Tracked issues become hazards/tests starting `UNTESTED` and unsigned — the release starts `BLOCKED` (fail-closed).
4. **Rovo:** open Rovo chat, choose **MedTrace Auditor**, and use a conversation starter (e.g., hazard lineage or an IEC 62304 compliance check).
5. **Atlassian MCP:** a site or org admin enables external MCP exposure in Atlassian Administration → Apps → Sites → site → Connected apps → MedTrace, then connect an MCP client to `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` via the OAuth consent screen.
