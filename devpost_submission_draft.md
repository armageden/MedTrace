# MedTrace: IEC 62304 Traceability & Blast Radius Engine

## Tagline
Deterministic IEC 62304 & ISO 14971 traceability for Jira, Rovo, and MCP, computing multi-hop regulatory blast radius with sub-20ms BFS graph traversal and zero outbound egress.

---

## Track & Category Nominations
* **Primary Category:** Apps for Specialized Industries (Medical Devices & Healthcare Engineering)
* **Target Bonus Prizes:**
  * Best Agents - Rovo / Assignable agents (`rovo:agent` MedTrace Auditor + actions)
  * Best App with Atlassian MCP (`rovo:mcp` + local stdio MCP server for Cursor)
  * Best Apps with Teamwork Graph (TWG) integration (AGG GraphQL traversal with Jira REST fallback)
  * Best Marketplace published app (Listing prepared with full legal & support documentation)

---

## Inspiration
Medical device software engineering is governed by strict life-safety standards: IEC 62304 (Medical Device Software Lifecycle Processes), ISO 14971 (Application of Risk Management to Medical Devices), and FDA 21 CFR 807.92 (Premarket Notification 510(k) Summary Documentation). In medical device R&D, a code change is never just a code change: if an engineer modifies an infusion pump flow-rate constant from 5.0 mL/hr to 5.5 mL/hr, that single parameter update cascades across clinical hazard assessments, software requirement specifications (SRS), electronic approval hashes, and verification test runs.

Historically, engineering teams manage this burden through external Application Lifecycle Management (ALM) or electronic Quality Management Systems (eQMS) that require syncing sensitive design history files, proprietary device specifications, and architectural documentation to third-party cloud infrastructure.

> *"Before an FDA audit, our engineering team spent nearly three weeks cross-referencing Confluence PRDs against Jira issues and test logs in Excel just to prove a single algorithm tweak didn't invalidate our safety envelope. Having continuous blast-radius impact analysis inside Jira would have saved us 120+ hours of forensic reconciliation."*  
> (Team experience prior to MedTrace: embedded firmware engineering, Class II infusion systems)

Jira and Confluence already store the underlying engineering artifacts: Jira issues hold requirements, test runs, and tasks; Confluence holds clinical risk assessments and architecture specifications. What was missing was **deterministic, zero-egress graph traceability** linking these artifacts directly inside Atlassian Forge without exporting sensitive medical device designs outside the manufacturer's Atlassian tenant.

### Goals & Non-Goals
* **Goals:**
  * Automate bidirectional traceability verification directly within Jira and Confluence.
  * Enforce hard release gate transitions using fast-path workflow validation.
  * Provide developer-facing IDE assistance via Model Context Protocol (MCP) without compromising HIPAA boundaries.
  * Maintain tamper-evident cryptographic audit logs for electronic signatures.
* **Non-Goals:**
  * MedTrace is **not** an active Medical Device Data System (MDDS) and does not directly connect to infusion pump physical hardware or patient telemetry.
  * MedTrace does not replace formal notified body / FDA auditor evaluations; it generates the continuous compliance evidence required for submissions.

---

## What it does
MedTrace provides deterministic regulatory traceability and safety release gating for medical device software in Atlassian Cloud:

### 1. Deterministic Regulatory Blast Radius Engine
When a specification, hazard mitigation, or test run changes, MedTrace traverses the entire 5-stage transitive traceability chain:

`ISO 14971 Clinical Hazard ↔ Safety Requirement (Confluence SRS) ↔ Jira Work Item (e.g., MED-42) ↔ Verification Test Issue (e.g., TEST-88) ↔ Clinical Approval Hash`

On a synthetic 500-node graph benchmark (100 five-stage trace links: 500 artifact nodes indexed into an in-memory adjacency map in $O(n)$ time), MedTrace computes the complete blast radius in **under 20ms of breadth-first traversal (a ceiling enforced by an automated test assertion, single-digit ms on the seeded suite)**, terminating deterministically and handling circular trace links without infinite loops or duplicate node visits. Traversal is transitive: drift discovered on one spec propagates through shared hazard nodes into sibling requirements, tasks, and tests.

### 2. Cryptographic Approval Hash Drift Detection
Clinical authorities approve Confluence specifications (e.g., ISO 14971 Risk Mitigations) with reference SHA-256 content digests recorded in FDA 21 CFR Part 11 signature records. Whenever evaluated (during workflow transitions, Custom UI inspections, CI/CD pipeline checks, or developer MCP queries), MedTrace verifies the specification's registered content digest against the signed reference hash: any post-sign-off modification detects hash divergence, flags cryptographic approval drift, and marks the lineage as an unverified risk.

### 3. IEC 62304 Safety Release Gate (Jira Workflow Validator)
MedTrace enforces a release gate aligned with IEC 62304 Clause 5.7 (Software System Testing) and Clause 5.8 (Software Release), applying Class A/B/C safety logic per Clause 4.3:
* **Class A (No injury):** Requires documented safety requirements (verification test execution is informational/non-blocking).
* **Class B (Non-serious injury):** Requires passing verification tests and active requirement links. Unverified gaps result in `INCOMPLETE` status and **block transitions**.
* **Class C (Death or serious injury):** Strictly requires passing automated verification tests and matching approval hashes before related Jira issues can transition to "Done" or "Release". Unverified gaps or signature drift trigger a hard **`SAFETY_VIOLATION` transition lockout**.

*Deployment Architecture & Evaluator Testing:* The release gate is implemented as a Forge `jira:workflowValidator` module declared in `manifest.yml` (`src/workflow-validator.ts`). Because attaching Forge validators to live workflows requires Jira site-admin privileges, MedTrace provides two direct evaluator verification paths: (1) an in-app "Test Human Gate" button in the Custom UI header and issue panel running the live backend validator handler, and (2) an authenticated webtrigger action (`simulate_transition` or `verify-release-gate`) runnable via curl.

### 4. Structured 510(k) eSTAR-Aligned Software Lifecycle Dossier View
Provides an interactive in-browser regulatory evidence dossier formatted after the software documentation section of an FDA 510(k) eSTAR (*electronic Submission Template And Resource*) submission (21 CFR 807.92 content structure; eSTAR Software section). The view compiles 5-stage bidirectional traceability matrices, risk classifications (ISO 14971), and SHA-256 verification records into a printable audit dossier ready for regulatory review.

### 5. Optional Developer Assistant: Connected IDE Context (MCP) & Rovo Compliance Agent
*Optional, non-PHI, assistive tooling: does not affect the core regulatory engine.*

For developer convenience during implementation, MedTrace provides:
* **Atlassian Rovo Agent (`rovo:agent`):** An AI regulatory officer that runs deterministic BFS graph traversal across the active compliance graph to return affected hazards, blocked Jira items, and actionable remediation steps directly inside Jira.
* **Model Context Protocol (MCP) Server:** Allows local IDEs (such as Cursor or Claude Desktop) to query live traceability state and blast radius calculations via a cryptographically authenticated Forge webtrigger protected by HMAC-SHA256 signatures, a 300-second timestamp validity window, atomic Forge KVS nonce deduplication, and fail-closed secret verification.

*Example IDE Interaction:*
> **Developer in Cursor:** *"I am modifying `pump_motor.c` to change bolus flow-rate threshold to 5.5 mL/hr. Does this touch any IEC 62304 hazard?"*  
> **MedTrace MCP Response:** *"⚠️ CRITICAL: Diff modifies bolus delivery logic governed by ISO 14971 Class C Hazard HAZ-101. IEC 62304 verification test TEST-88 is UNTESTED and Confluence spec SRS-104 has signature drift. Release is BLOCKED until remediated."*

*Non-PHI Engineering Metadata Boundary:* The MCP assistant operates strictly on non-PHI engineering metadata (Jira issue keys, requirement IDs, and verification test execution status). It does not ingest patient health data, is strictly decoupled from medical device runtime execution, and does not render regulatory judgment: it serves purely as an assistive developer utility to surface traceability gaps directly in the code editor.

---

## How we built it
MedTrace was built natively on the Atlassian Forge platform using TypeScript, React, and `@forge/kvs`:

* **Atlassian Forge Custom UI:** React frontend running inside Jira Cloud (issue panel + project page) providing interactive traceability graphs (`@xyflow/react`), real-time blast radius inspection, and safety gate status.
* **Deterministic BFS Traversal Engine (`src/compliance-engine.ts`):** In-memory adjacency-list graph engine engineered with cycle detection, pre-computed edge sets, and zero external database round-trips.
* **Jira Workflow Validator (`src/workflow-validator.ts`):** Native workflow transition validator implementing IEC 62304 Class A/B/C safety logic and cryptographic approval hash validation with a sub-80ms execution path.
* **Teamwork Graph (TWG) Integration (`src/teamwork-graph.ts`):** Traverses Jira issue links and remote links through the Atlassian GraphQL Gateway (AGG), with automatic fallback to Jira REST API v3 for maximum reliability.
* **Secure Webtrigger Gateway (`src/index.ts`, `src/nonce-store.ts`):**
  * **HMAC-SHA256 Auth:** Cryptographic HMAC-SHA256 signature verification (`x-medtrace-signature`) over `${timestamp}.${nonce}.${rawBody}`, with a required nonce and 5-minute replay window. The shared secret is never transmitted.
  * **Anti-Replay Defense:** Enforces a 300-second timestamp validity window and atomic single-operation nonce reservation via `@forge/kvs` with `keyPolicy: 'FAIL_IF_EXISTS'` and TTL, eliminating race conditions across serverless micro-VMs.
* **Zero Outbound External Egress Guarantee:**
  MedTrace does not declare `permissions.external.fetch.backend` in its `manifest.yml`. All clinical hazard data, Jira issue keys, and Confluence page hashes remain strictly confined to the customer's Atlassian Forge tenant.

### Architectural Alternatives Considered
* **Inbound Webtrigger vs. Outbound Event Webhooks / Polling:** Inbound webtriggers eliminate the need for outbound network permissions (`permissions.external.fetch.backend`), keeping the app strictly zero-egress while allowing local developer IDEs to query compliance state.
* **In-Memory BFS Traversal vs. Live GraphQL Multi-Join:** Pre-indexing the trace graph into memory avoids multi-hop REST/GraphQL network calls during Jira workflow transitions, meeting Forge's serverless execution timeout limits without database round-trips.
* **Tenant-Confined KVS vs. External eQMS Database:** Using `@forge/kvs` keeps device architecture and risk assessments strictly inside Atlassian's security boundary, avoiding third-party data processor agreements.
* **Artifact-Node BFS vs. Per-Link Fixed Walk (ADR 004):** A naive per-link walk was rejected because it never traversed into sibling requirements mitigating the same hazard. We built genuine artifact-node BFS traversal so drift propagates transitively across shared hazard nodes.

---

## Challenges we ran into
* **Serverless Nonce Persistence in Forge:** Forge webtriggers execute in ephemeral serverless micro-VMs where module-level in-memory caches do not persist between invocations. To prevent replay attacks across distinct runtime instances, we abstracted storage behind a `NonceStore` interface using `@forge/kvs` native atomic TTL and collision detection (`keyPolicy: 'FAIL_IF_EXISTS'`).
* **Circular Regulatory Traceability:** Real-world engineering requirements frequently contain circular references (e.g., Hazard -> Spec -> Sub-Hazard -> Spec). We implemented visited-set cycle prevention in our BFS engine to guarantee deterministic termination on circular trace links.
* **Platform Limitation Defense (ECO-624):** In Atlassian Cloud, Jira Automation rules and direct REST API calls can bypass workflow validators (Atlassian issue ECO-624). MedTrace provides defense-in-depth by mirroring identical compliance checks inside its authenticated CI/CD webtrigger (`verify-release-gate`), returning HTTP 403 on open gaps, allowing CI/CD pipelines (such as GitHub Actions, with an example workflow provided in the repository) to enforce the gate at the pull request boundary.
* **Cryptographic Timing Defenses:** Ensuring HMAC validation was protected against timing side-channel attacks required validating signature buffer lengths prior to executing constant-time `crypto.timingSafeEqual`.
* **A Real Credential Leak, Handled in the Open:** Our own `.env.example` briefly shipped a live secret to the public repo during development. We rotated the secret across both deployed environments with a one-shot script and re-verified the outcome live against production: leaked key -> HTTP 401, fresh key -> 200, replay -> 200/409/409/200, CI gate -> 403. The rotation is reproducible via `scripts/rotate-mcp-secret.sh`, and the incident is documented rather than hidden.

---

## Honest Scope & System Limitations
To ensure transparent evaluation by technical judges, we explicitly document MedTrace's architectural boundaries:
* **Workflow Validator Attachment Requires Jira Site-Admin:** The release gate is implemented as a native Forge `jira:workflowValidator` declared in `manifest.yml`. Attaching it to a live Jira workflow transition requires Jira site-administration permissions; for non-admin evaluators, the app includes an interactive in-app simulation harness invoking the exact same validator handler.
* **Validator Automation Bypass (ECO-624):** As documented in Atlassian platform issue ECO-624, Jira Automation rules and direct REST API calls can bypass workflow validators. MedTrace addresses this defense-in-depth by exposing an authenticated CI/CD webtrigger so pipelines can enforce identical gate logic at the PR/build boundary.
* **Developer Preview API Fallback:** The Atlassian Teamwork Graph (TWG) via the Atlassian GraphQL Gateway (AGG) is currently in Developer Preview; MedTrace implements an automatic fallback to Jira REST API v3 to ensure zero evaluation crashes during schema or gateway fluctuations.
* **Forge KVS Storage Ceilings:** Forge KVS enforces a strict 32 KB per-entity quota. A single compliance suite entity comfortably stores ~25 to 30 complete trace links (~120 to 150 nodes / ~30 KB). Scaling to massive enterprise device architectures (10,000+ items) is designed around entity-scoped sharding (`medtrace:link:{id}`).
* **Non-PHI Engineering Metadata Only:** MedTrace governs software requirements, tasks, test runs, and specification hashes. It does not ingest, process, or store Protected Health Information (PHI), and the optional MCP assistant is excluded from HIPAA BAA considerations by design.
* **Deterministic Demo Fixture & Zero-Egress Architecture:** MedTrace is a compliance reasoning engine with a zero-egress security model. It ships with a deterministic demo fixture so judges can reproduce results without provisioning infrastructure; the engine operates on any Jira/Confluence project once installed. On clean evaluator sandboxes lacking pre-existing clinical trace links, the 1-click seeder provisions modeled Smart Infusion Pump records (prominently labeled with a persistent "DEMO DATASET: MODELED RECORDS" badge). Every backend failure renders an honest error state: the app never fabricates compliance evidence or remediation success.
* **Regulatory Framing:** MedTrace is an assistive traceability engine, not an autonomous regulatory authority. It generates verification records to support IEC 62304 and ISO 14971 compliance dossiers, but does not render legal or regulatory determinations.

---

## Accomplishments that we're proud of
* **Test-Enforced Deterministic Traversal:** Blast-radius BFS over the artifact-node graph completes the 500-node synthetic benchmark in under 20ms (a ceiling asserted by the automated test suite itself), delivering instant transitive impact analysis inside Jira.
* **Defensible Regulatory Framing:** Grounded MedTrace strictly in formal IEC 62304 software verification clauses (Clause 5.7 system testing and Clause 5.8 software release) and ISO 14971 risk classifications, avoiding ungrounded marketing claims.
* **Empirical Replay Defense:** An empirically verified 5-step replay and CI gate test sequence (`200 -> 409 -> 409 -> 200 -> 403`) running live on Atlassian Forge production storage.
* **Automated Test Suite:** 40 unit and integration tests passing in under 250ms, including coverage of the `verify-release-gate` CI endpoint (HTTP 403-on-block semantics), the Forge `rovo:action` payload contract, and transitive blast-radius propagation, accompanied by a zero-warning doc-sync verification system.
* **Honest-Failure UX as a Feature:** Every backend failure path renders an explicit error banner or a "no verdict rendered" state: the UI and MCP tools never fabricate compliance evidence, remediation success, or Teamwork Graph traversals, and demo records carry a persistent `DEMO DATASET: MODELED RECORDS` badge.

---

## What we learned
* How to query Atlassian Forge's connected context across Jira issues and Confluence pages without compromising data privacy.
* The nuances of building resilient idempotency and replay guards in serverless Atlassian environments using `@forge/kvs`.
* How to bridge developer IDEs via local MCP to Atlassian Cloud while maintaining strict regulatory traceability, non-PHI isolation, and cryptographic integrity.
* That "honest or it didn't happen" applies to algorithms too: our original "BFS" was really a per-link walk, so we rebuilt it as a genuine artifact-node breadth-first traversal (ADR 004) rather than rewording the claim.

---

## What's next for MedTrace
* **Atlassian Teamwork Graph API Expansion:** Extending our read-only traversal to deeper Teamwork Graph edge schemas as Atlassian expands the GraphQL Gateway (AGG) beyond its current preview state.
* **Sharded Trace Storage:** Partitioning large compliance graphs across entity-scoped Forge KVS keys (`medtrace:link:{id}`) to scale beyond single-entity storage boundaries for 10,000+ item device architectures.
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
* **Judges' Installation Link:**  
  https://developer.atlassian.com/console/install/5e49c10e-696f-4984-9d00-4a47d0a5dd99?signature=AYABeGCme19auHJhjNUvEFcI4mcAAAADAAdhd3Mta21zAEthcm46YXdzOmttczp1cy13ZXN0LTI6NzA5NTg3ODM1MjQzOmtleS83MDVlZDY3MC1mNTdjLTQxYjUtOWY5Yi1lM2YyZGNjMTQ2ZTcAuAECAQB4CxqLTo9l4lqXuFjNim1xJM%2Bp%2F3TVP9xHS2BrU5DRRucBBGkKOe0%2FvccRxu918mRRxQAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDGnUJZO%2BP6fZzIYHawIBEIA7%2FLJbWz1Wgou7E6blbEy7%2Bf%2FhagpCkz1Z1k6Nw9bkb9uTOgquby%2FGpEoV%2FWBBNMVsT6aqZLUsbk%2Bl%2F3wAB2F3cy1rbXMAS2Fybjphd3M6a21zOmV1LXdlc3QtMTo3MDk1ODc4MzUyNDM6a2V5LzQ2MzBjZTZiLTAwYzMtNGRlMi04NzdiLTYyN2UyMDYwZTVjYwC4AQICAHi9bVMAkme4qVQX1fQHo6ePw3H40A7cGfz7yrmSfBWMXgGc8A3ksbtLvz81ATrPybd1AAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQM8kuGyM%2F4RiRFR1pbAgEQgDtslbfng%2FctfzdXkBuVxD%2FZ3Bn%2F%2FZqFeL3kQOOW%2FHHfuG%2FdLFDWgNsgAdjfBhgeH58TvnJULklEXcO8DQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtZWFzdC0xOjcwOTU4NzgzNTI0MzprZXkvNmMxMjBiYTAtNGNkNS00OTg1LWI4MmUtNDBhMDQ5NTJjYzU3ALgBAgIAeDYASx0XCjkny4iLV6vz%2BKtEGSGT6kdt0QRpkn6D%2FlVEATa7vBTu8clWoy%2F0Df57nOUAAAB%2BMHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAxTuBdnO6SIydTy74ECARCAO2LkZ1%2FqLnWR7RJ5bJnJymaVMNymPTqxgHoTlttTyoG0WExeUn7yicWSDKcF1uBOEDJRq0D%2Frh397b4AAgAAAAAMAAAQAAAAAAAAAAAAAAAAAJAZ9eb6OkPjsbTya19Mcjb%2F%2F%2F%2F%2FAAAAAQAAAAAAAAAAAAAAAQAAADLNW%2BBw%2FL87DPzUfn%2FfQnPcOv5NJiaf2TZQ6lKb5ub%2BNZg0%2FAzxtph%2Fk5dSlQh1Qk3N0t2gqHZp049lWyoTj6Cdrww%3D&product=jira
* **Live Demo Site & Credentials:**  
  Site: `https://one-atlas-feur.atlassian.net`  
  *(Judge evaluation accounts and the rotated webtrigger secret are provided in the private Devpost submission fields)*
* **Demo Video Walkthrough (3:10):**  
  *Production video script, timecoded shots, and captions are prepared in [`devpost_video_script.md`](./devpost_video_script.md) and [`devpost_video_captions.srt`](./devpost_video_captions.srt). Embed YouTube walkthrough link here upon recording: `https://youtu.be/<VIDEO_ID>`*  
  *(Comprehensive demo of Jira project page, Confluence drift detection, workflow validator gate, Rovo agent audit, and FDA dossier export)*
* **Marketplace Listing / Review Submission:**  
  *Submitted via Atlassian Developer Console → [MedTrace App](https://developer.atlassian.com/console/myapps/5e49c10e-696f-4984-9d00-4a47d0a5dd99) → Manage Marketplace Listing (Review ticket tracking in Devpost private submission notes).*
* **GitHub Repository:** [https://github.com/armageden/MedTrace](https://github.com/armageden/MedTrace) (Public, verified `200 OK`, complete with automated test suites and reproducible benchmarks)
* **Self-Serve Forge Installation (Site Admins):** Install directly to your Atlassian Cloud development or testing tenant via Forge CLI:
  ```bash
  forge install --site <your-domain>.atlassian.net --product jira
  ```
* **Local Developer Assistant (MCP):** Connect Cursor or Claude Desktop to live compliance state following the setup guide in [mcp-server/README.md](https://github.com/armageden/MedTrace/blob/main/mcp-server/README.md)
