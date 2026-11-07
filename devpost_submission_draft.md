# MedTrace: IEC 62304 Medical Device Regulatory Traceability & Blast Radius Engine

## Tagline
Deterministic IEC 62304 & ISO 14971 traceability for Jira and Confluence, computing multi-hop regulatory blast radius in ~0.5ms of in-memory BFS traversal with zero outbound egress.

---

## Track & Category Nominations
* **Primary Category:** Apps for Specialized Industries (Medical Devices & Healthcare Engineering)

---

## Inspiration
Medical device software engineering is governed by strict life-safety standards: IEC 62304 (Software Lifecycle Processes), ISO 14971 (Risk Management), and FDA 21 CFR 807.92. In medical device R&D, a code change is never just a code change—if an engineer modifies a pump flow-rate constant from 5.0 mL/hr to 5.5 mL/hr, that single parameter update cascades across clinical hazard assessments, software requirement specifications (SRS), approval hashes, and verification test runs.

Historically, engineering teams manage this burden through external Application Lifecycle Management (ALM) platforms that require syncing sensitive design history files, proprietary device specifications, and architectural documentation to third-party cloud infrastructure.

Our team has prior experience in embedded firmware engineering for Class II infusion pump systems. We saw that Jira and Confluence already store the underlying engineering artifacts—Jira issues hold requirements, test runs, and tasks; Confluence holds clinical risk assessments and architecture specifications. What was missing was **deterministic, zero-egress graph traceability** linking these artifacts directly inside Atlassian Forge without exporting sensitive medical device designs outside the manufacturer's Atlassian tenant.

---

## What it does
MedTrace provides deterministic regulatory traceability and safety release gating for medical device software in Atlassian Cloud:

### 1. Deterministic Regulatory Blast Radius Engine
When a specification, hazard mitigation, or test run changes, MedTrace traverses the entire 5-stage transitive traceability chain:

`ISO 14971 Clinical Hazard ↔ Safety Requirement (SRS) ↔ Jira Implementation (MED) ↔ Verification Test (TEST) ↔ Clinical Approval Hash`

On a synthetic 500-node graph benchmark, MedTrace calculates the complete blast radius in **~0.5ms of in-memory BFS (Breadth-First Search) traversal**, terminating deterministically and handling circular trace links without infinite loops or duplicate node visits.

### 2. Cryptographic Approval Hash Drift Detection
Clinical authorities approve Confluence specifications (e.g., ISO 14971 Risk Mitigations) with reference SHA-256 content digests stored in Forge KVS (Key-Value Storage). If an engineer modifies a Confluence page post-approval without clinical re-review, MedTrace immediately flags cryptographic approval hash drift and marks the lineage as an unverified risk.

### 3. IEC 62304 Safety Release Gate (Jira Workflow Validator)
MedTrace enforces a release gate aligned with IEC 62304 Clause 5.7 (Software System Testing) and Clause 5.8 (Software Release), applying Class A/B/C safety logic per Clause 4.3:
* **Class A (No injury):** Requires documented requirements and baseline test coverage.
* **Class B (Non-serious injury):** Requires verified test runs and active requirement links.
* **Class C (Death or serious injury):** Strictly requires passing automated verification tests and matching approval hashes before related Jira issues can transition to "Done" or "Release".

*Deployment Architecture:* The release gate is implemented as a Forge `jira:workflowValidator` module declared in `manifest.yml` and scoped to the issue key. Attaching it to a live Jira transition requires site-admin workflow editing; the in-app simulation harness invokes the same handler directly for evaluators. The handler source is `src/workflow-validator.ts`.

### 4. Structured 510(k) eSTAR-Aligned Software Lifecycle Dossier Export
Generates a structured regulatory evidence dossier formatted for the software documentation portion of a 510(k) submission (21 CFR 807.92 content requirements; eSTAR Software section), including complete 5-stage bidirectional traceability matrices, risk severity classifications (ISO 14971), and cryptographic verification records.

For Software of Unknown Provenance (SOUP), IEC 62304 Clauses 5.1.7, 5.3.3, 5.3.6 — MedTrace generates verification audit records that the manufacturer incorporates into their SOUP qualification dossier.

### 5. Optional Developer Assistant: Connected IDE Context (MCP)
*Optional, non-PHI, does not affect the core regulatory engine — included for developer convenience.*

For developer convenience during implementation, MedTrace provides an optional Model Context Protocol (MCP) assistant for local IDEs (such as Cursor or Claude Desktop). It queries live traceability state and blast radius calculations via a cryptographically authenticated Forge webtrigger protected by HMAC-SHA256 signatures, a 300-second timestamp validity window, and persistent Forge KVS nonce deduplication.

*Non-PHI Engineering Metadata Boundary:* The MCP assistant operates strictly on non-PHI engineering metadata (Jira issue keys, requirement IDs, and verification test execution status). It does not ingest patient health data, is strictly decoupled from medical device runtime execution, and does not render regulatory judgment—it serves purely as an assistive developer utility to surface traceability gaps directly in the code editor.

---

## How we built it
MedTrace was built natively on the Atlassian Forge platform using TypeScript, React, and `@forge/kvs`:

* **Atlassian Forge Custom UI:** React frontend running inside Jira and Confluence Cloud providing interactive traceability graphs, real-time blast radius inspection, and safety gate status.
* **Deterministic BFS Traversal Engine (`src/compliance-engine.ts`):** In-memory adjacency-list graph engine engineered with cycle detection, pre-computed edge sets, and zero external database round-trips.
* **Jira Workflow Validator (`src/workflow-validator.ts`):** Native workflow transition validator implementing IEC 62304 Class A/B/C safety logic and cryptographic approval hash validation.
* **Secure Webtrigger Gateway (`src/index.ts`, `src/nonce-store.ts`):**
  * **Dual-Layer Auth:** Perimeter token authentication (`x-medtrace-key`) paired with cryptographic HMAC-SHA256 signature verification (`x-medtrace-signature`) over `${timestamp}.${nonce}.${rawBody}`.
  * **Anti-Replay Defense:** Enforces a 300-second timestamp validity window and persistent nonce consumption using `@forge/kvs`, lazily pruning expired tokens on access.
* **Zero Outbound External Egress Guarantee:**
  MedTrace does not declare `permissions.external.fetch.backend` in its `manifest.yml`. All clinical hazard data, Jira issue keys, and Confluence page hashes remain strictly confined to the customer's Atlassian Forge tenant.

### Architectural Alternatives Considered
* **Inbound Webtrigger vs. Outbound Event Webhooks / Polling:** Inbound webtriggers eliminate the need for outbound network permissions (`permissions.external.fetch.backend`), keeping the app strictly zero-egress while allowing local developer IDEs to query compliance state.
* **In-Memory BFS Traversal vs. Live GraphQL Multi-Join:** Pre-indexing the trace graph into memory avoids multi-hop REST/GraphQL network calls during Jira workflow transitions, meeting Forge's serverless execution timeout limits without database round-trips.
* **Tenant-Confined KVS vs. External eQMS Database:** Using `@forge/kvs` keeps device architecture and risk assessments strictly inside Atlassian's security boundary, avoiding third-party data processor agreements.

---

## Challenges we ran into
* **Serverless Nonce Persistence in Forge:** Forge webtriggers execute in ephemeral serverless micro-VMs where module-level in-memory caches do not persist between invocations. To prevent replay attacks across distinct runtime instances, we abstracted storage behind a `NonceStore` interface using `@forge/kvs` with lazy TTL pruning on access.
* **Circular Regulatory Traceability:** Real-world engineering requirements frequently contain circular references (e.g., Hazard → Spec → Sub-Hazard → Spec). We implemented visited-set cycle prevention in our BFS engine to ensure deterministic termination in `< 1ms`.
* **Platform Limitation Defense (ECO-624):** In Atlassian Cloud, Jira Automation rules and direct REST API calls can bypass workflow validators (Atlassian issue ECO-624). MedTrace provides defense-in-depth by mirroring identical compliance checks inside its authenticated CI/CD webtrigger, allowing CI/CD pipelines (such as GitHub Actions, with an example workflow provided in the repository) to enforce the gate at the pull request boundary.
* **Cryptographic Timing Defenses:** Ensuring HMAC validation was protected against timing side-channel attacks required validating signature buffer lengths prior to executing constant-time `crypto.timingSafeEqual`.

---

## Honest Scope & System Limitations
To ensure transparent evaluation by technical judges, we explicitly document MedTrace's architectural boundaries:
* **Workflow Validator Attachment Requires Jira Site-Admin:** The release gate is implemented as a native Forge `jira:workflowValidator` declared in `manifest.yml`. Attaching it to a live Jira workflow transition requires Jira site-administration permissions; for non-admin evaluators, the app includes an interactive in-app simulation harness invoking the exact same validator handler.
* **Validator Automation Bypass (ECO-624):** As documented in Atlassian platform issue ECO-624, Jira Automation rules and direct REST API calls can bypass workflow validators. MedTrace addresses this defense-in-depth by exposing an authenticated CI/CD webtrigger so pipelines can enforce identical gate logic at the PR/build boundary.
* **Developer Preview API Fallback:** The Atlassian Teamwork Graph (TWG) via the Atlassian GraphQL Gateway (AGG) is currently in Developer Preview; MedTrace implements an automatic fallback to Jira REST API v3 to ensure zero evaluation crashes during schema or gateway fluctuations.
* **Forge KVS Storage Ceilings:** Forge KVS has bounded per-entity storage. While sufficient for seeded and medium projects (~500 nodes), scaling to massive enterprise device architectures (10,000+ items) requires partitioning the trace graph across entity-scoped shards.
* **Non-PHI Engineering Metadata Only:** MedTrace governs software requirements, tasks, test runs, and specification hashes. It does not ingest, process, or store Protected Health Information (PHI), and the optional MCP assistant is excluded from HIPAA BAA considerations by design.
* **Regulatory Framing:** MedTrace is an assistive traceability engine, not an autonomous regulatory authority. It generates verification records to support IEC 62304 and ISO 14971 compliance dossiers, but does not render legal or regulatory determinations.

---

## Accomplishments that we're proud of
* **Sub-millisecond Traversal:** Achieving ~0.5ms in-memory BFS blast radius traversal on a 500-node graph benchmark, delivering sub-millisecond blast-radius computation to developers inside Jira.
* **Defensible Regulatory Framing:** Grounded MedTrace strictly in formal IEC 62304 software verification clauses (Clause 5.7 system testing, Clause 5.8 software release, and Clauses 5.1.7, 5.3.3, 5.3.6 for SOUP verification records) and ISO 14971 risk classifications, avoiding ungrounded marketing claims.
* **Empirical Replay Defense:** An empirically verified 4-step replay test suite (`200 → 409 → 409 → 200`) running live on Atlassian Forge production storage.
* **Automated Test Suite:** 23 unit and integration tests passing in ~130ms, accompanied by a zero-warning doc-sync verification system.

---

## What we learned
* How to query Atlassian Forge's connected context across Jira issues and Confluence pages without compromising data privacy.
* The nuances of building resilient idempotency and replay guards in serverless Atlassian environments using `@forge/kvs`.
* How to bridge developer IDEs via local MCP to Atlassian Cloud while maintaining strict regulatory traceability, non-PHI isolation, and cryptographic integrity.

---

## What's next for MedTrace
* **Atlassian Teamwork Graph API Expansion:** Extending our read-only traversal to deeper Teamwork Graph edge schemas as Atlassian expands the GraphQL Gateway (AGG) beyond its current preview state.
* **Sharded Trace Storage:** Partitioning large compliance graphs across entity-scoped Forge KVS keys to scale beyond single-entity storage boundaries for 10,000+ item device architectures.
* **Jira Service Management Clinical Change Requests:** Connecting customer-reported medical device post-market surveillance issues directly into ISO 14971 risk mitigations.

---

## Built with
* Atlassian Forge
* TypeScript
* React
* Forge KVS
* Jira Cloud
* Confluence Cloud
* Model Context Protocol (MCP)
* Crypto HMAC-SHA256
* Node.js Test Runner

---

## Try it out
* **Demo Video Walkthrough:** [YouTube Video Walkthrough](https://youtu.be/YOUR_VIDEO_ID) (Comprehensive demo of Jira issue panel, Confluence drift detection, workflow validator gate, and dossier export)
* **GitHub Repository:** [https://github.com/armageden/MedTrace](https://github.com/armageden/MedTrace) (Public, verified `200 OK`, complete with automated test suites and reproducible benchmarks)
* **Self-Serve Forge Installation (Site Admins):** Install directly to your Atlassian Cloud development or testing tenant via Forge CLI:
  ```bash
  forge install --site <your-domain>.atlassian.net --product jira
  forge install --site <your-domain>.atlassian.net --product confluence
  ```
* **Local Developer Assistant (MCP):** Connect Cursor or Claude Desktop to live compliance state following the setup guide in [medtrace/mcp-server/README.md](https://github.com/armageden/MedTrace/blob/main/mcp-server/README.md)
