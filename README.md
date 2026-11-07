# MedTrace — Zero-Egress Regulatory Blast Radius & Living Traceability Engine

> **Built for Atlassian Codegeist 2026**  
> **Track:** Apps for Specialized Industries (Medical Devices & Healthcare)  
> **Target Bonuses:** Best Agents (Rovo) • Best App with Atlassian MCP • Best Teamwork Graph (TWG) Integration • Best Marketplace App  

---

## Executive Summary

In life-critical medical device software (e.g., smart infusion pumps, pacemakers, surgical robotics), regulatory bodies (FDA 21 CFR Part 11, EU MDR, and IEC 62304) legally mandate a **continuous, unbroken bidirectional software traceability matrix**:

$$\text{ISO 14971 Clinical Hazard} \longleftrightarrow \text{Safety Requirement (Confluence)} \longleftrightarrow \text{Firmware Task (Jira)} \longleftrightarrow \text{Pull Request} \longleftrightarrow \text{Verification Test (HIL/Unit)} \longleftrightarrow \text{Cryptographic Signature Evidence}$$

If a single requirement changes or code ships without an attached verification test, regulatory submissions stall and audit findings multiply. Today, medical device manufacturers are forced to buy complex external eQMS systems that require separate accounts and sync engineering data into third-party clouds.

**MedTrace** turns Atlassian Cloud into an automated, zero-egress regulatory governance platform:
1. **Deterministic Regulatory Blast Radius Engine:** A formal BFS traversal over typed trace links (`HAZARD`, `SPEC`, `WORK`, `TEST`, `SIGNATURE`) that recalculates downstream invalidated scope when a spec drifts or a test fails (measured at ~1.7ms p95 on the seeded suite).
2. **Interactive Visual Lineage Graph:** A React Flow (`@xyflow/react`) canvas rendering the 5-stage regulatory chain with animated status edges and pulsating alerts for unverified Class C risks.
3. **Teamwork Graph (TWG) Traversal:** Connects Jira issues, Confluence specifications, and remote repository links through the Atlassian GraphQL Gateway (AGG) with automatic Jira REST fallback.
4. **Human-Initiated Jira Release Gate (`jira:workflowValidator`):** Blocks human transitions to "Done" if an issue is linked to an unverified hazard or signature drift. CI/CD pipelines enforce identical policy via authenticated HMAC webtriggers (pre-empting platform issue ECO-624).
5. **Zero Outbound Data Egress:** Pure Forge serverless architecture with no `permissions.external.fetch.backend` declared in `manifest.yml`. Inbound CI events use authenticated HMAC-SHA256 webtriggers.
6. **Rovo Assignable Agent (`rovo:agent`):** The "MedTrace Auditor" AI compliance officer, capable of auditing sprints, analyzing hazard blast radius, and guiding remediation.
7. **Optional Developer MCP Server (`rovo:mcp` + Local Stdio):** Developer convenience tool auditing diffs against non-PHI engineering metadata in Cursor and Claude Desktop, keeping HIPAA boundaries cleanly isolated.
8. **1-Click Enterprise Demo Seeder:** Provisions a realistic Smart Infusion Pump Firmware v2.1 dataset with clinical hazards, Confluence SRS requirements, and tests in under 4 seconds.

### Regulatory Context & Compliance Standards

| Standard / Framework | Regulatory Scope | MedTrace Enforcement Invariant |
| :--- | :--- | :--- |
| **IEC 62304** | Medical device software lifecycle processes | Classifies risk severity (Class A, B, C); mandates verification tests for all safety-critical software items. |
| **ISO 14971** | Risk management for medical devices | Requires bidirectional links from Clinical Hazards to Safety Requirements and Verification Tests. |
| **FDA 21 CFR Part 11** | Electronic records & electronic signatures | Cryptographic SHA-256 fingerprinting of specifications; signature invalidation on content drift. |
| **FDA 510(k)** | Premarket notification submission | Generates printable Section 16 Traceability Dossier for regulatory auditors. |

#### Risk Severity Classification
* **Class A (Minor):** No injury or damage to health possible (e.g., UI display glitch). Informational warnings only.
* **Class B (Moderate):** Non-serious injury possible (e.g., under-infusion alert delay). Marked `INCOMPLETE` if untested; blocks release.
* **Class C (Catastrophic):** Death or serious injury possible (e.g., bolus over-infusion). **Hard transition lockout** (`SAFETY_VIOLATION`) in Jira release gate if untested or if signature drift exists.

### Goals & Non-Goals
* **Goals:**
  * Automate bidirectional traceability verification directly within Jira and Confluence.
  * Enforce hard release gate transitions using fast-path workflow validation.
  * Provide developer-facing IDE assistance via Model Context Protocol (MCP).
  * Maintain tamper-evident cryptographic audit logs for electronic signatures.
* **Non-Goals:**
  * MedTrace is **not** an active Medical Device Data System (MDDS) and does not directly connect to infusion pump physical hardware or patient telemetry.
  * MedTrace does not replace formal notified body / FDA auditor evaluations; it provides the continuous compliance evidence required for submissions.

---

## Architecture & Modules

```mermaid
flowchart TD
    subgraph Atlassian Cloud ["Atlassian Cloud (Jira & Confluence)"]
        UI["Custom UI: Interactive Lineage Graph<br/>(React 18 + @xyflow/react + Atlaskit)"]
        JiraGate["jira:workflowValidator<br/>(Fast-path <80ms Fail-Closed Transition Lockout)"]
        Rovo["rovo:agent & rovo:action<br/>(MedTrace Regulatory Auditor)"]
        Seeder["1-Click Enterprise Seeder<br/>(Promise.all Batching + Storage Bootstrap)"]
    end

    subgraph Forge Backend ["Forge Serverless Runtime (@forge/api + @forge/kvs)"]
        Resolvers["Forge Resolvers (index.ts)"]
        RovoHandler["Rovo Action Handler (mcp-server.ts)"]
        Webtrigger["mcp-sync-webtrigger<br/>(HMAC-SHA256 Auth + 300s Replay Window)"]
        TWG["Teamwork Graph AGG GraphQL Client<br/>(With Jira REST Fallback)"]
        Engine["IEC 62304 & 21 CFR Part 11 Rule Engine"]
        Storage["@forge/kvs High-Speed Persistence<br/>(Key: medtrace:compliance:active_suite)"]
    end

    subgraph External IDE ["Local AI Coding Environments (Cursor / Claude Desktop)"]
        MCPClient["Developer in Cursor IDE"]
        MCPServer["MedTrace MCP Server (stdio JSON-RPC)<br/>(mcp-server/index.mjs)"]
    end

    UI <-->|@forge/bridge IPC| Resolvers
    JiraGate <-->|Direct Read| Storage
    Resolvers <--> Storage
    Resolvers <--> TWG
    Resolvers <--> Engine
    Seeder --> Storage
    Rovo <--> RovoHandler
    RovoHandler <--> Engine
    RovoHandler <--> Storage
    MCPClient <-->|stdio| MCPServer
    MCPServer <==>|HTTPS POST + HMAC Signature| Webtrigger
    Webtrigger <--> Engine
    Webtrigger <--> Storage
```

### Module Contracts & APIs

#### 1. Forge Resolvers (`src/index.ts`)
* `getComplianceSuite`: Retrieves the active `ComplianceSummary` from KVS (auto-seeds if uninitialized).
* `seedDemoSuite`: Provisions the 3 hazards, SRS specifications, Jira issues, test executions, and Part 11 records.
* `remediateGap`: Payload `{ hazardKey?: string }` (default: `'HAZ-101'`). Re-certifies signatures and records test pass.
* `queryGraphContext`: Payload `{ issueKey?: string }`. Traverses the Teamwork Graph via AGG GraphQL with REST fallback.
* `simulateTransition`: Tests the workflow validator gate directly from the Custom UI.

#### 2. Jira Workflow Validator (`src/workflow-validator.ts`)
* **Execution Boundary:** Fast-path (<80ms) synchronous execution during Jira issue state transitions to "Done".
* **Fail-Closed Safety Invariant:** If KVS retrieval fails or an unhandled exception occurs, the validator defaults to `result: false` with:
  > *"MedTrace Safety Gate: Unable to verify IEC 62304 compliance integrity. Transition halted."*

#### 3. Teamwork Graph & Dual-Engine Fallback (`src/teamwork-graph.ts`)
* Queries AGG GraphQL `query GetIssueGraphContext($issueId: ID!)` to traverse Jira issue links and remote links.
* Automatically falls back to Jira REST API (`/rest/api/3/issue/...`) if AGG is unavailable, ensuring resilience.
* Synthesizes ISO 14971 entity ARIs formatted as `ari:cloud:medtrace::iso14971-hazard/${hazardKey}`.

---

## Quick Start & Testing Instructions for Judges

### Live Demo Site
* **Site URL:** [https://one-atlas-feur.atlassian.net](https://one-atlas-feur.atlassian.net)
* **Judge Credentials & Access:** Pre-configured evaluation accounts and guest access details are provided directly in the Devpost submission entry.
* **App Location:** 
  * In Jira: Open any project → Click **MedTrace IEC 62304** in the project sidebar.
  * In Jira Issue View: Open any issue → Click the **MedTrace Regulatory & Safety** issue panel.

### Testing the 1-Click Seeder
1. Open the **MedTrace IEC 62304** project page.
2. In the top right header, click **`[⚡ Seed Demo Suite]`**.
3. Within 3 seconds, the dashboard populates with:
   * 3 ISO 14971 Hazards (Class C Over-Infusion, Class B Under-Infusion, Class A Display Glitch).
   * 3 Confluence SRS Requirements (with cryptographic SHA-256 hashes).
   * 3 Jira Work Items & PR links.
   * 3 Verification Test executions.
   * 3 FDA 21 CFR Part 11 Electronic Signature audit records.

### Testing the Regulatory Safety Gate & Blast Radius Analyzer (Hero Demo)
1. Notice **`HAZ-101`** (Class C Catastrophic Hazard):
   * Verification Test `TEST-88` is **`UNTESTED`** (flashing red pulsating node).
   * Confluence requirement `SRS-104` has **Signature Drift** (spec was modified at v3 after approval of v2).
   * Top banner displays: **`🚨 RELEASE BLOCKED`**.
2. Click **`[⚡ Blast Radius]`** in the header or click `HAZ-101`:
   * The **Deterministic Blast Radius Engine** executes in < 2ms over the typed trace graph.
   * Drawer reveals the 4-hop cascade: Spec `SRS-104` drift $\rightarrow$ Signature evidence invalidated $\rightarrow$ Hazard `HAZ-101` compromised $\rightarrow$ Jira task `MED-42` locked $\rightarrow$ Verification test `TEST-88` invalidated.
   * Displays the exact transitive action checklist required for re-audit.
3. Click **`[🔒 Test Human Gate]`**:
   * Intercepts transition attempt for `MED-42` and halts it with human policy gate error.
4. Click **`[⚡ Remediate Class C Gap & Re-certify Gate]`**:
   * Simulates running the automated Hardware-in-the-Loop test (120/120 assertions passed).
   * Re-certifies signature evidence with current SHA-256 digest.
   * The graph turns green and the release status unlocks: **`✅ AUDIT READY (ZERO GAPS)`**!
5. Click **`[📄 Audit Evidence Export]`** to view and print the formal Software Lifecycle Traceability Dossier.

---

## Model Context Protocol (MCP) Integration for Cursor / Claude Desktop

MedTrace includes a standalone MCP server (`medtrace/mcp-server/index.mjs`) communicating with Forge over an authenticated HTTPS webtrigger.

### Tool Registry
* `medtrace_get_hazard_lineage`: Payload `{ hazardKey?: string }`. Returns the complete 5-stage traceability chain for a hazard.
* `medtrace_verify_iec_compliance`: Payload `{ prDiff?: string }`. Analyzes a proposed code diff against ISO 14971 hazards and flags required verification tests.
* `medtrace_remediate_safety_gap`: Payload `{ hazardKey: string }`. Remediates an unverified test and re-certifies signatures.

### Cryptographic Wire Protocol & Replay Guard
When mutating data or querying live compliance state, the local MCP client signs requests:
* **Header `x-medtrace-key`:** Secret shared token matching `process.env.MEDTRACE_MCP_SECRET` (default: `'medtrace-sec-2026'`).
* **Header `x-medtrace-timestamp`:** Epoch timestamp in milliseconds. Webtrigger enforces a **300,000ms (5-minute) anti-replay window** (`Math.abs(Date.now() - reqTime) > 300_000` halts with HTTP 401).
* **Header `x-medtrace-signature`:** Hex HMAC-SHA256 digest of `${timestamp}.${rawBody}` verified with constant-time `crypto.timingSafeEqual`.

### Adding to Cursor (`~/.cursor/mcp.json` or `.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "medtrace": {
      "command": "node",
      "args": ["/absolute/path/to/medtrace/mcp-server/index.mjs"],
      "env": {
        "MEDTRACE_MCP_SECRET": "medtrace-sec-2026",
        "MEDTRACE_WEBTRIGGER_URL": "https://<forge-app-id>.hello.atlassian-dev.net/x1/..."
      }
    }
  }
}
```

### Asking Cursor in your IDE
> *"I am editing `dose_calc.py` to change the bolus rate to 5.5 mL/hr. Does this touch any IEC 62304 Class C hazard in Jira, and what tests are required?"*

Cursor calls `medtrace_verify_iec_compliance` live and responds:
> *"⚠️ CRITICAL: Diff modifies bolus delivery logic governed by ISO 14971 Class C Hazard HAZ-101. IEC 62304 verification test TEST-88 is required before merge!"*

---

## Architecture Decision Records & Alternatives Considered

The project architecture is grounded in three formal Architecture Decision Records located under [`medtrace/docs/99-design-decisions/`](./docs/99-design-decisions/):

1. **[ADR 001: Hybrid Teamwork Graph (TWG) + Forge KVS Architecture](./docs/99-design-decisions/001-twg-and-kvs-hybrid.md)**
   * *Chosen:* KVS for sub-80ms workflow validator fast-path caching; AGG GraphQL for deep relational graph traversal.
   * *Alternative Rejected:* Pure TWG-only traversal was rejected due to GraphQL gateway cold-start latencies exceeding the 80ms validator SLA.
2. **[ADR 002: Webtrigger HMAC-SHA256 Authentication Protocol](./docs/99-design-decisions/002-webtrigger-hmac-authentication.md)**
   * *Chosen:* Cryptographic HMAC signatures with 5-minute timestamp replay window for external MCP IDE connections.
   * *Alternative Rejected:* Unauthenticated webtriggers or static Bearer tokens were rejected due to FDA Part 11 electronic record tamper-resistance requirements.
3. **[ADR 003: TWG Dual-Engine Resilient Fallback](./docs/99-design-decisions/003-twg-dual-engine-fallback.md)**
   * *Chosen:* Automatic seamless fallback to Jira REST API (`/rest/api/3/issue`) when AGG GraphQL encounters schema updates or rate limits.
   * *Alternative Rejected:* Fail-hard error propagation was rejected to ensure hospital release pipelines are never paralyzed by external API blips.

---

## System Limits & Architectural Safeguards

* **Storage Quotas:** Uses `@forge/kvs` with indexed summaries structured to fit well within Forge's 100KB per-entity value limit.
* **Rate Limits & Backoff:** AGG GraphQL requests are throttled and protected by the automatic REST fallback mechanism.
* **Execution Timeout:** Custom UI resolvers execute within 5 seconds; Jira workflow validator executes under 80ms to avoid blocking issue transitions.
* **Anti-Replay Window:** Local MCP synchronization rejects any payload with timestamp drift exceeding 5 minutes.

---

## Hackathon Submission & Verification Checklist

- [x] **Forge App Manifest:** Validated with `forge lint` (0 errors, 0 warnings).
- [x] **Automated Test Suite:** Verified with `npm test` (`tests/compliance-engine.test.cjs` passing 100% of unit tests for IEC 62304 rules, Part 11 drift detection, and HMAC replay prevention).
- [x] **Deployed & Installed:** Successfully deployed to `development` and installed in both Jira and Confluence on `one-atlas-feur.atlassian.net`.
- [x] **Teamwork Graph Bonus:** AGG GraphQL entity traversal + ISO 14971 entity registration.
- [x] **Rovo Agent Bonus:** `rovo:agent` (MedTrace Auditor) + `action` modules.
- [x] **Atlassian MCP Bonus:** `rovo:mcp` module in `manifest.yml` + working stdio MCP server for Cursor.
- [x] **Marketplace Bonus:** Prepared for listing submission on Atlassian Developer Console.
- [x] **Design & UX:** React Flow interactive visual canvas + Atlaskit design tokens + 1-Click FDA export.
