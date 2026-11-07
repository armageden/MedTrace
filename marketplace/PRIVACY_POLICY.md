# MedTrace Privacy Policy

**Effective Date:** November 5, 2026  
**Last Updated:** November 5, 2026  
**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Sentinel  

---

### 1. Architectural Privacy by Design

MedTrace is built exclusively on the **Atlassian Forge** serverless platform. This architecture guarantees that the application runs directly within Atlassian's isolated cloud runtime environment (`nodejs22.x`) and inherits Atlassian's enterprise security boundary.

- **No External Servers:** MedTrace does not operate secondary backend databases or multi-tenant servers outside of Atlassian Cloud.
- **Tenant Isolation:** All audit links, ISO 14971 hazard evaluations, Confluence specification hashes, and verification test states are persisted exclusively within the customer's own Atlassian tenant via `@forge/kvs`.
- **Zero Protected Health Information (PHI) / PII Ingestion:** MedTrace processes only engineering metadata (Jira issue keys, Confluence page titles, Git commit SHAs, automated test statuses, and cryptographic SHA-256 digests). MedTrace does not ingest, store, or transmit patient records, clinical trial subject data, or PII.

---

### 2. Data Handled & Storage

| Data Category | Purpose | Storage Location | Retention |
|---|---|---|---|
| **ISO 14971 Risk Metadata** | Hazard classifications (Class A/B/C), severity, and probability thresholds | Forge Tenant KVS | Controlled by tenant lifecycle |
| **Confluence Spec Hashes** | Cryptographic SHA-256 digests for 21 CFR Part 11 signature verification | Forge Tenant KVS | Controlled by tenant lifecycle |
| **Jira Issue Linkages** | Bidirectional traceability between tasks, tests, and requirements | Atlassian Teamwork Graph & KVS | Synchronized with Jira Cloud |
| **Verification Test States** | Pass/Fail outcomes and execution timestamps from CI/HIL pipelines | Forge Tenant KVS | Controlled by tenant lifecycle |

---

### 3. Third-Party Integrations & Model Context Protocol (MCP)

- **Atlassian Rovo:** Agent interactions occur entirely within Atlassian Cloud using Atlassian Intelligence security guarantees. Prompts and contextual compliance lineage are never sent to external model vendors for training.
- **Model Context Protocol (MCP) Stdio Server:** When engineers connect local development environments (e.g., Cursor, Claude Desktop), communication is routed through customer-owned, authenticated Forge webtriggers encrypted with TLS 1.3.

---

### 4. Regulatory Compliance Statements

- **FDA 21 CFR Part 11:** Audit trails are immutable and reflect state transitions without altering historical records.
- **GDPR / CCPA:** Since no personal user data is processed beyond standard Atlassian Account IDs required for transition logging, customer admins maintain complete deletion authority through standard Atlassian user lifecycle management.

---

### 5. Contact & Data Protection Officer

For inquiries regarding security, data handling, or audit compliance:
- **Email:** `support@medtrace.dev`
- **Developer Contact:** `farhantanvir277@gmail.com`
- **Security Portal:** `https://github.com/medtrace/security`
