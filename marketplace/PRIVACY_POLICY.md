# MedTrace Privacy Policy

**Effective Date:** `[CONFIGURE BEFORE LISTING: YYYY-MM-DD]`  
**Last Updated:** `[CONFIGURE BEFORE LISTING: YYYY-MM-DD]`  
**Vendor / Data Controller Contact:** `[CONFIGURE BEFORE LISTING: Legal Entity Name]` (`[CONFIGURE BEFORE LISTING: privacy@your-domain.example]`)  
**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Engine

---

### 1. Architectural Privacy by Design

MedTrace is built on the **Atlassian Forge** serverless platform (`nodejs22.x`) and runs inside Atlassian's isolated cloud runtime environment within the customer's Atlassian Cloud security boundary.

- **No External Backend Servers:** MedTrace does not operate secondary databases or multi-tenant servers outside of Atlassian Cloud, and `manifest.yml` declares no `permissions.external.fetch.backend` outbound network permissions.
- **Tenant Isolation (`@forge/kvs`):** All hazard trace links, Confluence specification SHA-256 digests, verification test records, signature attestations, and hash-chained audit ledger entries are persisted exclusively within the customer's Atlassian tenant via `@forge/kvs`.
- **Non-PHI / Non-Patient Data Boundary:** MedTrace is engineered to process engineering metadata only (Jira issue keys, Confluence page IDs/titles/content hashes, verification test states, Atlassian Account IDs, and signature attestation records). Customers must not store Protected Health Information (PHI) or clinical patient records in MedTrace-tracked fields.

---

### 2. Data Handled & Storage

| Data Category | Purpose | Storage Location | Retention |
|---|---|---|---|
| **ISO 14971 Risk & Traceability Metadata** | Hazard classifications (Class A/B/C), linked Jira issue keys, and verification test states | Forge Tenant KVS (`@forge/kvs`) | Controlled by tenant / app uninstall lifecycle |
| **Confluence Specification Digests** | Cryptographic SHA-256 digests of specification pages for drift detection | Forge Tenant KVS (`@forge/kvs`) | Controlled by tenant / app uninstall lifecycle |
| **Hash-Chained Audit Ledger** | Append-only, SHA-256 hash-chained log (`prevHash` → `entryHash`) of compliance mutations, test recordings, sign-offs, and syncs | Forge Tenant KVS (`@forge/kvs`) | Controlled by tenant / app uninstall lifecycle |
| **Replay-Protection Nonces** | SHA-256 hashed request nonces with short TTL to reject replayed webtrigger calls | Forge Tenant KVS (`@forge/kvs`) | Automatically expired via KVS TTL |
| **Atlassian Account IDs** | Attributing remediation, test execution, and signature attestation events | Forge Tenant KVS (`@forge/kvs`) | Controlled by tenant lifecycle |

---

### 3. Third-Party Integrations & Model Context Protocol (MCP)

- **Atlassian Rovo:** Agent and action invocations execute within Atlassian Cloud under Atlassian's intelligence and data governance boundary.
- **Local MCP Stdio Server (`mcp-server/index.mjs`):** When engineers connect a local IDE (such as Cursor or Claude Desktop), the local process communicates exclusively with the customer's deployed Atlassian Forge webtrigger over HTTPS using HMAC-SHA256 request signing (`MEDTRACE_MCP_SECRET`).

---

### 4. Regulatory & Privacy Statements

- **Audit Trail Integrity (21 CFR Part 11 Context):** MedTrace maintains an append-only, hash-chained audit ledger in `@forge/kvs` (`medtrace:audit:entry:<seq>`) recording state-changing actions (`seed`, `sync`, `bind`, `recordTest`, `signOff`, `remediate`) with `prevHash` → `entryHash` linkage. Full organizational compliance with FDA 21 CFR Part 11 remains the customer's responsibility (including Atlassian Identity/SSO controls, procedural SOPs, and system validation).
- **GDPR / CCPA:** MedTrace processes minimal personal identifiers (Atlassian Account IDs for audit attribution). Customer administrators manage user access and deletion requests through Atlassian Cloud user lifecycle controls and app uninstallation.

---

### 5. Contact & Security Inquiries

For privacy, data handling, or security inquiries:
- **Privacy & Support Email:** `[CONFIGURE BEFORE LISTING: support@your-domain.example]`
- **Security Contact & Disclosure Policy:** See `SECURITY.md` (`[CONFIGURE BEFORE LISTING: security@your-domain.example]`)
- **Data Processing Addendum (DPA):** `[CONFIGURE BEFORE LISTING: URL or request contact]`
