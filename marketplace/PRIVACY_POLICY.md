# MedTrace Privacy Policy

**Effective Date:** 2026-11-13  
**Last Updated:** 2026-11-13  
**Vendor / Data Controller Contact:** Farhan Tanvir (Individual Developer / Maintainer) (farhantanvir277@gmail.com)  
**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Engine

---

## 1. Architectural Privacy by Design

MedTrace is built on the **Atlassian Forge** serverless platform (`nodejs22.x`) and executes inside Atlassian's isolated cloud runtime within the customer's Atlassian Cloud security boundary.

- **No External Vendor Databases or Backend Egress:** MedTrace does not operate secondary vendor databases or multi-tenant storage servers outside of Atlassian Cloud, and [manifest.yml](../manifest.yml) declares no `permissions.external.fetch.backend` outbound network permissions.
- **Tenant Isolation (`@forge/kvs`) and RBAC:** All hazard trace links, Confluence specification digests and snippets, verification test records, signature attestations, and hash-chained audit ledger entries are persisted exclusively within the customer's Atlassian tenant via `@forge/kvs`. Custom UI access is gated server-side by `assertAuthorizedReader` and `assertAuthorizedOperator` in [src/index.ts](../src/index.ts), enforcing Atlassian session identity and Jira/Confluence project and global-space permissions.
- **Non-PHI / Non-Patient Data Boundary:** MedTrace is engineered to process non-PHI software engineering and quality metadata only. Customers must not store Protected Health Information (PHI) or patient-identifiable clinical records in Jira issues, Confluence pages, test notes, or evidence URLs ingested by MedTrace.

---

## 2. Data Handled, PII Excerpts, and Storage

MedTrace persists the following engineering metadata, user-attributable fields, excerpts, and URLs inside the customer's Atlassian tenant (`@forge/kvs`):

| Data Category | Specific Fields Persisted / Processed | Purpose | Storage Location & Retention |
|---|---|---|---|
| **User Identity & Signatory Attribution** | `actorAccountId`, `signedBy` (`<displayName> (<accountId>)`), `signedByAccountId`, `role` (server-derived Atlassian role), `assignee` (Jira issue assignee display name), `recordedBy` (operator `actorAccountId`) | Attributing Part 11 electronic signatures (`UserIdentityResolver`), Jira work assignments, test result recordings, and audit log actions | Forge Tenant KVS (`@forge/kvs` sharded `TraceLink`, `SignedSpecBaseline`, `AuditLogEntry`); retained until tenant app uninstall / lifecycle deletion |
| **Confluence Specification Digests & Excerpts** | `sha256Hash`, `lastSignedHash`, `pageId`, `title`, `version`, and `contentSnippet` (up to 220-character plain-text excerpt stripped from Confluence `body.storage.value`) | Detecting specification drift across versions and displaying requirement context in the UI and MCP/Rovo summaries | Forge Tenant KVS (`@forge/kvs` `TraceLink` shards and `SignedSpecBaseline`); retained until tenant app uninstall |
| **Verification Test Evidence & Notes** | `evidenceUrl` (`https://`-validated test artifact link), `notes` (operator execution notes), `executionDate`, `status`, `testKey` | Tracking IEC 62304 verification test outcomes and packaging FDA 510(k) JSON/CSV traceability exports | Forge Tenant KVS (`@forge/kvs` `TraceLink` shards and `RECORD_TEST_RESULT` audit `details`); retained until tenant app uninstall |
| **ISO 14971 Risk & Jira Work Metadata** | Hazard keys/titles/risk classes, Jira issue keys/titles/statuses, optional `prNumber` and `commitSha` (cleared on issue rebind), `meaning` (Part 11 signature meaning) | Bidirectional IEC 62304 traceability, blast-radius traversal, and release gating | Forge Tenant KVS (`@forge/kvs` `SHARDED_V2` suite and audit `details`); retained until tenant app uninstall |
| **Hash-Chained Audit Ledger** | `seq`, `timestamp`, `actorAccountId`, `action`, `targetKey`, `details` (mutation metadata including `signedBy`, `role`, `evidenceUrl`, `notes`), `prevHash`, `entryHash`, `authMethod` | Maintaining an append-only, SHA-256 hash-chained tamper-evident log (`medtrace:audit:entry:<seq>`) | Forge Tenant KVS (`@forge/kvs`); retained until tenant app uninstall |
| **Replay-Protection Nonces & Locks** | SHA-256 hashed request nonces (`nonce:${sha256Hex(key)}`) and optimistic version locks (`vlock:*`) | Preventing webtrigger replay attacks and concurrent KVS write corruption | Forge Tenant KVS (`@forge/kvs`); nonces expire via 7-minute KVS TTL (`NONCE_TTL_MS = 390_000` ms) and `vlock` expires via 1-minute TTL |

*Note on Transient Email Inspection:* During Part 11 sign-off in Jira or Confluence, `UserIdentityResolver` ([src/seeder.ts](../src/seeder.ts)) queries `/rest/api/3/myself` or `/wiki/rest/api/user/current` and may read `emailAddress` / `email` into in-memory `AuthorizedUserIdentity`; MedTrace does not persist email addresses into `Part11Signature`, `SignedSpecBaseline`, or `AuditLogEntry` records.

---

## 3. Third-Party Integrations, Rovo, and MCP Data Transfers

- **Local MCP Stdio Bridge ([mcp-server/index.mjs](../mcp-server/index.mjs)):**
  - Runs locally on the developer's workstation; `.env` configuration and secrets remain on the developer's machine and zero compliance state is persisted locally.
  - **Outbound from Developer IDE to Atlassian Cloud:** When an engineer or AI coding assistant invokes `medtrace_verify_iec_compliance`, caller-supplied `prDiff` (Git PR diffs or code excerpts), `componentName`, and `issueKey` values are transmitted over `https://` with HMAC-SHA256 authentication (`MEDTRACE_MCP_SECRET`, `[-300_000, +30_000]` ms timestamp window, single-use nonces) to the customer's deployed `mcp-sync-webtrigger` (`mcpWebtriggerHandler` in [src/index.ts](../src/index.ts)).
  - **Inbound from Atlassian Cloud to Developer IDE:** When an engineer invokes `medtrace_get_hazard_lineage` (or `medtrace_verify_iec_compliance` / `medtrace_remediate_safety_gap`), persisted `TraceLink` records—including `assignee`, `contentSnippet`, `evidenceUrl`, `notes`, `signedBy`, `signedByAccountId`, `role`, and `recordedBy`—are returned over `https://` to the local IDE MCP client session.
- **Atlassian Rovo (`rovoActionHandler` in [src/mcp-server.ts](../src/mcp-server.ts)):**
  - `get-hazard-lineage-action` and `verify-iec-compliance-action` (`rovo:agent` and `rovo:mcp` in [manifest.yml](../manifest.yml)) run inside Atlassian's Forge runtime and Atlassian's Rovo governance boundary.
  - Inputs (`issueKey`, `hazardKey`, `prDiff`, `componentName`) are analyzed in memory to extract matching keys, text tokens, and blast-radius graphs. `rovoActionHandler` does not log raw `prDiff` contents (logging only `actionKey`, `issueKey`/`hazardKey`, `componentName`, and boolean `hasPrDiff`).
- **Client-Side Dossier Exports (`FdaExportModal`):**
  - Exported JSON, CSV, and printable FDA 510(k) packages ([static/frontend/src/components/FdaExportModal.tsx](../static/frontend/src/components/FdaExportModal.tsx)) are generated client-side in the operator's browser and contain persisted suite, test evidence URL, signature, and audit ledger fields (`signedBy`, `actorAccountId`, `evidenceUrl`, etc.).

---

## 4. Regulatory, Part 11, and Forge Platform Disclosures

- **Audit Trail Actions and Auth Methods ([src/types.ts](../src/types.ts)):** MedTrace records state-changing actions under the canonical `AuditActionType` enum (`SEED_DEMO`, `SYNC_LIVE`, `BIND_ISSUE`, `RECORD_TEST_RESULT`, `PART11_SIGNOFF`, `DEMO_SIMULATION`, `CONFLUENCE_PAGE_DRIFT`) paired with `AuditAuthMethod` (`FORGE_USER_SESSION`, `PART11_ATTESTATION`, `HMAC_WEBTRIGGER`, `CONFLUENCE_EVENT_TRIGGER`, `SYSTEM_INIT`).
- **Honest Storage and Cryptography Boundaries (No WORM, HSM, or X.509/PKI):** `@forge/kvs` provides tenant-scoped persistence with `FAIL_IF_EXISTS` write guards and SHA-256 `prevHash` → `entryHash` chaining (`tamper-evident`). Forge KVS does **not** provide hardware Write-Once-Read-Many (WORM) storage, a Hardware Security Module (HSM), or X.509/PKI digital certificates. A Forge app deployer/administrator can redeploy app code, update environment variables, or trigger KVS removal upon app uninstallation.
- **21 CFR Part 11 Electronic Signature Scope:** Because Forge provides no IdP password re-authentication API or HSM/PKI key store, MedTrace implements §11.200/§11.50 controls by combining server-side `HMAC-SHA256-SEAL-V1` record sealing (`MEDTRACE_PART11_SECRET`), authenticated Atlassian session identity (`UserIdentityResolver`), explicit password/phrase attestation (`PART11_ATTESTATION_PHRASE = 'I CERTIFY THIS ELECTRONIC SIGNATURE'`), monotonic SHA-256 hash-chained audit logging, Confluence drift/revert non-resurrection, and RBAC (`assertAuthorizedReader` / `assertAuthorizedOperator`). Full regulatory compliance remains the customer's responsibility (including Computer Software Validation, organizational SOPs, Atlassian SSO/MFA enforcement, and external archival of exported dossiers).
- **Jira Workflow Gate Boundary (`ECO-624`):** Forge `jira:workflowValidator` evaluates human-initiated Jira transitions only; per Atlassian limitation `ECO-624`, Jira Automation rules and direct REST API transitions bypass `jira:workflowValidator`. Production deployments must pair it with CI/CD release gating ([.github/workflows/medtrace-release-gate.yml](../.github/workflows/medtrace-release-gate.yml) with `requireLiveMode: true`). See also [SECURITY.md](../SECURITY.md#honest-forge-platform-and-part-11-boundaries) and [TERMS_OF_SERVICE.md](TERMS_OF_SERVICE.md#3-medical-device-and-regulatory-disclaimer).
- **GDPR / CCPA & Data Lifecycle:** MedTrace processes minimal user identifiers (`actorAccountId`, `signedBy`, `role`, `assignee`, `recordedBy`) for regulatory traceability and audit attribution. Customer administrators manage access permissions, data retention, and deletion through Jira/Confluence administration and Atlassian Forge app uninstallation (which triggers `@forge/kvs` deletion under Atlassian Cloud retention policies). Export required audit dossiers before uninstalling.

---

## 5. Contact and Security Inquiries

For privacy, data handling, or security inquiries:
- **Privacy & Support Email:** farhantanvir277@gmail.com
- **Security Contact & Disclosure Policy:** See [SECURITY.md](../SECURITY.md#reporting-a-vulnerability) (farhantanvir277@gmail.com)
- **Data Processing Addendum (DPA):** Available on request via farhantanvir277@gmail.com
