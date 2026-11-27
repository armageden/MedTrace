# MedTrace Privacy Policy

**Effective Date:** 2026-11-13  
**Last Updated:** 2026-11-25  
**Vendor / Data Controller Contact:** Farhan Tanvir (Individual Developer / Maintainer) (farhantanvir277@gmail.com)  
**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Engine

---

## 1. Architectural Privacy by Design

MedTrace is built on the **Atlassian Forge** serverless platform (`nodejs22.x`) and executes inside Atlassian's isolated cloud runtime within the customer's Atlassian Cloud security boundary.

- **No External Vendor Database or External-Backend-Fetch Permission:** MedTrace does not operate a secondary vendor database, and [manifest.yml](../manifest.yml) declares no `permissions.external.fetch.backend`. This does not prevent configured MCP/CI clients from receiving data in authenticated webtrigger responses; those responses leave Atlassian Cloud.
- **Tenant Isolation (`@forge/kvs`) and RBAC:** All hazard trace links, Confluence specification digests and snippets, verification test records, signature attestations, and hash-chained audit ledger entries are persisted exclusively within the customer's Atlassian tenant via `@forge/kvs`. Custom UI access is gated server-side by `assertAuthorizedReader` and `assertAuthorizedOperator` in [src/index.ts](../src/index.ts), enforcing Atlassian session identity and Jira/Confluence project and global-space permissions.
- **Non-PHI Intended Use:** MedTrace is intended for non-PHI engineering metadata but does not detect or redact PHI in Jira issues, Confluence pages, test notes, evidence URLs, or MCP inputs. Customers must not submit PHI. This is not a technical DLP guarantee or a HIPAA/BAA determination.

---

## 2. Data Handled, PII Excerpts, and Storage

MedTrace persists the following engineering metadata, user-attributable fields, excerpts, and URLs inside the customer's Atlassian tenant (`@forge/kvs`). When MCP or CI tools are configured, requested results are returned to those clients outside the tenant; client-side storage and retention are governed by the client and its operator.

| Data Category | Specific Fields Persisted / Processed | Purpose | Storage Location & Retention |
|---|---|---|---|
| **User Identity & Signatory Attribution** | `actorAccountId`, `signedBy` (`<displayName> (<accountId>)`), `signedByAccountId`, `role` (server-derived Atlassian role), `assignee` (Jira issue assignee display name), `recordedBy` (operator `actorAccountId`) | Attributing Part 11 electronic signatures (`UserIdentityResolver`), Jira work assignments, test result recordings, and audit log actions | Forge Tenant KVS (`@forge/kvs` sharded `TraceLink`, `SignedSpecBaseline`, `AuditLogEntry`); retained until tenant app uninstall / lifecycle deletion |
| **Confluence Specification Digests & Excerpts** | `sha256Hash`, `lastSignedHash`, `pageId`, `title`, `version`, and `contentSnippet` (up to 220-character plain-text excerpt stripped from Confluence `body.storage.value`) | Detecting specification drift across versions and displaying requirement context in the UI and MCP/Rovo summaries | Forge Tenant KVS (`@forge/kvs` `TraceLink` shards and `SignedSpecBaseline`); retained until tenant app uninstall |
| **Verification Test Evidence & Notes** | `evidenceUrl` (`https://`-validated test artifact link), `notes` (operator execution notes), `executionDate`, `status`, `testKey` | Tracking IEC 62304 verification test outcomes and packaging FDA 510(k) JSON/CSV traceability exports | Forge Tenant KVS (`@forge/kvs` `TraceLink` shards and `RECORD_TEST_RESULT` audit `details`); retained until tenant app uninstall |
| **ISO 14971 Risk & Jira Work Metadata** | Hazard keys/titles/risk classes, Jira issue keys/titles/statuses, optional `prNumber` and `commitSha` (cleared on issue rebind), `meaning` (Part 11 signature meaning) | Bidirectional IEC 62304 traceability, blast-radius traversal, and release gating | Forge Tenant KVS (`@forge/kvs` `SHARDED_V2` suite and audit `details`); retained until tenant app uninstall |
| **Hash-Chained Audit Ledger** | `seq`, `timestamp`, `actorAccountId`, `action`, `targetKey`, `details` (mutation metadata including `signedBy`, `role`, `evidenceUrl`, `notes`), `prevHash`, `entryHash`, `authMethod` | Maintaining an append-only, SHA-256 hash-chained tamper-evident log (`medtrace:audit:entry:<seq>`) | Forge Tenant KVS (`@forge/kvs`); retained until tenant app uninstall |
| **Replay Nonces, Locks, Sync Cursors & Backups** | SHA-256 hashed request nonces (`nonce:${sha256Hex(key)}`), optimistic locks (`vlock:*`), paginated ingestion cursors (`medtrace:ingestion:cursor:*`), and pre-overwrite live suite backup (`medtrace:compliance:live_backup`) | Preventing webtrigger replay attacks, concurrent KVS corruption, truncated sync loss, and accidental admin overwrite of `LIVE` suites | Forge Tenant KVS (`@forge/kvs`); nonces expire via 7-minute TTL (`NONCE_TTL_MS = 390_000` ms), `vlock` via 1-minute TTL, and cursors/backups persist until resolved or tenant app uninstall |

*User-Initiated Live Proof Artifacts:* When a user explicitly clicks **Create Live Proof Chain**, MedTrace uses `api.asUser()` to create one Confluence proof SRS page, three Jira Tasks, Jira issue links, and one Jira remote link inside the customer's Atlassian tenant for evaluation. Those native Jira/Confluence artifacts persist under the customer's normal product retention controls until the customer corrects or deletes them; MedTrace does not automatically delete partial artifacts after a failed write.

*Note on Transient Email Inspection:* During Part 11 sign-off in Jira or Confluence, `UserIdentityResolver` ([src/seeder.ts](../src/seeder.ts)) queries `/rest/api/3/myself` or `/wiki/rest/api/user/current` and may read `emailAddress` / `email` into in-memory `AuthorizedUserIdentity`; MedTrace does not persist email addresses into `Part11Signature`, `SignedSpecBaseline`, or `AuditLogEntry` records.

---

## 3. Third-Party Integrations, Rovo, and MCP Data Transfers

- **Local MCP Stdio Bridge ([mcp-server/index.mjs](../mcp-server/index.mjs)):**
  - Runs locally on the developer's workstation; `.env` configuration and secrets remain on that machine. The bridge does not intentionally persist compliance state, but the MCP host or AI client may retain request/response content according to its own policies.
  - **Outbound from Developer IDE to Atlassian Cloud:** When an engineer or AI coding assistant invokes `medtrace_verify_iec_compliance`, caller-supplied `prDiff` (Git PR diffs or code excerpts), `componentName`, and `issueKey` values are transmitted over `https://` with HMAC-SHA256 authentication (`MEDTRACE_MCP_SECRET`, `[-300_000, +30_000]` ms timestamp window, single-use nonces) to the customer's deployed `mcp-sync-webtrigger` (`mcpWebtriggerHandler` in [src/index.ts](../src/index.ts)).
  - **Response to Developer IDE:** Lineage queries return a reduced project summary or a requested matching lineage; verification and demo-remediation calls return their results over `https://` to the local MCP client. The MCP host or AI client may retain this response under its own policies.
- **Atlassian Rovo & Graph Lookup (`rovoActionHandler` in [src/mcp-server.ts](../src/mcp-server.ts), [src/teamwork-graph.ts](../src/teamwork-graph.ts)):**
  - `get-hazard-lineage-action`, `verify-iec-compliance-action`, and `create-reverification-task-action` (`rovo:agent` and `rovo:mcp` in [manifest.yml](../manifest.yml)) run inside Atlassian's Forge runtime and Atlassian's Rovo governance boundary.
  - `TeamworkGraphService.queryIssueGraphContext` executes under `api.asUser()` to resolve Jira issue metadata and Confluence remote links (`JIRA_REST` / `JIRA_REMOTELINK_REST`); optional `confluencePageOwners` enrichment is disabled in production while `read:graph:*` Preview scopes are omitted from [manifest.yml](../manifest.yml).
  - Inputs (`issueKey`, `hazardKey`, `prDiff`, `componentName`, `reason`) are analyzed in memory (and `create-reverification-task-action` writes user-initiated Jira tasks/links under `api.asUser()`). `rovoActionHandler` does not log raw `prDiff` contents (logging only `actionKey`, `issueKey`/`hazardKey`, `componentName`, and boolean `hasPrDiff`).
- **Client-Side Dossier Exports (`FdaExportModal`):**
  - Exported JSON, CSV, and printable traceability reports ([static/frontend/src/components/FdaExportModal.tsx](../static/frontend/src/components/FdaExportModal.tsx)) are generated client-side and may contain suite, test evidence, signature, and audit-ledger fields. They are not official FDA 510(k) or eSTAR submissions.

---

## 4. Regulatory, Part 11, and Forge Platform Disclosures

- **Audit Trail Actions and Auth Methods ([src/types.ts](../src/types.ts)):** MedTrace records state-changing actions under the canonical `AuditActionType` enum (`SEED_DEMO`, `SYNC_LIVE`, `BIND_ISSUE`, `RECORD_TEST_RESULT`, `PART11_SIGNOFF`, `DEMO_SIMULATION`, `CONFLUENCE_PAGE_DRIFT`, `CREATE_REVERIFICATION_TASK`, `CREATE_LIVE_PROOF_SCENARIO`) paired with `AuditAuthMethod` (`FORGE_USER_SESSION`, `PART11_ATTESTATION`, `HMAC_WEBTRIGGER`, `CONFLUENCE_EVENT_TRIGGER`, `JIRA_EVENT_TRIGGER`, `SYSTEM_INIT`).
- **Honest Storage and Cryptography Boundaries (No WORM, HSM, or X.509/PKI):** `@forge/kvs` provides tenant-scoped persistence with `FAIL_IF_EXISTS` write guards and SHA-256 `prevHash` → `entryHash` chaining (`tamper-evident`). Forge KVS does **not** provide hardware Write-Once-Read-Many (WORM) storage, a Hardware Security Module (HSM), or X.509/PKI digital certificates. A Forge app deployer/administrator can redeploy app code, update environment variables, or trigger KVS removal upon app uninstallation.
- **Electronic Attestation Scope:** These are tamper-evident software controls, not a claim of 21 CFR Part 11 conformance. Forge does not expose an IdP password re-authentication API; `attestationChecked: true` is a session attestation checkbox, not proof of a second authentication component. Customers remain responsible for independent regulatory assessment and computer software validation.
- **Jira Workflow Validator Boundary:** Atlassian issue [`ECO-624`](https://jira.atlassian.com/browse/ECO-624) reports an Automation case but is marked Invalid and does not establish direct REST API behavior. The repository's CI calls the release-gate workflow on pull requests and pushes to main when its secrets are configured. See [SECURITY.md](../SECURITY.md#honest-forge-platform-and-part-11-boundaries).
- **GDPR / CCPA & Data Lifecycle:** MedTrace processes minimal user identifiers (`actorAccountId`, `signedBy`, `role`, `assignee`, `recordedBy`) for regulatory traceability and audit attribution. Customer administrators manage access permissions, data retention, and deletion through Jira/Confluence administration and Atlassian Forge app uninstallation (which triggers `@forge/kvs` deletion under Atlassian Cloud retention policies). Export required audit dossiers before uninstalling.

---

## 5. Contact and Security Inquiries

For privacy, data handling, or security inquiries:
- **Privacy & Support Email:** farhantanvir277@gmail.com
- **Security Contact & Disclosure Policy:** See [SECURITY.md](../SECURITY.md#reporting-a-vulnerability) (farhantanvir277@gmail.com)
- **Data Processing Addendum (DPA):** Available on request via farhantanvir277@gmail.com
