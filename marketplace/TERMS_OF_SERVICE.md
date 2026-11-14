# MedTrace End User License Agreement (EULA) and Terms of Service

**Effective Date:** 2026-11-13  
**Vendor:** Farhan Tanvir (Individual Developer / Maintainer)  
**Contact:** farhantanvir277@gmail.com  
**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Engine

---

## 1. Acceptance of Terms

By installing, enabling, or using MedTrace within an Atlassian Cloud site (Jira or Confluence), you and the organization you represent ("Customer") agree to be bound by this End User License Agreement ("Agreement") and the applicable Atlassian Marketplace Terms. If you do not agree, do not install or use the software.

---

## 2. Grant of License and Subscription Terms

Subject to timely payment of any applicable Atlassian Marketplace subscription fees (or free/evaluation license terms), Farhan Tanvir (Individual Developer / Maintainer) grants Customer a non-exclusive, non-transferable, revocable license to execute and use MedTrace within Customer's authorized Atlassian Cloud instance(s).

- **Billing, Refunds, and Cancellation:** Free and evaluation installations incur no fee; any paid Atlassian Marketplace subscriptions, renewals, billing, and refunds are governed by the applicable Atlassian Marketplace Billing & Refund Policy.
- **Termination and Data Deletion:** Customer may uninstall MedTrace at any time via Atlassian Administration. Upon uninstallation, Atlassian Forge removes tenant app storage (`@forge/kvs`) according to Atlassian Cloud retention policies. Customers are solely responsible for exporting required FDA 510(k) JSON/CSV traceability dossiers and audit logs before uninstalling.

---

## 3. Medical Device and Regulatory Disclaimer

> **IMPORTANT REGULATORY NOTICE:**  
> MedTrace is a software engineering productivity and automated traceability verification tool designed to assist medical device software teams in tracking engineering artifacts in relation to **IEC 62304:2006+A1:2015**, **ISO 14971:2019**, and **FDA 21 CFR Part 11** workflows.
>
> MedTrace is **NOT** a medical device, is not cleared or approved by the U.S. FDA, EMA, or any national competent authority, and does not perform clinical diagnosis, patient monitoring, or medical treatment. Customer is solely responsible for validating the software for its intended quality-system use (Computer Software Validation), verifying the accuracy of all regulatory submissions (including 510(k), De Novo, PMA, or EU MDR 2017/745 Technical Documentation), and maintaining its own Quality Management System (QMS) under ISO 13485 and 21 CFR Part 820.

- **Atlassian Forge Storage and Cryptography Boundaries:** MedTrace persists compliance state in Atlassian `@forge/kvs` using conditional write protection (`FAIL_IF_EXISTS`) and a monotonic SHA-256 hash-chained audit ledger (`prevHash` → `entryHash`). `@forge/kvs` provides **tamper-evident** storage within the customer's Atlassian Cloud tenant; it provides **no hardware WORM storage**, **no Hardware Security Module (HSM)**, and **no X.509/PKI digital certificates**. A Forge app deployer/administrator with environment access can redeploy application code, change environment variables, or cause tenant KVS deletion upon uninstallation.
- **21 CFR Part 11 Electronic Signature Scope:** Because Forge does not expose an IdP password re-authentication API or hardware PKI store, MedTrace implements §11.200/§11.50 sign-offs (`signOffPart11`) by combining server-side `HMAC-SHA256-SEAL-V1` record sealing (`MEDTRACE_PART11_SECRET`), authenticated Atlassian session identity (`UserIdentityResolver`), explicit password/phrase attestation (`PART11_ATTESTATION_PHRASE`), monotonic SHA-256 hash-chained audit logging, Confluence drift/revert non-resurrection, and RBAC (`assertAuthorizedReader` / `assertAuthorizedOperator`).
- **Jira Workflow Validator Limitation (`ECO-624`):** Forge `jira:workflowValidator` evaluates human-initiated Jira workflow transitions only; under Atlassian platform limitation `ECO-624`, Jira Automation rules and direct Jira REST API status transitions bypass `jira:workflowValidator`, and unlinked/untracked Jira issues are not blocked on initialized suites. Customer must deploy CI/CD release gating ([.github/workflows/medtrace-release-gate.yml](../.github/workflows/medtrace-release-gate.yml) with `requireLiveMode: true`) to enforce automated release blocks.
- **Demo vs Live Datasets:** `DEMO` mode datasets and `DEMO_SIMULATION` remediation actions (`remediateGap`) are strictly for evaluation and demonstration; only initialized `LIVE` suites reflect ingested production Jira and Confluence artifacts.

---

## 4. Responsibilities of Customer

1. **Jira Workflow, CI Gate, and Permission Configuration:** Customer is responsible for configuring Jira Workflow Validators (`medtrace-safety-validator`), automated CI release gates (`verify-release-gate` with `requireLiveMode: true` to cover `ECO-624` automation/REST bypasses), Jira/Confluence project and global-space permissions enforced by `assertAuthorizedReader` and `assertAuthorizedOperator`, and Atlassian Identity/SSO/MFA controls.
2. **Credential, Webtrigger, and Secret Management:** Customer is responsible for safeguarding `MEDTRACE_MCP_SECRET` (governing the `[-300_000, +30_000]` ms HMAC webtrigger replay window and single-use nonce store), `MEDTRACE_PART11_SECRET` (governing `HMAC-SHA256-SEAL-V1` Part 11 sealing), and `https://` webtrigger URLs; rotating compromised secrets promptly via [scripts/rotate-mcp-secret.sh](../scripts/rotate-mcp-secret.sh); scrubbing repository history with `git filter-repo` if any secret was committed (see [SECURITY.md](../SECURITY.md#secret-handling-and-rotation)); and archiving FDA dossier exports prior to rotating `MEDTRACE_PART11_SECRET` (rotation invalidates seal verification for prior signatures until re-signed).
3. **Electronic Signature Attestation and CSV:** Customer must ensure that electronic sign-off attestations recorded in MedTrace reflect genuine authorization by qualified personnel under Customer's SOPs and validated QMS procedures.
4. **Non-PHI Boundary:** Customer agrees not to store Protected Health Information (PHI) or patient-identifiable data in Jira/Confluence artifacts, test notes, evidence URLs, or `prDiff` payloads processed by MedTrace unless Customer has separately executed all required agreements with Atlassian and verified regulatory applicability.

---

## 5. Support and Data Processing

- **Support:** Provided per [SUPPORT.md](SUPPORT.md).
- **Privacy and DPA:** Governed by [PRIVACY_POLICY.md](PRIVACY_POLICY.md). A Data Processing Addendum (DPA) is available on request via farhantanvir277@gmail.com.

---

## 6. Limitation of Liability and Warranty Disclaimer

To the maximum extent permitted by applicable law:
- MedTrace is provided on an **"AS IS"** and **"AS AVAILABLE"** basis without implied warranties of merchantability, fitness for a particular purpose, or non-infringement.
- In no event shall Farhan Tanvir (Individual Developer / Maintainer), its contributors, or Atlassian be liable for any indirect, incidental, consequential, special, or punitive damages, including loss of data, regulatory fines, audit findings, or clinical or commercial delays.
- To the maximum extent permitted by applicable law, the aggregate liability of Farhan Tanvir (Individual Developer / Maintainer) under or in connection with this Agreement shall not exceed the total subscription fees paid by Customer for MedTrace during the 12 months preceding the claim, or USD $100 for free or evaluation use.

---

## 7. Governing Law and Jurisdiction

This Agreement shall be governed by and construed in accordance with the laws of the People's Republic of Bangladesh, without regard to conflict of law principles.
