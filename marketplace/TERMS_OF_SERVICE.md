# MedTrace End User License Agreement (EULA) & Terms of Service

**Effective Date:** `[CONFIGURE BEFORE LISTING: YYYY-MM-DD]`  
**Vendor:** `[CONFIGURE BEFORE LISTING: Legal Entity Name]`  
**Contact:** `[CONFIGURE BEFORE LISTING: legal@your-domain.example]`  
**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Engine

---

### 1. Acceptance of Terms

By installing, enabling, or using MedTrace within an Atlassian Cloud site (Jira, Confluence), you and the organization you represent ("Customer") agree to be bound by this End User License Agreement ("Agreement") and the applicable Atlassian Marketplace Terms. If you do not agree, do not install or use the software.

---

### 2. Grant of License & Subscription Terms

Subject to timely payment of any applicable Atlassian Marketplace subscription fees (or free/evaluation license terms), `[CONFIGURE BEFORE LISTING: Legal Entity Name]` grants Customer a non-exclusive, non-transferable, revocable license to execute and use MedTrace within Customer's authorized Atlassian Cloud instance(s).

- **Billing, Refunds & Cancellation:** `[CONFIGURE BEFORE LISTING: Governed by Atlassian Marketplace Billing & Refund Policy / Custom Enterprise Terms]`
- **Termination & Data Deletion:** Customer may uninstall MedTrace at any time via Atlassian Administration. Upon uninstallation, Atlassian Forge removes tenant app storage (`@forge/kvs`) according to Atlassian Cloud retention policies. Customers are responsible for exporting required audit evidence before uninstalling.

---

### 3. Medical Device & Regulatory Disclaimer

> **IMPORTANT REGULATORY NOTICE:**  
> MedTrace is a software engineering productivity and automated traceability verification tool designed to assist medical device software teams in tracking engineering artifacts in relation to **IEC 62304:2006+A1:2015**, **ISO 14971:2019**, and **FDA 21 CFR Part 11** workflows.
> 
> MedTrace is **NOT** a medical device, is not cleared or approved by the U.S. FDA, EMA, or any national competent authority, and does not perform clinical diagnosis, patient monitoring, or medical treatment. Customer is solely responsible for validating the software for its intended quality-system use (Computer Software Validation), verifying the accuracy of all regulatory submissions (including 510(k), De Novo, PMA, or EU MDR 2017/745 Technical Documentation), and maintaining its own Quality Management System (QMS) under ISO 13485 and 21 CFR Part 820.

---

### 4. Responsibilities of Customer

1. **Jira Workflow & Permission Configuration:** Customer is responsible for configuring Jira Workflow Validators, project permissions, and Atlassian Identity/SSO controls for authorized sign-off personnel.
2. **Credential & Webtrigger Security:** Customer is responsible for safeguarding `MEDTRACE_MCP_SECRET`, Forge environment variables, and webtrigger URLs used by CI pipelines or local MCP clients, and for rotating compromised secrets promptly (see `SECURITY.md`).
3. **Electronic Signature Attestation:** Customer must ensure that electronic sign-off attestations recorded in MedTrace reflect genuine authorization by qualified personnel under Customer's SOPs.
4. **Non-PHI Boundary:** Customer agrees not to store Protected Health Information (PHI) or patient-identifiable data in Jira/Confluence artifacts ingested by MedTrace unless Customer has separately executed all required agreements with Atlassian and verified applicability.

---

### 5. Support & Data Processing

- **Support:** Provided per `marketplace/SUPPORT.md`.
- **Privacy & DPA:** Governed by `marketplace/PRIVACY_POLICY.md`. `[CONFIGURE BEFORE LISTING: Link to executed Data Processing Addendum if applicable]`

---

### 6. Limitation of Liability & Warranty Disclaimer

To the maximum extent permitted by applicable law:
- MedTrace is provided on an **"AS IS"** and **"AS AVAILABLE"** basis without implied warranties of merchantability, fitness for a particular purpose, or non-infringement.
- In no event shall `[CONFIGURE BEFORE LISTING: Legal Entity Name]`, its contributors, or Atlassian be liable for any indirect, incidental, consequential, special, or punitive damages, including loss of data, regulatory fines, audit findings, or clinical/commercial delays.
- `[CONFIGURE BEFORE LISTING: Aggregate liability cap clause per commercial/legal counsel]`

---

### 7. Governing Law & Jurisdiction

This Agreement shall be governed by and construed in accordance with the laws of `[CONFIGURE BEFORE LISTING: State/Country Jurisdiction]`, without regard to conflict of law principles.
