# MedTrace Customer Support & SLA Policy

**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Engine  
**Vendor / Maintainer:** `[CONFIGURE BEFORE LISTING: Legal Entity / Vendor Name]`  
**Support Email:** `[CONFIGURE BEFORE LISTING: support@your-domain.example]`  
**Support Portal / Issue Tracker:** `[CONFIGURE BEFORE LISTING: https://your-support-portal.example]`

---

### 1. Support Channels

For technical issues, deployment questions, or bug reports:

- **Support Portal:** `[CONFIGURE BEFORE LISTING: https://your-support-portal.example]`
- **Email Support:** `[CONFIGURE BEFORE LISTING: support@your-domain.example]`
- **Business Hours:** `[CONFIGURE BEFORE LISTING: e.g., Mon–Fri 09:00–17:00 UTC]`
- **Security Vulnerabilities:** Please do not file public tickets for security issues; follow `SECURITY.md`.

---

### 2. Target Service Level Objectives (SLOs)

`[CONFIGURE BEFORE LISTING: Confirm commercial SLA commitments prior to paid Marketplace launch]`

| Severity Level | Definition | Target Initial Response |
|---|---|---|
| **P1 - Critical** | Safety gate validator or core compliance resolver unavailable across production projects. | `[CONFIGURE BEFORE LISTING: e.g., < 8 business hours]` |
| **P2 - Major** | Trace matrix rendering issues, Rovo action failures, live Jira/Confluence sync errors, or MCP webtrigger failures. | `[CONFIGURE BEFORE LISTING: e.g., < 24 business hours]` |
| **P3 - Minor** | Cosmetic UI glitches, export formatting feedback, or general configuration questions. | `[CONFIGURE BEFORE LISTING: e.g., < 48 business hours]` |

---

### 3. Opening a Support Ticket

When reporting a defect, please include:
1. Atlassian Cloud Site URL (e.g., `your-site.atlassian.net`) and product context (Jira or Confluence).
2. Relevant Jira Issue Key, Confluence Page ID, or Hazard Key exhibiting the issue.
3. Installed Forge app major version from **Atlassian Administration → Apps → Manage apps** (or `forge install list` / `forge logs` output for self-hosted deployments).
4. Browser console error logs or screenshots of the error banner / inspection drawer.
5. Note whether the workspace is running in `DEMO` or `LIVE` dataset mode.

---

### 4. Updates & Maintenance

MedTrace runs on Atlassian Forge serverless infrastructure. Major permission or scope upgrades require administrator approval in Atlassian Administration (or `forge install --upgrade`) before taking effect.
