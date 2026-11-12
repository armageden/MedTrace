# MedTrace Customer Support & SLA Policy

**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Sentinel  
**Maintained by:** Farhan Dev (`farhantanvir277@gmail.com`)  
**Issue Tracker:** `https://github.com/armageden/MedTrace/issues`  

---

### 1. Support Channels

For technical issues, bug reports, or regulatory workflow inquiries:

- **Email Support:** `farhantanvir277@gmail.com` (Response within 24 business hours)
- **Atlassian Developer Community:** Mention `@MedTrace` in Marketplace discussions.
- **Issue Tracker:** `https://github.com/armageden/MedTrace/issues`

---

### 2. Service Level Agreements (SLAs)

| Severity Level | Definition | Target Initial Response |
|---|---|---|
| **P1 - Critical** | Safety gate validator malfunctioning; preventing legitimate Jira releases across all projects. | $< 8\text{ hours}$ |
| **P2 - Major** | Trace matrix graph rendering issues, Rovo action timeouts, or MCP sync failures. | $< 24\text{ hours}$ |
| **P3 - Minor** | Cosmetic UI glitches, report formatting feedback, or non-blocking queries. | $< 48\text{ hours}$ |

---

### 3. Reporting a Defect

When opening a ticket, please provide:
1. Atlassian Cloud Site URL (e.g., `your-site.atlassian.net`)
2. Jira Issue Key or Confluence Page ID exhibiting the issue
3. Browser version and Forge app installation version (visible in the app header or `forge install list`; e.g., major version 2 or 3)
4. Console error logs or screenshot of the MedTrace inspection drawer

---

### 4. Release & Maintenance Windows

MedTrace updates are deployed automatically via the Atlassian Forge infrastructure with zero downtime. Schema upgrades and major version migrations are validated through automated pre-deployment testing.
