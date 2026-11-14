# MedTrace Customer Support and SLA Policy

**Product:** MedTrace IEC 62304 & FDA 21 CFR Part 11 Regulatory Traceability Engine  
**Vendor / Maintainer:** Farhan Tanvir (Individual Developer / Maintainer)  
**Support Email:** farhantanvir277@gmail.com  
**Support Portal / Issue Tracker:** https://github.com/armageden/MedTrace/issues

---

## 1. Support Channels

For technical issues, deployment questions, or bug reports:

- **Support Portal:** https://github.com/armageden/MedTrace/issues
- **Email Support:** farhantanvir277@gmail.com
- **Business Hours:** Mon–Fri 09:00–17:00 UTC+6
- **Security Vulnerabilities:** Please do not file public tickets for security issues; follow [SECURITY.md](../SECURITY.md#reporting-a-vulnerability).
- **Legal and Privacy Documents:** See [PRIVACY_POLICY.md](PRIVACY_POLICY.md) and [TERMS_OF_SERVICE.md](TERMS_OF_SERVICE.md).

---

## 2. Target Service Level Objectives

The targets below are non-binding target response objectives for standard maintainer/free-tier support; commercial SLAs must be confirmed separately prior to any paid enterprise launch.

| Severity Level | Definition | Target Initial Response |
|---|---|---|
| **P1 - Critical** | Safety gate validator or core compliance resolver unavailable across production projects. | < 8 business hours |
| **P2 - Major** | Trace matrix rendering issues, Rovo action failures, live Jira/Confluence sync errors, or MCP webtrigger failures. | < 24 business hours |
| **P3 - Minor** | Cosmetic UI glitches, export formatting feedback, or general configuration questions. | < 48 business hours |

---

## 3. Opening a Support Ticket

When reporting a defect, please include (and redact all secrets, `.env` files, `MEDTRACE_MCP_SECRET`, `MEDTRACE_PART11_SECRET`, and Atlassian API tokens):
1. Atlassian Cloud Site URL (e.g., `your-site.atlassian.net`) and product context (Jira or Confluence).
2. Relevant Jira Issue Key, Confluence Page ID, or Hazard Key exhibiting the issue.
3. Installed Forge app major version from **Atlassian Administration → Apps → Manage apps** (or `forge install list` / `forge logs` output for self-hosted deployments).
4. Browser console error logs or screenshots of the error banner (`role="alert"`) or inspection drawer.
5. Active workspace state: `DEMO` vs `LIVE` dataset mode (and whether the `LIVE` workspace is initialized or still in its cold-start uninitialized state with `releaseBlocked: true`).

---

## 4. Platform Boundaries and Maintenance

- **Forge Serverless Runtime and Variable Snapshots:** MedTrace runs on Atlassian Forge (`nodejs22.x`). Encrypted environment variables (`MEDTRACE_MCP_SECRET` for HMAC webtrigger authentication and `MEDTRACE_PART11_SECRET` for Part 11 `HMAC-SHA256-SEAL-V1` record sealing) are snapshotted at `forge deploy` time; see [docs/00-how-to/03-deploy-production.md](../docs/00-how-to/03-deploy-production.md) and [scripts/rotate-mcp-secret.sh](../scripts/rotate-mcp-secret.sh). Rotating `MEDTRACE_PART11_SECRET` requires re-signing affected Part 11 records (archive FDA dossier exports beforehand).
- **MCP Webtrigger Diagnostics:** `mcp-sync-webtrigger` enforces an asymmetric `[-300_000, +30_000]` ms timestamp window and single-use nonce tracking (`409` on replay within the 7-minute KVS TTL), and requires `https://` URLs from [mcp-server/index.mjs](../mcp-server/index.mjs) (see [mcp-server/README.md](../mcp-server/README.md)).
- **Jira Workflow Gate Boundary (`ECO-624`):** Forge `jira:workflowValidator` intercepts human-initiated UI transitions only; Jira Automation and direct REST API transitions bypass `jira:workflowValidator`. Production teams should enforce [.github/workflows/medtrace-release-gate.yml](../.github/workflows/medtrace-release-gate.yml) (`requireLiveMode: true`) as part of release pipelines.
- **Storage and Export Responsibility:** `@forge/kvs` provides tenant-scoped tamper-evident storage (`FAIL_IF_EXISTS` conditional writes + SHA-256 hash-chained audit logs), not hardware WORM, HSM, or X.509/PKI certificates. Major permission or scope upgrades require administrator approval in Atlassian Administration (or `forge install --upgrade`). Export regulatory dossiers prior to uninstalling the app.
