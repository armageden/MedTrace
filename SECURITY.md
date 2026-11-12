# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MedTrace, **do not open a public GitHub issue**.

- **Security Contact:** `[CONFIGURE BEFORE LISTING: security@your-domain.example]`
- **Private Advisory Channel:** `[CONFIGURE BEFORE LISTING: https://github.com/<org>/<repo>/security/advisories/new]`
- **PGP / Encryption Key (Optional):** `[CONFIGURE BEFORE LISTING]`

Please include:
1. Affected component (`manifest.yml`, Forge backend resolver/webtrigger, Custom UI, or `mcp-server/index.mjs`).
2. Reproduction steps or proof-of-concept request (redact all real secrets and tenant IDs).
3. Potential impact on tenant isolation, authentication, or audit-chain integrity.

---

## Supported Versions

| Component | Status | Notes |
|---|---|---|
| Forge App (`main` / latest deployed version) | Supported | Deployed via Atlassian Forge `nodejs22.x` runtime |
| Local Stdio MCP Server (`mcp-server/index.mjs`) | Supported | Requires `MEDTRACE_MCP_SECRET` and TLS Forge webtrigger URL |

---

## Security Architecture & Boundaries

- **Zero Outbound Egress:** `manifest.yml` omits `permissions.external.fetch.backend`. The Forge backend cannot initiate outbound network connections to third-party servers.
- **Tenant-Confined Persistence (`@forge/kvs`):** Compliance suites, Confluence specification SHA-256 digests, and the hash-chained append-only audit ledger (`prevHash` → `entryHash`) are stored exclusively inside the customer's Atlassian Cloud tenant.
- **Authenticated Inbound Webtrigger (`mcp-sync-webtrigger`):**
  - Fails closed if `MEDTRACE_MCP_SECRET` is unset in the Forge environment.
  - Requires `x-medtrace-timestamp`, `x-medtrace-nonce`, and `x-medtrace-signature: sha256=<hex>` over `${timestamp}.${nonce}.${rawBody}`, verified with `crypto.timingSafeEqual`.
  - Enforces a 300-second timestamp window and atomic per-nonce claim (`FAIL_IF_EXISTS` with TTL in `@forge/kvs` using SHA-256 hashed nonce keys).
- **Non-PHI Engineering Boundary:** MedTrace is designed strictly for non-PHI engineering metadata (Jira issue keys, Confluence specification pages/hashes, test status, and signature attestation metadata). Do not store Protected Health Information (PHI) or patient identifiers in tracked Jira/Confluence fields.

---

## Secret Handling & Rotation

- Never commit `.env`, `.forge-env`, API tokens, or `MEDTRACE_MCP_SECRET` values to source control. Use `.env.example` strictly as a placeholder template.
- If a `MEDTRACE_MCP_SECRET` is ever exposed, rotate it immediately across all Forge environments (`production` and `development`) using `scripts/rotate-mcp-secret.sh` and redeploy so running Forge environments snapshot the updated variable.
