# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in MedTrace, **do not open a public GitHub issue**.

- **Security Contact:** farhantanvir277@gmail.com
- **Private Advisory Channel:** https://github.com/armageden/MedTrace/security/advisories/new
- **PGP / Encryption Key (Optional):** None (use GitHub Private Vulnerability Reporting above)

Please include:
1. Affected component (`manifest.yml`, Forge backend resolver, webtrigger, or product trigger in [src/index.ts](src/index.ts), Custom UI under `static/frontend/`, or local MCP stdio server [mcp-server/index.mjs](mcp-server/index.mjs)).
2. Reproduction steps or proof-of-concept request (redact all real secrets, tokens, and tenant IDs).
3. Potential impact on tenant isolation, authentication, RBAC, or audit-chain integrity.

---

## Supported Versions

| Component | Status | Notes |
|---|---|---|
| Forge App (`main` / latest deployed version) | Supported | Deployed via Atlassian Forge `nodejs22.x` runtime |
| Local Stdio MCP Server ([mcp-server/index.mjs](mcp-server/index.mjs)) | Supported | Requires `MEDTRACE_MCP_SECRET` and `https://` `MEDTRACE_WEBTRIGGER_URL` (`MEDTRACE_ALLOW_INSECURE_LOCALHOST=true` permits loopback `http://` for local dev/testing only) |

---

## Security Architecture and Boundaries

- **Zero Outbound Backend Egress:** [manifest.yml](manifest.yml) omits `permissions.external.fetch.backend`. The Forge backend cannot initiate outbound network connections to third-party servers. Declared scopes are limited to `read:jira-work`, `read:jira-user`, `read:page:confluence`, `read:space:confluence`, `read:user:confluence`, `read:content.metadata:confluence`, and `storage:app`, with `permissions.content.styles: ['unsafe-inline']` solely for `@xyflow/react` runtime `transform` styles (no script `'unsafe-inline'`).
- **Tenant-Confined Persistence (`@forge/kvs`):** Compliance suites (`SHARDED_V2` with `vlock` optimistic locking, `kvs.transact()` up to 25 operations, versioned chunked staging above 25 operations, and save-before-audit compensating rollback), Confluence specification SHA-256 digests (`SignedSpecBaseline`), replay nonces, and the monotonic SHA-256 hash-chained audit ledger (`prevHash` → `entryHash` in [src/audit-log.ts](src/audit-log.ts) using `keyPolicy: 'FAIL_IF_EXISTS'`) are stored exclusively inside the customer's Atlassian Cloud tenant. Cold-start empty KVS returns a read-only uninitialized `LIVE` suite (`initialized: false`, `totalHazards: 0`, `releaseBlocked: true`) with zero automatic KVS writes or synthetic demo seeding.
- **Resolver RBAC and Confused-Deputy Protection ([src/index.ts](src/index.ts)):**
  - Every Custom UI resolver enforces authenticated Atlassian session checks (`accountId`), Jira identity/permission validation (`/rest/api/3/myself` and project/issue-scoped `/rest/api/3/mypermissions`), and Confluence identity/permission validation (`/wiki/rest/api/user/current`, `/wiki/api/v2/pages/{id}/operations`, `/wiki/api/v2/spaces/{id}/operations`, and `/wiki/api/v2/spaces?type=global&limit=25`).
  - `assertAuthorizedReader` gates all 6 read resolvers (`getComplianceSuite`, `queryGraphContext`, `simulateTransition`, `analyzeBlastRadius`, `getAuditLog`, `verifyAuditChain`).
  - `assertAuthorizedOperator` gates all 6 mutating resolvers (`seedDemoSuite`, `syncLiveSuite`, `remediateGap`, `recordTestResult`, `signOffPart11`, `bindIssueToHazard`), rejecting Confluence read-only viewers (even with personal-space write permissions) and blocking cross-project `projectKey`, `issueKey`, or `jql` overrides.
  - Interactive Jira and Confluence calls execute under `api.asUser()` (`callerMode: 'USER'`). Rovo handlers (`rovoActionHandler` in [src/mcp-server.ts](src/mcp-server.ts)) enforce an explicit action allowlist and user read probes when `accountId` is supplied in Forge runtime.
- **Authenticated Inbound Webtrigger (`mcp-sync-webtrigger` / `mcpWebtriggerHandler`):**
  - Fails closed (`500`) if `MEDTRACE_MCP_SECRET` is unset or empty in the Forge environment.
  - Accepts only `GET` and `POST` (`405` with `Allow: GET, POST` for unsupported methods before consuming nonces).
  - Requires `x-medtrace-timestamp` (Unix epoch milliseconds), `x-medtrace-nonce` (or `x-medtrace-event-id`, 1–256 chars), and `x-medtrace-signature: sha256=<hex>` over `${timestamp}.${nonce}.${rawBody}`, verified with `crypto.timingSafeEqual`.
  - Enforces an asymmetric timestamp window of `[-300_000, +30_000]` ms (`MAX_TIMESTAMP_AGE_MS = 300_000` past age, `MAX_FUTURE_SKEW_MS = 30_000` future skew in [src/nonce-store.ts](src/nonce-store.ts)) and atomic single-use nonce claiming (`kvsNonceStore.claimDetailed` via `keyPolicy: 'FAIL_IF_EXISTS'` on `nonce:${sha256Hex(key)}` with `NONCE_TTL_MS = 390_000`, rounded to 7 minutes / 420 seconds in Forge KVS; replays return `409`).
  - Rejects `POST` `seed` and `remediate` actions with `403` when active `datasetMode` is `'LIVE'`; `verify-release-gate` enforces `requireLiveMode: true` (`403` unless an initialized `LIVE` suite passes release checks).
  - [mcp-server/index.mjs](mcp-server/index.mjs) fails closed on startup if `MEDTRACE_MCP_SECRET` or `MEDTRACE_WEBTRIGGER_URL` is missing or invalid, enforces `https://` without embedded credentials (loopback `http://` permitted only if `MEDTRACE_ALLOW_INSECURE_LOCALHOST=true`), and applies a `15000` ms default timeout (`MEDTRACE_REQUEST_TIMEOUT_MS`, clamped `1000..60000`).
- **Evidence URL and Export Hardening:** `validateHttpsUrl` in [src/crypto-utils.ts](src/crypto-utils.ts) enforces `https://` without embedded credentials on `evidenceUrl`, and `escapeCsvCell` in [static/frontend/src/components/FdaExportModal.tsx](static/frontend/src/components/FdaExportModal.tsx) neutralizes spreadsheet formula injection (`CWE-1236`).
- **Non-PHI Engineering Boundary:** MedTrace is designed strictly for non-PHI engineering metadata (Jira issue keys, Confluence specification titles/excerpts/hashes, test status, and signature attestation metadata). Do not store Protected Health Information (PHI) or patient identifiers in tracked Jira or Confluence fields.

---

## Honest Forge Platform and Part 11 Boundaries

- **No Hardware WORM, HSM, or X.509/PKI Certificates:** `@forge/kvs` provides tenant-scoped storage with `FAIL_IF_EXISTS` conditional write guards and SHA-256 audit hash-chaining (`tamper-evident`). Forge KVS is **not** hardware Write-Once-Read-Many (WORM) storage, provides **no** Hardware Security Module (HSM), and does **not** issue X.509/PKI digital certificates. A Forge app administrator/deployer with Forge CLI or environment access can redeploy app code, update environment variables, or trigger tenant KVS removal upon app uninstallation.
- **21 CFR Part 11 Electronic Signature Controls (`signOffPart11`):** Because Atlassian Forge does not expose an IdP password re-authentication API or hardware PKI, MedTrace combines:
  1. Authoritative Atlassian session identity (`UserIdentityResolver` in [src/seeder.ts](src/seeder.ts), binding `signedBy`, `signedByAccountId`, and server-derived `role` while ignoring client-supplied signer fields),
  2. Explicit §11.200/§11.50 runtime attestation (`attestationConfirmed: true`, `passwordConfirmed: true` session re-attestation, exact `PART11_ATTESTATION_PHRASE = 'I CERTIFY THIS ELECTRONIC SIGNATURE'`, and `meaning` of at least 5 characters),
  3. Server-side `HMAC-SHA256-SEAL-V1` record sealing (`ComplianceEngine.computePart11Seal` / `verifyPart11Seal` in [src/compliance-engine.ts](src/compliance-engine.ts)) requiring `MEDTRACE_PART11_SECRET` (plus comma-separated `MEDTRACE_PART11_PREVIOUS_SECRETS` key-ring verification via `resolvePart11VerificationSecrets` and `computePart11KeyFingerprint`), and optional hybrid asymmetric `ECDSA-P256-SHA256+HMAC-SEAL-V1` client `prime256v1` non-repudiation signature verification (`computePart11ClientChallenge`, `verifyPart11ClientSignature`, and `computeClientKeyFingerprint` supporting both WebCrypto IEEE P1363 64-byte and ASN.1 DER signatures), and
  4. Monotonic SHA-256 hash-chained audit logging ([src/audit-log.ts](src/audit-log.ts)) plus Confluence drift/revert non-resurrection (`invalidatedAt` persists if a modified page is reverted until freshly re-signed).
  Customers remain responsible for Computer Software Validation (CSV), organizational SOPs, Atlassian SSO/MFA enforcement, and external archival of FDA dossier exports.
- **Jira Workflow Validator Limitation (Atlassian `ECO-624`):** `jira:workflowValidator` (`workflowValidatorHandler` in [src/workflow-validator.ts](src/workflow-validator.ts)) evaluates human-initiated Jira workflow transitions only. Under Atlassian platform limitation `ECO-624`, Jira Automation rules and direct Jira REST API status transitions bypass `jira:workflowValidator`, and unlinked/untracked Jira issues are not blocked on initialized suites. Production releases **must** also run [.github/workflows/medtrace-release-gate.yml](.github/workflows/medtrace-release-gate.yml) (`action: 'verify-release-gate'` with `requireLiveMode: true`).

---

## Secret Handling and Rotation

- Never commit `.env`, `.env.*`, `.forge-env`, API tokens, `MEDTRACE_MCP_SECRET`, or `MEDTRACE_PART11_SECRET` values to source control. Use [.env.example](.env.example) strictly as a placeholder template.
- **Rotating `MEDTRACE_MCP_SECRET`:** Run [scripts/rotate-mcp-secret.sh](scripts/rotate-mcp-secret.sh) to generate a new 256-bit secret, set `MEDTRACE_MCP_SECRET` (`--encrypt`) across Forge environments (`production`, `development`), redeploy so Forge snapshots the updated variable, update local `.env` (`chmod 600`), and verify `401` rejection on the old secret alongside `200`/`409` live checks. Update any local Cursor, Claude Desktop, or CI `MEDTRACE_MCP_SECRET` configurations afterward.
- **Provisioning and Rotating `MEDTRACE_PART11_SECRET`:** Set an independent 256-bit secret via `forge variables set MEDTRACE_PART11_SECRET "<new-secret>" --encrypt -e production`. For zero-downtime key rotation, append the retiring key(s) to comma-separated `MEDTRACE_PART11_PREVIOUS_SECRETS` (`forge variables set MEDTRACE_PART11_PREVIOUS_SECRETS "<old-secret-1>,<old-secret-2>" --encrypt -e production`) before updating `MEDTRACE_PART11_SECRET` and running `forge deploy -e production`. New `signOffPart11` operations seal with the primary `MEDTRACE_PART11_SECRET` and record `keyFingerprint` (`computePart11KeyFingerprint`), while historical `HMAC-SHA256-SEAL-V1` / `ECDSA-P256-SHA256+HMAC-SEAL-V1` records sealed under retired keys remain verifiable via `resolvePart11VerificationSecrets`. Prior to retiring keys completely from `MEDTRACE_PART11_PREVIOUS_SECRETS`, export and archive FDA dossiers and re-sign any specs whose retired secrets are being decommissioned.
- **Rewriting Git History After Secret Exposure (`git filter-repo`):** If a pre-rotation `MEDTRACE_MCP_SECRET`, `MEDTRACE_PART11_SECRET`, or private webtrigger URL ever touched committed repository history:
  1. Immediately rotate the exposed secret in all Forge environments (`production`, `staging`, `development`) and run `forge deploy` first so the leaked secret is rejected at runtime (`401`).
  2. Install `git-filter-repo` and rewrite repository history (`git filter-repo --replace-text expressions.txt` to redact exposed secret literals across all commits, or `git filter-repo --invert-paths --path <exposed-file>`).
  3. Force-push rewritten branches and tags (`git push --force --all` and `git push --force --tags`), instruct collaborators to re-clone fresh copies, and contact your Git hosting provider to purge cached commit/PR refs.

---

## Related Documentation and Pre-Listing Gate

- Privacy Policy: [marketplace/PRIVACY_POLICY.md](marketplace/PRIVACY_POLICY.md)
- Terms of Service and EULA: [marketplace/TERMS_OF_SERVICE.md](marketplace/TERMS_OF_SERVICE.md)
- Customer Support and SLA Policy: [marketplace/SUPPORT.md](marketplace/SUPPORT.md)
- Production Deployment Runbook: [docs/00-how-to/03-deploy-production.md](docs/00-how-to/03-deploy-production.md)
- MCP Webtrigger Contract: [docs/03-mcp-integration/live-sync.md](docs/03-mcp-integration/live-sync.md)
- Pre-Marketplace Gate: All vendor/legal configuration placeholders in this file and under `marketplace/` must be populated before Atlassian Marketplace submission and verified with `node scripts/docs-check.mjs --strict-listing` (exit `0`).
