[<- How-To Overview](./00-overview.md)

# Deploy to Production Atlassian Site

Follow this runbook to deploy MedTrace to a production or staging Atlassian Cloud site with Jira and Confluence, configure both encrypted runtime secrets, bind the workflow gate (`ECO-624`-aware), enable CI release checks, and pass the pre-Marketplace listing gate.

## Prerequisites

- Atlassian Forge CLI v15 (`forge login` authenticated as an app developer/admin, or `FORGE_EMAIL` / `FORGE_API_TOKEN` configured).
- Node.js 22 (`nodejs22.x` Forge runtime compatibility). Forge CLI v15 supports Node.js 22.x or 24.x only; other versions (e.g. 26.x) print an unsupported-version warning.
- `forge lint` fails with `Error: Not logged in` unless authenticated (observed with CLI 15.0.0); deploy and tunnel also require authentication. Make sure the global CLI's bin directory (`$(npm prefix -g)/bin`) is on `PATH`.
- An Atlassian Cloud site with Jira and Confluence enabled.

## 1. Install Dependencies & Build

Install root and Custom UI frontend dependencies, then run the full verification and bundle scripts defined in `package.json`:

```bash
npm install
cd static/frontend && npm install && cd ../..

npm run typecheck
npm run build:all
npm run test:all
npm run docs:check
npm run lint:manifest
forge lint
```

- `npm run lint:manifest` invokes `scripts/validate-manifest.mjs`, running offline `@forge/manifest` validations (`FULL`, `PRODUCT_TRIGGER`, `AGENT_PRODUCT_CONTEXT`), checking all compiled handler exports under `dist/index.js`, and blocking remote `http://` or `https://` UI icon URLs.

## 2. Configure Required Encrypted Secrets

MedTrace enforces fail-closed security using **two independent 256-bit secrets** stored as Forge encrypted environment variables per target environment (`production`, `staging`, `development`):

1. `MEDTRACE_MCP_SECRET`: Shared HMAC-SHA256 perimeter secret protecting the MCP/CI webtrigger (`mcpWebtriggerHandler` in `src/index.ts`, failing closed with HTTP `500` when unset) and required at startup by `mcp-server/index.mjs`.
2. `MEDTRACE_PART11_SECRET`: Dedicated 21 CFR Part 11 signature sealing secret read solely inside the Forge runtime (`getPart11SigningSecret()` in `src/seeder.ts`) to compute and verify `HMAC-SHA256-SEAL-V1` and hybrid `ECDSA-P256-SHA256+HMAC-SEAL-V1` electronic signature seals (`signOffPart11`, which also verifies client ECDSA P-256 SPKI signatures when provided). Keep this value **separate** from `MEDTRACE_MCP_SECRET` and **never** copy it into local MCP `.env` files. When rotating `MEDTRACE_PART11_SECRET`, set comma-separated retired secrets in `MEDTRACE_PART11_PREVIOUS_SECRETS` so `ComplianceEngine.verifyPart11Seal` continues verifying historical signatures in constant time while new sign-offs seal with the active primary secret (use `ComplianceEngine.computePart11KeyFingerprint` to identify keys without exposing secret bytes).
3. `MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES` (optional): Positive integer capping how many entries `AuditLogService.verifyAuditChain()` verifies per invocation when `maxEntries` is omitted (`500` default in `AuditLogService`, capped at `200` default / `500` max in the Custom UI `verifyAuditChain` resolver). UI modals automatically step sequentially across truncated windows.

Generate two distinct 32-byte random hex secrets and encrypt them into Forge:

```bash
MCP_SECRET=$(openssl rand -hex 32)
PART11_SECRET=$(openssl rand -hex 32)

forge variables set MEDTRACE_MCP_SECRET "$MCP_SECRET" --encrypt -e production
forge variables set MEDTRACE_PART11_SECRET "$PART11_SECRET" --encrypt -e production
```

Forge captures environment variables when deploying, so deploy the target environment (`forge deploy -e production`) whenever secrets are initialized or rotated. Never commit unencrypted `.env` or `.forge-env` files to git; if a secret ever reached commit history, rotate all affected secrets and scrub git history manually with `git filter-repo`.

## 3. Deploy & Install on Jira and Confluence

```bash
forge deploy -e production
forge install -e production --site <your-site>.atlassian.net --product jira
forge install -e production --site <your-site>.atlassian.net --product confluence
```

When updating scopes or manifest modules on an existing installation, pass `--upgrade` to `forge install`.

## 4. Bind the Jira Workflow Safety Gate & `ECO-624` Boundary

To enforce IEC 62304 checks on interactive Jira issue transitions:

1. Open **Jira Project Settings -> Workflows** and edit the target release workflow.
2. Select the release transition (for example, `In Review -> Done` or `Ready for Release`).
3. Add a **Validator** and choose **MedTrace Safety Gate** (`medtrace-safety-validator` in [manifest.yml](../../manifest.yml), backed by `src/workflow-validator.ts`).
4. Publish the workflow. Transitions on safety-tracked issues fail closed when the `LIVE` suite is uninitialized or when any matching trace link fails compliance evaluation (`requireTestEvidence: true` in `LIVE` mode).

> **Atlassian Platform Limitation (`ECO-624` Defense-in-Depth):**
> Per Atlassian ecosystem issue `ECO-624`, Jira `jira:workflowValidator` Forge modules are evaluated **only** on human-initiated UI transitions — Jira Automation rules and direct REST API transitions bypass Forge workflow validators. Always pair the Jira workflow validator with the CI release gate ([`.github/workflows/medtrace-release-gate.yml`](../../.github/workflows/medtrace-release-gate.yml) below) or authenticated `POST` probes (`"action": "verify-release-gate"` / `"action": "simulate_transition"`) at deployment boundaries.

## 5. Obtain & Configure the MCP Webtrigger URL (Forge CLI v15)

Fetch the deployed HTTPS webtrigger URL using Forge CLI v15:

```bash
forge webtrigger list -f mcp-sync-webtrigger -e production
# If no URL is provisioned yet:
forge webtrigger create -f mcp-sync-webtrigger -e production
```

Use [`.env.example`](../../.env.example) as a template for local MCP clients (`mcp-server/index.mjs`):
- `MEDTRACE_WEBTRIGGER_URL`: HTTPS webtrigger URL from `forge webtrigger list`.
- `MEDTRACE_MCP_SECRET`: Exact perimeter secret encrypted into the matching Forge environment (never put `MEDTRACE_PART11_SECRET` here).
- `MEDTRACE_REQUEST_TIMEOUT_MS` (optional): Request timeout in milliseconds (`15000` default, clamped to `1000..60000`).
- `MEDTRACE_ALLOW_INSECURE_LOCALHOST` (optional): Keep unset/`false` in production; `true`/`1` permits `http://` **only** for loopback harnesses (`localhost`, `127.0.0.1`, `::1`).

## 6. Configure GitHub Actions CI & Release Gate

MedTrace includes two workflows under `.github/workflows/`:

- [.github/workflows/ci.yml](../../.github/workflows/ci.yml): Runs with `contents: read` permissions on `push` to `main` and `pull_request` using Node.js 22 (`package-lock.json` and `static/frontend/package-lock.json` caches). Runs `npm run typecheck`, `npm run build:all`, `npm run test:all`, `npm run docs:check`, syntax checks (`mcp-server/index.mjs`, `scripts/validate-manifest.mjs`, `scripts/docs-check.mjs`, `scripts/rotate-mcp-secret.sh`), offline `npm run lint:manifest`, root/frontend `npm audit` checks (now clean with 0 vulnerabilities via `overrides` in `package.json` and `static/frontend/package.json`), tracked-file secret/env-file hygiene checks, and `npx --yes @forge/cli@15.0.0 lint` when `FORGE_API_TOKEN` and `FORGE_EMAIL` secrets are set.
- [.github/workflows/medtrace-release-gate.yml](../../.github/workflows/medtrace-release-gate.yml): `ECO-624` defense-in-depth release gate triggered via `workflow_dispatch`, `workflow_call`, and `release` (`published`). Accepts `issueKey` and `requireLiveMode` (`true` default, forced `true` on `release` events), enforces `https://` URL + `issueKey` validation, sends a single bounded `POST` request (`action: "verify-release-gate"`, no `--retry` to avoid `409` replay errors) signed with `MEDTRACE_MCP_SECRET`, and fails unless the webtrigger returns HTTP `200`, `result: true`, and `releaseBlocked !== true`.

## 7. Secret Rotation

Rotate `MEDTRACE_MCP_SECRET` across Forge environments, redeploy, atomically rewrite `.env` (`0600`), and execute live verification using [scripts/rotate-mcp-secret.sh](../../scripts/rotate-mcp-secret.sh):

```bash
bash scripts/rotate-mcp-secret.sh --help
```

Key flags and behavior in `scripts/rotate-mcp-secret.sh`:
- `--skip-rotate` (`SKIP_ROTATE=1`): Read-only verification against existing endpoints without running `forge lint`, rotating secrets, deploying, or modifying `.env`.
- `--skip-deploy` (`SKIP_DEPLOY=1`): Updates Forge variables and `.env` without running `forge deploy`.
- `--force`: Continues if a target environment has no deployed webtrigger URL yet, provided at least one valid target URL resolves.
- `--approve-major` (`FORGE_APPROVE_MAJOR=1`): Opts into `--approve MAJOR_VERSION_RULE` on `forge lint` and `forge deploy`.
- Targets `ENVIRONMENTS` (default `"production development"`, falling back to `ENVIRONMENT` when unset) and supports `FORGE_SITE`, `FORGE_PRODUCT` (default `"Jira"`), `FORGE_BIN`, `MEDTRACE_ALLOW_INSECURE_LOCALHOST`, and `LEAKED_SECRET`.
- Live verification proves: optional `LEAKED_SECRET` rejection (`401`), invalid HMAC signature rejection (`401`), valid `GET` (`200`), 4-step `POST {"action":"status"}` nonce replay protection (`200`/`409`/`409`/`200`), unknown `POST` action rejection (`400`), and `POST {"action":"verify-release-gate"}` (`200` with `result: true` or `403` with `result: false`).

## 8. Post-Install Live Ingestion

1. Open **MedTrace Safety Matrix** in Jira (`jira:projectPage`) or **MedTrace Compliance** in Confluence (`confluence:globalPage`).
2. Fresh `LIVE` installations start empty (`initialized: false`), keeping release gates fail-closed until live compliance artifacts are synced.
3. Click **Sync Live Atlassian Data** to invoke `syncLiveSuite` (`LiveIngestionService.syncFromAtlassian`) with `LIVE` dataset mode.
4. Inspect the hash-chained ledger in **Audit Log** (`getAuditLog` / `verifyAuditChain`) and confirm `verify-release-gate` passes once safety trace links carry `PASSED` evidence and valid `HMAC-SHA256-SEAL-V1` or `ECDSA-P256-SHA256+HMAC-SEAL-V1` Part 11 signatures.

## 9. Pre-Marketplace Listing Gate Checklist

Before submitting MedTrace to the Atlassian Marketplace, replace every `[CONFIGURE BEFORE LISTING]` placeholder across [SECURITY.md](../../SECURITY.md) and the `marketplace/` documentation ([PRIVACY_POLICY.md](../../marketplace/PRIVACY_POLICY.md), [SUPPORT.md](../../marketplace/SUPPORT.md), [TERMS_OF_SERVICE.md](../../marketplace/TERMS_OF_SERVICE.md)), then run the strict listing gate and confirm `0` errors:

```bash
node scripts/docs-check.mjs --strict-listing
```
