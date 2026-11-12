[<- How-To Overview](./00-overview.md)

# Deploy to Production Atlassian Site

Follow this runbook to deploy MedTrace to a production or staging Atlassian Cloud site with Jira and Confluence, bind the workflow gate, configure encrypted secrets, and enable CI release checks.

## Prerequisites

- Atlassian Forge CLI v15 (`forge login` authenticated as an app developer/admin).
- Node.js 22 (`nodejs22.x` Forge runtime compatibility).
- An Atlassian Cloud site with Jira and Confluence enabled.

## 1. Install Dependencies & Build

```bash
npm install
cd static/frontend && npm install && npm run build && cd ../..
npm run build
```

Verify types, tests, docs, and manifest lint before deploying:

```bash
npx tsc --noEmit
cd static/frontend && npx tsc --noEmit && cd ../..
npm test
npm run docs:check
forge lint
```

## 2. Configure Required Encrypted Secret (`MEDTRACE_MCP_SECRET`)

Both the Forge webtrigger and local/CI MCP callers fail closed if `MEDTRACE_MCP_SECRET` is unset. Generate a 32-byte random hex secret and store it encrypted per environment:

```bash
SECRET=$(openssl rand -hex 32)
forge variables set MEDTRACE_MCP_SECRET "$SECRET" --encrypt -e production
```

For staging/development environments, set `-e development` or `-e staging` separately. Never commit secrets into git or `.env` files.

## 3. Deploy & Install on Jira and Confluence

```bash
forge deploy -e production
forge install -e production --site <your-site>.atlassian.net --product jira
forge install -e production --site <your-site>.atlassian.net --product confluence
```

If updating scopes or manifest modules on an existing installation, pass `--upgrade` to `forge install`.

## 4. Bind the Jira Workflow Safety Gate

To enforce IEC 62304 release blocking on Jira issue transitions:
1. Open **Jira Project Settings -> Workflows** and edit the target workflow.
2. Select the release transition (for example, `In Review -> Done` or `Ready for Release`).
3. Add a **Validator** and choose **MedTrace Safety Gate** (`medtrace-safety-validator` from [manifest.yml](../../manifest.yml)).
4. Publish the updated workflow. Any linked issue whose trace chain is not `VERIFIED` (or suite is blocked) will halt transition with an explicit error message. Unlinked issues pass without blocking unrelated work.

## 5. Obtain & Configure the MCP Webtrigger URL

Fetch the deployed HTTPS webtrigger URL:

```bash
forge webtrigger -f mcp-sync-webtrigger -e production
```

Configure `.env` (for local `mcp-server/index.mjs`) or your CI environment with:
- `MEDTRACE_WEBTRIGGER_URL`: the URL returned above.
- `MEDTRACE_MCP_SECRET`: the exact encrypted secret set in Step 2.

## 6. Configure GitHub Actions CI & Release Gate

MedTrace includes two workflows under `.github/workflows/`:
- [.github/workflows/ci.yml](../../.github/workflows/ci.yml): Runs on `push` to `main` and `pull_request` — installs backend + frontend dependencies, runs TypeScript checks, builds both targets, runs `npm test`, `npm run docs:check`, `node --check mcp-server/index.mjs`, validates `manifest.yml` against `@forge/manifest`, and runs `forge lint` when `FORGE_EMAIL` / `FORGE_API_TOKEN` repository secrets are configured.
- [.github/workflows/medtrace-release-gate.yml](../../.github/workflows/medtrace-release-gate.yml): `workflow_dispatch` release gate calling `action=verify-release-gate` over HMAC-SHA256. Requires GitHub repository/environment secrets `MEDTRACE_WEBTRIGGER_URL` and `MEDTRACE_MCP_SECRET` (fails closed if missing; requires HTTP `200` and `"result": true`).

## 7. Secret Rotation

Rotate `MEDTRACE_MCP_SECRET` cleanly across Forge environments and update local `.env` using [scripts/rotate-mcp-secret.sh](../../scripts/rotate-mcp-secret.sh):

```bash
bash scripts/rotate-mcp-secret.sh --help
```

The script validates prerequisites, generates a new 32-byte hex secret, sets `MEDTRACE_MCP_SECRET --encrypt` across target Forge environments, optionally redeploys and verifies `action=validate`, and avoids printing raw secret material to stdout.

## 8. Post-Install Live Ingestion

1. Open **MedTrace Safety Matrix** in Jira (`jira:projectPage`) or **MedTrace Compliance** in Confluence (`confluence:globalPage`).
2. Click **Sync Live Atlassian Data** to invoke `syncLiveSuite` (`LiveIngestionService.syncFromAtlassian`) with `LIVE` dataset mode.
3. Verify the hash-chained audit ledger in **Audit Log** (`getAuditLog` / `verifyAuditChain`).
