# Codegeist 2026 / MedTrace Audit

Audit date: 2026-11-15 (re-verified against commit `62abc3b`)

## Verdict

MedTrace meets the Codegeist 2026 Forge requirement and declares the modules named by the Best Agents (`rovo:agent` + `action`) and Best app with Atlassian MCP (`rovo:mcp`) bonus rules. Build, typecheck, tests, coverage, manifest validation, docs validation, `npm audit`, and `forge lint` all pass. Submission readiness depends on items outside the code: a public YouTube video, a judge-tested installation link, and a demo that shows live tenant data rather than only the modeled demo dataset.

## Official Rules Checked

Source: [Codegeist 2026 Official Rules](https://codegeist2026.devpost.com/rules), fetched 2026-11-15.

- Submission period ends **December 22, 2026, 12:00 PM Pacific**.
- Stage One is pass/fail on theme fit and use of the required APIs/SDKs. Stage Two weights Technological Implementation, Design, Potential Impact, Innovation/Idea, and Presentation equally; ties break on Technological Implementation first, which asks whether the app is "not just a shallow wrapper or a single hardcoded demo path".
- The project "must be capable of being successfully installed in a judge's test environment via an installation link".
- The video must be under five minutes, show the project functioning, and be public on YouTube.
- Existing projects are eligible if "updated or rebuilt in the Forge platform after the start of the Hackathon Submission Period". The GitHub repository was created 2026-11-07, after the 2026-10-27 start.
- One submission can win at most one main-category prize and one bonus prize.
- "Runs on Atlassian" is not a Codegeist 2026 requirement or bonus. `forge eligibility` reports the app is ineligible for that program only because "App is using a webtrigger module that can egress data".

## Bonus Fit

| Bonus | Status |
|---|---|
| Best Agents | `rovo:agent` `medtrace-regulatory-auditor` with two `action` modules is declared. |
| Best app with Atlassian MCP | `rovo:mcp` `medtrace-mcp-server` exposes both actions. The rule requires tools exposed "via the Atlassian MCP server using the rovo:mcp module", i.e. `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` after a site admin enables external MCP exposure. The local stdio bridge in `mcp-server/` is a separate, HMAC-webtrigger integration and does not by itself demonstrate this path. |
| Teamwork Graph | Superseded by working-tree update (see below). At commit `62abc3b` on 2026-11-15, `src/teamwork-graph.ts` had not yet migrated to `requestTeamworkGraph`; the current working tree integrates `confluencePageOwners` via `api.asUser().requestTeamworkGraph` under `read:graph:page:confluence` + `read:graph:user:atlassian`. |
| Marketplace | Not claimed. Atlassian's distribution docs state apps submitted for Marketplace listing "can't be shared via installation link". |

## Previously Reported Findings: Resolved

| Finding | Current state |
|---|---|
| Rovo actions could run without a user identity | `rovoActionHandler` (`src/mcp-server.ts`) rejects missing/empty `accountId` in the Forge runtime, checks target-scoped Jira `BROWSE_PROJECTS` / Confluence read access, and filters LIVE suites to caller-authorized projects. The runtime check uses `globalThis.__forge_runtime__`, which `@forge/api` itself requires (`node_modules/@forge/api/out/api/runtime.js`). |
| Project operators could overwrite a LIVE suite with demo data | `seedDemoSuite` (`src/index.ts`) now requires `confirmOverwriteLive: true` and Jira site-administrator (`ADMINISTER`) permission, and writes a pre-overwrite backup. |
| Rovo output used certification/authorization wording | Removed. Passing checks return "Configured traceability checks passed; independent regulatory assessment is still required." |
| "Zero Egress" and "<1.5ms" marketing claims | Removed from README and thumbnails. The only performance claim is the test-enforced `<20 ms` ceiling on a synthetic 500-node graph. |
| MCP secret committed in Git history (`e48253e`) | Rotated. A signed GET using the historical value returned HTTP 401 on both the production and development webtriggers on 2026-11-15; the current secret returned 200. The historical value is no longer accepted and is not recoverable from the repository's reachable Git history. |

## Verification Performed (2026-11-15)

| Check | Result |
|---|---|
| `npm run typecheck` | Pass |
| `npm run build:all` | Pass |
| `npm run test:all` | Pass: 158 backend/MCP/script + 33 frontend tests |
| `npm run test:coverage:all` | Pass: backend lines 88.84%, branches 77.33%, functions 85.62%; frontend lines 77.44% |
| `npm run docs:check` / `--strict-listing` | Pass: 0 errors, 0 warnings |
| `npm run lint:manifest` | Pass |
| `forge lint` | Pass: "No issues found." (local Node 26 is outside the Forge CLI's supported 22.x/24.x range) |
| `npm audit` (root + frontend) | 0 vulnerabilities |
| Installations | production and development, Jira and Confluence, on one site |

## Not Verified (2026-11-15 Baseline)

Fresh-site installation from the share link and the Confluence page-update drift trigger in production remain unverified. Note: this `2026-11-15` section reflects commit `62abc3b`; see the post-`62abc3b` working-tree update below for current state.

## Working-Tree & Live Verification Update (2026-11-18 / 2026-11-19)

| Item | Verified Current State |
|---|---|
| Manifest & TWG (`src/teamwork-graph.ts`) | Removed legacy AGG `requestGraph`; added `fetchSpecOwnersFromTeamworkGraph` (`confluencePageOwners`, `@forge/api` `8.5.0`) with `read:graph:page:confluence` and `read:graph:user:atlassian`, plus partial GraphQL error tolerance (extracting valid `AtlassianUser` edges even alongside partial app-owner errors) and full `matchedLinks` `pageId` coverage in `getHazardLineage`. Executed live in `development` (v6) on `MEDTRACE-1` / `SRS-201` (`pageId=3964930`), logging `status=OK` (`1 owner(s)`) in both `queryGraphContext` and dev Rovo `get-hazard-lineage-action`. **Still pending:** `production` remains on v4 and must be deployed + upgraded (`forge install --upgrade`). |
| Live Ingestion, Seals & Confluence RBAC | Skipped full-tenant `/wiki/api/v2/pages` pagination when `spaceId` is unset in Jira-project mode (eliminating the `25.00s` Forge timeout on 536-page tenants), fixed `persistOrClearCursor` + filtered-JQL link preservation, unified `{ requireCryptographicSeal: true, requireTestEvidence: datasetMode === 'LIVE' }` across `bindIssueToHazard` / `recordTestResult` / `signOffPart11` / `handleConfluencePageUpdated`, rejected signing missing-sentinel or empty-`sha256Hash` specs, and tightened Confluence-to-Jira `LIVE` read isolation (`filterLiveSuiteForCaller`), unbound-hazard operator guards, and `bindIssueToHazard` hijack prevention. |
| Automated Tests & Coverage | `npm run typecheck`, `npm run build:all`, `npm run test:coverage:all`, `npm run lint:manifest`, and `npm run docs:check -- --strict-listing` pass: **219 tests** (`180` backend/MCP/script across `29` suites + `39` React/Vitest across `7` files; coverage verified at `89.17%` backend lines / `77.68%` branches / `85.01%` functions, and `80.97%` frontend lines). |
| Dependency Audit | Root `npm audit --audit-level=high`: `0` vulnerabilities. Frontend `npm --prefix static/frontend audit --audit-level=high`: `0` vulnerabilities (`picomatch@4.0.7`). |
| Rovo & Atlassian MCP (`rovo:mcp`) | Rovo `get-hazard-lineage-action` executed live on both `development` (`LIVE` synced `MEDTRACE-1`) and `production` (`DEMO` fixture). External `rovo:mcp` (`https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99`) enabled in Connected apps, authorized via OAuth 2.1 (`mcp-remote@0.16.6`), and executed `verify-iec-compliance-action` + `get-hazard-lineage-action` against `production` — returning `"MedTrace Uninitialized Workspace"` (`initialized: false`), confirming Jira and Confluence production partitions must match the exposed MCP context after deploy/upgrade. |
