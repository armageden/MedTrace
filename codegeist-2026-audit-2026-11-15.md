# Codegeist 2026 / MedTrace Audit

Audit date: 2026-11-15

## Verdict

MedTrace appears to meet Codegeist's basic Forge-project requirement and has code-level evidence for the Rovo Agents and Atlassian MCP bonus tracks. That makes it a plausible eligible submission, not a predicted winner. It is **not submission-ready based on the material in this repository**: the draft says there is no public demo-video URL, the current shared install link is Jira-only, and judge installation has not been verified on a fresh site.

The strongest evidence is a substantive Forge app and a broad passing test suite. The largest preventable judging risk is presentation/readiness; the largest product risk is Rovo authorization fail-open behavior. No reliable win probability can be inferred from this repository.

## Official Rules and Track Fit

The official rules set the submission deadline at **December 22, 2026, 12:00 PM Pacific**. They require a Forge project integrated with at least one Atlassian capability, a working judge installation link with instructions, and a public YouTube demonstration under five minutes that shows the app functioning. Stage One is a pass/fail viability check; Stage Two weights Technological Implementation, Design, Potential Impact, Innovation/Idea, and Presentation equally. The same submission may win at most one Grand Prize and one Bonus Prize.

- **Main category:** Apps for Specialized Industries is the natural fit: MedTrace targets medical-device software engineering and integrates Jira/Confluence on Forge. Judges still decide category fit.
- **Best Agents:** Manifest declares `rovo:agent` and its actions. This matches the published module-based eligibility description.
- **Best app with Atlassian MCP:** Manifest declares `rovo:mcp` and exposes the actions as tools. This matches the published `rovo:mcp` requirement.
- **Marketplace:** Not evidenced as submitted or published here. Prepared legal pages are not a listing or Marketplace review ticket.
- **Teamwork Graph:** Do not claim this bonus based on the current implementation. `src/teamwork-graph.ts` calls `requestGraph` against Atlassian's GraphQL Gateway for Jira context; the manifest declares no `read:graph:*` scopes, and the source itself distinguishes this from `requestTeamworkGraph`.
- **Existing-project rule:** The visible Git history starts with the initial app commit on 2026-11-05, after the 2026-10-27 submission-period start. This supports the timing requirement for this repository, but Git history cannot prove that no earlier unpublished or separately hosted version existed.
- **Personal eligibility:** Age, residence/excluded jurisdiction, team authorization, and ownership/originality cannot be established from source files.

## Findings

### P1 — Rovo authorization can fail open and is not target-scoped

`src/mcp-server.ts:549-563` runs the Rovo permission check only when a nonempty `accountId` is present. If the Forge runtime provides no account ID, the action proceeds without a user probe. In `assertRovoUserReadAccess` (`src/mcp-server.ts:200-242`), a Jira `200` response is accepted unless `BROWSE_PROJECTS.havePermission` is explicitly `false`; a missing permission field is accepted. The check is also not bound to the requested issue/project. `McpToolService.getHazardLineage` reads the unfiltered suite and can return a matching record, a reduced all-record summary, or keys from the whole suite (`src/mcp-server.ts:254-323`).

I ran a local synthetic Forge-runtime check against the compiled handler: a missing account ID made zero Jira probes and returned a successful action response; a `200` response with no `BROWSE_PROJECTS` entry also returned successfully. This verifies the code path, **not** that Atlassian's production Rovo runtime omits those fields. If the suite contains multiple projects, the missing target scope also creates cross-project exposure risk.

**Before judge access:** fail closed on missing identity and incomplete permission responses; check the caller's access to the requested project/issue and return only that authorized scope. Add tests for absent identity, absent permission fields, and cross-project inputs.

### P1 — A project operator can request a LIVE-to-DEMO suite replacement

`seedDemoSuite` first calls `assertAuthorizedOperator`, then trusts the client payload's `confirmOverwriteLive` boolean (`src/index.ts:633-638`). The service refuses replacement without that boolean but permits it when true (`src/seeder.ts:680-690`). The existing UI asks for confirmation, but a UI confirmation is not an authorization boundary. The operator gate allows project edit/admin permissions, not specifically site administration; the tests explicitly verify that `confirmOverwriteLive: true` replaces an initialized LIVE suite (`tests/seeder-storage.test.cjs:367-384`, `tests/index-rbac-webtrigger.test.cjs:1221-1227`).

This is a high-impact integrity operation: an editor able to invoke the resolver can replace live compliance state with modeled data. Require a server-enforced privileged role and a stronger, auditable recovery/backup policy before enabling this in a live tenant.

### P1 — A passing modeled check is worded like a regulatory authorization

The Rovo verification response emits `CERTIFIED_READY` and “Authorized for 510(k) release packaging” when its internal modeled checks find no gaps (`src/mcp-server.ts:444-480`). The Rovo prompt describes the agent as a regulatory compliance officer that “enforce[s]” IEC 62304, ISO 14971, and Part 11 (`manifest.yml:42-49`). This conflicts with MedTrace's own submission non-goals and disclosures that it is not a standards-conformance determination, validated QMS, or official FDA submission (`devpost_submission_draft.md:31-32, 47-58`).

The output is not evidence of regulatory authorization. Replace certification/authorization language with a scoped statement such as “configured traceability checks passed; independent regulatory assessment required,” including in Rovo responses.

### P1 — A 64-character hex MCP secret remains in Git history

The historical `.env.example` at commit `e48253e` contains a 64-character hex value assigned to `MEDTRACE_MCP_SECRET`. I did not print or copy the value. Removing it from the current tree does not remove it from repository history. The current draft says the secret was rotated and that removal from history is pending (`devpost_submission_draft.md:100`), but I did not independently verify the deployed Forge or CI secrets or test the old value against production.

Treat the historical value as compromised. Confirm that Forge development/production and CI secrets are all rotated to new independent values and that the old value is rejected. Do not distribute any production secret to judges. History rewriting is intentionally not performed in this audit.

### P2 — “Zero Egress” and one benchmark graphic overstate the evidence

The README says “Zero Egress” in its architecture diagram (`README.md:37`), and `devpost_thumbnail_hero.png` says “Zero Outbound Egress.” That is misleading: README itself says authenticated MCP/CI responses return data to those clients (`README.md:7`), and the submission draft explicitly disclaims a zero-data-egress guarantee (`devpost_submission_draft.md:85-90`). Say “no Forge external backend-fetch permission” instead.

The benchmark test asserts a `<20 ms` ceiling for one synthetic 500-node case (`tests/compliance-engine.test.cjs:942-1018`). `devpost_thumbnail.png` also advertises “<1.5ms Active,” which I found no automated assertion or reproducible documented environment for. Keep the claim to the test-enforced `<20 ms` synthetic ceiling unless the lower number is measured and methodologically documented.

### P2 — The submission package has explicit blockers

The draft marks the video as a blocker and says there is no public YouTube URL (`devpost_submission_draft.md:157-158`). It says the current shared link is Jira-only and still needs judge-tested Jira and Confluence installation instructions/links (`devpost_submission_draft.md:153, 162`). The official rules require a working install in a judge environment and a public YouTube video under five minutes; local build/tests do not prove either.

The planned script is 3:10 and within the limit (`devpost_video_script.md:9-10`), but the captions do not match the script during 0:25-0:48: the script narrates empty LIVE state and demo seeding, while the SRT narrates Forge/MCP data flow and then the badge. Resync captions to the final recorded edit. No recording or live install was available for this audit.

### P2 — No Teamwork Graph bonus evidence

Atlassian's Teamwork Graph API documentation specifies `requestTeamworkGraph()` and graph-object scopes. This app calls `requestGraph()` and declares no graph scopes (`src/teamwork-graph.ts:222-226, 293`; `manifest.yml:115-125`). The official Forge docs distinguish the GraphQL Gateway's `requestGraph` from the Teamwork Graph API. This does not invalidate the main entry or the Rovo/MCP bonuses, but it does not substantiate the Teamwork Graph bonus.

## Evidence That Helps

- The project uses Forge and Atlassian capabilities, with Jira, Confluence, Rovo Agent, Rovo actions, and `rovo:mcp` declared in `manifest.yml`.
- Build, typecheck, backend tests, frontend tests, coverage thresholds, manifest validation, docs validation, secret-hygiene CI scan, and dependency audit all passed locally (details below).
- The test suite has 158 backend/MCP/script tests and 33 frontend tests. The BFS test really does build 100 five-stage links (500 modeled nodes) and checks a `<20 ms` threshold.
- The draft consistently distinguishes modeled data from customer evidence and disclaims Part 11 conformity, HIPAA/BAA status, and official FDA submission generation. Keep those boundaries visible in the video and Devpost copy.

## Verification Performed

| Check | Result |
|---|---|
| `npm run typecheck` | Pass |
| `npm run build:all` | Pass |
| `npm run test:all` | Pass: 158 backend/MCP/script + 33 frontend tests |
| `npm run test:coverage:all` | Pass; backend lines 88.92%, branches 77.53%, functions 85.88%; frontend thresholds also passed |
| `npm run docs:check` | Pass: 0 errors, 0 warnings |
| `npm run lint:manifest` | Pass: full manifest validation, five handler exports verified |
| `node scripts/docs-check.mjs --strict-listing` | Pass |
| `npm audit --audit-level=high` and frontend equivalent | Pass: 0 reported vulnerabilities |
| `git diff --check` | Pass |
| Forge CLI lint | Pass: “No issues found.” CLI warned that the local Node 26 runtime is unsupported; Forge CLI supports Node 22/24 per repo docs. CI uses Node 22. |

Not verified: production deployment behavior, a fresh-site install, Jira/Confluence links, production release-gate/replay behavior, current credential rotation, public Devpost submission status, actual video quality, and any regulatory fitness for use. Devpost's pages returned HTTP 403 to direct fetch; the rule claims above were checked via search excerpts from the official Devpost rules page and first-party Atlassian documentation, not a complete raw rules-page capture.

## Primary Sources

- [Codegeist 2026 Official Rules](https://codegeist2026.devpost.com/rules)
- [Codegeist 2026 challenge page, requirements, categories, and judging criteria](https://codegeist2026.devpost.com/)
- [Atlassian Forge: Call the Teamwork Graph API](https://developer.atlassian.com/platform/forge/call-the-teamwork-graph-api/)
- [Atlassian Forge: `requestTeamworkGraph`](https://developer.atlassian.com/platform/forge/apis-reference/ui-api-bridge/requestTeamworkGraph/)
- [Atlassian Forge: `requestGraph`](https://developer.atlassian.com/platform/forge/apis-reference/fetch-api-product.requestgraph/)
- [Atlassian Forge: Start sharing your app](https://developer.atlassian.com/platform/forge/distribute-your-apps/#start-sharing-your-app)
