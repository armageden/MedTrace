[<- MCP Integration Overview](./00-overview.md)

# Hosted Atlassian MCP Verification Runbook

Use this runbook when proving the **Best app with Atlassian MCP** path or validating a deployment for another agent. It distinguishes real hosted `rovo:mcp` evidence from local test evidence.

## 1. Evidence hierarchy

| Evidence | What it proves | What it does not prove |
|---|---|---|
| `rovo:mcp` in [manifest.yml](../../manifest.yml) | The hosted MCP module and three tool backing actions are declared. | That an external client completed OAuth or invoked tools. |
| Backend tests in [tests/workflow-validator-and-mcp.test.cjs](../../tests/workflow-validator-and-mcp.test.cjs) | `rovoActionHandler` and the backing service enforce inputs, permissions, lineage, verification, and re-verification behavior. | Atlassian's hosted MCP transport. |
| Local stdio bridge tests in [tests/mcp-server.test.mjs](../../tests/mcp-server.test.mjs) | The optional HMAC webtrigger MCP bridge speaks JSON-RPC/MCP correctly. | Anything about hosted `rovo:mcp`. |
| A real external MCP client session | OAuth consent, hosted tool discovery, invocation, user permission enforcement, and visible Jira/Confluence effects. | Nothing less; this is the required judge-grade proof. |

Do not claim hosted Atlassian MCP was externally verified unless the fourth row was actually performed and captured.

## 2. Prerequisites

1. Deploy the current production manifest and upgrade both Jira and Confluence installations.
2. Initialize live data in the product partition that the MCP session will use. Forge KVS is product-partitioned; if the proof chain was created from Jira, run MedTrace in Jira and prefer the Jira-connected MCP context. If demonstrating from Confluence, open the Confluence workspace and run **Sync Live Atlassian** there first.
3. A site or org admin must enable MedTrace's external MCP tools under **Atlassian Administration -> Apps -> Sites -> <site> -> Connected apps -> MedTrace**. Exposure is off by default.
4. Use a test user who can read the relevant Jira project and Confluence page. For `create-reverification-task-action`, the same user needs Jira `CREATE_ISSUES` plus `EDIT_ISSUES` or project administration permission.
5. Use an MCP client that supports remote OAuth 2.1 servers. The exact connection UI is client-specific; do not invent client output in documentation or Devpost.

Hosted server URL:

```text
https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99
```

The UUID is the app id suffix from [manifest.yml](../../manifest.yml).

## 3. External verification procedure

1. Connect the external MCP client to the hosted URL and complete the Atlassian OAuth consent flow as the test user.
2. List tools. Capture the client-visible names for the three logical MedTrace tools backed by:
   - `get-hazard-lineage-action`
   - `verify-iec-compliance-action`
   - `create-reverification-task-action`
3. Invoke the compliance verification tool with the live proof implementation key (for example, the `workIssueKey` created by [../00-how-to/04-live-judge-proof.md](../00-how-to/04-live-judge-proof.md)). Capture the tool response showing drift or configured-check failure after the `5.0 -> 5.5 mL/hr` edit.
4. Invoke the lineage tool with the same implementation or hazard key. Capture the connected hazard/spec/work/test/signature lineage.
5. Invoke the re-verification creation tool with the affected hazard or work key and a reason such as `Confluence requirement changed from 5.0 to 5.5 mL/hr`.
6. Open the created Jira issue natively and capture:
   - issue key and summary;
   - links to the affected hazard/work/test issues when available;
   - reporter/permission behavior consistent with the invoking user;
   - the MedTrace audit entry or UI state after the next trigger/sync refresh.
7. Repeat a read-only invocation as a user without project access if a negative permission proof is needed. It must fail closed rather than leaking restricted traceability data.

## 4. Minimum judge evidence checklist

Capture these artifacts in one continuous sequence:

- OAuth/connection success in the external MCP client.
- Tool list containing the MedTrace tools.
- Verification response for the drifted live proof issue.
- Lineage response for the same chain.
- Re-verification tool response containing the created or reused Jira key.
- The created Jira issue and its native links in Jira.
- MedTrace blast radius or audit evidence tying the task to the drifted chain.

Screenshots of the local stdio MCP bridge, source code, or the manifest are supporting evidence only; they are not substitutes for this sequence.

## 5. Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| MedTrace tools absent from the client | External MCP exposure disabled, wrong site/product installation, or stale deployment | Enable Connected apps access, upgrade both product installations, redeploy, and reconnect OAuth. |
| Read tools return an uninitialized or empty suite | MCP is reading the other Forge product KVS partition | Run **Sync Live Atlassian** in the product context being exposed through MCP, then retry. |
| Lineage misses a Confluence change | The partition has not reconciled yet | Invoke a read/gate path again after opening MedTrace or running sync; `reconcileConfluenceSpecs` runs on read/gate paths. |
| Re-verification creation is forbidden | Invoking user lacks Jira create/edit permission or cannot access the target artifact | Grant project permission or use the correct evaluation user. |
| Links are partially missing | Native issue-link creation can fail independently after task creation | The backend response reports partial success honestly; inspect `failedLinkKeys` / `missingLinkKeys` and Jira issue-link permission. |

## 6. Future `app.rovo` manifest metadata compatibility

Atlassian's Forge documentation describes future `app.rovo` metadata (`tag`, `description`, and `keywords`) becoming required for apps declaring Rovo modules. The repository must not add that field before the installed tooling supports it: `@forge/manifest` `13.9.0` currently rejects `app.rovo` as an unknown property, so adding it makes `npm run lint:manifest` fail.

When upgrading Forge CLI or `@forge/manifest`, future agents must:

1. check the current Atlassian `rovo:mcp` / Rovo manifest documentation;
2. test a small manifest change locally with `npm run lint:manifest`;
3. add `app.rovo` only when the installed schema accepts it;
4. run `forge lint` before deployment;
5. update this section and [../01-architecture/forge-modules.md](../01-architecture/forge-modules.md) with the verified schema behavior.

Never force invalid manifest syntax merely to satisfy future documentation.

## Verified production evidence (2026-11-25, v7.0.0)

Autonomous production probes against the live v7.0.0 deployment confirmed:

- Hosted MCP endpoint `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` returns correct `401` with RFC 9728 `WWW-Authenticate` protected-resource metadata; OAuth registration, authorization, and token endpoints live; dynamic client registration succeeds.
- HMAC webtrigger `verify-release-gate` returns live gate decisions (HTTP 403 blocked with real violation detail).
- Workflow validator blocked a real REST-initiated `MEDTRACE-2` → Done transition: Class C test coverage gap.
- Confluence page edit (SRS-201, v4→v5, 5.5→5.6 mL/hr) automatically revoked signature `sig-srs-3964930` within seconds (`AUTOMATIC REVOCATION` invalidation reason, hash drift `41e2589b...` → `c56a3eee...`), flipped hazard to `ACTION_REQUIRED`, dropped suite to `verifiedPercentage: 0` with `releaseBlocked: true`.
- Workflow validator **blocked** `MEDTRACE-2` into the release status `10002` (5 occurrences) at the same target as the row below.
- A `MEDTRACE-6` transition was also **approved** into the same target status `10002` at `2026-11-25T19:27:51Z`, but this is **not** proof of the compliant path: a signed `get-hazard-lineage` probe reports `found: false` for `MEDTRACE-6`, i.e. it is an **untracked, non-safety-tagged** issue, so the approval exercised the fail-open untracked-issue path. The compliant positive path — a **tracked** chain member transitioning to `Done` with a valid signed baseline — remains **unproven** and must be demonstrated with a `get-hazard-lineage`-visible issue key.
- Live Teamwork Graph spec-owner lookup returned `status=OK` with `1 owner(s)` for Confluence pages `3964930` and `3964950` (`fetchSpecOwnersFromTeamworkGraph`).
- Live Rovo/MCP `verify-iec-compliance-action` executed against `MEDTRACE-2` on an initialized `LIVE` suite and correctly reported `signatureDriftDetected: true` with `configuredChecksPassed: false`.

Remaining manual steps (each requires an interactive Atlassian browser session, not this runbook's signed probes):

1. Re-prove the compliant positive path with a `get-hazard-lineage`-visible tracked issue: record `PASSED` evidence, sign off, transition to `Done` in the real Jira UI, then capture the same key's lineage as `VERIFIED`.
2. Re-establish a signed compliant baseline: the production suite is currently fully drifted (`verifiedPercentage: 0`, `releaseBlocked: true`), so no compliant demo path exists until a chain member is re-signed.
3. Complete the browser OAuth consent flow with an external MCP client.

## Verified production evidence (2026-11-26/27, v7.5.0)

Live verification against production (`7.4.0` and `7.5.0` after resolving the `reverificationTaskKey`, deleted-Confluence `404`, dynamic `createmeta`, post-append audit head, focus-reconcile, and `DEMO`-to-`LIVE` fixes):

- **Production deployment & HMAC webtrigger (`2026-11-26T20:05:54Z` UTC):** `forge deploy -e production --non-interactive --approve MAJOR_VERSION_RULE` deployed `7.5.0` across all 4 installations (`one-atlas-feur.atlassian.net` and `farhantanvir277.atlassian.net` for Jira & Confluence, all `Up-to-date`), and `SKIP_ROTATE=1 FORGE_SITE=farhantanvir277.atlassian.net bash scripts/rotate-mcp-secret.sh` passed (`401` invalid sig, `200` GET, `200`/`409`/`409`/`200` replay defense, `400` unknown action, `403` `verify-release-gate` on global drifted suite).
- **Compliant tracked baseline & re-verification closeout (`one-atlas-feur.atlassian.net`, `MEDTRACE`):**
  - `MEDTRACE-4` (`HAZ-MEDTRACE-4`, `SRS-204 Display Auto-Dim`, `TEST-MEDTRACE-4` `PASSED`, valid Part 11 signature) reached **`VERIFIED`**, `verify-release-gate` (`transitionToDone: true`) returned HTTP `200` (`result: true`), and its linked `medtrace-reverification` task `MEDTRACE-8` returned HTTP `200` (`result: true`), matching production `WorkflowValidator` `Transition APPROVED` logs (`MEDTRACE-4`, `MEDTRACE-8`) and `[TeamworkGraph] specOwners 3866646: 1 owner(s), status=OK`.
- **Service Management live proof bootstrap (`farhantanvir277.atlassian.net`, `SMK`):**
  - **Sync Live Atlassian** cleared `SMK`'s synthetic `DEMO` dataset into uninitialized `LIVE` onboarding (`Audit Log (1)` -> `Audit Log (2)`).
  - **Create Live Proof Chain** created Confluence SRS page `4620289` (`SRS MedTrace Live Proof SMK 20261126-200729`, SHA-256 `5a855fae6a4220b90124e29c7a48bf90fbf983adde19676839e58bf0694a9b33`), native Jira Hazard `SMK-1` (`CLASS C`), native Verification Test `SMK-2`, and native Implementation Work `SMK-3` (`Audit Log (4)`), and recorded `SMK-2` as `PASSED` (`Audit Log (5)`).
  - User completed **Sign Off Spec (Attestation)** (`PART11_SIGNOFF`, `HMAC-SHA256-SEAL-V1`, `Audit Log (6)`), bound **MedTrace IEC 62304 Safety Gate** onto `SMK`'s `Mark as done (61)` workflow transition, and transitioned `SMK-3` to `Done` (`Transition APPROVED (SMK-3)`), bringing `SMK` to **`100% (1/1 Hazards)` `VERIFIED`** (`Audit Log (7)`).
  - Edited Confluence page `4620289` (`5.0` -> `5.5 mL/hr`, published `v2`, SHA-256 `00cbcbac9c496de76df8dbdb7d6978e182bc0ddfd185391082c67748895116a9`). Reloading `SMK` MedTrace automatically detected drift without clicking Sync (`0%`, `RELEASE BLOCKED`, `1 Drifted`, `INVALIDATED`, `Audit Log (8)`), **Blast Radius** traced all 4 hops (`SMK-1`, `SMK-3`, `SMK-2`, revoked `PART11_ATTESTATION` signature), and **Test Human Gate** blocked on `Cryptographic Signature Drift`.
  - Created linked Jira re-verification task `SMK-4` (`class-c`, `medtrace-reverification`, linked to `SMK-3`, `SMK-1`, `SMK-2`, `Audit Log (9)`/`(10)`). Attempting `Mark as done` on `SMK-4` in Jira UI while `SMK-1` was drifted **blocked live** via the workflow validator (`❌ [MedTrace Safety Gate] Human-initiated transition blocked for SMK-4! • Cryptographic Signature Drift...`), leaving `SMK-4` `Open`. Re-recorded `SMK-2` `PASSED` (`https://ci.example.internal/medtrace/smk-run-2`, `Audit Log (11)`).
  - User completed the second **Sign Off Spec (Attestation)** on `SMK-1` for `4620289` `v2` (`00cbcbac9c496de76df8dbdb7d6978e182bc0ddfd185391082c67748895116a9`), returning `SMK` to **`100% (1/1 Hazards)` `VERIFIED`** (`CONFIGURED CHECKS PASSED`, `Open Gaps (0)`, `Audit Log (14)`). Closing **`SMK-4` -> `Done`** (`Mark as done`) in Jira UI then succeeded (`Transition APPROVED (SMK-4)`, persisted as `Done`).

Remaining interactive human actions (requires human browser session / OAuth consent, not automation):

1. Finish the Confluence `"Allow access"` consent popup on `farhantanvir277.atlassian.net` (`https://farhantanvir277.atlassian.net/wiki`) if testing the Confluence global page UI.
2. Connect an external OAuth 2.1 MCP client to `https://mcp.atlassian.com/forge/5e49c10e-696f-4984-9d00-4a47d0a5dd99` and capture live `verify-iec-compliance-action` / `create-reverification-task-action` calls for the video.
