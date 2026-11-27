[<- How-To Overview](./00-overview.md)

# Live Judge Proof Runbook

Use this runbook to demonstrate MedTrace's central live workflow with real Jira and Confluence artifacts rather than app-managed fallback records. The proof story is:

> A Confluence requirement changes from `5.0` to `5.5 mL/hr`; MedTrace proves which hazard, Jira work item, verification test, and approval are affected, revokes stale approval evidence, blocks unsafe release, and creates linked re-verification work.

## 1. Prerequisites

1. Deploy the current manifest and upgrade both product installations. `createLiveProofScenario` requires the manifest scope `write:page:confluence` in addition to the existing Jira write scopes; an older installation cannot create the Confluence proof page until the major-version consent/upgrade is completed. See [03-deploy-production.md](./03-deploy-production.md).
2. Use an evaluation project/space, not a production workspace. The bootstrap creates real artifacts and never deletes them automatically.
3. The acting user needs Jira `BROWSE_PROJECTS`, `CREATE_ISSUES`, `EDIT_ISSUES`, and issue-linking permission in the selected project, plus permission to create a page in the target Confluence space. When no space is supplied by context or payload, the resolver first looks for a space key matching the Jira project key and then falls back to the first readable global Confluence space; use a dedicated evaluation tenant so that fallback cannot surprise a production workspace.
4. Open MedTrace from a **Jira project page** (`Apps -> MedTrace IEC 62304`). The **Create Live Proof Chain** button is disabled when the current extension context has no Jira project key (for example, the Confluence global page).
5. Bind **MedTrace IEC 62304 Safety Gate** to the workflow transition into `Done` before demonstrating the human release gate. `ECO-624` does not establish REST/automation coverage, so treat those paths as unproven and use the CI release gate for them.
6. Use real HTTPS verification evidence when possible. MedTrace validates URL shape and safety, not whether the evidence contents are authentic.

## 2. Create the real proof chain

1. In the uninitialized `LIVE` workspace (or directly from the header when in `DEMO` mode with a Jira `projectKey`), click **Create Live Proof Chain**. Clicking **Sync Live Atlassian** while in `DEMO` mode with 0 live safety issues also clears synthetic `DEMO` data into uninitialized `LIVE` onboarding instead of trapping the workspace in `DEMO`.
2. The `createLiveProofScenario` resolver calls [src/live-proof-scenario.ts](../../src/live-proof-scenario.ts) under `api.asUser()` and creates:
   - one Confluence SRS page titled `SRS MedTrace Live Proof <PROJECT> <timestamp>` containing `Bolus delivery threshold: 5.0 mL/hr`;
   - one native Jira hazard issue labeled `medtrace-live-proof`, `medtrace-hazard`, and `class-c`;
   - one native Jira verification-test issue labeled `medtrace-live-proof`, `medtrace-test`, `hil-test`, and `class-c`;
   - one native Jira implementation issue labeled `medtrace-live-proof` and `class-c`;
   - two Jira `Relates` issue links (hazard-to-work and test-to-work);
   - one Jira remote link from the implementation issue to the Confluence page.

   All three Jira issues use the project's real issue type resolved from `createmeta` (preferring `Task`, then `Story`, then the first non-subtask type; falling back to `Task` only when the lookup fails), so the bootstrap works in projects that do not expose a `Task` issue type.
3. The backend immediately runs a bounded live ingestion scoped to the three exact created Jira keys. If Jira indexing is still settling, the response warning tells the user to click **Sync Live Atlassian** once; do not create a second chain.
4. On success, MedTrace auto-selects the created implementation trace link and displays the artifact keys. The bootstrap does **not** record test evidence, sign approvals, mark work done, or fabricate compliance.

If creation, linking, initial ingestion, or audit recording fails partway through, the error lists any real artifacts already created. MedTrace intentionally does not delete partial artifacts automatically; remove or correct them manually in the evaluation tenant.

## 3. Establish the compliant baseline

1. In the auto-opened inspection drawer, record the verification test as `PASSED` with a real `https://` evidence URL and meaningful execution notes.
2. Complete **Sign Off Spec (Attestation)** using the exact phrase `I CERTIFY THIS ELECTRONIC SIGNATURE` and a meaningful attestation such as `Approval of IEC 62304 safety specification and risk mitigation`.
3. Select the implementation issue and run **Test Human Gate**. Because the simulated transition is into `Done`, the transition-aware gate evaluates the pre-`Done` work item as if the release transition completes. It must pass only when the spec link, passed test evidence, valid attestation, and safety classification are complete.
4. Optionally perform the real Jira transition into `Done`. After the Jira issue trigger or next sync refreshes status, the trace link should become fully `VERIFIED`.

## 4. Trigger and prove requirement drift

1. Open the created Confluence SRS page.
2. Edit only the requirement value from `5.0` to `5.5 mL/hr` and publish the page.
3. Return to MedTrace and click **Blast Radius** for the affected chain. `analyzeBlastRadius` reconciles Confluence content before computing impact, so the report reflects live drift even when the visible matrix has not yet refreshed.
4. Windows that lose and regain focus auto-reconcile: returning from the Confluence editor to the MedTrace tab fires a debounced `focus` refresh that calls `getComplianceSuite` **without** `{ skipReconcile: true }`, so the matrix picks up the drift automatically. Background 30-second interval polling stays cache-only (`{ skipReconcile: true }`) to avoid a Confluence sweep every cycle. If the matrix still shows the pre-edit state, click **Sync Live Atlassian** once or reload the page; server-side gates always reconcile Confluence content before making release decisions.
5. Expected proof points:
   - the prior electronic attestation is invalid/revoked and cannot be resurrected by reverting the page;
   - blast radius shows the connected hazard, specification, implementation work item, verification test, and approval record;
   - **Test Human Gate** now blocks the implementation issue;
   - a real Jira transition into `Done` is blocked by the workflow validator when bound;
   - the audit log contains drift and mutation evidence in sequence.

## 5. Create re-verification work through Atlassian MCP

Follow [../03-mcp-integration/hosted-mcp-verification.md](../03-mcp-integration/hosted-mcp-verification.md). For the strongest judge proof, use the hosted Atlassian MCP connection (not merely the local stdio bridge) to:

1. call `verify-iec-compliance-action` for the implementation issue key;
2. call `get-hazard-lineage-action` for the same issue or hazard;
3. call `create-reverification-task-action` with the affected hazard or work key;
4. open the created Jira re-verification task and show its native links;
5. return to MedTrace and show the task/audit evidence after the next sync or trigger refresh.

## 6. Manual fallback when bootstrap is unavailable

Use this only when the current build is not deployed or the user lacks create permissions:

1. Create a Confluence SRS page containing `Bolus delivery threshold: 5.0 mL/hr`.
2. Create three native Jira Tasks: a hazard (`medtrace-hazard`, `class-c`), a verification test (`medtrace-test`, `hil-test`, `class-c`), and implementation work (`class-c`).
3. Link hazard and test to the implementation issue with Jira issue links.
4. Link the implementation issue to the Confluence page as a remote/web link.
5. Click **Sync Live Atlassian**, then continue from Section 3.

Avoid relying on app-managed `HAZ-*` or `TEST-*` fallback records for the main judge path; native Jira issues make the traceability claim much stronger.

## 7. Cross-product KVS caveat

Forge partitions app KVS state by installed product context. The bootstrap normally initializes the **Jira** partition because it is launched from a Jira project page. If demonstrating hosted MCP or the Confluence workspace against the Confluence partition, run **Sync Live Atlassian** in that product context before invoking tools. Do not assume evidence or signatures written in one product partition are already replicated to the other; MedTrace reconciles Confluence drift on demand, but it does not provide a single cross-product evidence database.

The MedTrace Confluence view surfaces this directly: when `panelContext.isConfluence` is true, `LiveOnboardingCard` renders a notice explaining that Forge partitions storage per product (Jira vs Confluence), that this surface reads Confluence's own partition, and that the user should either open MedTrace from a Jira project page (for Jira's compliance suite) or click **Sync Live Atlassian** here to populate Confluence's local partition.
