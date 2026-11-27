[<- Design Decisions Overview](./00-overview.md)

# ADR-006: User-Initiated Live Proof Bootstrap

**Status:** Accepted

## Context

MedTrace's strongest evaluation path requires real native artifacts: a Confluence SRS requirement, a Jira hazard, implementation work item, verification test, Jira issue links, and a Jira remote link to Confluence. The fully manual setup was accurate but slow and error-prone, which weakened judge evaluation and encouraged reliance on app-managed fallback records. Synthetic Demo Mode remains useful, but it does not prove live Jira/Confluence traceability.

At the same time, a bootstrap that silently writes broad tenant data, fabricates evidence, signs approvals, or cleans up artifacts automatically would violate MedTrace's safety and trust model.

## Decision

Add an explicit user-initiated **Create Live Proof Chain** action implemented by [src/live-proof-scenario.ts](../../src/live-proof-scenario.ts) and exposed through the `createLiveProofScenario` resolver in [src/index.ts](../../src/index.ts):

- Run entirely under `api.asUser()` and require authenticated operator RBAC, Jira `CREATE_ISSUES`, `LINK_ISSUES`, plus `EDIT_ISSUES`/`ADMINISTER_PROJECTS` permission, and verified Confluence page-create capability in the selected space before writes.
- Create exactly one Confluence proof SRS page and three native Jira issues (hazard, verification test, implementation work) in the current Jira project context, resolving the project's real issue type from `createmeta` (preferring `Task`, then `Story`, then the first non-subtask type; falling back to `Task` only when the lookup fails) via the shared `resolveCreatemetaIssueTypeRef` helper instead of hardcoding `Task`.
- Apply explicit `medtrace-live-proof`, hazard/test, and `class-c` labels; create two `Relates` issue links; create one Jira remote link to the Confluence page; then run live ingestion scoped to the exact three created issue keys.
- Record a hash-chained `CREATE_LIVE_PROOF_SCENARIO` audit entry after creation and ingestion, then return `summary.auditEntryCount` / `summary.auditHeadHash` re-read from `AuditLogService.getHead()` so callers receive the post-append chain state rather than pre-append counts.
- Never record verification evidence, execute Part 11 attestation, transition work, or mark the chain compliant automatically.
- Never delete partial artifacts automatically. If a later create/link step fails, the error names real artifacts already created so the user can correct or remove them deliberately.

The feature requires `write:page:confluence` in [manifest.yml](../../manifest.yml). MedTrace uses this scope only to create the explicit proof page; it does not modify existing pages.

## Consequences

Positive:

- Judges and developers can create a native end-to-end live proof chain in one explicit action instead of manually assembling five artifact relationships.
- The central demo still requires real user attestation and evidence, preserving the difference between bootstrap convenience and compliance proof.
- Native Jira artifacts avoid over-reliance on app-managed fallback records in the primary evaluation path.
- Permission failures occur before writes where possible, and partial-write disclosure avoids hidden tenant state.

Trade-offs and limits:

- The action creates real artifacts in the selected evaluation project/space and is not idempotent across separate clicks. When no space is supplied, it tries the project-key-matching space before falling back to the first readable global space, so evaluation tenants are mandatory.
- The button is disabled when the extension context has no Jira project key; Confluence-global users must open MedTrace from a Jira project or use the manual fallback.
- The implementation resolves the project's issue type from `createmeta` (preferring `Task`, then `Story`, then the first non-subtask type) and assumes the standard `Relates` link type. Tenants that remove `Relates` can encounter a partial-create failure even though the labels carry MedTrace's semantic roles.
- The new Confluence write scope requires a major-version installation upgrade/consent before the button works against an existing production installation.
- Forge product-partitioned KVS still applies. Bootstrapping from Jira initializes the Jira partition; hosted MCP or Confluence-context demonstrations may need an explicit sync in that product partition.

Verification coverage lives in [tests/live-proof-scenario.test.cjs](../../tests/live-proof-scenario.test.cjs) and the onboarding integration test in [static/frontend/src/__tests__/App.races.test.tsx](../../static/frontend/src/__tests__/App.races.test.tsx). Operational usage is documented in [../00-how-to/04-live-judge-proof.md](../00-how-to/04-live-judge-proof.md).
