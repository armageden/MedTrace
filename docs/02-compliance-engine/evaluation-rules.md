[<- Compliance Engine Overview](./00-overview.md)

# Compliance Evaluation, Ingestion & Audit Rules

Core deterministic logic lives in [src/compliance-engine.ts](../../src/compliance-engine.ts), persisted via sharded KVS in [src/seeder.ts](../../src/seeder.ts), populated from live tenants via [src/ingestion.ts](../../src/ingestion.ts), and audited by [src/audit-log.ts](../../src/audit-log.ts), using types from [src/types.ts](../../src/types.ts).

## 1. Trace Link Evaluation (`ComplianceEngine.evaluateTraceLink`)

Every `TraceLink` spans five stages: `HAZARD` (ISO 14971 `RiskClass`: `CLASS_A`, `CLASS_B`, `CLASS_C`), `SPEC` (Confluence SRS page + SHA-256 `contentHash`), `WORK` (Jira issue), `TEST` (verification evidence), and `SIGNATURE` (21 CFR Part 11 electronic signature).

Evaluation checks run in deterministic order:
1. **Missing Spec Title (`INCOMPLETE`):** `!link.spec?.title?.trim()` produces `INCOMPLETE` with blocking message `'Missing Confluence Software Requirement Specification (SRS).'`.
2. **Missing Work Item (`INCOMPLETE`):** `!link.work?.key?.trim()` produces `INCOMPLETE` with blocking message `'Missing Jira implementation work item.'`.
3. **Safety-Critical Test Gate (`SAFETY_VIOLATION`):** `CLASS_C` hazards with `link.test.status !== 'PASSED'` produce `SAFETY_VIOLATION`.
4. **Class B Verification Gate (`INCOMPLETE`):** `CLASS_B` hazards with `link.test.status !== 'PASSED'` produce `INCOMPLETE`.
5. **Class A Failure Gate (`INCOMPLETE`):** `CLASS_A` hazards with `link.test.status === 'FAILED'` produce `INCOMPLETE` (pending/not-run Class A tests do not block by themselves).
6. **Spec Drift & Signature Validity (`SIGNATURE_DRIFT`):**
   - `hasHashDrift = Boolean(link.spec.contentHash && link.signature.specContentHash && link.spec.contentHash !== link.signature.specContentHash)`
   - `hasInvalidSignature = !link.signature.isValid || !link.signature.signedBy?.trim() || !link.signature.signedAt?.trim()`
   - If either holds (and the link was not already flagged `SAFETY_VIOLATION`), `status` becomes `SIGNATURE_DRIFT`.
7. **Verified (`VERIFIED`):** Only links with valid spec, Jira work key, satisfying test evidence, matching content hashes, and an intact Part 11 signature achieve `VERIFIED`.

### Summary Counts (`ComplianceEngine.generateComplianceReport`)

- `signatureDriftCount` counts every link where `hasHashDrift || hasInvalidSignature` is true, **even if** the link's overall status is `SAFETY_VIOLATION` (ensuring drift is never masked by a concurrent Class C failure).
- `releaseBlocked` is `true` whenever `safetyViolationCount > 0 || signatureDriftCount > 0 || incompleteCount > 0`.

## 2. Shared Release Gate (`ComplianceEngine.evaluateIssueReleaseGate`)

Both the Jira workflow validator ([src/workflow-validator.ts](../../src/workflow-validator.ts)) and the MCP/CI release gate (`action=verify-release-gate` in [src/index.ts](../../src/index.ts)) call `ComplianceEngine.evaluateIssueReleaseGate(issueKey, suite)`:
- **Issue-scoped evaluation (when `issueKey` is provided):**
  - If `issueKey` is not linked to any trace link in `suite.links`, the gate **passes** (`{ result: true }`) rather than blocking unrelated Jira issues.
  - If one or more links match `issueKey` (exact uppercase match on `link.work?.key`) and any matched link has `status !== 'VERIFIED'`, the gate **blocks** (`{ result: false, errorMessage }`).
- **Global suite evaluation (when `issueKey` is omitted):** Blocks if `suite.releaseBlocked` is `true`.

## 3. 5-Stage Blast Radius (`ComplianceEngine.computeBlastRadius`)

Given an `artifactKey`:
1. Matches affected links using exact key comparison (`matchesLinkByKey`): `link.hazard.id`, `link.spec.id`, `link.spec.pageId`, `link.work.key`, `link.test.id`, or `link.signature.id`.
2. Sets `triggerArtifact.type` dynamically (`HAZARD`, `SPEC`, `WORK`, `TEST`, or `SIGNATURE`) and constructs a bipartite-free 5-stage graph (`HAZARD -> SPEC -> WORK -> TEST -> SIGNATURE`).
3. Runs BFS from the trigger node across adjacent nodes, propagating `REQUIRES_RETEST` / `IMPACTED` states when a link is impacted (`status !== 'VERIFIED'`, non-Done work, non-PASSED test, or `componentHasSignatureDrift`), while preserving `VERIFIED` / `Done` / `PASSED` states in drift-free components.

## 4. Sharded KVS Persistence (`SeederService` — [src/seeder.ts](../../src/seeder.ts))

To prevent single-key Forge KVS size exhaustion on growing trace suites:
- Metadata lives at `medtrace:compliance:suite_meta` (`storageFormat: 'SHARDED_V2'`, tracking `version`, `datasetMode`, `lastUpdated`, `linkIds`, `auditEntryCount`, `auditHeadHash`).
- Individual links live at `medtrace:compliance:link:<id>`, written and read in chunks of `BATCH_CHUNK_SIZE = 25` via `kvs.batchSet` / `kvs.batchGet`.
- Signed spec baselines are persisted separately at `medtrace:compliance:signed_spec:<id>` (`SpecBaselineRecord`) so live ingestion preserves Part 11 signatures across sync cycles unless a Confluence page's SHA-256 content hash changes.
- Legacy `medtrace:compliance:active_suite` records (`SINGLE_KEY_V1`) are automatically migrated into `SHARDED_V2` on read.

## 5. Live Atlassian Ingestion & Drift Trigger ([src/ingestion.ts](../../src/ingestion.ts))

`LiveIngestionService` requires `isForgeRuntime()` for live tenant calls (`syncFromAtlassian`):
1. Queries Jira issues via `/rest/api/3/search/jql` (`maxResults=50`) and Confluence pages via `/wiki/api/v2/pages?body-format=storage&limit=50` (optionally space-scoped).
2. Enriches each issue through `TeamworkGraphService.queryIssueGraphContext(issueKey)` (AGG + Jira `issuelinks` and Confluence `remotelink` extraction) with SRS title matching fallback (`SRS-\d+`).
3. Computes SHA-256 hex digests of Confluence `body.storage.value` and compares against `SeederService.getSignedSpecBaseline(...)`. Matching digests retain valid Part 11 signatures; changed digests invalidate the signature (`isValid: false`) and trigger `SIGNATURE_DRIFT`.
4. Persists the suite with `datasetMode: 'LIVE'` and appends a `'SYNC_LIVE'` entry to `AuditLogService`.

`LiveIngestionService.handleConfluencePageUpdated(event)` runs on `avi:confluence:updated:page`:
- Locates trace links matching the updated `pageId`, fetches `/wiki/api/v2/pages/${pageId}?body-format=storage` (or accepts test hash payloads outside Forge), invalidates drifted signatures, appends a `'CONFLUENCE_PAGE_DRIFT'` audit entry, and re-evaluates and saves the suite.

## 6. Mutations & 21 CFR Part 11 Attestation ([src/seeder.ts](../../src/seeder.ts))

Every state mutation requires an explicit, caller-scoped actor and appends an audit record:
- `bindIssueToHazard`: Verifies `cleanIssueKey` exists via `/rest/api/3/issue/${cleanIssueKey}` in Forge runtime, binds the Jira issue to the hazard link, and logs `'BIND_ISSUE'`.
- `recordTestResult`: Validates `status` (`PASSED` | `FAILED` | `PENDING`) and non-empty `actorAccountId`, updates test evidence and `recordedBy`/`notes`, and logs `'RECORD_TEST_RESULT'`.
- `signOffPart11`: Requires `attestationConfirmed === true`, `meaning.trim().length >= 5`, and `actorAccountId`. Records `Part11Signature` with `authMethod` (`FORGE_SESSION` or `SYSTEM`), writes `signed_spec` baseline, and logs `'PART11_SIGNOFF'`.
- `remediateClassCGap`: **Demo-only** simulation guard. Rejects `datasetMode === 'LIVE'`, requires `simulate: true` and `attestationConfirmed: true`, and logs `'DEMO_SIMULATION'`.

## 7. Hash-Chained Audit Ledger ([src/audit-log.ts](../../src/audit-log.ts))

`AuditLogService` maintains a tamper-evident append-only ledger in Forge KVS (using `inMemoryAuditAdapter` only when `!isForgeRuntime()`):
- Genesis constant: `AUDIT_GENESIS_HASH` (`'0'.repeat(64)`).
- Keys: `medtrace:audit:head` and `medtrace:audit:entry:<seq>`.
- Each entry computes `entryHash` via canonical sorted-key JSON SHA-256 (`computeAuditEntryHash`), binding `seq`, `timestamp`, `action`, `actorAccountId`, `authMethod`, `prevHash`, optional `targetId`/`meaning`/`details`, and `previousSuiteHash`/`nextSuiteHash`.
- Entries are written immutably with `kvs.set(..., { keyPolicy: 'FAIL_IF_EXISTS' })` and up to 12 concurrency retries via `resolveChainTail()`.
- `verifyAuditChain()` walks from sequence `1` to `head.seq`, validating sequence continuity, `prevHash` linkage, and recomputed `entryHash`.

## 8. Verification Suite

Unit and integration tests live in [tests/compliance-engine.test.cjs](../../tests/compliance-engine.test.cjs) (**57 tests across 14 suites**), covering 5-stage rule evaluation, `signatureDriftCount`, `computeBlastRadius`, `evaluateIssueReleaseGate`, sharded KVS roundtrips & migration, `LiveIngestionService` sync & page-update drift, `AuditLogService` hash chaining & tamper detection, `TeamworkGraphService` AGG/REST fallback, `mcpWebtriggerHandler` HMAC/replay/fail-closed errors, and `McpToolService` lookup & diff analysis.
