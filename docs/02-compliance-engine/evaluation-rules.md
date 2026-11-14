[<- Compliance Engine Overview](./00-overview.md)

# Compliance Evaluation, Ingestion & Audit Rules

Core deterministic logic lives in [src/compliance-engine.ts](../../src/compliance-engine.ts), shared types in [src/types.ts](../../src/types.ts), cryptographic and key helpers in [src/crypto-utils.ts](../../src/crypto-utils.ts), sharded KVS persistence in [src/seeder.ts](../../src/seeder.ts), live Atlassian ingestion in [src/ingestion.ts](../../src/ingestion.ts), and the hash-chained audit ledger in [src/audit-log.ts](../../src/audit-log.ts).

## 1. Trace Link Evaluation (`ComplianceEngine.evaluateTraceLink`)

Every `TraceLink` spans five stages:
- `HAZARD`: ISO 14971 hazard (`riskClass`: `CLASS_A | CLASS_B | CLASS_C`).
- `SPEC`: Confluence Software Safety Specification (`title`, optional `id`/`pageId`, `sha256Hash`, `lastSignedHash`, `isSignatureInvalidated`, and optional sentinel flag `isMissingSentinel`).
- `WORK`: Jira implementation work item (`key`, `status`).
- `TEST`: Verification test (`testKey`, `status`: `'PASSED' | 'FAILED' | 'UNTESTED' | 'IN_PROGRESS'`, `evidenceUrl`, `executionDate`).
- `SIGNATURE`: FDA 21 CFR Part 11 electronic signature (`id`, `isValid`, `signedBy`, `signedByAccountId`, `signedAt`, `invalidatedAt`, `artifactSha256`, `signatureSeal`, `signatureAlgorithm`: `'HMAC-SHA256-SEAL-V1' | 'ECDSA-P256-SHA256+HMAC-SEAL-V1'`, optional `clientPublicKeySpki`, `clientSignatureBase64`, `clientKeyFingerprint`).

Evaluation checks apply precedence `SAFETY_VIOLATION` (3) > `SIGNATURE_DRIFT` (2) > `INCOMPLETE` (1) > `VERIFIED` (0) (where `severityForRiskClass` yields `SAFETY_VIOLATION` for `CLASS_C` and `INCOMPLETE` for `CLASS_A` / `CLASS_B`):

1. **Missing or Sentinel Spec:** If `!spec || !spec.title || spec.title.trim() === '' || spec.isMissingSentinel === true`, flags `severityForRiskClass`:
   - `'ISO 14971 Violation: Hazard lacks linked Software Safety Specification (Confluence SRS).'`
2. **Missing Work Item:** If `!work || !work.key`, flags `severityForRiskClass`:
   - `` `IEC 62304 Traceability Gap: Hazard [${hazard.key}] lacks a linked Jira implementation work item.` ``
3. **Unfinished Work Item:** Else if `work.status !== 'Done'`, flags `severityForRiskClass`:
   - `` `IEC 62304 Traceability Gap: Implementation work item [${work.key}] for Hazard [${hazard.key}] is "${work.status || 'Unknown'}" (must be "Done" for release).` ``
4. **Verification Test Status:**
   - `CLASS_C` with `test?.status !== 'PASSED'` -> `SAFETY_VIOLATION`:
     - `` `IEC 62304 Critical Gap: Class C Hazard [${hazard.key}] requires verified test coverage. Current test [${test?.testKey || 'UNLINKED'}] status is ${test?.status || 'MISSING'}.` ``
   - `CLASS_B` with `test?.status !== 'PASSED'` -> `INCOMPLETE`:
     - `` `IEC 62304 Notice: Class B Hazard [${hazard.key}] verification test is ${test?.status || 'MISSING'}.` ``
   - `CLASS_A` with `test?.status === 'FAILED'` -> `INCOMPLETE`:
     - `` `IEC 62304 Notice: Class A Hazard [${hazard.key}] verification test [${test.testKey}] FAILED.` ``
   - `CLASS_A` with any other non-`PASSED` state (`UNTESTED`, `IN_PROGRESS`, or missing) -> `INCOMPLETE`:
     - `` `IEC 62304 Notice: Class A Hazard [${hazard.key}] verification test [${test?.testKey || 'UNLINKED'}] is ${test?.status || 'MISSING'} (requires PASSED).` ``
5. **Evidence URL Validation (`validateHttpsUrl`):** If `test?.evidenceUrl` is non-empty and invalid/unsafe, flags `severityForRiskClass`:
   - `` `IEC 62304 Verification Evidence Violation: Test [${test.testKey}] has unsafe or invalid evidenceUrl (${reason}).` ``
6. **Passed Test Evidence Completeness (`requireTestEvidence`):** When `options?.requireTestEvidence` is enabled (`true` in `LIVE` mode for `bindIssueToHazard`, `recordTestResult`, and `syncFromAtlassian`; omitted in `DEMO` evaluation) and `test?.status === 'PASSED'`, missing `evidenceUrl` or `executionDate` flags `severityForRiskClass`:
   - `` `IEC 62304 Verification Evidence Gap: Passed test [${test.testKey}] for Hazard [${hazard.key}] is missing required ${missingParts.join(' and ')}.` ``
7. **Spec Drift, Signature Attestation & HMAC Seal (`SIGNATURE_DRIFT`):**
   - `hasHashDrift`: Checks `!spec || !signature || spec.sha256Hash !== signature.artifactSha256 || Boolean(spec.isSignatureInvalidated)` (while `spec.lastSignedHash` mirrors the baseline signed digest on the spec node). Message:
     - `` `Cryptographic Signature Drift: Confluence Spec [${spec?.title || spec?.id || 'Unlinked'}] was modified after clinical sign-off. Expected hash ${(signature?.artifactSha256 || '').slice(0, 8)}..., current hash ${(spec?.sha256Hash || '').slice(0, 8)}...` ``
   - `hasInvalidSignature`: Checks `!signature || !signature.isValid || !signature.signedBy || !signature.signedAt` as well as baseline timestamp invalidation (`signedMs <= invalidatedMs`). Message:
     - `` `FDA 21 CFR Part 11 Violation: Electronic signature [${signature?.id || 'missing'}] is invalid or missing required signer attestation.` ``
   - `hasSealFailure`: When `requireCryptographicSeal` is enabled, `signature?.signatureSeal` is present, or asymmetric client fields (`clientSignatureBase64` / `clientPublicKeySpki`) are present, runs `verifyPart11Seal` (`HMAC-SHA256-SEAL-V1` keyed by `MEDTRACE_PART11_SECRET`, with comma-separated retired verification key-ring support via `MEDTRACE_PART11_PREVIOUS_SECRETS` and `computePart11KeyFingerprint` helpers). When `signatureAlgorithm === 'ECDSA-P256-SHA256+HMAC-SEAL-V1'` or client asymmetric fields are supplied, `verifyPart11Seal` validates **both** the client's ECDSA P-256 (`prime256v1`) SHA-256 signature (`verifyPart11ClientSignature` over canonical `computePart11ClientChallenge`, supporting IEEE P1363 WebCrypto and ASN.1 DER formats) **and** the bound server HMAC-SHA256 seal. Failure message:
     - `` `FDA 21 CFR Part 11 Cryptographic Seal Violation: Electronic signature [${signature?.id || 'missing'}] failed HMAC-SHA256 integrity verification.` ``
8. **Verified (`VERIFIED`):** Achieved only when all spec, work, test, evidence, hash, signature attestation, and cryptographic seal checks pass.

### Summary Counts (`ComplianceEngine.generateComplianceReport`)

- `signatureDriftCount` counts every link exhibiting hash drift, invalid/invalidated attestation, or seal failure, **even if** the link's aggregate state is `SAFETY_VIOLATION` so drift is never masked by a concurrent Class C failure.
- An empty suite (`traceLinks.length === 0`) appends a blocking reason (`Compliance suite is uninitialized or contains 0 hazard trace links...`).
- `releaseBlocked` is `true` whenever `blockingReasons.length > 0`.

## 2. Shared Release Gate (`ComplianceEngine.evaluateIssueReleaseGate`)

Both the Jira workflow validator ([src/workflow-validator.ts](../../src/workflow-validator.ts)) and the MCP/CI release gate (`action=verify-release-gate` in [src/index.ts](../../src/index.ts)) call `ComplianceEngine.evaluateIssueReleaseGate(issueKey, suite)`:
- **Fail-Closed Initialization Check:** Blocks immediately (`{ result: false }`) if `!suite || suite.initialized === false || !Array.isArray(suite.traceLinks) || (suite.traceLinks.length === 0 && (!cleanIssueKey || (suite.totalHazards ?? 0) === 0))` (distinguishing genuinely uninitialized/global empty suites from an O(1) fast-path empty match on an unrelated issue in a populated `LIVE` suite).
- **Issue-Scoped Evaluation (when `issueKey` is provided):**
  - Matches links where `(l.work?.key || '').toUpperCase() === cleanIssueKey || (l.hazard?.key || '').toUpperCase() === cleanIssueKey`. Callers (`workflowValidatorHandler` and `verify-release-gate`) pass `{ issueKeyFilter: issueKey }` to `SeederService.getActiveComplianceSuite` so only matching shards are loaded when `issueKeyIndex` is present on metadata.
  - If an initialized, non-empty suite has no trace link referencing `cleanIssueKey`, the gate **passes** (`{ result: true }`) so unrelated Jira work is not blocked.
  - If any matched link has `complianceState !== 'VERIFIED'`, the gate **blocks** (`{ result: false, errorMessage }`).
- **Global Suite Evaluation (when `issueKey` is omitted):** Blocks if `suite.releaseBlocked` is `true`.

## 3. 5-Stage Blast Radius (`computeBlastRadius` & `computeMultiBlastRadius`)

`ComplianceEngine.computeBlastRadius(suite, artifactKey)` and `computeMultiBlastRadius(suite, artifactKeys)`:
1. **Empty Trigger Guard:** If `triggerKey` is empty/whitespace, returns an empty report with reason `'No Trigger Artifact Specified'` (`impactedCount: 0`).
2. **Artifact Key Matching (`matchesLinkByKey`):** Matches hazard key/ID, spec `id`/`pageId`/short key (guarded by `/^[a-z]{2,10}-\d+$/i`), work key, test `id`/`testKey`, and signature `id` without false substring collisions.
3. **Component BFS & Fixed Edge Labels:** Indexes links into artifact-node adjacency lists and runs BFS over the connected component using the exact four directed/relationship edge labels: `SIGNS`, `MITIGATES`, `IMPLEMENTS`, `VERIFIES` (clean `SIGNS` hops are preserved accurately; there are no synthetic `REQUIRES_RETEST` or `IMPACTED` edge labels).
4. **Per-Hazard / Per-Spec Isolation:** Traversal preserves per-hazard and per-spec drift isolation so unrelated sibling links sharing a `work.key` are not spuriously marked drifted unless connected through the drifted hazard/spec component.

## 4. Sharded KVS Persistence & Concurrency ([src/seeder.ts](../../src/seeder.ts))

To keep compliance state deterministic under Forge KVS limits and concurrent invocations:
- **Cold-Start `LIVE` Behavior (`getUninitializedLiveSuite`):** When Forge KVS contains neither a sharded suite nor a legacy `SINGLE_KEY_V1` suite, `SeederService.getActiveSuite()` returns an uninitialized empty `LIVE` suite (`initialized: false`, zero links) without writing or auto-seeding synthetic `DEMO` records on read.
- **Suite Metadata (`medtrace:compliance:suite_meta`, `ShardedSuiteMetaV2`):** Stored with `storageFormat: 'SHARDED_V2'`, tracking `version`, `initialized`, `datasetMode`, `lastUpdated`, `linkKeys`, `linkKeyShardKeys`, `blockingReasonShardKeys`, `issueKeyIndex` (`work.key` / `hazard.key` -> link shard keys for O(1) issue-scoped release-gate lookups via `getActiveComplianceSuite({ issueKeyFilter })`) or overflow `issueKeyIndexShardKeys` (`medtrace:compliance:meta_index:v<version>:<idx>`), and suite counters. Metadata size is bounded by `MAX_KVS_META_BYTES` (`128 * 1024` bytes), sharding overflowing blocking reasons, link keys, and `issueKeyIndex` records so O(1)/bounded issue-scoped fast-path lookups continue working even above 128 KiB metadata; `auditEntryCount` and `auditHeadHash` are populated dynamically from `AuditLogService.getHead()`.
- **Optimistic Locking & Atomic Writes:** Mutations acquire/check optimistic `vlock` (`VLOCK_PREFIX`) versioning:
  - Batches with `<= 25` KVS operations within `MAX_TRANSACT_BYTES` commit atomically via `kvs.transact()`.
  - Larger batches commit via version-prefixed `v<version>:` staged link keys and shard metadata updates, reusing prior `v<version>:` link shards whose canonical SHA-256 content hash is unchanged and staging only new/modified link keys via `batchSetStrict` before deleting obsolete shard keys; `batchSetStrict` and `batchGetStrict` retry transient KVS errors and fail closed if reads/writes remain incomplete.
- **Composite Signed Spec Baselines (`SIGNED_SPEC_PREFIX`):** `SignedSpecBaseline` records are keyed by composite `(hazardKey, specId)` (`sanitizeKvsKeySegment`) with backwards-compatible fallback reads from legacy `medtrace:compliance:signed_spec:<id>` keys.
- **Legacy Migration & Save-Before-Audit Rollback:** Any legacy `SINGLE_KEY_V1` suite at `medtrace:compliance:active_suite` is migrated into `SHARDED_V2`. `commitSuiteMutation` commits suite storage first and performs compensating rollback if appending the audit log entry fails.

## 5. Live Atlassian Ingestion & Drift Trigger ([src/ingestion.ts](../../src/ingestion.ts))

`LiveIngestionService.syncFromAtlassian` requires `isForgeRuntime()` for live Jira/Confluence API access:
1. **Paginated Jira & Confluence Queries & Resumable Sync Cursor:** Pages through `/rest/api/3/search/jql` using `nextPageToken` (`DEFAULT_SYNC_MAX_ISSUES = 250`, `MAX_SYNC_MAX_ISSUES = 500`, `LIVE_SYNC_BUDGET_MS = 15_000`) and `/wiki/api/v2/pages?body-format=storage` via `_links.next`. When Jira pagination truncates on budget or exact `maxIssues` page boundaries with a remaining `nextPageToken`, `syncFromAtlassian` returns `nextPageToken` and persists a scoped cursor at `medtrace:ingestion:cursor:<projectKey || 'GLOBAL'>` so subsequent invocations with `resumeFromCursor: true` (or explicit `pageToken`) continue from that page and merge with earlier synced links before clearing the cursor upon `truncated: false`.
2. **Safety Tracking Filter & M:N Trace Links:** Evaluates `isSafetyTrackedIssue` (counting filtered non-safety items in `skippedUntaggedCount`), passes `requireConfluenceLinkToEnrich: !hasStaticTrack` to `TeamworkGraphService.queryIssueGraphContext` so untagged issues lacking Confluence remote links short-circuit `/issue` + AGG GraphQL calls while preserving bounded worker concurrency (`<= 5`), assigns M:N multi-spec composite trace IDs (`buildTraceLinkId`), and preserves existing `LIVE` trace links belonging to other Jira projects or unreached issues after sync truncation (`warnings`).
3. **SHA-256 Digest & Revert Non-Resurrection:** Hashes Confluence `body.storage.value` into `spec.sha256Hash` and evaluates against `SignedSpecBaseline` with `requireTestEvidence: true` and `requireCryptographicSeal: true`. When a baseline has an invalidation timestamp (`isBaselineInvalidated` / `signedMs <= invMs`), reverting a Confluence page to an older hash does **not** resurrect an invalidated signature.
4. **Confluence Page Update Event (`handleConfluencePageUpdated`):** Triggered by `avi:confluence:updated:page`; executes up to `MAX_CAS_RETRY_ATTEMPTS = 3` optimistic CAS attempts on `vlock`, invalidates affected baselines/signatures, appends `'CONFLUENCE_PAGE_DRIFT'` (actor attributed cleanly, `authMethod: 'CONFLUENCE_EVENT_TRIGGER'`), and persists the updated `LIVE` suite.

## 6. Mutations & 21 CFR Part 11 Attestation ([src/seeder.ts](../../src/seeder.ts))

Every mutation runs inside `commitSuiteMutation`, enforces role/runtime preconditions, and appends a hash-chained audit record:
- `bindIssueToHazard`: Verifies target Jira issue via `/rest/api/3/issue/${cleanIssueKey}` in Forge runtime, honors `callerMode: 'USER' | 'APP'`, clears stale `prNumber`, `commitSha`, and `graphMetadata` on rebinding, validates with `requireTestEvidence: true` in `LIVE`, and logs `'BIND_ISSUE'`.
- `recordTestResult`: Accepts `'PASSED' | 'FAILED' | 'UNTESTED' | 'IN_PROGRESS'`, validates `evidenceUrl` via `validateHttpsUrl` (passing `""` clears the URL), records actor/notes/date, evaluates with `requireTestEvidence: true` in `LIVE`, and logs `'RECORD_TEST_RESULT'`.
- `signOffPart11`: Requires `attestationConfirmed === true`, `passwordConfirmed === true`, exact `attestationPhrase === PART11_ATTESTATION_PHRASE` (`'I CERTIFY THIS ELECTRONIC SIGNATURE'`), and `meaning.trim().length >= 5`; verifies signer identity via `UserIdentityResolver`, validates optional asymmetric ECDSA P-256 client signature/SPKI public key (`clientPublicKeySpki`, `clientSignatureBase64`, throwing `PART11_CLIENT_SIGNATURE_INVALID` if mismatched or incomplete) for hybrid `ECDSA-P256-SHA256+HMAC-SEAL-V1` non-repudiation or falls back to server `HMAC-SHA256-SEAL-V1` using `MEDTRACE_PART11_SECRET`, saves composite `(hazardKey, specId)` `SignedSpecBaseline`, and logs `'PART11_SIGNOFF'` (`authMethod: 'PART11_ATTESTATION'`).
- `remediateClassCGap`: **DEMO-only simulation guard.** Rejects `LIVE` mode, requires non-empty `targetHazardKey`, `simulate: true`, and `attestationConfirmed: true`, and logs `'DEMO_SIMULATION'`.

## 7. Hash-Chained Audit Ledger ([src/audit-log.ts](../../src/audit-log.ts))

`AuditLogService` maintains a tamper-evident software hash chain in Forge KVS (using the in-memory adapter only when `!isForgeRuntime()`):
- **Genesis & Size Bounds:** `AUDIT_GENESIS_HASH = '0'.repeat(64)`; entries exceeding `MAX_AUDIT_ENTRY_BYTES` (`220 * 1024` bytes) are rejected before write.
- **Keys & Immutability:** Chain head at `medtrace:audit:head`; individual records at `medtrace:audit:entry:<seq>` written via `kvs.set(..., { keyPolicy: 'FAIL_IF_EXISTS' })`. Head updates enforce monotonic sequence guards via `returnValue: 'PREVIOUS'`.
- **Canonical Entry Hash (`computeAuditEntryHash`):** Canonical sorted-key JSON (`canonicalJsonStringify`) SHA-256 over exact fields: `seq`, `timestamp`, `actorAccountId`, `action`, `targetKey`, `details`, `prevHash`, and `authMethod`.
  - `AuditActionType`: `'SEED_DEMO' | 'SYNC_LIVE' | 'BIND_ISSUE' | 'RECORD_TEST_RESULT' | 'PART11_SIGNOFF' | 'DEMO_SIMULATION' | 'CONFLUENCE_PAGE_DRIFT'`.
  - `AuditAuthMethod`: `'FORGE_USER_SESSION' | 'PART11_ATTESTATION' | 'HMAC_WEBTRIGGER' | 'CONFLUENCE_EVENT_TRIGGER' | 'SYSTEM_INIT'`.
- **Tail Discovery, Pagination & Batched Verification:** `resolveChainTail()` scans forward from `head.lastSeq` in 10-entry probes (up to 500 hops) to resolve partial writes; `getAuditLog(limit, beforeSeq?)` supports cursor pagination; `verifyAuditChain(options?: VerifyAuditChainOptions)` fetches entries in `AUDIT_BATCH_CHUNK_SIZE = 25` chunks via `kvs.batchGet`, verifying sequence continuity, `prevHash` links, and recomputed `entryHash` values bounded to `MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES` (`500` default in service, `200` default in Custom UI resolver, returning `verifiedFromSeq`, `verifiedToSeq`, `nextFromSeq`, `truncated`, `windowEntryCount` whenever bounded or truncated), anchored against verified predecessor `fromSeq - 1` and optional `expectedPrevHash`; UI modals (`AuditLogModal`, `FdaExportModal`) continue stepping through truncated windows sequentially via `verifyAuditChainBounded`. `kvsAuditStorageAdapter.getEntriesBatch` treats `failedKeys` with `error.code === 'KEY_NOT_FOUND'` as not-present and omits them silently; only non-`KEY_NOT_FOUND` codes (e.g. `QUOTA_EXCEEDED`, `KVS_UNAVAILABLE`) are retried once and then fail closed.
  - *Platform Boundary:* Hash chaining + `FAIL_IF_EXISTS` in Forge KVS provides **tamper-evidence** against silent alteration; Forge KVS is not hardware WORM, HSM-backed, or X.509/PKI non-repudiation.

## 8. Verification Suites

Modular backend test coverage lives across:
- [tests/compliance-engine.test.cjs](../../tests/compliance-engine.test.cjs) — 5-stage rule evaluation, `signatureDriftCount`, `computeBlastRadius` / `computeMultiBlastRadius` BFS, `evaluateIssueReleaseGate`, and HMAC Part 11 seals.
- [tests/seeder-storage.test.cjs](../../tests/seeder-storage.test.cjs) — `SHARDED_V2` roundtrips, `vlock` optimistic locking, `kvs.transact()` & staged chunking, composite `(hazardKey, specId)` baselines, rollback, and `signOffPart11` / `remediateClassCGap` guards.
- [tests/ingestion.test.cjs](../../tests/ingestion.test.cjs) — Paginated `LiveIngestionService.syncFromAtlassian`, M:N trace linking, revert non-resurrection, and `handleConfluencePageUpdated` CAS retries.
- [tests/audit-log.test.cjs](../../tests/audit-log.test.cjs) — `computeAuditEntryHash`, `FAIL_IF_EXISTS`, monotonic head updates, `beforeSeq` pagination, `verifyAuditChain` tamper detection, and `KEY_NOT_FOUND` `failedKeys` filtering on an unseeded/empty store.
- [tests/nonce-store.test.cjs](../../tests/nonce-store.test.cjs), [tests/workflow-validator-and-mcp.test.cjs](../../tests/workflow-validator-and-mcp.test.cjs), [tests/index-rbac-webtrigger.test.cjs](../../tests/index-rbac-webtrigger.test.cjs), and [tests/mcp-server.test.mjs](../../tests/mcp-server.test.mjs).
