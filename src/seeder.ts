import api, { route } from '@forge/api';
import { kvs } from '@forge/kvs';
import { AuditLogService } from './audit-log';
import { ComplianceEngine } from './compliance-engine';
import {
  canonicalJsonStringify,
  isKvsConflictError,
  measureJsonBytes,
  sanitizeKvsKeySegment,
  sha256Hex,
  validateHttpsUrl,
} from './crypto-utils';
import { isForgeRuntime } from './runtime';
import {
  getActiveUserIdentityResolver,
  getPart11SigningSecret,
  mapJiraStatusToWorkStatus,
} from './seeder-identity';
import {
  BATCH_CHUNK_SIZE,
  batchDeleteBestEffort,
  batchGetStrict,
  batchSetStrict,
  buildMetaAndShardItems,
  buildSafeKvsKey,
  buildSignedBaselineRecord,
  cloneJsonValue,
  getBaselineKeyCandidates,
  LEGACY_STORAGE_KEY,
  LINK_KEY_PREFIX,
  MAX_AUDIT_DETAILS_BYTES,
  MAX_TRANSACT_BYTES,
  resolveTraceLinkByHazard,
  SIGNED_SPEC_PREFIX,
  SUITE_META_KEY,
  VLOCK_PREFIX,
} from './seeder-storage';
import type { ShardedSuiteMetaV2 } from './seeder-storage';
import {
  ComplianceSummary,
  ConfluenceSpec,
  IsoHazard,
  JiraWorkItem,
  PART11_ATTESTATION_PHRASE,
  Part11Attestation,
  Part11Signature,
  SeedDemoResponse,
  TraceLink,
  VerificationTest,
} from './types';
import type { SignedSpecBaseline } from './seeder-storage';

export { SignedSpecBaseline } from './seeder-storage';
export {
  forgeUserIdentityResolver,
  getPart11SigningSecret,
  mapJiraStatusToWorkStatus,
  setUserIdentityResolver,
} from './seeder-identity';
export type { UserIdentityResolver, UserIdentityResolverContext } from './seeder-identity';

type AuditAppendInput = Parameters<typeof AuditLogService.append>[0];
type AuditAuthMethod = NonNullable<AuditAppendInput['authMethod']>;


/**
 * Optional guard parameters for seeding demo data.
 */
export interface SeedDemoOptions {
  confirmOverwriteLive?: boolean;
  authorizedSiteAdmin?: boolean;
}

export const LIVE_BACKUP_KEY = 'medtrace:compliance:live_backup_latest';

export interface LiveSuiteBackupSnapshot {
  backedUpAt: string;
  backedUpBy: string;
  authMethod: AuditAuthMethod;
  previousVersion: number;
  previousAuditHeadHash?: string;
  previousTraceLinkCount: number;
  truncated: boolean;
  summary: ComplianceSummary;
}

/**
 * Optional caller-context override for Jira issue binding.
 */
export interface BindIssueOptions {
  callerMode?: 'USER' | 'APP';
  linkId?: string;
}

/**
 * Parameters for recording a verification test execution result.
 */
export interface RecordTestResultParams {
  hazardKey?: string;
  testKey?: string;
  linkId?: string;
  status: VerificationTest['status'];
  evidenceUrl?: string;
  executionDate?: string;
  notes?: string;
  actorAccountId: string;
  authMethod?: AuditAuthMethod;
}

/**
 * Parameters for executing a 21 CFR Part 11 electronic signature sign-off.
 */
export interface SignOffPart11Params {
  hazardKey: string;
  specId?: string;
  workKey?: string;
  linkId?: string;
  attestation: Part11Attestation;
  actorAccountId: string;
  authMethod?: AuditAuthMethod;
  extensionType?: string;
  projectKey?: string;
  spaceKey?: string;
}

/**
 * Parameters for demo-only remediation of a Class C gap.
 */
export interface RemediateGapOptions {
  simulate?: boolean;
  attestationConfirmed?: boolean;
  meaning?: string;
  authMethod?: AuditAuthMethod;
}

/**
 * Parameters for invalidating persisted Part 11 baselines after a spec modification.
 */
export interface InvalidateSignedSpecBaselineInput {
  hazardKey?: string;
  specId: string;
  pageId?: string;
  newHash: string;
  reason?: string;
  invalidatedAt?: string;
}

/**
 * Baseline write or invalidation action paired with an atomic suite commit.
 */
export interface BaselineMutationRecord {
  action: 'SET' | 'INVALIDATE';
  baseline?: SignedSpecBaseline;
  invalidation?: InvalidateSignedSpecBaselineInput;
}

/**
 * Input contract for atomic save-before-audit suite commits with compensating rollback.
 */
export interface CommitSuiteMutationParams {
  summary: ComplianceSummary;
  expectedVersion: number;
  auditEntry: AuditAppendInput;
  baselineUpdates?: BaselineMutationRecord[];
}

export interface GetSuiteOptions {
  issueKeyFilter?: string;
  projectKey?: string;
}

export interface CreateReverificationTaskParams {
  hazardKey?: string;
  linkId?: string;
  issueKey?: string;
  summary?: string;
  reason?: string;
  force?: boolean;
  actorAccountId: string;
  callerMode?: 'USER' | 'APP';
  authMethod?: AuditAuthMethod;
}

export interface CreateReverificationTaskResult {
  success: boolean;
  partialSuccess?: boolean;
  fullyLinked?: boolean;
  linksVerified?: boolean;
  createdIssueKey: string;
  linkedIssueKeys: string[];
  failedLinkKeys?: string[];
  linkErrors?: Array<{ issueKey: string; error: string }>;
  missingLinkKeys?: string[];
  projectKey: string;
  alreadyExisted?: boolean;
  summary: ComplianceSummary;
}

const JIRA_ISSUE_KEY_PATTERN = /^[A-Z][A-Z0-9_]{0,20}-\d+$/;

function extractProjectKeyFromTraceLink(link: TraceLink): string | undefined {
  const workKey = link.work?.key?.trim().toUpperCase();
  if (workKey && JIRA_ISSUE_KEY_PATTERN.test(workKey)) {
    return workKey.split('-')[0];
  }
  const hazDerived = link.hazard?.key?.trim().toUpperCase().replace(/^HAZ-/i, '');
  if (hazDerived && JIRA_ISSUE_KEY_PATTERN.test(hazDerived)) {
    return hazDerived.split('-')[0];
  }
  const testDerived = link.test?.testKey?.trim().toUpperCase().replace(/^TEST-/i, '');
  if (testDerived && JIRA_ISSUE_KEY_PATTERN.test(testDerived)) {
    return testDerived.split('-')[0];
  }
  return undefined;
}

/**
 * Manages MedTrace compliance suite persistence, 21 CFR Part 11 sign-off workflows,
 * verification test recording, Jira issue binding, and demo fixtures.
 */
export class SeederService {
  private static inMemorySuite: ComplianceSummary | null = null;
  private static inMemoryVersion = 0;
  private static inMemorySignedSpecs = new Map<string, SignedSpecBaseline>();
  private static inMemoryLiveBackup: LiveSuiteBackupSnapshot | null = null;
  private static lastKvsShardState: {
    version: number;
    entriesByLogicalId: Map<string, { key: string; contentHash: string }>;
  } | null = null;

  /**
   * Resets volatile in-memory suite and baseline caches (used by local unit tests).
   */
  static resetInMemoryState(): void {
    this.inMemorySuite = null;
    this.inMemoryVersion = 0;
    this.inMemorySignedSpecs.clear();
    this.inMemoryLiveBackup = null;
    this.lastKvsShardState = null;
  }

  /**
   * Returns the latest pre-overwrite LIVE suite backup snapshot if one was recorded.
   */
  static async getLastLiveBackup(): Promise<LiveSuiteBackupSnapshot | null> {
    if (!isForgeRuntime()) {
      return this.inMemoryLiveBackup ? cloneJsonValue(this.inMemoryLiveBackup) : null;
    }
    const stored = await kvs.get<LiveSuiteBackupSnapshot>(LIVE_BACKUP_KEY);
    return stored ?? null;
  }

  private static computeTraceLinkHash(link: TraceLink): string {
    return sha256Hex(canonicalJsonStringify(link));
  }

  private static buildLogicalLinkId(link: TraceLink): string {
    return link.id || ComplianceEngine.buildTraceLinkId(link.hazard.key, link.spec.id, link.work?.key);
  }

  private static recordKvsShardState(
    version: number,
    entries: Array<{ key: string; value: TraceLink }>
  ): void {
    const entriesByLogicalId = new Map<string, { key: string; contentHash: string }>();
    for (const { key, value } of entries) {
      entriesByLogicalId.set(this.buildLogicalLinkId(value), {
        key,
        contentHash: this.computeTraceLinkHash(value),
      });
    }
    this.lastKvsShardState = { version, entriesByLogicalId };
  }

  /**
   * Preflight check to determine if Confluence Cloud is installed and accessible.
   */
  static async checkConfluenceAvailable(): Promise<boolean> {
    if (!isForgeRuntime()) return false;
    try {
      const resp = await api.asApp().requestConfluence(route`/wiki/api/v2/spaces?limit=1`);
      return resp.status === 200;
    } catch {
      return false;
    }
  }

  /**
   * Constructs a fail-closed empty LIVE suite descriptor with zero KVS writes and zero audit log entries.
   */
  static async getUninitializedLiveSuite(): Promise<ComplianceSummary> {
    const auditHead = await AuditLogService.getHead();
    return ComplianceEngine.generateComplianceReport([], 'LIVE', 'MedTrace Uninitialized Workspace', {
      storageFormat: 'SHARDED_V2',
      auditEntryCount: auditHead.lastSeq,
      auditHeadHash: auditHead.headHash,
      initialized: false,
    });
  }

  private static async readBaselineEntry(shortKey: string): Promise<SignedSpecBaseline | undefined> {
    if (!isForgeRuntime()) {
      const val = this.inMemorySignedSpecs.get(shortKey);
      return val ? cloneJsonValue(val) : undefined;
    }
    return await kvs.get<SignedSpecBaseline>(buildSafeKvsKey(SIGNED_SPEC_PREFIX, shortKey));
  }

  private static async writeBaselineEntry(shortKey: string, baseline: SignedSpecBaseline): Promise<void> {
    if (!isForgeRuntime()) {
      this.inMemorySignedSpecs.set(shortKey, cloneJsonValue(baseline));
      return;
    }
    await kvs.set(buildSafeKvsKey(SIGNED_SPEC_PREFIX, shortKey), baseline);
  }

  private static async deleteBaselineEntry(shortKey: string): Promise<void> {
    if (!isForgeRuntime()) {
      this.inMemorySignedSpecs.delete(shortKey);
      return;
    }
    await kvs.delete(buildSafeKvsKey(SIGNED_SPEC_PREFIX, shortKey));
  }

  /**
   * Retrieves a persisted Part 11 spec baseline. When `hazardKey` is supplied, reads strictly
   * from composite `(hazardKey, specOrPageId)` storage so unrelated hazards stay isolated.
   */
  static async getSignedSpecBaseline(specOrPageId: string, hazardKey?: string): Promise<SignedSpecBaseline | undefined> {
    const cleanId = (specOrPageId || '').trim();
    if (!cleanId) return undefined;

    const cleanHaz = hazardKey?.trim();
    if (cleanHaz) {
      const compKey = sanitizeKvsKeySegment(`${cleanHaz}--${cleanId}`, 180);
      return await this.readBaselineEntry(compKey);
    }

    const unscopedKey = sanitizeKvsKeySegment(cleanId, 180);
    return await this.readBaselineEntry(unscopedKey);
  }

  /**
   * Persists a Part 11 signed spec baseline under composite `(hazardKey, specId)` keys when
   * `hazardKey` is present, plus legacy unscoped keys when unscoped or unowned.
   */
  static async setSignedSpecBaseline(baseline: SignedSpecBaseline): Promise<void> {
    const { compositeKeys, unscopedKeys } = getBaselineKeyCandidates(
      baseline.specId,
      baseline.pageId,
      baseline.hazardKey
    );

    if (compositeKeys.length > 0) {
      for (const key of compositeKeys) {
        await this.writeBaselineEntry(key, baseline);
      }
      for (const key of unscopedKeys) {
        const existing = await this.readBaselineEntry(key);
        if (!existing || !existing.hazardKey || existing.hazardKey === baseline.hazardKey) {
          await this.writeBaselineEntry(key, baseline);
        }
      }
      return;
    }

    for (const key of unscopedKeys) {
      await this.writeBaselineEntry(key, baseline);
    }
  }

  /**
   * Marks matching persisted `SignedSpecBaseline` record(s) as invalidated with `invalidatedAt`
   * and `invalidatedByHash` while leaving unrelated hazards' baselines untouched.
   */
  static async invalidateSignedSpecBaselines(input: InvalidateSignedSpecBaselineInput): Promise<void> {
    const at = input.invalidatedAt || new Date().toISOString();
    const { compositeKeys, unscopedKeys } = getBaselineKeyCandidates(input.specId, input.pageId, input.hazardKey);

    const updateIfMatches = async (shortKey: string, requireMatchingHazard: boolean): Promise<void> => {
      const existing = await this.readBaselineEntry(shortKey);
      if (!existing) return;
      if (requireMatchingHazard && input.hazardKey && existing.hazardKey && existing.hazardKey !== input.hazardKey) {
        return;
      }
      const updated: SignedSpecBaseline = {
        ...existing,
        invalidatedAt: at,
        invalidatedByHash: input.newHash,
        invalidationReason: input.reason ?? existing.invalidationReason,
      };
      await this.writeBaselineEntry(shortKey, updated);
    };

    if (compositeKeys.length > 0) {
      for (const key of compositeKeys) {
        await updateIfMatches(key, false);
      }
      for (const key of unscopedKeys) {
        await updateIfMatches(key, true);
      }
      return;
    }

    // Spec-wide invalidation when hazardKey was omitted: update composite baselines of linked hazards + unscoped
    const { summary } = await this.getSuiteWithVersion();
    const linkedHazards = new Set<string>();
    for (const link of summary.traceLinks) {
      if (link.spec.id === input.specId || (input.pageId && link.spec.pageId === input.pageId)) {
        linkedHazards.add(link.hazard.key);
      }
    }
    for (const haz of linkedHazards) {
      const candidates = getBaselineKeyCandidates(input.specId, input.pageId, haz);
      for (const key of candidates.compositeKeys) {
        await updateIfMatches(key, false);
      }
    }
    for (const key of unscopedKeys) {
      await updateIfMatches(key, false);
    }
  }

  private static computeAffectedBaselineKeys(updates: BaselineMutationRecord[]): string[] {
    const keys = new Set<string>();
    for (const update of updates) {
      const target = update.action === 'SET' ? update.baseline : update.invalidation;
      if (!target) continue;
      const candidates = getBaselineKeyCandidates(target.specId, target.pageId, target.hazardKey);
      for (const k of candidates.compositeKeys) keys.add(k);
      for (const k of candidates.unscopedKeys) keys.add(k);
    }
    return Array.from(keys);
  }

  /**
   * Persists the compliance suite sharded across Forge KVS using `vlock` optimistic locking,
   * single-transaction commits when `<= 25` ops, and versioned chunked staging + metadata sharding + GC above 25 ops.
   */
  static async saveComplianceSuite(
    summary: ComplianceSummary,
    expectedVersion?: number
  ): Promise<ComplianceSummary> {
    const auditHead = await AuditLogService.getHead();
    const initialized = summary.initialized ?? (summary.traceLinks.length > 0 || summary.datasetMode === 'DEMO');
    const enrichedSummary: ComplianceSummary = {
      ...summary,
      datasetMode: summary.datasetMode ?? 'LIVE',
      initialized,
      storageFormat: 'SHARDED_V2',
      auditEntryCount: auditHead.lastSeq,
      auditHeadHash: auditHead.headHash,
    };

    if (!isForgeRuntime()) {
      if (typeof expectedVersion === 'number' && this.inMemoryVersion !== expectedVersion) {
        throw new Error(
          `Concurrent modification detected on compliance suite (expected version ${expectedVersion}, found ${this.inMemoryVersion}). Please retry.`
        );
      }
      this.inMemoryVersion += 1;
      this.inMemorySuite = cloneJsonValue(enrichedSummary);
      return cloneJsonValue(enrichedSummary);
    }

    const existingMeta = await kvs.get<ShardedSuiteMetaV2>(SUITE_META_KEY);
    const currentVersion = existingMeta?.version ?? 0;
    if (typeof expectedVersion === 'number' && currentVersion !== expectedVersion) {
      throw new Error(
        `Concurrent modification detected on compliance suite (expected version ${expectedVersion}, found ${currentVersion}). Please retry.`
      );
    }

    const nextVersion = currentVersion + 1;
    const vlockKey = buildSafeKvsKey(VLOCK_PREFIX, String(nextVersion));
    try {
      await kvs.set(
        vlockKey,
        { claimedAt: Date.now(), expectedVersion: currentVersion, nextVersion },
        { keyPolicy: 'FAIL_IF_EXISTS', ttl: { value: 1, unit: 'MINUTES' } }
      );
    } catch (err) {
      if (isKvsConflictError(err)) {
        throw new Error(
          `Concurrent modification detected: version lock conflict on ${vlockKey} (version ${nextVersion}). Please retry.`
        );
      }
      throw err;
    }

    let committed = false;
    try {
      const recheckedMeta = await kvs.get<ShardedSuiteMetaV2>(SUITE_META_KEY);
      const recheckedVersion = recheckedMeta?.version ?? 0;
      if (recheckedVersion !== currentVersion) {
        throw new Error(
          `Concurrent modification detected after vlock acquisition (expected version ${currentVersion}, found ${recheckedVersion}). Please retry.`
        );
      }

      const previousKeys = new Set<string>(recheckedMeta?.linkKeys || []);
      for (const k of recheckedMeta?.blockingReasonShardKeys || []) previousKeys.add(k);
      for (const k of recheckedMeta?.linkKeyShardKeys || []) previousKeys.add(k);
      for (const k of recheckedMeta?.issueKeyIndexShardKeys || []) previousKeys.add(k);
      if (recheckedMeta?.linkKeyShardKeys && recheckedMeta.linkKeyShardKeys.length > 0) {
        const oldLinkShards = await batchGetStrict<string[]>(recheckedMeta.linkKeyShardKeys);
        for (const shardArr of oldLinkShards.values()) {
          for (const k of shardArr) previousKeys.add(k);
        }
      }

      const unversionedLinkItems = enrichedSummary.traceLinks.map((link) => ({
        key: buildSafeKvsKey(
          LINK_KEY_PREFIX,
          link.id || ComplianceEngine.buildTraceLinkId(link.hazard.key, link.spec.id, link.work?.key)
        ),
        value: link,
      }));
      const { meta: smallMeta, metaShardItems: smallMetaShards } = buildMetaAndShardItems(
        enrichedSummary,
        unversionedLinkItems.map((i) => i.key),
        nextVersion
      );
      const smallNewKeySet = new Set<string>([
        ...unversionedLinkItems.map((i) => i.key),
        ...smallMetaShards.map((i) => i.key),
      ]);
      const smallObsoleteKeys = Array.from(previousKeys).filter((k) => !smallNewKeySet.has(k));
      const smallTotalOps =
        unversionedLinkItems.length + smallMetaShards.length + 1 + smallObsoleteKeys.length;
      const smallPayloadBytes =
        measureJsonBytes(unversionedLinkItems) +
        measureJsonBytes(smallMetaShards) +
        measureJsonBytes(smallMeta);

      if (smallTotalOps <= BATCH_CHUNK_SIZE && smallPayloadBytes <= MAX_TRANSACT_BYTES) {
        const tx = kvs.transact();
        for (const item of unversionedLinkItems) tx.set(item.key, item.value);
        for (const item of smallMetaShards) tx.set(item.key, item.value);
        tx.set(SUITE_META_KEY, smallMeta);
        for (const oldKey of smallObsoleteKeys) tx.delete(oldKey);
        await tx.execute();
        committed = true;
        this.recordKvsShardState(nextVersion, unversionedLinkItems);
        return cloneJsonValue(enrichedSummary);
      }

      const canReusePriorShards =
        this.lastKvsShardState !== null &&
        currentVersion > 0 &&
        this.lastKvsShardState.version === currentVersion;

      const versionedLinkKeys: string[] = [];
      const versionedLinkItemsToWrite: Array<{ key: string; value: TraceLink }> = [];
      const allVersionedLinkEntries: Array<{ key: string; value: TraceLink }> = [];

      for (const link of enrichedSummary.traceLinks) {
        const logicalId = this.buildLogicalLinkId(link);
        const contentHash = this.computeTraceLinkHash(link);
        const prior = canReusePriorShards
          ? this.lastKvsShardState!.entriesByLogicalId.get(logicalId)
          : undefined;
        if (
          prior &&
          prior.contentHash === contentHash &&
          prior.key.startsWith(`${LINK_KEY_PREFIX}v`) &&
          previousKeys.has(prior.key)
        ) {
          versionedLinkKeys.push(prior.key);
          allVersionedLinkEntries.push({ key: prior.key, value: link });
          continue;
        }

        const key = buildSafeKvsKey(`${LINK_KEY_PREFIX}v${nextVersion}:`, logicalId);
        versionedLinkKeys.push(key);
        versionedLinkItemsToWrite.push({ key, value: link });
        allVersionedLinkEntries.push({ key, value: link });
      }

      const { meta, metaShardItems } = buildMetaAndShardItems(
        enrichedSummary,
        versionedLinkKeys,
        nextVersion
      );

      let stagedKeys: string[] = [];
      try {
        stagedKeys = await batchSetStrict([...versionedLinkItemsToWrite, ...metaShardItems]);
        await kvs.set(SUITE_META_KEY, meta);
        committed = true;
      } catch (stageErr) {
        if (!committed && stagedKeys.length > 0) {
          try {
            await batchDeleteBestEffort(stagedKeys);
          } catch {
            // Preserve primary staging error
          }
        }
        throw stageErr;
      }

      const newKeySet = new Set<string>([
        ...versionedLinkKeys,
        ...metaShardItems.map((i) => i.key),
      ]);
      const obsoleteKeys = Array.from(previousKeys).filter((k) => !newKeySet.has(k));
      await batchDeleteBestEffort(obsoleteKeys);
      this.recordKvsShardState(nextVersion, allVersionedLinkEntries);
      return cloneJsonValue(enrichedSummary);
    } finally {
      if (!committed) {
        try {
          await kvs.delete(vlockKey);
        } catch {
          // Best-effort lock release on aborted write
        }
      }
    }
  }

  private static async loadShardedSuiteFromKvs(): Promise<{ summary: ComplianceSummary; version: number } | undefined> {
    const meta = await kvs.get<ShardedSuiteMetaV2>(SUITE_META_KEY);
    if (!meta || (!Array.isArray(meta.linkKeys) && !Array.isArray(meta.linkKeyShardKeys))) {
      return undefined;
    }

    let blockingReasons = Array.isArray(meta.blockingReasons) ? [...meta.blockingReasons] : [];
    if (meta.blockingReasonShardKeys && meta.blockingReasonShardKeys.length > 0) {
      const reasonShards = await batchGetStrict<string[]>(meta.blockingReasonShardKeys);
      blockingReasons = [];
      for (const key of meta.blockingReasonShardKeys) {
        blockingReasons.push(...(reasonShards.get(key) || []));
      }
    }

    let resolvedLinkKeys = Array.isArray(meta.linkKeys) ? [...meta.linkKeys] : [];
    if (meta.linkKeyShardKeys && meta.linkKeyShardKeys.length > 0) {
      const linkKeyShards = await batchGetStrict<string[]>(meta.linkKeyShardKeys);
      resolvedLinkKeys = [];
      for (const key of meta.linkKeyShardKeys) {
        resolvedLinkKeys.push(...(linkKeyShards.get(key) || []));
      }
    }

    const linkMap = await batchGetStrict<TraceLink>(resolvedLinkKeys);
    const traceLinks = resolvedLinkKeys.map((key) => linkMap.get(key)!);
    const auditHead = await AuditLogService.getHead();
    this.recordKvsShardState(
      meta.version ?? 0,
      resolvedLinkKeys.map((key) => ({ key, value: linkMap.get(key)! }))
    );

    return {
      version: meta.version ?? 0,
      summary: {
        projectName: meta.projectName,
        datasetMode: meta.datasetMode ?? 'LIVE',
        initialized: meta.initialized ?? (traceLinks.length > 0 || meta.datasetMode === 'DEMO'),
        standards: meta.standards,
        totalHazards: meta.totalHazards,
        classCCount: meta.classCCount,
        classBCount: meta.classBCount,
        classACount: meta.classACount,
        verifiedPercentage: meta.verifiedPercentage,
        releaseBlocked: meta.releaseBlocked,
        blockingReasons,
        signatureDriftCount: meta.signatureDriftCount,
        traceLinks,
        lastAuditTimestamp: meta.lastAuditTimestamp,
        ...(meta.lastSyncedAt ? { lastSyncedAt: meta.lastSyncedAt } : {}),
        ...(meta.syncIncomplete === true ? { syncIncomplete: true } : {}),
        storageFormat: 'SHARDED_V2',
        auditEntryCount: auditHead.lastSeq,
        auditHeadHash: auditHead.headHash,
      },
    };
  }

  /**
   * Executes save-before-audit suite persistence with pre-flight audit size validation and
   * compensating rollback of both the suite version and affected `SignedSpecBaseline` entries.
   */
  static async commitSuiteMutation(params: CommitSuiteMutationParams): Promise<ComplianceSummary> {
    if (measureJsonBytes(params.auditEntry.details) > MAX_AUDIT_DETAILS_BYTES) {
      throw new Error(
        `Audit entry details exceed ${MAX_AUDIT_DETAILS_BYTES} byte limit; aborting suite mutation before KVS write.`
      );
    }

    const previousState = await this.getSuiteWithVersion();
    const previousSuiteSnapshot = cloneJsonValue(previousState.summary);
    const baselineSnapshots = new Map<string, SignedSpecBaseline | undefined>();
    const baselineKeys = this.computeAffectedBaselineKeys(params.baselineUpdates || []);

    for (const shortKey of baselineKeys) {
      baselineSnapshots.set(shortKey, await this.readBaselineEntry(shortKey));
    }

    let suiteSaved = false;
    let baselinesTouched = false;
    try {
      const savedSuite = await this.saveComplianceSuite(params.summary, params.expectedVersion);
      suiteSaved = true;

      if (params.baselineUpdates && params.baselineUpdates.length > 0) {
        baselinesTouched = true;
        for (const update of params.baselineUpdates) {
          if (update.action === 'SET' && update.baseline) {
            await this.setSignedSpecBaseline(update.baseline);
          } else if (update.action === 'INVALIDATE' && update.invalidation) {
            await this.invalidateSignedSpecBaselines(update.invalidation);
          }
        }
      }

      const appendedAudit = await AuditLogService.append(params.auditEntry);
      const finalSummary: ComplianceSummary = {
        ...savedSuite,
        auditEntryCount: appendedAudit.seq,
        auditHeadHash: appendedAudit.entryHash,
      };
      if (!isForgeRuntime()) {
        this.inMemorySuite = cloneJsonValue(finalSummary);
      }
      return finalSummary;
    } catch (err) {
      if (baselinesTouched) {
        for (const [shortKey, snapshot] of baselineSnapshots.entries()) {
          try {
            if (snapshot === undefined) {
              await this.deleteBaselineEntry(shortKey);
            } else {
              await this.writeBaselineEntry(shortKey, snapshot);
            }
          } catch {
            // Continue restoring remaining baselines
          }
        }
      }
      if (suiteSaved) {
        const rollbackExpectedVersion = params.expectedVersion + 1;
        await this.saveComplianceSuite(previousSuiteSnapshot, rollbackExpectedVersion);
      }
      throw err;
    }
  }

  /**
   * 1-Click Demo Dataset Seeder (explicitly labeled DEMO mode; refuses to overwrite an initialized LIVE suite
   * unless both `options.confirmOverwriteLive === true` and `options.authorizedSiteAdmin === true` are supplied,
   * and writes an auditable pre-overwrite recovery backup before replacing LIVE state).
   */
  static async seedEnterpriseDemoSuite(
    actorAccountId = 'system:demo-seeder',
    authMethod: AuditAuthMethod = 'SYSTEM_INIT',
    options?: SeedDemoOptions
  ): Promise<SeedDemoResponse> {
    const existing = await this.getSuiteWithVersion();
    const isInitializedLive =
      existing.summary.datasetMode === 'LIVE' && existing.summary.initialized;
    if (isInitializedLive) {
      if (!options?.confirmOverwriteLive) {
        throw new Error(
          'Refusing to overwrite initialized LIVE compliance suite with DEMO data without explicit confirmOverwriteLive: true.'
        );
      }
      if (!options?.authorizedSiteAdmin) {
        throw new Error(
          'Forbidden: Overwriting an initialized LIVE compliance suite requires Jira site administrator (ADMINISTER) authorization.'
        );
      }

      const fullBackup: LiveSuiteBackupSnapshot = {
        backedUpAt: new Date().toISOString(),
        backedUpBy: actorAccountId,
        authMethod,
        previousVersion: existing.version ?? 0,
        previousAuditHeadHash: existing.summary.auditHeadHash,
        previousTraceLinkCount: existing.summary.traceLinks.length,
        truncated: false,
        summary: cloneJsonValue(existing.summary),
      };
      let backupToPersist = fullBackup;
      if (measureJsonBytes(fullBackup) > MAX_AUDIT_DETAILS_BYTES) {
        backupToPersist = {
          ...fullBackup,
          truncated: true,
          summary: {
            ...cloneJsonValue(existing.summary),
            traceLinks: [],
          },
        };
      }
      if (!isForgeRuntime()) {
        this.inMemoryLiveBackup = backupToPersist;
      } else {
        await kvs.set(LIVE_BACKUP_KEY, backupToPersist);
      }
    }

    const confluenceEnabled = await this.checkConfluenceAvailable();
    console.log(`[MedTrace Seeder] Seeding DEMO suite (Confluence available: ${confluenceEnabled})`);

    const hazards: IsoHazard[] = [
      {
        id: 'haz-101',
        key: 'HAZ-101',
        title: 'Over-Infusion Hazard: Bolus delivery exceeds 5.0 mL/hr clinical safety threshold',
        riskClass: 'CLASS_C',
        severity: 'CATASTROPHIC',
        probability: 'OCCASIONAL',
        mitigationRequirementId: 'srs-104',
        status: 'UNVERIFIED_RISK',
      },
      {
        id: 'haz-102',
        key: 'HAZ-102',
        title: 'Under-Infusion Hazard: Unintended pump stall leading to severe hypoglycemia',
        riskClass: 'CLASS_B',
        severity: 'CRITICAL',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-105',
        status: 'MITIGATED',
      },
      {
        id: 'haz-103',
        key: 'HAZ-103',
        title: 'Display Transient Glitch: OLED backlight flicker during emergency battery cutover',
        riskClass: 'CLASS_A',
        severity: 'MINOR',
        probability: 'OCCASIONAL',
        mitigationRequirementId: 'srs-106',
        status: 'MITIGATED',
      },
    ];

    const srs104ApprovedSnippet =
      'Clause 4.2.1: Bolus delivery rate must be hardware-clamped by MCU2 with 10ms watchdog timeout at max 5.0 mL/hr.';
    const srs104CurrentSnippet =
      'Clause 4.2.1: Bolus delivery rate must be hardware-clamped by MCU2 with 10ms watchdog timeout at max 5.5 mL/hr.';
    const srs105Snippet = 'Clause 4.3.5: Dual IR photodiodes calculate basal drop count every 250 milliseconds.';
    const srs106Snippet =
      'Clause 6.1.2: Buck converter must maintain 3.3V bus within +/- 2% during primary cell cutover.';

    const srs104ApprovedHash = sha256Hex(srs104ApprovedSnippet);
    const srs104CurrentHash = sha256Hex(srs104CurrentSnippet);
    const srs105Hash = sha256Hex(srs105Snippet);
    const srs106Hash = sha256Hex(srs106Snippet);

    const specs: ConfluenceSpec[] = [
      {
        id: 'srs-104',
        title: 'SRS-104: Dual-Core Microcontroller Hardware Bolus Clamp (Max 5.0 mL/hr)',
        version: 3,
        sha256Hash: srs104CurrentHash,
        lastSignedHash: srs104ApprovedHash,
        isSignatureInvalidated: true,
        contentSnippet: srs104CurrentSnippet,
        lastUpdated: '10 minutes ago (Modified by engineer: changed threshold 5.0 -> 5.5 mL/hr)',
      },
      {
        id: 'srs-105',
        title: 'SRS-105: Optical Droplet Sensor Real-Time Flow Rate Verification',
        version: 2,
        sha256Hash: srs105Hash,
        lastSignedHash: srs105Hash,
        isSignatureInvalidated: false,
        contentSnippet: srs105Snippet,
        lastUpdated: '2 days ago',
      },
      {
        id: 'srs-106',
        title: 'SRS-106: Power Management Rail Glitch Filter & OLED Retention',
        version: 1,
        sha256Hash: srs106Hash,
        lastSignedHash: srs106Hash,
        isSignatureInvalidated: false,
        contentSnippet: srs106Snippet,
        lastUpdated: '1 week ago',
      },
    ];

    const workItems: JiraWorkItem[] = [
      {
        id: 'med-42',
        key: 'MED-42',
        title: 'Implement Dual-Core Hardware PWM Clamp on Infusion Motor',
        status: 'In Progress',
        assignee: 'Dr. Sarah Lin (Lead Firmware)',
        prNumber: '#142',
        commitSha: '7f9a12c',
      },
      {
        id: 'med-43',
        key: 'MED-43',
        title: 'Integrate Optical Droplet Sensor Interrupt Routine',
        status: 'Done',
        assignee: 'David Chen (Embedded Systems)',
        prNumber: '#139',
        commitSha: '3a4b981',
      },
      {
        id: 'med-44',
        key: 'MED-44',
        title: 'Calibrate OLED SPI Bus Low-Power Sleep Transitions',
        status: 'Done',
        assignee: 'Elena Rostova (Hardware QA)',
        prNumber: '#135',
        commitSha: '5c2e811',
      },
    ];

    const tests: VerificationTest[] = [
      {
        id: 'test-88',
        testKey: 'TEST-88',
        title: 'Hardware-in-the-Loop Occlusion & Over-Infusion Motor Stress Test',
        testType: 'Automated HIL (Hardware-in-Loop)',
        status: 'UNTESTED',
        executionDate: 'Pending HIL Bench Run',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/hil-88',
      },
      {
        id: 'test-89',
        testKey: 'TEST-89',
        title: 'Closed-Loop Droplet Pulse Waveform Verification',
        testType: 'Integration Test',
        status: 'PASSED',
        executionDate: 'Yesterday 14:22 UTC (48/48 Assertions Passed)',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/droplet-89',
      },
      {
        id: 'test-90',
        testKey: 'TEST-90',
        title: 'Power Rail Cutover Voltage Sag Automated Benchmark',
        testType: 'Unit Test',
        status: 'PASSED',
        executionDate: '3 days ago 09:10 UTC',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/power-90',
      },
    ];

    const signatures: Part11Signature[] = [
      {
        id: 'sig-001',
        signedBy: 'Marcus Vance, MD (Chief Medical Officer)',
        signedAt: '2026-10-15T11:30:00Z',
        role: 'Clinical Safety Authority',
        meaning: 'Approval of ISO 14971 Risk Assessment & Mitigation Architecture',
        artifactSha256: srs104ApprovedHash,
        isValid: false,
        invalidationReason:
          'AUTOMATIC REVOCATION: Confluence spec modified at version 3 without clinical re-signature.',
      },
      {
        id: 'sig-002',
        signedBy: 'Rachel Adams (Director of Regulatory Affairs)',
        signedAt: '2026-10-20T16:45:00Z',
        role: 'Quality Assurance Director',
        meaning: 'IEC 62304 Software Verification Plan Approval',
        artifactSha256: srs105Hash,
        isValid: true,
      },
      {
        id: 'sig-003',
        signedBy: 'Rachel Adams (Director of Regulatory Affairs)',
        signedAt: '2026-10-21T09:15:00Z',
        role: 'Quality Assurance Director',
        meaning: 'Class A Software Verification Protocol Approval',
        artifactSha256: srs106Hash,
        isValid: true,
      },
    ];

    const graphMetadatas: NonNullable<TraceLink['graphMetadata']>[] = [
      {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10042',
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-101',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98304',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'MODELED (demo lineage)',
      },
      {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10043',
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-102',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98305',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'MODELED (demo lineage)',
      },
      {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10044',
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-103',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98306',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'MODELED (demo lineage)',
      },
    ];

    const traceLinks = hazards.map((hazard, index) =>
      ComplianceEngine.evaluateTraceLink(
        hazard,
        specs[index],
        workItems[index],
        tests[index],
        signatures[index],
        graphMetadatas[index]
      )
    );

    const summary = ComplianceEngine.generateComplianceReport(
      traceLinks,
      'DEMO',
      'Smart Infusion Pump Firmware v2.1',
      { initialized: true }
    );

    const committed = await this.commitSuiteMutation({
      summary,
      expectedVersion: existing.version,
      auditEntry: {
        actorAccountId,
        action: 'SEED_DEMO',
        targetKey: 'DEMO_SUITE',
        details: {
          hazardCount: traceLinks.length,
          confluenceEnabled,
          ...(isInitializedLive
            ? {
                overwroteInitializedLive: true,
                previousMode: 'LIVE',
                previousTraceLinkCount: existing.summary.traceLinks.length,
                previousAuditHeadHash: existing.summary.auditHeadHash ?? null,
                liveBackupKey: LIVE_BACKUP_KEY,
              }
            : {}),
        },
        authMethod,
      },
    });

    return {
      success: true,
      confluenceEnabled,
      summary: committed,
      message:
        'Successfully seeded simulated IEC 62304 Smart Infusion Pump Firmware DEMO dataset (3 Hazards, 3 SRS Specs, 3 Work Items, 3 Tests, 3 Signatures).',
    };
  }

  /**
   * Retrieves the active compliance suite from sharded Forge KVS (migrating `SINGLE_KEY_V1` on demand),
   * or returns a read-only uninitialized LIVE suite on cold start without creating KVS entries or audit logs.
   */
  private static applyProjectKeyFilter(
    suite: ComplianceSummary,
    projectKey?: string
  ): ComplianceSummary {
    const cleanProject = projectKey?.trim().toUpperCase();
    if (
      !cleanProject ||
      suite.initialized === false ||
      suite.datasetMode === 'DEMO' ||
      suite.traceLinks.length === 0
    ) {
      return suite;
    }

    const prefix = `${cleanProject}-`;
    const filteredLinks = suite.traceLinks.filter(
      (link) =>
        (link.work?.key || '').trim().toUpperCase().startsWith(prefix) ||
        (link.hazard?.key || '').trim().toUpperCase().startsWith(prefix)
    );
    if (filteredLinks.length === suite.traceLinks.length) {
      return suite;
    }

    return ComplianceEngine.generateComplianceReport(
      filteredLinks,
      suite.datasetMode ?? 'LIVE',
      `${cleanProject} (${suite.projectName})`,
      {
        storageFormat: suite.storageFormat,
        auditEntryCount: suite.auditEntryCount,
        auditHeadHash: suite.auditHeadHash,
        initialized: true,
        lastSyncedAt: suite.lastSyncedAt,
        syncIncomplete: suite.syncIncomplete,
      }
    );
  }

  private static async loadFastPathSuiteByIssueKey(
    issueKeyFilter: string
  ): Promise<ComplianceSummary | undefined> {
    const cleanKey = issueKeyFilter.trim().toUpperCase();
    if (!cleanKey) {
      return undefined;
    }

    if (!isForgeRuntime()) {
      if (!this.inMemorySuite) {
        return await this.getUninitializedLiveSuite();
      }
      const head = await AuditLogService.getHead();
      const filteredLinks = this.inMemorySuite.traceLinks.filter(
        (link) =>
          (link.work?.key || '').trim().toUpperCase() === cleanKey ||
          (link.hazard?.key || '').trim().toUpperCase() === cleanKey
      );
      return cloneJsonValue({
        ...this.inMemorySuite,
        traceLinks: filteredLinks,
        auditEntryCount: head.lastSeq,
        auditHeadHash: head.headHash,
      });
    }

    const meta = await kvs.get<ShardedSuiteMetaV2>(SUITE_META_KEY);
    if (!meta) {
      return undefined;
    }
    if (meta.initialized === false) {
      return await this.getUninitializedLiveSuite();
    }
    let matchedKeys: string[];
    if (meta.issueKeyIndex) {
      matchedKeys = meta.issueKeyIndex[cleanKey] || [];
    } else if (
      Array.isArray(meta.issueKeyIndexShardKeys) &&
      meta.issueKeyIndexShardKeys.length > 0
    ) {
      const indexShardMap = await batchGetStrict<Record<string, string[]>>(
        meta.issueKeyIndexShardKeys
      );
      const collectedKeys: string[] = [];
      for (const shardObj of indexShardMap.values()) {
        const shardMatches = shardObj?.[cleanKey];
        if (Array.isArray(shardMatches)) {
          for (const k of shardMatches) {
            if (!collectedKeys.includes(k)) {
              collectedKeys.push(k);
            }
          }
        }
      }
      matchedKeys = collectedKeys;
    } else {
      return undefined;
    }

    let traceLinks: TraceLink[] = [];
    if (matchedKeys.length > 0) {
      const linkMap = await batchGetStrict<TraceLink>(matchedKeys);
      traceLinks = matchedKeys.map((key) => linkMap.get(key)!);
    }

    let blockingReasons = Array.isArray(meta.blockingReasons) ? [...meta.blockingReasons] : [];
    if (
      blockingReasons.length === 0 &&
      Array.isArray(meta.blockingReasonShardKeys) &&
      meta.blockingReasonShardKeys.length > 0
    ) {
      const reasonShardMap = await batchGetStrict<string[]>(meta.blockingReasonShardKeys);
      blockingReasons = meta.blockingReasonShardKeys.flatMap((k) => reasonShardMap.get(k) || []);
    }

    const auditHead = await AuditLogService.getHead();

    return {
      projectName: meta.projectName,
      datasetMode: meta.datasetMode ?? 'LIVE',
      initialized: meta.initialized ?? (meta.totalHazards > 0 || meta.datasetMode === 'DEMO'),
      standards: meta.standards,
      totalHazards: meta.totalHazards,
      classCCount: meta.classCCount,
      classBCount: meta.classBCount,
      classACount: meta.classACount,
      verifiedPercentage: meta.verifiedPercentage,
      releaseBlocked: meta.releaseBlocked,
      blockingReasons,
      signatureDriftCount: meta.signatureDriftCount,
      traceLinks,
      lastAuditTimestamp: meta.lastAuditTimestamp,
      ...(meta.lastSyncedAt ? { lastSyncedAt: meta.lastSyncedAt } : {}),
      ...(meta.syncIncomplete === true ? { syncIncomplete: true } : {}),
      storageFormat: 'SHARDED_V2',
      auditEntryCount: auditHead.lastSeq,
      auditHeadHash: auditHead.headHash,
    };
  }

  private static filterSuiteLinksByIssueKey(
    suite: ComplianceSummary,
    issueKeyFilter?: string
  ): ComplianceSummary {
    const cleanKey = issueKeyFilter?.trim().toUpperCase();
    if (!cleanKey || suite.initialized === false) {
      return suite;
    }
    return {
      ...suite,
      traceLinks: suite.traceLinks.filter(
        (link) =>
          (link.work?.key || '').trim().toUpperCase() === cleanKey ||
          (link.hazard?.key || '').trim().toUpperCase() === cleanKey
      ),
    };
  }

  static async getActiveComplianceSuite(options?: GetSuiteOptions): Promise<ComplianceSummary> {
    if (options?.issueKeyFilter && !options?.projectKey) {
      const fastPath = await this.loadFastPathSuiteByIssueKey(options.issueKeyFilter);
      if (fastPath) {
        return fastPath;
      }
    }

    if (!isForgeRuntime()) {
      if (this.inMemorySuite) {
        const head = await AuditLogService.getHead();
        const projectScoped = this.applyProjectKeyFilter(
          cloneJsonValue({
            ...this.inMemorySuite,
            auditEntryCount: head.lastSeq,
            auditHeadHash: head.headHash,
          }),
          options?.projectKey
        );
        return this.filterSuiteLinksByIssueKey(projectScoped, options?.issueKeyFilter);
      }
      return await this.getUninitializedLiveSuite();
    }

    const sharded = await this.loadShardedSuiteFromKvs();
    if (sharded) {
      return this.filterSuiteLinksByIssueKey(
        this.applyProjectKeyFilter(sharded.summary, options?.projectKey),
        options?.issueKeyFilter
      );
    }

    const legacy = await kvs.get<ComplianceSummary>(LEGACY_STORAGE_KEY);
    if (legacy && Array.isArray(legacy.traceLinks) && legacy.traceLinks.length > 0) {
      const migrated = await this.saveComplianceSuite(
        {
          ...legacy,
          datasetMode: legacy.datasetMode ?? 'LIVE',
          initialized: true,
          storageFormat: 'SHARDED_V2',
        },
        0
      );
      await kvs.delete(LEGACY_STORAGE_KEY);
      return this.filterSuiteLinksByIssueKey(
        this.applyProjectKeyFilter(migrated, options?.projectKey),
        options?.issueKeyFilter
      );
    }

    return await this.getUninitializedLiveSuite();
  }

  /**
   * Returns the active compliance suite together with its current optimistic-lock version number.
   */
  static async getSuiteWithVersion(): Promise<{ summary: ComplianceSummary; version: number }> {
    if (!isForgeRuntime()) {
      return {
        summary: await this.getActiveComplianceSuite(),
        version: this.inMemoryVersion,
      };
    }

    const sharded = await this.loadShardedSuiteFromKvs();
    if (sharded) {
      return sharded;
    }
    const active = await this.getActiveComplianceSuite();
    const afterMigration = active.initialized ? await this.loadShardedSuiteFromKvs() : undefined;
    return afterMigration ?? { summary: active, version: 0 };
  }

  /**
   * Binds a Jira issue key into a hazard's trace link work item, clearing stale PR/commit/graph fields.
   * Uses `api.asUser()` by default (`callerMode: 'USER'`) in Forge runtime so user permissions are respected.
   */
  static async bindIssueToHazard(
    hazardKey: string,
    issueKey: string,
    actorAccountId = 'system',
    authMethod: AuditAuthMethod = 'FORGE_USER_SESSION',
    options?: BindIssueOptions
  ): Promise<ComplianceSummary> {
    const cleanIssueKey = (issueKey || '').trim().toUpperCase();
    if (!/^[A-Z][A-Z0-9_]+-\d+$/.test(cleanIssueKey)) {
      throw new Error(`Invalid Jira issue key format: "${issueKey}". Expected format like MED-42.`);
    }

    const { summary: current, version } = await this.getSuiteWithVersion();
    const idx = resolveTraceLinkByHazard(current.traceLinks, hazardKey, undefined, undefined, options?.linkId);
    if (idx < 0) {
      throw new Error(`Hazard ${hazardKey} not found in the active compliance suite.`);
    }

    const targetLink = current.traceLinks[idx];
    const previousIssueKey = targetLink.work.key;

    if (isForgeRuntime()) {
      const callerMode = options?.callerMode === 'APP' ? 'APP' : 'USER';
      const requester = callerMode === 'APP' ? api.asApp() : api.asUser();
      const resp = await requester.requestJira(
        route`/rest/api/3/issue/${cleanIssueKey}?fields=summary,status,assignee`
      );
      if (resp.status !== 200) {
        throw new Error(`Jira issue ${cleanIssueKey} could not be verified (HTTP ${resp.status}).`);
      }
      const issueData = (await resp.json()) as {
        id?: string;
        key?: string;
        fields?: {
          summary?: string;
          status?: { name?: string; statusCategory?: { key?: string; name?: string } };
          assignee?: { displayName?: string } | null;
        };
      };
      targetLink.work.id = String(issueData?.id || cleanIssueKey.toLowerCase());
      targetLink.work.key = String(issueData?.key || cleanIssueKey);
      if (issueData?.fields?.summary) {
        targetLink.work.title = issueData.fields.summary;
      }
      targetLink.work.status = mapJiraStatusToWorkStatus(issueData?.fields?.status);
      targetLink.work.assignee = issueData?.fields?.assignee?.displayName || 'Unassigned';
    } else {
      targetLink.work.key = cleanIssueKey;
      targetLink.work.id = cleanIssueKey.toLowerCase();
    }

    delete targetLink.work.prNumber;
    delete targetLink.work.commitSha;
    targetLink.graphMetadata = undefined;

    const evaluated = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      undefined,
      {
        linkId: targetLink.id,
        part11Secret: process.env.MEDTRACE_PART11_SECRET,
        requireCryptographicSeal: true,
        requireTestEvidence: current.datasetMode === 'LIVE',
        reverificationTaskKey: targetLink.reverificationTaskKey,
      }
    );
    evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
    current.traceLinks[idx] = evaluated;

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'LIVE',
      current.projectName,
      { initialized: current.initialized ?? true, lastSyncedAt: current.lastSyncedAt, syncIncomplete: current.syncIncomplete }
    );

    return await this.commitSuiteMutation({
      summary: updated,
      expectedVersion: version,
      auditEntry: {
        actorAccountId,
        action: 'BIND_ISSUE',
        targetKey: targetLink.hazard.key,
        details: {
          previousIssueKey,
          newIssueKey: targetLink.work.key,
          workKey: targetLink.work.key,
          projectKey: extractProjectKeyFromTraceLink(evaluated) || null,
        },
        authMethod,
      },
    });
  }

  /**
   * Records an explicit verification test execution result while enforcing safe HTTPS evidence URLs.
   */
  static async recordTestResult(params: RecordTestResultParams): Promise<ComplianceSummary> {
    const allowedStatuses: VerificationTest['status'][] = ['PASSED', 'FAILED', 'UNTESTED', 'IN_PROGRESS'];
    if (!allowedStatuses.includes(params.status)) {
      throw new Error(`Invalid test status: ${params.status}`);
    }
    if (!params.actorAccountId || params.actorAccountId.trim() === '') {
      throw new Error('actorAccountId is required to record verification test results.');
    }

    const { summary: current, version } = await this.getSuiteWithVersion();
    const cleanLinkId = params.linkId?.trim();
    const cleanHazard = params.hazardKey?.trim().toLowerCase();
    const cleanTest = params.testKey?.trim().toLowerCase();
    const idx = cleanLinkId
      ? current.traceLinks.findIndex(
          (l) =>
            l.id === cleanLinkId &&
            (!cleanHazard || l.hazard.key.toLowerCase() === cleanHazard) &&
            (!cleanTest || l.test.testKey.toLowerCase() === cleanTest)
        )
      : current.traceLinks.findIndex(
          (l) =>
            (cleanHazard && l.hazard.key.toLowerCase() === cleanHazard) ||
            (cleanTest && l.test.testKey.toLowerCase() === cleanTest)
        );
    if (idx < 0) {
      throw new Error(
        `Target trace link not found (${params.linkId || params.hazardKey || params.testKey || 'unspecified'}).`
      );
    }

    const targetLink = current.traceLinks[idx];
    const previousStatus = targetLink.test.status;
    targetLink.test.status = params.status;
    targetLink.test.executionDate = params.executionDate?.trim() || new Date().toISOString();
    targetLink.test.recordedBy = params.actorAccountId.trim();

    if (params.evidenceUrl !== undefined) {
      const trimmedUrl = params.evidenceUrl.trim();
      if (trimmedUrl === '') {
        delete targetLink.test.evidenceUrl;
      } else {
        targetLink.test.evidenceUrl = validateHttpsUrl(trimmedUrl);
      }
    }

    if (params.notes !== undefined) {
      const trimmedNotes = params.notes.trim();
      if (trimmedNotes === '') {
        delete targetLink.test.notes;
      } else {
        targetLink.test.notes = trimmedNotes;
      }
    }

    const evaluated = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      targetLink.graphMetadata,
      {
        linkId: targetLink.id,
        part11Secret: process.env.MEDTRACE_PART11_SECRET,
        requireCryptographicSeal: true,
        requireTestEvidence: current.datasetMode === 'LIVE',
        reverificationTaskKey: targetLink.reverificationTaskKey,
      }
    );
    evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
    current.traceLinks[idx] = evaluated;

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'LIVE',
      current.projectName,
      { initialized: current.initialized ?? true, lastSyncedAt: current.lastSyncedAt, syncIncomplete: current.syncIncomplete }
    );

    return await this.commitSuiteMutation({
      summary: updated,
      expectedVersion: version,
      auditEntry: {
        actorAccountId: params.actorAccountId,
        action: 'RECORD_TEST_RESULT',
        targetKey: targetLink.test.testKey,
        details: {
          hazardKey: targetLink.hazard.key,
          workKey: targetLink.work?.key || null,
          projectKey: extractProjectKeyFromTraceLink(evaluated) || null,
          previousStatus,
          newStatus: params.status,
          evidenceUrl: targetLink.test.evidenceUrl || null,
          notes: targetLink.test.notes || null,
        },
        authMethod: params.authMethod || 'FORGE_USER_SESSION',
      },
    });
  }

  /**
   * Executes a 21 CFR Part 11 electronic signature sign-off on a specification artifact.
   * Enforces `MEDTRACE_PART11_SECRET`, explicit signer confirmation + exact attestation phrase,
   * server-side identity binding via `UserIdentityResolver`, HMAC-SHA256 sealing, and rollback-safe commits.
   */
  static async signOffPart11(params: SignOffPart11Params): Promise<ComplianceSummary> {
    const part11Secret = getPart11SigningSecret();
    const actorId = (params.actorAccountId || '').trim();
    if (!actorId) {
      throw new Error('Authenticated actorAccountId is required for 21 CFR Part 11 sign-off.');
    }
    if (params.attestation?.attestationConfirmed !== true) {
      throw new Error(
        '21 CFR Part 11 Violation: Explicit attestation confirmation (attestationConfirmed: true) is required.'
      );
    }
    if (
      params.attestation?.attestationChecked !== true &&
      params.attestation?.passwordConfirmed !== true
    ) {
      throw new Error(
        'Part 11 attestation: Explicit signer confirmation (attestationChecked: true) is required.'
      );
    }
    const normalizedPhrase = (params.attestation?.attestationPhrase || '').trim();
    if (normalizedPhrase !== PART11_ATTESTATION_PHRASE) {
      throw new Error(
        `21 CFR Part 11 Violation: Exact attestationPhrase "${PART11_ATTESTATION_PHRASE}" is required.`
      );
    }
    const meaning = (params.attestation.meaning || '').trim();
    if (meaning.length < 5) {
      throw new Error('21 CFR Part 11 §11.50 Violation: A non-empty signature meaning (>= 5 chars) is required.');
    }

    const { summary: current, version } = await this.getSuiteWithVersion();
    const idx = resolveTraceLinkByHazard(
      current.traceLinks,
      params.hazardKey,
      params.specId,
      params.workKey,
      params.linkId
    );
    if (idx < 0) {
      throw new Error(`Hazard ${params.hazardKey} not found in the active compliance suite.`);
    }

    const targetLink = current.traceLinks[idx];
    if (
      targetLink.spec.isMissingSentinel === true ||
      typeof targetLink.spec.sha256Hash !== 'string' ||
      targetLink.spec.sha256Hash.trim() === ''
    ) {
      throw new Error(
        `21 CFR Part 11 Violation: Cannot sign hazard ${targetLink.hazard.key} because no linked Confluence SRS specification with a valid SHA-256 hash exists.`
      );
    }
    const identityResolver = getActiveUserIdentityResolver();
    const resolvedIdentity = await identityResolver.resolveSignerIdentity({
      actorAccountId: actorId,
      extensionType: params.extensionType,
      projectKey: params.projectKey,
      spaceKey: params.spaceKey,
      authMethod: params.authMethod,
    });

    const signedBy = resolvedIdentity.displayName;
    const signedByAccountId = resolvedIdentity.accountId;
    const role = resolvedIdentity.role;
    const authMethod = params.authMethod || 'PART11_ATTESTATION';

    const rawClientPub =
      typeof params.attestation?.clientPublicKeySpki === 'string'
        ? params.attestation.clientPublicKeySpki.trim()
        : '';
    const rawClientSig =
      typeof params.attestation?.clientSignatureBase64 === 'string'
        ? params.attestation.clientSignatureBase64.trim()
        : '';
    const hasHybridInput = rawClientPub.length > 0 || rawClientSig.length > 0;
    let signatureAlgorithm: 'HMAC-SHA256-SEAL-V1' | 'ECDSA-P256-SHA256+HMAC-SEAL-V1' =
      'HMAC-SHA256-SEAL-V1';
    let clientKeyFingerprint: string | undefined;

    if (hasHybridInput) {
      if (!rawClientPub || !rawClientSig) {
        throw new Error(
          '21 CFR Part 11 Violation (PART11_CLIENT_SIGNATURE_INVALID): Both clientPublicKeySpki and clientSignatureBase64 are required for asymmetric signing.'
        );
      }
      const challengePayload = ComplianceEngine.computePart11ClientChallenge({
        hazardKey: targetLink.hazard.key,
        specId: targetLink.spec.id,
        artifactSha256: targetLink.spec.sha256Hash,
        meaning,
        attestationPhrase: PART11_ATTESTATION_PHRASE,
      });
      if (!ComplianceEngine.verifyPart11ClientSignature(challengePayload, rawClientSig, rawClientPub)) {
        throw new Error(
          '21 CFR Part 11 Violation (PART11_CLIENT_SIGNATURE_INVALID): Client ECDSA P-256 signature failed verification against live SRS SHA-256 and attestation meaning.'
        );
      }
      clientKeyFingerprint = ComplianceEngine.computeClientKeyFingerprint(rawClientPub);
      signatureAlgorithm = 'ECDSA-P256-SHA256+HMAC-SEAL-V1';
    }

    const existingBaseline = await this.getSignedSpecBaseline(targetLink.spec.id, targetLink.hazard.key);
    let signedMs = Date.now();
    const baselineInvMs = existingBaseline?.invalidatedAt ? Date.parse(existingBaseline.invalidatedAt) : NaN;
    const sigInvMs = targetLink.signature.invalidatedAt ? Date.parse(targetLink.signature.invalidatedAt) : NaN;
    const maxInvMs = Math.max(
      Number.isFinite(baselineInvMs) ? baselineInvMs : 0,
      Number.isFinite(sigInvMs) ? sigInvMs : 0
    );
    if (maxInvMs > 0 && signedMs <= maxInvMs) {
      signedMs = maxInvMs + 1;
    }
    const signedAt = new Date(signedMs).toISOString();

    const signatureSeal = ComplianceEngine.computePart11Seal(
      {
        hazardKey: targetLink.hazard.key,
        specId: targetLink.spec.id,
        artifactSha256: targetLink.spec.sha256Hash,
        signedByAccountId,
        signedBy,
        role,
        meaning,
        signedAt,
        authMethod,
        ...(hasHybridInput
          ? {
              signatureAlgorithm,
              clientPublicKeySpki: rawClientPub,
              clientSignatureBase64: rawClientSig,
            }
          : {}),
      },
      part11Secret
    );

    const targetHazardLower = targetLink.hazard.key.trim().toLowerCase();
    const targetSpecLower = targetLink.spec.id.trim().toLowerCase();
    const targetPageLower = (targetLink.spec.pageId || '').trim().toLowerCase();
    const signedHash = targetLink.spec.sha256Hash;
    const affectedWorkKeys: string[] = [];

    for (let i = 0; i < current.traceLinks.length; i++) {
      const candidate = current.traceLinks[i];
      const sameBaseline =
        i === idx ||
        (candidate.hazard.key.trim().toLowerCase() === targetHazardLower &&
          (candidate.spec.id.trim().toLowerCase() === targetSpecLower ||
            (targetPageLower !== '' &&
              (candidate.spec.pageId || '').trim().toLowerCase() === targetPageLower)) &&
          candidate.spec.isMissingSentinel !== true &&
          candidate.spec.sha256Hash === signedHash);

      if (!sameBaseline) {
        continue;
      }

      candidate.signature.artifactSha256 = signedHash;
      candidate.signature.isValid = true;
      candidate.signature.signedAt = signedAt;
      candidate.signature.signedBy = signedBy;
      candidate.signature.signedByAccountId = signedByAccountId;
      candidate.signature.role = role;
      candidate.signature.meaning = meaning;
      candidate.signature.authMethod = authMethod;
      candidate.signature.signatureAlgorithm = signatureAlgorithm;
      candidate.signature.signatureSeal = signatureSeal;
      candidate.signature.sealKeyId = 'env:MEDTRACE_PART11_SECRET';
      if (hasHybridInput) {
        candidate.signature.clientPublicKeySpki = rawClientPub;
        candidate.signature.clientSignatureBase64 = rawClientSig;
        candidate.signature.clientKeyFingerprint = clientKeyFingerprint;
      } else {
        candidate.signature.clientPublicKeySpki = undefined;
        candidate.signature.clientSignatureBase64 = undefined;
        candidate.signature.clientKeyFingerprint = undefined;
      }
      candidate.signature.invalidatedAt = undefined;
      candidate.signature.invalidationReason = undefined;
      candidate.spec.lastSignedHash = signedHash;
      candidate.spec.isSignatureInvalidated = false;

      const evaluated = ComplianceEngine.evaluateTraceLink(
        candidate.hazard,
        candidate.spec,
        candidate.work,
        candidate.test,
        candidate.signature,
        candidate.graphMetadata,
        {
          linkId: candidate.id,
          part11Secret,
          requireCryptographicSeal: true,
          requireTestEvidence: current.datasetMode === 'LIVE',
          reverificationTaskKey: candidate.reverificationTaskKey,
        }
      );
      evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
      current.traceLinks[i] = evaluated;
      if (evaluated.work?.key && !affectedWorkKeys.includes(evaluated.work.key)) {
        affectedWorkKeys.push(evaluated.work.key);
      }
    }

    const evaluatedTarget = current.traceLinks[idx];

    const baselineRecord = buildSignedBaselineRecord(
      evaluatedTarget,
      signedBy,
      signedByAccountId,
      signedAt,
      role,
      meaning,
      authMethod,
      signatureSeal,
      hasHybridInput
        ? {
            signatureAlgorithm,
            clientPublicKeySpki: rawClientPub,
            clientSignatureBase64: rawClientSig,
            clientKeyFingerprint,
          }
        : undefined
    );

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'LIVE',
      current.projectName,
      { initialized: current.initialized ?? true, lastSyncedAt: current.lastSyncedAt, syncIncomplete: current.syncIncomplete }
    );

    return await this.commitSuiteMutation({
      summary: updated,
      expectedVersion: version,
      baselineUpdates: [{ action: 'SET', baseline: baselineRecord }],
      auditEntry: {
        actorAccountId: signedByAccountId,
        action: 'PART11_SIGNOFF',
        targetKey: evaluatedTarget.hazard.key,
        details: {
          specId: evaluatedTarget.spec.id,
          workKey: evaluatedTarget.work?.key || null,
          affectedWorkKeys,
          projectKey: extractProjectKeyFromTraceLink(evaluatedTarget) || null,
          artifactSha256: evaluatedTarget.spec.sha256Hash,
          signedBy,
          signedByAccountId,
          role,
          meaning,
          signatureAlgorithm,
          ...(clientKeyFingerprint ? { clientKeyFingerprint } : {}),
        },
        authMethod,
      },
    });
  }

  /**
   * Creates a linked Jira re-verification task under the invoking user's permissions (`api.asUser()`)
   * when a trace link has approval drift or verification gaps, links it to affected Jira artifacts,
   * persists `reverificationTaskKey` on the link, and records an immutable audit trail entry.
   */
  static async createReverificationTask(
    params: CreateReverificationTaskParams
  ): Promise<CreateReverificationTaskResult> {
    if (!isForgeRuntime()) {
      throw new Error('SeederService.createReverificationTask requires an active Atlassian Forge runtime.');
    }
    const actor = (params.actorAccountId || '').trim();
    if (!actor) {
      throw new Error('Authenticated actorAccountId is required to create a re-verification Jira task.');
    }

    const { summary: current, version } = await this.getSuiteWithVersion();
    if (current.datasetMode !== 'LIVE' || current.initialized === false) {
      throw new Error(
        'Re-verification Jira tasks can only be created on an initialized LIVE compliance suite.'
      );
    }

    const cleanLinkId = params.linkId?.trim();
    const cleanHazard = params.hazardKey?.trim().toLowerCase();
    const cleanIssue = params.issueKey?.trim().toLowerCase();
    const idx = cleanLinkId
      ? current.traceLinks.findIndex((l) => l.id === cleanLinkId)
      : current.traceLinks.findIndex(
          (l) =>
            (cleanHazard && l.hazard.key.toLowerCase() === cleanHazard) ||
            (cleanIssue &&
              ((l.work?.key || '').toLowerCase() === cleanIssue ||
                (l.hazard?.key || '').toLowerCase() === cleanIssue ||
                (l.test?.testKey || '').toLowerCase() === cleanIssue))
        );

    if (idx < 0) {
      throw new Error(
        `Target trace link not found (${params.linkId || params.hazardKey || params.issueKey || 'unspecified'}).`
      );
    }

    const targetLink = current.traceLinks[idx];
    const targetProjectKey =
      extractProjectKeyFromTraceLink(targetLink) ||
      (params.issueKey && JIRA_ISSUE_KEY_PATTERN.test(params.issueKey.trim().toUpperCase())
        ? params.issueKey.trim().toUpperCase().split('-')[0]
        : undefined);

    if (!targetProjectKey) {
      throw new Error(
        `Cannot determine target Jira projectKey for ${targetLink.hazard.key}; bind a Jira issue first.`
      );
    }

    const requester = params.callerMode === 'APP' ? api.asApp() : api.asUser();

    // 1. Verify caller holds CREATE_ISSUES in target project
    const permResp = await requester.requestJira(
      route`/rest/api/3/mypermissions?projectKey=${targetProjectKey}&permissions=CREATE_ISSUES`
    );
    if (permResp.status !== 200) {
      throw new Error(
        `Forbidden: Unable to verify Jira CREATE_ISSUES permission in project ${targetProjectKey} (HTTP ${permResp.status}).`
      );
    }
    const permJson = (await permResp.json().catch(() => ({}))) as {
      permissions?: { CREATE_ISSUES?: { havePermission?: boolean } };
    };
    if (permJson?.permissions?.CREATE_ISSUES?.havePermission !== true) {
      throw new Error(
        `Forbidden: Requires Jira CREATE_ISSUES permission in project ${targetProjectKey}.`
      );
    }

    const getCandidateLinkTargets = (excludedKey?: string): string[] => {
      const excluded = (excludedKey || '').trim().toUpperCase();
      const rawTargets = [
        targetLink.work?.key,
        targetLink.hazard?.source === 'JIRA_ISSUE' ? targetLink.hazard?.key : undefined,
        targetLink.test?.source === 'JIRA_ISSUE' ? targetLink.test?.testKey : undefined,
      ];
      return Array.from(
        new Set(
          rawTargets
            .map((k) => (typeof k === 'string' ? k.trim().toUpperCase() : ''))
            .filter((k) => k && k !== excluded && JIRA_ISSUE_KEY_PATTERN.test(k))
        )
      );
    };

    // 1b. Open-task reuse guard: reuse an existing open re-verification Jira task and verify actual issuelinks
    if (targetLink.reverificationTaskKey && !params.force) {
      let existingResp: { status: number; json: () => Promise<unknown> };
      try {
        existingResp = await requester.requestJira(
          route`/rest/api/3/issue/${targetLink.reverificationTaskKey}?fields=status,issuelinks`
        );
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        throw new Error(
          `Unable to verify status of existing re-verification task ${targetLink.reverificationTaskKey}: ${msg}`
        );
      }

      if (existingResp.status === 200) {
        const existingJson = (await existingResp.json().catch(() => ({}))) as {
          fields?: {
            status?: { name?: string; statusCategory?: { key?: string; name?: string } };
            issuelinks?: Array<{
              inwardIssue?: { key?: string };
              outwardIssue?: { key?: string };
            }>;
          };
        };
        const catKey = String(existingJson?.fields?.status?.statusCategory?.key || '')
          .trim()
          .toLowerCase();
        const statusName = String(existingJson?.fields?.status?.name || '')
          .trim()
          .toLowerCase();
        const isClosed =
          catKey === 'done' ||
          statusName === 'done' ||
          statusName === 'closed' ||
          statusName === 'resolved';
        if (!isClosed) {
          const expectedTargets = getCandidateLinkTargets(targetLink.reverificationTaskKey);
          const hasIssueLinksField = Array.isArray(existingJson?.fields?.issuelinks);
          const actualLinkedSet = new Set<string>();
          if (hasIssueLinksField) {
            for (const entry of existingJson.fields!.issuelinks!) {
              const inward = typeof entry?.inwardIssue?.key === 'string' ? entry.inwardIssue.key.trim().toUpperCase() : '';
              const outward = typeof entry?.outwardIssue?.key === 'string' ? entry.outwardIssue.key.trim().toUpperCase() : '';
              if (inward) actualLinkedSet.add(inward);
              if (outward) actualLinkedSet.add(outward);
            }
          }
          const linkedIssueKeys = hasIssueLinksField
            ? expectedTargets.length > 0
              ? expectedTargets.filter((k) => actualLinkedSet.has(k))
              : Array.from(actualLinkedSet)
            : [];
          const missingLinkKeys = hasIssueLinksField
            ? expectedTargets.filter((k) => !actualLinkedSet.has(k))
            : expectedTargets;
          const fullyLinked = hasIssueLinksField && missingLinkKeys.length === 0;
          return {
            success: fullyLinked,
            fullyLinked,
            linksVerified: hasIssueLinksField,
            createdIssueKey: targetLink.reverificationTaskKey,
            linkedIssueKeys,
            ...(missingLinkKeys.length > 0 ? { missingLinkKeys } : {}),
            projectKey: targetProjectKey,
            alreadyExisted: true,
            summary: current,
          };
        }
      } else if (existingResp.status !== 404) {
        throw new Error(
          `Unable to verify status of existing re-verification task ${targetLink.reverificationTaskKey} (HTTP ${existingResp.status}); refusing duplicate creation.`
        );
      }
    }

    // 2. Resolve a valid non-subtask Jira issueType for the target project (prefer Task)
    let issueTypeRef: { id?: string; name?: string } = { name: 'Task' };
    try {
      const metaResp = await requester.requestJira(
        route`/rest/api/3/issue/createmeta/${targetProjectKey}/issuetypes`
      );
      if (metaResp.status === 200) {
        const metaJson = (await metaResp.json().catch(() => ({}))) as {
          issueTypes?: Array<{ id?: string; name?: string; subtask?: boolean }>;
          values?: Array<{ id?: string; name?: string; subtask?: boolean }>;
        };
        const list = Array.isArray(metaJson.issueTypes)
          ? metaJson.issueTypes
          : Array.isArray(metaJson.values)
            ? metaJson.values
            : [];
        const candidates = list.filter((it) => it && it.subtask !== true);
        const preferred =
          candidates.find((it) => String(it.name || '').toLowerCase() === 'task') ||
          candidates.find((it) => String(it.name || '').toLowerCase() === 'story') ||
          candidates[0];
        if (preferred?.id) {
          issueTypeRef = { id: String(preferred.id) };
        } else if (preferred?.name) {
          issueTypeRef = { name: String(preferred.name) };
        }
      }
    } catch {
      // Fall back to { name: 'Task' }
    }

    const customSummary = typeof params.summary === 'string' ? params.summary.trim() : '';
    const issueSummary = (
      customSummary ||
      `[MedTrace Re-Verification] ${targetLink.hazard.key}: ${targetLink.spec.title || targetLink.work.title || targetLink.work.key}`
    ).slice(0, 240);

    const reasonText =
      (typeof params.reason === 'string' && params.reason.trim()) ||
      targetLink.signature.invalidationReason ||
      targetLink.violations[0] ||
      `Re-verification required after requirement or verification state change (${targetLink.complianceState}).`;

    const descriptionParagraphs = [
      `Automated MedTrace re-verification work item created for ${targetLink.hazard.key} (${targetLink.hazard.riskClass.replace('_', ' ')}).`,
      `Trigger Reason: ${reasonText}`,
      `Confluence SRS: ${targetLink.spec.title || targetLink.spec.id} (Current SHA-256: ${targetLink.spec.sha256Hash || 'none'}, Last Signed SHA-256: ${targetLink.spec.lastSignedHash || 'none'})`,
      `Affected Jira Work Item: ${targetLink.work.key || 'Unbound'} | Verification Test: ${targetLink.test.testKey} (${targetLink.test.status})`,
      `Action Required: Review risk mitigation, execute verification test ${targetLink.test.testKey} with https:// evidence, and re-execute Part 11 attestation sign-off in MedTrace.`,
    ];

    const createResp = await requester.requestJira(route`/rest/api/3/issue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        fields: {
          project: { key: targetProjectKey },
          issuetype: issueTypeRef,
          summary: issueSummary,
          labels: [
            'medtrace-reverification',
            targetLink.hazard.riskClass.toLowerCase().replace('_', '-'),
          ],
          description: {
            type: 'doc',
            version: 1,
            content: descriptionParagraphs.map((text) => ({
              type: 'paragraph',
              content: [{ type: 'text', text }],
            })),
          },
        },
      }),
    });

    if (createResp.status !== 200 && createResp.status !== 201) {
      const errBody = await createResp.text().catch(() => '');
      throw new Error(
        `Failed to create Jira re-verification task in ${targetProjectKey} (HTTP ${createResp.status}): ${errBody.slice(0, 200)}`
      );
    }

    const createdJson = (await createResp.json().catch(() => ({}))) as { key?: string; id?: string };
    const createdIssueKey = typeof createdJson?.key === 'string' ? createdJson.key.trim().toUpperCase() : '';
    if (!createdIssueKey) {
      throw new Error('Jira issue creation succeeded without returning an issue key.');
    }

    // 3. Link newly created task to affected native Jira issues (work, plus native Jira hazard/test issues when source === 'JIRA_ISSUE')
    const candidateLinkTargets = getCandidateLinkTargets(createdIssueKey);

    let linkTypeName = 'Relates';
    if (candidateLinkTargets.length > 0) {
      try {
        const ltResp = await requester.requestJira(route`/rest/api/3/issueLinkType`);
        if (ltResp.status === 200) {
          const ltJson = (await ltResp.json().catch(() => ({}))) as {
            issueLinkTypes?: Array<{ name?: string }>;
          };
          const types = Array.isArray(ltJson.issueLinkTypes) ? ltJson.issueLinkTypes : [];
          const relates = types.find((t) => String(t.name || '').toLowerCase() === 'relates');
          if (relates?.name) {
            linkTypeName = relates.name;
          } else if (types[0]?.name) {
            linkTypeName = String(types[0].name);
          }
        }
      } catch {
        // Keep 'Relates' default
      }
    }

    const linkedIssueKeys: string[] = [];
    const failedLinkKeys: string[] = [];
    const linkErrors: Array<{ issueKey: string; error: string }> = [];
    for (const targetKey of candidateLinkTargets) {
      try {
        const linkResp = await requester.requestJira(route`/rest/api/3/issueLink`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({
            type: { name: linkTypeName },
            inwardIssue: { key: createdIssueKey },
            outwardIssue: { key: targetKey },
          }),
        });
        if (linkResp.status === 200 || linkResp.status === 201 || linkResp.status === 204) {
          linkedIssueKeys.push(targetKey);
        } else {
          const errText = await linkResp.text().catch(() => '');
          failedLinkKeys.push(targetKey);
          linkErrors.push({
            issueKey: targetKey,
            error: `HTTP ${linkResp.status}${errText ? `: ${errText.slice(0, 120)}` : ''}`,
          });
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        failedLinkKeys.push(targetKey);
        linkErrors.push({ issueKey: targetKey, error: msg.slice(0, 120) });
      }
    }

    targetLink.reverificationTaskKey = createdIssueKey;
    const evaluated = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      targetLink.graphMetadata,
      {
        linkId: targetLink.id,
        part11Secret: process.env.MEDTRACE_PART11_SECRET,
        requireCryptographicSeal: true,
        requireTestEvidence: true,
        reverificationTaskKey: createdIssueKey,
      }
    );
    evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
    current.traceLinks[idx] = evaluated;

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'LIVE',
      current.projectName,
      { initialized: current.initialized ?? true, lastSyncedAt: current.lastSyncedAt, syncIncomplete: current.syncIncomplete }
    );

    const committed = await this.commitSuiteMutation({
      summary: updated,
      expectedVersion: version,
      auditEntry: {
        actorAccountId: actor,
        action: 'CREATE_REVERIFICATION_TASK',
        targetKey: createdIssueKey,
        details: {
          projectKey: targetProjectKey,
          hazardKey: targetLink.hazard.key,
          workKey: targetLink.work?.key || null,
          testKey: targetLink.test?.testKey || null,
          specId: targetLink.spec.id,
          createdIssueKey,
          linkedIssueKeys,
          ...(failedLinkKeys.length > 0 ? { failedLinkKeys } : {}),
          reason: reasonText,
        },
        authMethod: params.authMethod || 'FORGE_USER_SESSION',
      },
    });

    const fullyLinked = failedLinkKeys.length === 0;
    return {
      success: fullyLinked,
      ...(failedLinkKeys.length > 0 ? { partialSuccess: true, failedLinkKeys, linkErrors } : {}),
      fullyLinked,
      createdIssueKey,
      linkedIssueKeys,
      projectKey: targetProjectKey,
      summary: committed,
    };
  }

  /**
   * Demo-only combined remediation flow. Disallowed in LIVE mode; in DEMO mode requires explicit
   * non-empty `targetHazardKey`, `simulate: true`, and `attestationConfirmed: true`.
   */
  static async remediateClassCGap(
    targetHazardKey?: string,
    accountId?: string,
    options?: RemediateGapOptions
  ): Promise<ComplianceSummary> {
    const cleanHazardKey = (targetHazardKey || '').trim();
    if (!cleanHazardKey) {
      throw new Error('targetHazardKey is required to remediate a compliance gap.');
    }

    const { summary: current, version } = await this.getSuiteWithVersion();
    const idx = resolveTraceLinkByHazard(current.traceLinks, cleanHazardKey);
    if (idx < 0) {
      throw new Error(`Hazard ${cleanHazardKey} not found in the active compliance suite — nothing was remediated.`);
    }
    if (current.datasetMode === 'LIVE') {
      throw new Error(
        `Demo quick-remediate is disabled in LIVE dataset mode. Use recordTestResult and signOffPart11 for ${cleanHazardKey}.`
      );
    }
    if (!options?.simulate || !options?.attestationConfirmed) {
      throw new Error(
        'Explicit simulation consent (simulate: true) and Part 11 attestation confirmation (attestationConfirmed: true) are required.'
      );
    }
    const actor = accountId?.trim();
    if (!actor) {
      throw new Error('Authenticated actor identity is required to remediate and attest compliance gaps.');
    }

    const targetLink = current.traceLinks[idx];
    const nowIso = new Date().toISOString();
    const authMethod = options.authMethod || 'PART11_ATTESTATION';
    const baseMeaning = options.meaning?.trim() || targetLink.signature.meaning || 'Simulated QA verification';
    const meaning = baseMeaning.includes('(DEMO_SIMULATION)') ? baseMeaning : `${baseMeaning} (DEMO_SIMULATION)`;
    const signedBy = actor.startsWith('service:') ? actor : `accountId:${actor}`;
    const role = targetLink.signature.role || 'Demo Simulation Operator';

    targetLink.work.status = 'Done';
    targetLink.test.status = 'PASSED';
    targetLink.test.executionDate = nowIso;
    targetLink.test.recordedBy = actor;
    targetLink.test.notes = 'DEMO_SIMULATION: Operator-confirmed simulated verification run.';

    targetLink.signature.artifactSha256 = targetLink.spec.sha256Hash;
    targetLink.signature.isValid = true;
    targetLink.signature.signedAt = nowIso;
    targetLink.signature.signedBy = signedBy;
    targetLink.signature.signedByAccountId = actor;
    targetLink.signature.role = role;
    targetLink.signature.meaning = meaning;
    targetLink.signature.authMethod = authMethod;
    targetLink.signature.invalidatedAt = undefined;
    targetLink.signature.invalidationReason = undefined;

    const secret = (process.env.MEDTRACE_PART11_SECRET || '').trim();
    if (secret) {
      targetLink.signature.signatureAlgorithm = 'HMAC-SHA256-SEAL-V1';
      targetLink.signature.sealKeyId = 'env:MEDTRACE_PART11_SECRET';
      targetLink.signature.signatureSeal = ComplianceEngine.computePart11Seal(
        {
          hazardKey: targetLink.hazard.key,
          specId: targetLink.spec.id,
          artifactSha256: targetLink.spec.sha256Hash,
          signedByAccountId: actor,
          signedBy,
          role,
          meaning,
          signedAt: nowIso,
          authMethod,
        },
        secret
      );
    } else {
      delete targetLink.signature.signatureAlgorithm;
      delete targetLink.signature.signatureSeal;
      delete targetLink.signature.sealKeyId;
    }

    targetLink.spec.lastSignedHash = targetLink.spec.sha256Hash;
    targetLink.spec.isSignatureInvalidated = false;

    const evaluated = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      targetLink.graphMetadata,
      { linkId: targetLink.id, part11Secret: secret }
    );
    evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
    current.traceLinks[idx] = evaluated;

    const updatedSummary = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'DEMO',
      current.projectName,
      { initialized: current.initialized ?? true }
    );

    return await this.commitSuiteMutation({
      summary: updatedSummary,
      expectedVersion: version,
      auditEntry: {
        actorAccountId: actor,
        action: 'DEMO_SIMULATION',
        targetKey: targetLink.hazard.key,
        details: {
          simulatedTestKey: targetLink.test.testKey,
          specId: targetLink.spec.id,
          artifactSha256: targetLink.spec.sha256Hash,
          meaning,
        },
        authMethod,
      },
    });
  }
}

/**
 * Named helper re-export for Phase 1C ingestion baseline invalidation.
 */
export const invalidateSignedSpecBaselines = (
  input: InvalidateSignedSpecBaselineInput
): Promise<void> => SeederService.invalidateSignedSpecBaselines(input);

/**
 * Named helper re-export for Phase 1C atomic save-before-audit suite commits.
 */
export const commitSuiteMutation = (
  params: CommitSuiteMutationParams
): Promise<ComplianceSummary> => SeederService.commitSuiteMutation(params);
