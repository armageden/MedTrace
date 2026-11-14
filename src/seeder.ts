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
  AuthorizedUserIdentity,
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

const SUITE_META_KEY = 'medtrace:compliance:suite_meta';
const LINK_KEY_PREFIX = 'medtrace:compliance:link:';
const SIGNED_SPEC_PREFIX = 'medtrace:compliance:signed_spec:';
const VLOCK_PREFIX = 'medtrace:compliance:vlock:';
const META_REASONS_SHARD_PREFIX = 'medtrace:compliance:meta_reasons:';
const META_LINKS_SHARD_PREFIX = 'medtrace:compliance:meta_links:';
const META_INDEX_SHARD_PREFIX = 'medtrace:compliance:meta_index:';
const LEGACY_STORAGE_KEY = 'medtrace:compliance:active_suite';

const BATCH_CHUNK_SIZE = 25;
const MAX_TRANSACT_BYTES = Math.floor(3.5 * 1024 * 1024);
const MAX_KVS_META_BYTES = 128 * 1024;
const MAX_META_SHARD_BYTES = 96 * 1024;
const MAX_AUDIT_DETAILS_BYTES = 200 * 1024;
const MAX_KVS_KEY_LENGTH = 500;
const FORGE_KVS_KEY_REGEX = /^(?!\s+$)[a-zA-Z0-9:._\s-#]+$/;

type AuditAppendInput = Parameters<typeof AuditLogService.append>[0];
type AuditAuthMethod = NonNullable<AuditAppendInput['authMethod']>;

/**
 * Persisted baseline snapshot for an electronically signed Confluence SRS revision.
 * Scoped per `(hazardKey, specId)` when `hazardKey` is supplied to prevent cross-hazard leakage.
 */
export interface SignedSpecBaseline {
  hazardKey?: string;
  specId: string;
  pageId?: string;
  sha256Hash: string;
  signedBy: string;
  signedByAccountId?: string;
  signedAt: string;
  role: string;
  meaning: string;
  authMethod?: string;
  signatureAlgorithm?: 'HMAC-SHA256-SEAL-V1' | 'ECDSA-P256-SHA256+HMAC-SEAL-V1';
  signatureSeal?: string;
  sealKeyId?: string;
  clientPublicKeySpki?: string;
  clientSignatureBase64?: string;
  clientKeyFingerprint?: string;
  invalidatedAt?: string;
  invalidatedByHash?: string;
  invalidationReason?: string;
}

/**
 * Context supplied to a `UserIdentityResolver` when authenticating a Part 11 signatory.
 */
export interface UserIdentityResolverContext {
  actorAccountId: string;
  extensionType?: string;
  projectKey?: string;
  spaceKey?: string;
  authMethod?: AuditAuthMethod;
}

/**
 * Authoritative identity and role resolver used to bind Part 11 signatures on the server.
 */
export interface UserIdentityResolver {
  resolveSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity>;
}

/**
 * Optional guard parameters for seeding demo data.
 */
export interface SeedDemoOptions {
  confirmOverwriteLive?: boolean;
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
  expectedVersion?: number;
  auditEntry: AuditAppendInput;
  baselineUpdates?: BaselineMutationRecord[];
}

export interface GetSuiteOptions {
  issueKeyFilter?: string;
  projectKey?: string;
}

interface ShardedSuiteMetaV2 {
  projectName: string;
  datasetMode: 'DEMO' | 'LIVE';
  initialized: boolean;
  standards: string[];
  totalHazards: number;
  classCCount: number;
  classBCount: number;
  classACount: number;
  verifiedPercentage: number;
  releaseBlocked: boolean;
  blockingReasons: string[];
  blockingReasonShardKeys?: string[];
  signatureDriftCount: number;
  lastAuditTimestamp: string;
  linkKeys: string[];
  linkKeyShardKeys?: string[];
  issueKeyIndex?: Record<string, string[]>;
  issueKeyIndexShardKeys?: string[];
  storageFormat: 'SHARDED_V2';
  version: number;
}

let customUserIdentityResolver: UserIdentityResolver | null = null;

/**
 * Overrides the active `UserIdentityResolver` (pass `null` to restore runtime default).
 */
export function setUserIdentityResolver(resolver: UserIdentityResolver | null): void {
  customUserIdentityResolver = resolver;
}

const localFallbackIdentityResolver: UserIdentityResolver = {
  async resolveSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity> {
    return {
      accountId: ctx.actorAccountId,
      displayName: `accountId:${ctx.actorAccountId}`,
      role: 'Authorized Signatory',
      authSource: 'LOCAL_TEST',
    };
  },
};

function hasConfluenceEditorPermission(operations: Array<{ operation?: string; targetType?: string }>): {
  canEdit: boolean;
  isAdmin: boolean;
} {
  let canEdit = false;
  let isAdmin = false;
  for (const op of operations) {
    const operation = String(op?.operation || '').toLowerCase();
    const targetType = String(op?.targetType || '').toLowerCase();
    if (operation === 'administer') {
      canEdit = true;
      isAdmin = true;
    } else if (
      (operation === 'create' || operation === 'update' || operation === 'delete') &&
      (targetType === 'page' || targetType === 'space' || targetType === 'comment' || targetType === '')
    ) {
      canEdit = true;
    }
  }
  return { canEdit, isAdmin };
}

async function resolveJiraSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity> {
  const myselfResp = await api.asUser().requestJira(route`/rest/api/3/myself?expand=groups`);
  if (myselfResp.status !== 200) {
    throw new Error(`Forbidden: Failed to verify Jira signatory identity (HTTP ${myselfResp.status}).`);
  }
  const userData = (await myselfResp.json()) as {
    accountId?: string;
    displayName?: string;
    emailAddress?: string;
    active?: boolean;
  };
  if (!userData?.accountId || userData.active === false) {
    throw new Error('Forbidden: Authenticated Jira user account is inactive or missing accountId.');
  }
  if (ctx.actorAccountId && userData.accountId !== ctx.actorAccountId) {
    throw new Error('Forbidden: Signatory accountId does not match authenticated Jira session user.');
  }

  const permsRoute = ctx.projectKey?.trim()
    ? route`/rest/api/3/mypermissions?projectKey=${ctx.projectKey.trim()}&permissions=EDIT_ISSUES,ADMINISTER_PROJECTS`
    : route`/rest/api/3/mypermissions?permissions=EDIT_ISSUES,ADMINISTER_PROJECTS`;
  const permsResp = await api.asUser().requestJira(permsRoute);
  if (permsResp.status !== 200) {
    throw new Error(`Forbidden: Unable to verify Jira permissions for signatory (HTTP ${permsResp.status}).`);
  }
  const permsData = (await permsResp.json()) as {
    permissions?: Record<string, { havePermission?: boolean }>;
  };
  const canEdit = Boolean(permsData?.permissions?.EDIT_ISSUES?.havePermission);
  const isAdmin = Boolean(permsData?.permissions?.ADMINISTER_PROJECTS?.havePermission);
  if (!canEdit && !isAdmin) {
    throw new Error('Forbidden: Jira user lacks EDIT_ISSUES or ADMINISTER_PROJECTS permission for Part 11 sign-off.');
  }

  const displayName = (userData.displayName || userData.accountId).trim();
  const role = isAdmin
    ? 'Project Administrator / Compliance Approver'
    : 'Jira Engineering Approver';

  return {
    accountId: userData.accountId,
    displayName: `${displayName} (${userData.accountId})`,
    role,
    emailAddress: userData.emailAddress,
    authSource: 'JIRA_MYSELF',
  };
}

async function resolveConfluenceSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity> {
  const userResp = await api.asUser().requestConfluence(route`/wiki/rest/api/user/current`);
  if (userResp.status !== 200) {
    throw new Error(`Forbidden: Failed to verify Confluence signatory identity (HTTP ${userResp.status}).`);
  }
  const userData = (await userResp.json()) as {
    accountId?: string;
    displayName?: string;
    publicName?: string;
    email?: string;
  };
  if (!userData?.accountId) {
    throw new Error('Forbidden: Authenticated Confluence user response missing accountId.');
  }
  if (ctx.actorAccountId && userData.accountId !== ctx.actorAccountId) {
    throw new Error('Forbidden: Signatory accountId does not match authenticated Confluence session user.');
  }

  const spacesResp = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces?type=global&limit=25`);
  if (spacesResp.status !== 200) {
    throw new Error(`Forbidden: Unable to inspect Confluence global space permissions (HTTP ${spacesResp.status}).`);
  }
  const spacesJson = (await spacesResp.json()) as {
    results?: Array<{ id?: string; key?: string; type?: string }>;
  };
  const globalSpaces = (spacesJson?.results || []).filter(
    (s) => s?.id && (!s.type || s.type.toLowerCase() === 'global') && (!ctx.spaceKey || s.key === ctx.spaceKey)
  );

  let authorizedEditor = false;
  let authorizedAdmin = false;
  for (const space of globalSpaces) {
    const opsResp = await api
      .asUser()
      .requestConfluence(route`/wiki/api/v2/spaces/${space.id!}/operations`);
    if (opsResp.status !== 200) continue;
    const opsJson = (await opsResp.json()) as {
      operations?: Array<{ operation?: string; targetType?: string }>;
    };
    const perms = hasConfluenceEditorPermission(opsJson?.operations || []);
    if (perms.canEdit) {
      authorizedEditor = true;
      if (perms.isAdmin) authorizedAdmin = true;
      break;
    }
  }

  if (!authorizedEditor) {
    throw new Error(
      'Forbidden: Confluence user lacks edit permission in any global space and cannot perform Part 11 sign-off.'
    );
  }

  const displayName = (userData.displayName || userData.publicName || userData.accountId).trim();
  return {
    accountId: userData.accountId,
    displayName: `${displayName} (${userData.accountId})`,
    role: authorizedAdmin
      ? 'Confluence Space Administrator / Compliance Approver'
      : 'Confluence Compliance Approver',
    emailAddress: userData.email,
    authSource: 'CONFLUENCE_CURRENT_USER',
  };
}

/**
 * Production Forge identity resolver querying `/rest/api/3/myself` + `/mypermissions`
 * or Confluence `/wiki/rest/api/user/current` + global-space `/operations` as the calling user.
 */
export const forgeUserIdentityResolver: UserIdentityResolver = {
  async resolveSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity> {
    if (ctx.actorAccountId.startsWith('service:')) {
      throw new Error('Forbidden: Automated service principals cannot execute human Part 11 signatures.');
    }
    const ext = (ctx.extensionType || '').toLowerCase();
    if (ext.startsWith('confluence:')) {
      return await resolveConfluenceSignerIdentity(ctx);
    }
    if (ext.startsWith('jira:')) {
      return await resolveJiraSignerIdentity(ctx);
    }

    try {
      return await resolveJiraSignerIdentity(ctx);
    } catch (jiraErr) {
      if (jiraErr instanceof Error && jiraErr.message.includes('lacks EDIT_ISSUES')) {
        throw jiraErr;
      }
      try {
        return await resolveConfluenceSignerIdentity(ctx);
      } catch (confErr) {
        if (confErr instanceof Error && confErr.message.startsWith('Forbidden:')) {
          throw confErr;
        }
        throw jiraErr;
      }
    }
  },
};

function getActiveUserIdentityResolver(): UserIdentityResolver {
  if (customUserIdentityResolver) {
    return customUserIdentityResolver;
  }
  return isForgeRuntime() ? forgeUserIdentityResolver : localFallbackIdentityResolver;
}

/**
 * Retrieves `MEDTRACE_PART11_SECRET` for Part 11 HMAC-SHA256 signing and fails closed if missing.
 */
export function getPart11SigningSecret(): string {
  const secret = (process.env.MEDTRACE_PART11_SECRET || '').trim();
  if (!secret) {
    throw new Error(
      '21 CFR Part 11 configuration error: MEDTRACE_PART11_SECRET environment variable must be set before signing.'
    );
  }
  return secret;
}

/**
 * Maps Jira `fields.status` name and category onto MedTrace's canonical workflow statuses.
 */
export function mapJiraStatusToWorkStatus(statusField?: {
  name?: string;
  statusCategory?: { key?: string; name?: string };
}): JiraWorkItem['status'] {
  const rawName = String(statusField?.name || '').trim().toLowerCase();
  const categoryKey = String(statusField?.statusCategory?.key || '').trim().toLowerCase();
  const categoryName = String(statusField?.statusCategory?.name || '').trim().toLowerCase();

  if (
    categoryKey === 'done' ||
    categoryName === 'done' ||
    rawName === 'done' ||
    rawName === 'closed' ||
    rawName === 'resolved' ||
    rawName === 'verified' ||
    rawName === 'completed' ||
    rawName === 'complete'
  ) {
    return 'Done';
  }
  if (
    rawName === 'under review' ||
    rawName === 'in review' ||
    rawName === 'code review' ||
    rawName === 'qa review' ||
    rawName === 'peer review' ||
    rawName === 'review'
  ) {
    return 'Under Review';
  }
  if (
    categoryKey === 'indeterminate' ||
    categoryName === 'in progress' ||
    rawName === 'in progress' ||
    rawName === 'in development' ||
    rawName === 'active' ||
    rawName === 'doing'
  ) {
    return 'In Progress';
  }
  return 'To Do';
}

function cloneJsonValue<T>(val: T): T {
  return JSON.parse(JSON.stringify(val)) as T;
}

function buildSafeKvsKey(prefix: string, rawSegment: string): string {
  const remaining = MAX_KVS_KEY_LENGTH - prefix.length;
  const maxSegLen = Math.max(16, Math.min(180, remaining));
  const safeSegment = sanitizeKvsKeySegment(rawSegment, maxSegLen);
  const fullKey = `${prefix}${safeSegment}`;
  if (fullKey.length > MAX_KVS_KEY_LENGTH || !FORGE_KVS_KEY_REGEX.test(fullKey)) {
    throw new Error(`Constructed invalid Forge KVS key: ${fullKey}`);
  }
  return fullKey;
}

function chunkArray<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

function shardStringArray(
  items: string[],
  prefix: string,
  version: number
): Array<{ key: string; value: string[] }> {
  const shards: Array<{ key: string; value: string[] }> = [];
  let current: string[] = [];

  for (const item of items) {
    const candidate = [...current, item];
    if (current.length > 0 && measureJsonBytes(candidate) > MAX_META_SHARD_BYTES) {
      shards.push({ key: `${prefix}v${version}:${shards.length}`, value: current });
      current = [item];
    } else {
      current = candidate;
    }
  }
  if (current.length > 0 || shards.length === 0) {
    shards.push({ key: `${prefix}v${version}:${shards.length}`, value: current });
  }
  return shards;
}

function shardRecordOfStringArrays(
  record: Record<string, string[]>,
  prefix: string,
  nextVersion: number
): Array<{ key: string; value: Record<string, string[]> }> {
  const shards: Array<{ key: string; value: Record<string, string[]> }> = [];
  let current: Record<string, string[]> = {};
  let currentCount = 0;

  for (const [entryKey, entryVal] of Object.entries(record)) {
    const candidate = currentCount === 0 ? { [entryKey]: entryVal } : { ...current, [entryKey]: entryVal };
    if (currentCount > 0 && measureJsonBytes(candidate) > MAX_META_SHARD_BYTES) {
      shards.push({
        key: `${prefix}v${nextVersion}:${shards.length}`,
        value: current,
      });
      current = { [entryKey]: entryVal };
      currentCount = 1;
    } else {
      current[entryKey] = entryVal;
      currentCount++;
    }
  }
  if (currentCount > 0) {
    shards.push({
      key: `${prefix}v${nextVersion}:${shards.length}`,
      value: current,
    });
  }
  return shards;
}

function buildMetaAndShardItems(
  summary: ComplianceSummary,
  linkKeys: string[],
  nextVersion: number
): {
  meta: ShardedSuiteMetaV2;
  metaShardItems: Array<{ key: string; value: string[] | Record<string, string[]> }>;
} {
  const initialized = summary.initialized ?? (summary.traceLinks.length > 0 || summary.datasetMode === 'DEMO');
  const issueKeyIndex: Record<string, string[]> = {};
  summary.traceLinks.forEach((link, idx) => {
    const kvsKey = linkKeys[idx];
    if (!kvsKey) return;
    for (const rawKey of [link.work?.key, link.hazard?.key]) {
      const normalized = rawKey?.trim().toUpperCase();
      if (!normalized) continue;
      const existing = issueKeyIndex[normalized];
      if (!existing) {
        issueKeyIndex[normalized] = [kvsKey];
      } else if (!existing.includes(kvsKey)) {
        existing.push(kvsKey);
      }
    }
  });

  const meta: ShardedSuiteMetaV2 = {
    projectName: summary.projectName,
    datasetMode: summary.datasetMode ?? 'LIVE',
    initialized,
    standards: summary.standards,
    totalHazards: summary.totalHazards,
    classCCount: summary.classCCount,
    classBCount: summary.classBCount,
    classACount: summary.classACount,
    verifiedPercentage: summary.verifiedPercentage,
    releaseBlocked: summary.releaseBlocked,
    blockingReasons: [...summary.blockingReasons],
    signatureDriftCount: summary.signatureDriftCount,
    lastAuditTimestamp: summary.lastAuditTimestamp,
    linkKeys: [...linkKeys],
    ...(Object.keys(issueKeyIndex).length > 0 ? { issueKeyIndex } : {}),
    storageFormat: 'SHARDED_V2',
    version: nextVersion,
  };

  if (measureJsonBytes(meta) <= MAX_KVS_META_BYTES) {
    return { meta, metaShardItems: [] };
  }

  const metaShardItems: Array<{ key: string; value: string[] | Record<string, string[]> }> = [];
  if (measureJsonBytes(meta.blockingReasons) > 32 * 1024) {
    const reasonShards = shardStringArray(meta.blockingReasons, META_REASONS_SHARD_PREFIX, nextVersion);
    meta.blockingReasons = [];
    meta.blockingReasonShardKeys = reasonShards.map((s) => s.key);
    metaShardItems.push(...reasonShards);
  }

  if (measureJsonBytes(meta) > MAX_KVS_META_BYTES && meta.linkKeys.length > 0) {
    const linkShards = shardStringArray(meta.linkKeys, META_LINKS_SHARD_PREFIX, nextVersion);
    meta.linkKeys = [];
    meta.linkKeyShardKeys = linkShards.map((s) => s.key);
    metaShardItems.push(...linkShards);
  }

  if (measureJsonBytes(meta) > MAX_KVS_META_BYTES && meta.issueKeyIndex) {
    const indexShards = shardRecordOfStringArrays(
      meta.issueKeyIndex,
      META_INDEX_SHARD_PREFIX,
      nextVersion
    );
    delete meta.issueKeyIndex;
    meta.issueKeyIndexShardKeys = indexShards.map((s) => s.key);
    metaShardItems.push(...indexShards);
  }

  return { meta, metaShardItems };
}

async function batchGetStrict<T>(keys: string[]): Promise<Map<string, T>> {
  const result = new Map<string, T>();
  if (keys.length === 0) return result;

  for (const chunk of chunkArray(keys, BATCH_CHUNK_SIZE)) {
    const firstPass = await kvs.batchGet<T>(chunk.map((key) => ({ key })));
    for (const item of firstPass.successfulKeys || []) {
      result.set(item.key, item.value);
    }

    const failedOnce = firstPass.failedKeys || [];
    if (failedOnce.length > 0) {
      const retryPass = await kvs.batchGet<T>(failedOnce.map((f) => ({ key: f.key })));
      for (const item of retryPass.successfulKeys || []) {
        result.set(item.key, item.value);
      }
      if (retryPass.failedKeys && retryPass.failedKeys.length > 0) {
        const details = retryPass.failedKeys.map((f) => `${f.key}:${f.error?.code || 'ERR'}`).join(', ');
        throw new Error(`Failed to batch-read KVS shards after retry: ${details}`);
      }
    }
  }

  for (const key of keys) {
    if (!result.has(key)) {
      throw new Error(`Missing expected KVS shard key during fail-closed suite load: ${key}`);
    }
  }
  return result;
}

async function batchSetStrict(items: Array<{ key: string; value: unknown }>): Promise<string[]> {
  const writtenKeys: string[] = [];
  for (const chunk of chunkArray(items, BATCH_CHUNK_SIZE)) {
    const res = await kvs.batchSet(chunk);
    for (const item of chunk) {
      writtenKeys.push(item.key);
    }
    if (res.failedKeys && res.failedKeys.length > 0) {
      throw new Error(
        `Failed to persist compliance shards to Forge KVS: ${res.failedKeys.map((f) => `${f.key}:${f.error.code}`).join(', ')}`
      );
    }
  }
  return writtenKeys;
}

async function batchDeleteBestEffort(keys: string[]): Promise<void> {
  if (keys.length === 0) return;
  for (const chunk of chunkArray(keys, BATCH_CHUNK_SIZE)) {
    await kvs.batchDelete(chunk.map((key) => ({ key })));
  }
}

function getBaselineKeyCandidates(specId: string, pageId?: string, hazardKey?: string): {
  compositeKeys: string[];
  unscopedKeys: string[];
} {
  const compositeKeys: string[] = [];
  const unscopedKeys: string[] = [];

  const cleanSpec = specId.trim();
  const cleanPage = pageId?.trim() || '';
  const cleanHaz = hazardKey?.trim() || '';

  if (cleanHaz) {
    if (cleanSpec) {
      compositeKeys.push(sanitizeKvsKeySegment(`${cleanHaz}--${cleanSpec}`, 180));
    }
    if (cleanPage && cleanPage !== cleanSpec) {
      compositeKeys.push(sanitizeKvsKeySegment(`${cleanHaz}--${cleanPage}`, 180));
    }
  }
  if (cleanSpec) {
    unscopedKeys.push(sanitizeKvsKeySegment(cleanSpec, 180));
  }
  if (cleanPage && cleanPage !== cleanSpec) {
    unscopedKeys.push(sanitizeKvsKeySegment(cleanPage, 180));
  }

  return { compositeKeys, unscopedKeys };
}

function buildSignedBaselineRecord(
  link: TraceLink,
  signedBy: string,
  signedByAccountId: string,
  signedAt: string,
  role: string,
  meaning: string,
  authMethod: string,
  signatureSeal: string,
  hybrid?: {
    signatureAlgorithm?: 'HMAC-SHA256-SEAL-V1' | 'ECDSA-P256-SHA256+HMAC-SEAL-V1';
    clientPublicKeySpki?: string;
    clientSignatureBase64?: string;
    clientKeyFingerprint?: string;
  }
): SignedSpecBaseline {
  return {
    hazardKey: link.hazard.key,
    specId: link.spec.id,
    pageId: link.spec.pageId,
    sha256Hash: link.spec.sha256Hash,
    signedBy,
    signedByAccountId,
    signedAt,
    role,
    meaning,
    authMethod,
    signatureAlgorithm: hybrid?.signatureAlgorithm ?? 'HMAC-SHA256-SEAL-V1',
    signatureSeal,
    sealKeyId: 'env:MEDTRACE_PART11_SECRET',
    ...(hybrid?.clientPublicKeySpki ? { clientPublicKeySpki: hybrid.clientPublicKeySpki } : {}),
    ...(hybrid?.clientSignatureBase64
      ? { clientSignatureBase64: hybrid.clientSignatureBase64 }
      : {}),
    ...(hybrid?.clientKeyFingerprint
      ? { clientKeyFingerprint: hybrid.clientKeyFingerprint }
      : {}),
  };
}

function resolveTraceLinkByHazard(
  traceLinks: TraceLink[],
  hazardKey: string,
  specId?: string,
  workKey?: string,
  linkId?: string
): number {
  const cleanLinkId = linkId?.trim();
  const cleanHaz = (hazardKey || '').trim().toLowerCase();
  const cleanSpec = specId?.trim().toLowerCase();
  const cleanWork = workKey?.trim().toLowerCase();
  if (cleanLinkId) {
    return traceLinks.findIndex(
      (l) =>
        l.id === cleanLinkId &&
        (!cleanHaz || l.hazard.key.toLowerCase() === cleanHaz) &&
        (!cleanSpec || l.spec.id.toLowerCase() === cleanSpec) &&
        (!cleanWork || l.work.key.toLowerCase() === cleanWork)
    );
  }
  return traceLinks.findIndex(
    (l) =>
      l.hazard.key.toLowerCase() === cleanHaz &&
      (!cleanSpec || l.spec.id.toLowerCase() === cleanSpec) &&
      (!cleanWork || l.work.key.toLowerCase() === cleanWork)
  );
}

/**
 * Manages MedTrace compliance suite persistence, 21 CFR Part 11 sign-off workflows,
 * verification test recording, Jira issue binding, and demo fixtures.
 */
export class SeederService {
  private static inMemorySuite: ComplianceSummary | null = null;
  private static inMemoryVersion = 0;
  private static inMemorySignedSpecs = new Map<string, SignedSpecBaseline>();
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
    this.lastKvsShardState = null;
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
        const baseVersion =
          typeof params.expectedVersion === 'number' ? params.expectedVersion : previousState.version ?? 0;
        const rollbackExpectedVersion = baseVersion + 1;
        await this.saveComplianceSuite(previousSuiteSnapshot, rollbackExpectedVersion);
      }
      throw err;
    }
  }

  /**
   * 1-Click Demo Dataset Seeder (explicitly labeled DEMO mode; refuses to overwrite an initialized LIVE suite
   * unless `options.confirmOverwriteLive === true`).
   */
  static async seedEnterpriseDemoSuite(
    actorAccountId = 'system:demo-seeder',
    authMethod: AuditAuthMethod = 'SYSTEM_INIT',
    options?: SeedDemoOptions
  ): Promise<SeedDemoResponse> {
    const existing = await this.getSuiteWithVersion();
    if (existing.summary.datasetMode === 'LIVE' && existing.summary.initialized && !options?.confirmOverwriteLive) {
      throw new Error(
        'Refusing to overwrite initialized LIVE compliance suite with DEMO data without explicit confirmOverwriteLive: true.'
      );
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
        aggTraversalStatus: 'MODELED (demo lineage — live AGG query via queryGraphContext)',
      },
      {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10043',
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-102',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98305',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'MODELED (demo lineage — live AGG query via queryGraphContext)',
      },
      {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10044',
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-103',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98306',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'MODELED (demo lineage — live AGG query via queryGraphContext)',
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
    if (!cleanProject || suite.initialized === false || suite.traceLinks.length === 0) {
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
      storageFormat: 'SHARDED_V2',
      auditEntryCount: auditHead.lastSeq,
      auditHeadHash: auditHead.headHash,
    };
  }

  static async getActiveComplianceSuite(options?: GetSuiteOptions): Promise<ComplianceSummary> {
    if (options?.issueKeyFilter) {
      const fastPath = await this.loadFastPathSuiteByIssueKey(options.issueKeyFilter);
      if (fastPath) {
        return this.applyProjectKeyFilter(fastPath, options.projectKey);
      }
    }

    if (!isForgeRuntime()) {
      if (this.inMemorySuite) {
        const head = await AuditLogService.getHead();
        return this.applyProjectKeyFilter(
          cloneJsonValue({
            ...this.inMemorySuite,
            auditEntryCount: head.lastSeq,
            auditHeadHash: head.headHash,
          }),
          options?.projectKey
        );
      }
      return await this.getUninitializedLiveSuite();
    }

    const sharded = await this.loadShardedSuiteFromKvs();
    if (sharded) {
      return this.applyProjectKeyFilter(sharded.summary, options?.projectKey);
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
      return this.applyProjectKeyFilter(migrated, options?.projectKey);
    }

    return await this.getUninitializedLiveSuite();
  }

  /**
   * Returns the active compliance suite together with its current optimistic-lock version number.
   */
  static async getSuiteWithVersion(): Promise<{ summary: ComplianceSummary; version?: number }> {
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
        requireTestEvidence: current.datasetMode === 'LIVE',
      }
    );
    evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
    current.traceLinks[idx] = evaluated;

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'LIVE',
      current.projectName,
      { initialized: current.initialized ?? true }
    );

    return await this.commitSuiteMutation({
      summary: updated,
      expectedVersion: version,
      auditEntry: {
        actorAccountId,
        action: 'BIND_ISSUE',
        targetKey: targetLink.hazard.key,
        details: { previousIssueKey, newIssueKey: targetLink.work.key },
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
        requireTestEvidence: current.datasetMode === 'LIVE',
      }
    );
    evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
    current.traceLinks[idx] = evaluated;

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'LIVE',
      current.projectName,
      { initialized: current.initialized ?? true }
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
   * Enforces `MEDTRACE_PART11_SECRET`, §11.200 re-authentication + exact attestation phrase,
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
    if (params.attestation?.passwordConfirmed !== true) {
      throw new Error(
        '21 CFR Part 11 §11.200 Violation: Explicit re-authentication confirmation (passwordConfirmed: true) is required.'
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

    targetLink.signature.artifactSha256 = targetLink.spec.sha256Hash;
    targetLink.signature.isValid = true;
    targetLink.signature.signedAt = signedAt;
    targetLink.signature.signedBy = signedBy;
    targetLink.signature.signedByAccountId = signedByAccountId;
    targetLink.signature.role = role;
    targetLink.signature.meaning = meaning;
    targetLink.signature.authMethod = authMethod;
    targetLink.signature.signatureAlgorithm = signatureAlgorithm;
    targetLink.signature.signatureSeal = signatureSeal;
    targetLink.signature.sealKeyId = 'env:MEDTRACE_PART11_SECRET';
    if (hasHybridInput) {
      targetLink.signature.clientPublicKeySpki = rawClientPub;
      targetLink.signature.clientSignatureBase64 = rawClientSig;
      targetLink.signature.clientKeyFingerprint = clientKeyFingerprint;
    } else {
      targetLink.signature.clientPublicKeySpki = undefined;
      targetLink.signature.clientSignatureBase64 = undefined;
      targetLink.signature.clientKeyFingerprint = undefined;
    }
    targetLink.signature.invalidatedAt = undefined;
    targetLink.signature.invalidationReason = undefined;
    targetLink.spec.lastSignedHash = targetLink.spec.sha256Hash;
    targetLink.spec.isSignatureInvalidated = false;

    const evaluated = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      targetLink.graphMetadata,
      { linkId: targetLink.id, part11Secret, requireCryptographicSeal: true }
    );
    evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
    current.traceLinks[idx] = evaluated;

    const baselineRecord = buildSignedBaselineRecord(
      targetLink,
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
      { initialized: current.initialized ?? true }
    );

    return await this.commitSuiteMutation({
      summary: updated,
      expectedVersion: version,
      baselineUpdates: [{ action: 'SET', baseline: baselineRecord }],
      auditEntry: {
        actorAccountId: signedByAccountId,
        action: 'PART11_SIGNOFF',
        targetKey: targetLink.hazard.key,
        details: {
          specId: targetLink.spec.id,
          artifactSha256: targetLink.spec.sha256Hash,
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
