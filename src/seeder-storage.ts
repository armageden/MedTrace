import { kvs } from '@forge/kvs';
import { measureJsonBytes, sanitizeKvsKeySegment } from './crypto-utils';
import { ComplianceSummary, TraceLink } from './types';

export const SUITE_META_KEY = 'medtrace:compliance:suite_meta';
export const LINK_KEY_PREFIX = 'medtrace:compliance:link:';
export const SIGNED_SPEC_PREFIX = 'medtrace:compliance:signed_spec:';
export const VLOCK_PREFIX = 'medtrace:compliance:vlock:';
const META_REASONS_SHARD_PREFIX = 'medtrace:compliance:meta_reasons:';
const META_LINKS_SHARD_PREFIX = 'medtrace:compliance:meta_links:';
const META_INDEX_SHARD_PREFIX = 'medtrace:compliance:meta_index:';
export const LEGACY_STORAGE_KEY = 'medtrace:compliance:active_suite';

export const BATCH_CHUNK_SIZE = 25;
export const MAX_TRANSACT_BYTES = Math.floor(3.5 * 1024 * 1024);
const MAX_KVS_META_BYTES = 128 * 1024;
const MAX_META_SHARD_BYTES = 96 * 1024;
export const MAX_AUDIT_DETAILS_BYTES = 200 * 1024;
const MAX_KVS_KEY_LENGTH = 500;
const FORGE_KVS_KEY_REGEX = /^(?!\s+$)[a-zA-Z0-9:._\s-#]+$/;
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

export interface ShardedSuiteMetaV2 {
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

export function cloneJsonValue<T>(val: T): T {
  return JSON.parse(JSON.stringify(val)) as T;
}

export function buildSafeKvsKey(prefix: string, rawSegment: string): string {
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

export function buildMetaAndShardItems(
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
  const shardReasons = () => {
    if (meta.blockingReasons.length === 0) return;
    const reasonShards = shardStringArray(meta.blockingReasons, META_REASONS_SHARD_PREFIX, nextVersion);
    meta.blockingReasons = [];
    meta.blockingReasonShardKeys = reasonShards.map((s) => s.key);
    metaShardItems.push(...reasonShards);
  };

  if (measureJsonBytes(meta.blockingReasons) > 32 * 1024) {
    shardReasons();
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

  if (measureJsonBytes(meta) > MAX_KVS_META_BYTES && meta.blockingReasons.length > 0) {
    shardReasons();
  }

  return { meta, metaShardItems };
}

export async function batchGetStrict<T>(keys: string[]): Promise<Map<string, T>> {
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

export async function batchSetStrict(items: Array<{ key: string; value: unknown }>): Promise<string[]> {
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

export async function batchDeleteBestEffort(keys: string[]): Promise<void> {
  if (keys.length === 0) return;
  for (const chunk of chunkArray(keys, BATCH_CHUNK_SIZE)) {
    await kvs.batchDelete(chunk.map((key) => ({ key })));
  }
}

export function getBaselineKeyCandidates(specId: string, pageId?: string, hazardKey?: string): {
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

export function buildSignedBaselineRecord(
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

export function resolveTraceLinkByHazard(
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

