import { kvs } from '@forge/kvs';
import crypto from 'node:crypto';
import { canonicalJsonStringify, isKvsConflictError, measureJsonBytes } from './crypto-utils';
import { isForgeRuntime } from './runtime';
import {
  AuditActionType,
  AuditAuthMethod,
  AuditChainVerificationResult,
  AuditLogEntry,
  VerifyAuditChainOptions,
} from './types';

export const AUDIT_GENESIS_HASH = '0'.repeat(64);
export const MAX_AUDIT_ENTRY_BYTES = 220 * 1024;
export const AUDIT_BATCH_CHUNK_SIZE = 25;
export const AUDIT_TAIL_PROBE_BATCH_SIZE = 10;
export const AUDIT_TAIL_MAX_RECOVERY_HOPS = 500;

const AUDIT_HEAD_KEY = 'medtrace:audit:head';
const AUDIT_ENTRY_PREFIX = 'medtrace:audit:entry:';

export interface AuditHead {
  lastSeq: number;
  headHash: string;
}

export interface AuditStorageAdapter {
  getHead(): Promise<AuditHead>;
  setHead(head: AuditHead): Promise<void>;
  getEntry(seq: number): Promise<AuditLogEntry | undefined>;
  getEntriesBatch?(seqs: number[]): Promise<Map<number, AuditLogEntry>>;
  createEntryImmutable(seq: number, entry: AuditLogEntry): Promise<'CREATED' | 'EXISTS'>;
}

export type BatchAuditStorageAdapter = AuditStorageAdapter &
  Required<Pick<AuditStorageAdapter, 'getEntriesBatch'>>;

function cloneAuditValue<T>(value: T): T {
  if (value === undefined) return value;
  if (typeof structuredClone === 'function') {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value)) as T;
}

async function fetchEntriesBatchFromAdapter(
  adapter: AuditStorageAdapter,
  seqs: number[]
): Promise<Map<number, AuditLogEntry>> {
  const uniqueSeqs = Array.from(new Set(seqs.filter((seq) => Number.isInteger(seq) && seq >= 1)));
  if (uniqueSeqs.length === 0) {
    return new Map<number, AuditLogEntry>();
  }
  if (typeof adapter.getEntriesBatch === 'function') {
    return await adapter.getEntriesBatch(uniqueSeqs);
  }
  const fetched = await Promise.all(
    uniqueSeqs.map(async (seq) => ({ seq, entry: await adapter.getEntry(seq) }))
  );
  const map = new Map<number, AuditLogEntry>();
  for (const item of fetched) {
    if (item.entry) {
      map.set(item.seq, item.entry);
    }
  }
  return map;
}

async function resolveChainTailFromHead(
  adapter: AuditStorageAdapter,
  initialHead: AuditHead
): Promise<AuditHead> {
  let current: AuditHead = {
    lastSeq:
      typeof initialHead?.lastSeq === 'number' && Number.isInteger(initialHead.lastSeq) && initialHead.lastSeq >= 0
        ? initialHead.lastSeq
        : 0,
    headHash:
      typeof initialHead?.headHash === 'string' && initialHead.headHash
        ? initialHead.headHash
        : AUDIT_GENESIS_HASH,
  };

  let probedHops = 0;
  while (probedHops < AUDIT_TAIL_MAX_RECOVERY_HOPS) {
    const remaining = AUDIT_TAIL_MAX_RECOVERY_HOPS - probedHops;
    const batchCount = Math.min(AUDIT_TAIL_PROBE_BATCH_SIZE, remaining);
    const startSeq = current.lastSeq + 1;
    const seqs: number[] = [];
    for (let i = 0; i < batchCount; i++) {
      seqs.push(startSeq + i);
    }

    const foundMap = await fetchEntriesBatchFromAdapter(adapter, seqs);
    let advancedInBatch = 0;
    for (const seq of seqs) {
      const nextEntry = foundMap.get(seq);
      if (!nextEntry) {
        break;
      }
      current = {
        lastSeq: seq,
        headHash: nextEntry.entryHash,
      };
      advancedInBatch++;
      probedHops++;
    }

    if (advancedInBatch < batchCount) {
      break;
    }
  }

  return current;
}

/**
 * Computes deterministic SHA-256 hash over an audit log entry's immutable fields.
 */
export function computeAuditEntryHash(entry: Omit<AuditLogEntry, 'entryHash'>): string {
  const canonical = canonicalJsonStringify({
    seq: entry.seq,
    timestamp: entry.timestamp,
    actorAccountId: entry.actorAccountId,
    action: entry.action,
    targetKey: entry.targetKey,
    details: entry.details,
    prevHash: entry.prevHash,
    authMethod: entry.authMethod,
  });
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export const kvsAuditStorageAdapter: BatchAuditStorageAdapter = {
  getHead: async (): Promise<AuditHead> => {
    const head = (await kvs.get(AUDIT_HEAD_KEY)) as AuditHead | undefined;
    return head && typeof head.lastSeq === 'number' && typeof head.headHash === 'string'
      ? head
      : { lastSeq: 0, headHash: AUDIT_GENESIS_HASH };
  },
  setHead: async (head: AuditHead): Promise<void> => {
    if (typeof head?.lastSeq !== 'number' || !Number.isInteger(head.lastSeq) || head.lastSeq < 0) {
      return;
    }
    let targetHead = head;
    for (let attempt = 0; attempt < 8; attempt++) {
      const prev = await kvs.set<AuditHead, AuditHead>(AUDIT_HEAD_KEY, targetHead, {
        keyPolicy: 'OVERRIDE',
        returnValue: 'PREVIOUS',
      });
      if (!prev?.value || typeof prev.value.lastSeq !== 'number' || prev.value.lastSeq <= targetHead.lastSeq) {
        return;
      }
      // Recover monotonically if a concurrent or prior writer already recorded a higher head.
      targetHead = await resolveChainTailFromHead(kvsAuditStorageAdapter, prev.value);
    }
  },
  getEntry: async (seq: number): Promise<AuditLogEntry | undefined> => {
    return (await kvs.get(`${AUDIT_ENTRY_PREFIX}${seq}`)) as AuditLogEntry | undefined;
  },
  getEntriesBatch: async (seqs: number[]): Promise<Map<number, AuditLogEntry>> => {
    const uniqueSeqs = Array.from(new Set(seqs.filter((seq) => Number.isInteger(seq) && seq >= 1)));
    const result = new Map<number, AuditLogEntry>();
    if (uniqueSeqs.length === 0) {
      return result;
    }

    const keyToSeq = new Map<string, number>();
    const allKeys: string[] = [];
    for (const seq of uniqueSeqs) {
      const key = `${AUDIT_ENTRY_PREFIX}${seq}`;
      keyToSeq.set(key, seq);
      allKeys.push(key);
    }

    for (let i = 0; i < allKeys.length; i += AUDIT_BATCH_CHUNK_SIZE) {
      const chunkKeys = allKeys.slice(i, i + AUDIT_BATCH_CHUNK_SIZE);
      const batchRes = await kvs.batchGet<AuditLogEntry>(chunkKeys.map((key) => ({ key })));
      for (const item of batchRes.successfulKeys || []) {
        const seq = keyToSeq.get(item.key);
        if (seq !== undefined && item.value !== undefined) {
          result.set(seq, item.value);
        }
      }

      if (batchRes.failedKeys && batchRes.failedKeys.length > 0) {
        const retryable = batchRes.failedKeys.filter((failed) => failed.error?.code !== 'KEY_NOT_FOUND');
        if (retryable.length > 0) {
          const retryRes = await kvs.batchGet<AuditLogEntry>(
            retryable.map((failed) => ({ key: failed.key }))
          );
          for (const item of retryRes.successfulKeys || []) {
            const seq = keyToSeq.get(item.key);
            if (seq !== undefined && item.value !== undefined) {
              result.set(seq, item.value);
            }
          }
          if (retryRes.failedKeys && retryRes.failedKeys.length > 0) {
            const terminal = retryRes.failedKeys.filter((failed) => failed.error?.code !== 'KEY_NOT_FOUND');
            if (terminal.length > 0) {
              const detail = terminal
                .map((failed) => `${failed.key}:${failed.error?.code || 'ERROR'}`)
                .join(', ');
              throw new Error(`Failed to batch-read audit log entries from Forge KVS: ${detail}`);
            }
          }
        }
      }
    }

    return result;
  },
  createEntryImmutable: async (seq: number, entry: AuditLogEntry): Promise<'CREATED' | 'EXISTS'> => {
    try {
      await kvs.set(`${AUDIT_ENTRY_PREFIX}${seq}`, entry, { keyPolicy: 'FAIL_IF_EXISTS' });
      return 'CREATED';
    } catch (err) {
      if (isKvsConflictError(err)) {
        return 'EXISTS';
      }
      throw err;
    }
  },
};

export function createInMemoryAuditStorageAdapter(): BatchAuditStorageAdapter {
  let head: AuditHead = { lastSeq: 0, headHash: AUDIT_GENESIS_HASH };
  const entries = new Map<number, AuditLogEntry>();
  return {
    getHead: async () => ({ ...head }),
    setHead: async (next: AuditHead) => {
      if (typeof next?.lastSeq !== 'number' || !Number.isInteger(next.lastSeq) || next.lastSeq <= head.lastSeq) {
        return;
      }
      head = { lastSeq: next.lastSeq, headHash: next.headHash };
    },
    getEntry: async (seq: number) => {
      const entry = entries.get(seq);
      return entry ? cloneAuditValue(entry) : undefined;
    },
    getEntriesBatch: async (seqs: number[]) => {
      const uniqueSeqs = Array.from(new Set(seqs.filter((seq) => Number.isInteger(seq) && seq >= 1)));
      const result = new Map<number, AuditLogEntry>();
      for (const seq of uniqueSeqs) {
        const entry = entries.get(seq);
        if (entry) {
          result.set(seq, cloneAuditValue(entry));
        }
      }
      return result;
    },
    createEntryImmutable: async (seq: number, entry: AuditLogEntry) => {
      if (entries.has(seq)) {
        return 'EXISTS';
      }
      entries.set(seq, cloneAuditValue(entry));
      return 'CREATED';
    },
  };
}

let inMemoryAuditAdapter: BatchAuditStorageAdapter = createInMemoryAuditStorageAdapter();
let customAuditAdapter: AuditStorageAdapter | null = null;

function getActiveAdapter(): AuditStorageAdapter {
  if (customAuditAdapter) return customAuditAdapter;
  if (isForgeRuntime()) return kvsAuditStorageAdapter;
  return inMemoryAuditAdapter;
}

export function setAuditStorageAdapter(adapter: AuditStorageAdapter | null): void {
  customAuditAdapter = adapter;
}

export function resetInMemoryAuditStorage(): void {
  inMemoryAuditAdapter = createInMemoryAuditStorageAdapter();
}

export class AuditLogService {
  /**
   * Resolves the true chain tail by checking the stored head pointer and probing forward
   * in batches of 10 (capped at 500 hops) in case entries were written before a head update.
   */
  private static async resolveChainTail(adapter: AuditStorageAdapter): Promise<AuditHead> {
    const head = await adapter.getHead();
    return await resolveChainTailFromHead(adapter, head);
  }

  public static async append(params: {
    actorAccountId: string;
    action: AuditActionType | string;
    targetKey: string;
    details?: Record<string, unknown>;
    authMethod: AuditAuthMethod | string;
    timestamp?: string;
  }): Promise<AuditLogEntry> {
    const adapter = getActiveAdapter();
    const maxAttempts = 12;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const tail = await this.resolveChainTail(adapter);
      const seq = tail.lastSeq + 1;
      const prevHash = tail.headHash || AUDIT_GENESIS_HASH;
      const baseEntry: Omit<AuditLogEntry, 'entryHash'> = {
        seq,
        timestamp: params.timestamp || new Date().toISOString(),
        actorAccountId: params.actorAccountId || 'unknown',
        action: params.action,
        targetKey: params.targetKey,
        details: params.details || {},
        prevHash,
        authMethod: params.authMethod,
      };
      const entryHash = computeAuditEntryHash(baseEntry);
      const fullEntry: AuditLogEntry = { ...baseEntry, entryHash };

      const entryBytes = measureJsonBytes(fullEntry);
      if (entryBytes > MAX_AUDIT_ENTRY_BYTES) {
        throw new Error(
          `AuditLogService: Audit entry size (${entryBytes} bytes) exceeds maximum ${MAX_AUDIT_ENTRY_BYTES} bytes.`
        );
      }

      const outcome = await adapter.createEntryImmutable(seq, fullEntry);
      if (outcome === 'CREATED') {
        await adapter.setHead({ lastSeq: seq, headHash: entryHash });
        return fullEntry;
      }
      // Collision on seq: another concurrent writer claimed seq; loop and advance to new tail.
    }

    throw new Error('AuditLogService: Failed to append immutable audit entry after concurrency retries.');
  }

  public static async getHead(): Promise<AuditHead> {
    const adapter = getActiveAdapter();
    return await this.resolveChainTail(adapter);
  }

  /**
   * Returns up to `limit` entries strictly older than `beforeSeq` (or most recent when omitted),
   * sorted in ascending chronological `seq` order.
   */
  public static async getAuditLog(limit: number = 50, beforeSeq?: number): Promise<AuditLogEntry[]> {
    const adapter = getActiveAdapter();
    const safeLimit = Math.max(
      1,
      Math.min(200, Math.floor(typeof limit === 'number' && Number.isFinite(limit) && limit !== 0 ? limit : 50))
    );

    if (beforeSeq !== undefined) {
      if (typeof beforeSeq !== 'number' || !Number.isFinite(beforeSeq) || Math.floor(beforeSeq) <= 1) {
        return [];
      }
    }

    const tail = await this.resolveChainTail(adapter);
    if (tail.lastSeq === 0) return [];

    const endSeq =
      beforeSeq !== undefined ? Math.min(tail.lastSeq, Math.floor(beforeSeq) - 1) : tail.lastSeq;
    if (endSeq < 1) return [];

    const startSeq = Math.max(1, endSeq - safeLimit + 1);
    const seqs: number[] = [];
    for (let seq = startSeq; seq <= endSeq; seq++) {
      seqs.push(seq);
    }

    const entryMap = await fetchEntriesBatchFromAdapter(adapter, seqs);
    const entries: AuditLogEntry[] = [];
    for (const seq of seqs) {
      const entry = entryMap.get(seq);
      if (entry) entries.push(entry);
    }
    return entries;
  }

  /**
   * Default upper bound on entries scanned in a single `verifyAuditChain` invocation so
   * multi-thousand-entry chains cannot breach the 25s Forge invocation timeout.
   */
  private static readonly DEFAULT_VERIFY_MAX_ENTRIES = 500;

  private static resolveDefaultVerifyMaxEntries(): number {
    const raw = process.env.MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES;
    if (typeof raw === 'string' && raw.trim() !== '') {
      const parsed = Number(raw);
      if (Number.isFinite(parsed) && parsed >= 1) {
        return Math.floor(parsed);
      }
    }
    return this.DEFAULT_VERIFY_MAX_ENTRIES;
  }

  /**
   * Verifies SHA-256 hash linkage and entry integrity across the audit ledger using batched reads.
   * Scans up to `options.maxEntries` (defaulting to `MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES` or 500)
   * starting at `fromSeq` (default 1), anchored against predecessor `startSeq - 1` (and optional
   * `expectedPrevHash`) to keep every invocation bounded within Forge KVS/execution limits.
   */
  public static async verifyAuditChain(
    options?: VerifyAuditChainOptions
  ): Promise<AuditChainVerificationResult> {
    const adapter = getActiveAdapter();
    const tail = await this.resolveChainTail(adapter);
    const isBounded =
      options !== undefined &&
      (options.fromSeq !== undefined ||
        options.maxEntries !== undefined ||
        options.expectedPrevHash !== undefined);

    const startSeq =
      typeof options?.fromSeq === 'number' && Number.isFinite(options.fromSeq) && options.fromSeq >= 1
        ? Math.floor(options.fromSeq)
        : 1;
    const maxEntries =
      typeof options?.maxEntries === 'number' &&
      Number.isFinite(options.maxEntries) &&
      options.maxEntries >= 1
        ? Math.floor(options.maxEntries)
        : this.resolveDefaultVerifyMaxEntries();

    if (tail.lastSeq === 0) {
      return {
        valid: true,
        totalEntries: 0,
        headHash: AUDIT_GENESIS_HASH,
        ...(isBounded
          ? {
              verifiedFromSeq: startSeq,
              verifiedToSeq: 0,
              truncated: false,
              windowEntryCount: 0,
            }
          : {}),
      };
    }

    if (startSeq > tail.lastSeq) {
      return {
        valid: true,
        totalEntries: tail.lastSeq,
        headHash: tail.headHash,
        ...(isBounded
          ? {
              verifiedFromSeq: startSeq,
              verifiedToSeq: tail.lastSeq,
              truncated: false,
              windowEntryCount: 0,
            }
          : {}),
      };
    }

    const endSeq = Math.min(tail.lastSeq, startSeq + maxEntries - 1);
    const truncated = endSeq < tail.lastSeq;
    const windowMeta: Partial<AuditChainVerificationResult> =
      isBounded || truncated
        ? {
            verifiedFromSeq: startSeq,
            verifiedToSeq: endSeq,
            windowEntryCount: endSeq - startSeq + 1,
            truncated,
            ...(truncated ? { nextFromSeq: endSeq + 1 } : {}),
          }
        : {};

    let expectedPrevHash = AUDIT_GENESIS_HASH;
    if (startSeq === 1) {
      if (options?.expectedPrevHash !== undefined && options.expectedPrevHash !== AUDIT_GENESIS_HASH) {
        return {
          valid: false,
          totalEntries: tail.lastSeq,
          headHash: tail.headHash,
          brokenAtSeq: 1,
          reason: `Window anchor mismatch at genesis: expected ${options.expectedPrevHash.slice(0, 12)}, found ${AUDIT_GENESIS_HASH.slice(0, 12)}.`,
          ...windowMeta,
        };
      }
    } else {
      const predSeq = startSeq - 1;
      const predMap = await fetchEntriesBatchFromAdapter(adapter, [predSeq]);
      const predEntry = predMap.get(predSeq);
      if (!predEntry) {
        return {
          valid: false,
          totalEntries: tail.lastSeq,
          headHash: tail.headHash,
          brokenAtSeq: predSeq,
          reason: `Missing predecessor audit log entry at sequence ${predSeq}.`,
          ...windowMeta,
        };
      }
      if (predEntry.seq !== predSeq) {
        return {
          valid: false,
          totalEntries: tail.lastSeq,
          headHash: tail.headHash,
          brokenAtSeq: predSeq,
          reason: `Sequence mismatch at predecessor ${predSeq}: found ${predEntry.seq}.`,
          ...windowMeta,
        };
      }
      const predRecomputed = computeAuditEntryHash(predEntry);
      if (predRecomputed !== predEntry.entryHash) {
        return {
          valid: false,
          totalEntries: tail.lastSeq,
          headHash: tail.headHash,
          brokenAtSeq: predSeq,
          reason: `Tampered payload at predecessor seq ${predSeq}: entryHash mismatch.`,
          ...windowMeta,
        };
      }
      if (options?.expectedPrevHash !== undefined && predEntry.entryHash !== options.expectedPrevHash) {
        return {
          valid: false,
          totalEntries: tail.lastSeq,
          headHash: tail.headHash,
          brokenAtSeq: startSeq,
          reason: `Window anchor mismatch at predecessor seq ${predSeq}: expected ${options.expectedPrevHash.slice(0, 12)}, found ${predEntry.entryHash.slice(0, 12)}.`,
          ...windowMeta,
        };
      }
      expectedPrevHash = predEntry.entryHash;
    }

    for (let chunkStart = startSeq; chunkStart <= endSeq; chunkStart += AUDIT_BATCH_CHUNK_SIZE) {
      const chunkEnd = Math.min(endSeq, chunkStart + AUDIT_BATCH_CHUNK_SIZE - 1);
      const chunkSeqs: number[] = [];
      for (let seq = chunkStart; seq <= chunkEnd; seq++) {
        chunkSeqs.push(seq);
      }

      const entryMap = await fetchEntriesBatchFromAdapter(adapter, chunkSeqs);
      for (const seq of chunkSeqs) {
        const entry = entryMap.get(seq);
        if (!entry) {
          return {
            valid: false,
            totalEntries: tail.lastSeq,
            headHash: tail.headHash,
            brokenAtSeq: seq,
            reason: `Missing audit log entry at sequence ${seq}.`,
            ...windowMeta,
          };
        }
        if (entry.seq !== seq) {
          return {
            valid: false,
            totalEntries: tail.lastSeq,
            headHash: tail.headHash,
            brokenAtSeq: seq,
            reason: `Sequence mismatch at ${seq}: found ${entry.seq}.`,
            ...windowMeta,
          };
        }
        if (entry.prevHash !== expectedPrevHash) {
          const prevPreview = typeof entry.prevHash === 'string' ? entry.prevHash.slice(0, 12) : String(entry.prevHash);
          return {
            valid: false,
            totalEntries: tail.lastSeq,
            headHash: tail.headHash,
            brokenAtSeq: seq,
            reason: `Hash chain break at seq ${seq}: prevHash ${prevPreview} !== expected ${expectedPrevHash.slice(0, 12)}.`,
            ...windowMeta,
          };
        }
        const recomputed = computeAuditEntryHash(entry);
        if (recomputed !== entry.entryHash) {
          return {
            valid: false,
            totalEntries: tail.lastSeq,
            headHash: tail.headHash,
            brokenAtSeq: seq,
            reason: `Tampered payload at seq ${seq}: entryHash mismatch.`,
            ...windowMeta,
          };
        }
        expectedPrevHash = entry.entryHash;
      }
    }

    return {
      valid: true,
      totalEntries: tail.lastSeq,
      headHash: expectedPrevHash,
      ...windowMeta,
    };
  }
}
