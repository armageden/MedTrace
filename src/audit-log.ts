import { kvs, ForgeKvsAPIError } from '@forge/kvs';
import crypto from 'node:crypto';
import { isForgeRuntime } from './runtime';
import { AuditActionType, AuditAuthMethod, AuditChainVerification, AuditLogEntry } from './types';

export const AUDIT_GENESIS_HASH = '0'.repeat(64);
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
  createEntryImmutable(seq: number, entry: AuditLogEntry): Promise<'CREATED' | 'EXISTS'>;
}

function isKeyAlreadyExistsError(err: unknown): boolean {
  if (err instanceof ForgeKvsAPIError) {
    if (err.responseDetails?.status === 409) return true;
    if (/EXISTS|CONFLICT/i.test(err.code || '')) return true;
    if (/already exists|conflict/i.test(err.message || '')) return true;
  }
  const anyErr = err as { status?: number; code?: string; message?: string } | undefined;
  if (anyErr?.status === 409) return true;
  if (anyErr?.code && /EXISTS|CONFLICT/i.test(anyErr.code)) return true;
  if (anyErr?.message && /already exists|key already exists/i.test(anyErr.message)) return true;
  return false;
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Computes deterministic SHA-256 hash over an audit log entry's immutable fields.
 */
export function computeAuditEntryHash(entry: Omit<AuditLogEntry, 'entryHash'>): string {
  const canonical = JSON.stringify(
    sortKeysDeep({
      seq: entry.seq,
      timestamp: entry.timestamp,
      actorAccountId: entry.actorAccountId,
      action: entry.action,
      targetKey: entry.targetKey,
      details: entry.details,
      prevHash: entry.prevHash,
      authMethod: entry.authMethod,
    })
  );
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

export const kvsAuditStorageAdapter: AuditStorageAdapter = {
  getHead: async (): Promise<AuditHead> => {
    const head = (await kvs.get(AUDIT_HEAD_KEY)) as AuditHead | undefined;
    return head && typeof head.lastSeq === 'number' && typeof head.headHash === 'string'
      ? head
      : { lastSeq: 0, headHash: AUDIT_GENESIS_HASH };
  },
  setHead: async (head: AuditHead): Promise<void> => {
    await kvs.set(AUDIT_HEAD_KEY, head);
  },
  getEntry: async (seq: number): Promise<AuditLogEntry | undefined> => {
    return (await kvs.get(`${AUDIT_ENTRY_PREFIX}${seq}`)) as AuditLogEntry | undefined;
  },
  createEntryImmutable: async (seq: number, entry: AuditLogEntry): Promise<'CREATED' | 'EXISTS'> => {
    try {
      await kvs.set(`${AUDIT_ENTRY_PREFIX}${seq}`, entry, { keyPolicy: 'FAIL_IF_EXISTS' });
      return 'CREATED';
    } catch (err) {
      if (isKeyAlreadyExistsError(err)) {
        return 'EXISTS';
      }
      throw err;
    }
  },
};

export function createInMemoryAuditStorageAdapter(): AuditStorageAdapter {
  let head: AuditHead = { lastSeq: 0, headHash: AUDIT_GENESIS_HASH };
  const entries = new Map<number, AuditLogEntry>();
  return {
    getHead: async () => ({ ...head }),
    setHead: async (next: AuditHead) => {
      head = { ...next };
    },
    getEntry: async (seq: number) => entries.get(seq),
    createEntryImmutable: async (seq: number, entry: AuditLogEntry) => {
      if (entries.has(seq)) {
        return 'EXISTS';
      }
      entries.set(seq, entry);
      return 'CREATED';
    },
  };
}

let inMemoryAuditAdapter: AuditStorageAdapter = createInMemoryAuditStorageAdapter();
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
   * in case an entry was written right before a head update failure.
   */
  private static async resolveChainTail(adapter: AuditStorageAdapter): Promise<AuditHead> {
    let head = await adapter.getHead();
    while (true) {
      const nextEntry = await adapter.getEntry(head.lastSeq + 1);
      if (!nextEntry) break;
      head = { lastSeq: nextEntry.seq, headHash: nextEntry.entryHash };
    }
    return head;
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
   * Returns up to `limit` most recent entries in chronological order (oldest-to-newest within window).
   */
  public static async getAuditLog(limit: number = 50): Promise<AuditLogEntry[]> {
    const adapter = getActiveAdapter();
    const safeLimit = Math.max(1, Math.min(200, Math.floor(limit || 50)));
    const tail = await this.resolveChainTail(adapter);
    if (tail.lastSeq === 0) return [];

    const startSeq = Math.max(1, tail.lastSeq - safeLimit + 1);
    const entries: AuditLogEntry[] = [];
    for (let seq = startSeq; seq <= tail.lastSeq; seq++) {
      const entry = await adapter.getEntry(seq);
      if (entry) entries.push(entry);
    }
    return entries;
  }

  /**
   * Verifies SHA-256 hash linkage and entry integrity across the full audit ledger.
   */
  public static async verifyAuditChain(): Promise<AuditChainVerification> {
    const adapter = getActiveAdapter();
    const tail = await this.resolveChainTail(adapter);
    if (tail.lastSeq === 0) {
      return {
        valid: true,
        totalEntries: 0,
        headHash: AUDIT_GENESIS_HASH,
      };
    }

    let expectedPrevHash = AUDIT_GENESIS_HASH;
    for (let seq = 1; seq <= tail.lastSeq; seq++) {
      const entry = await adapter.getEntry(seq);
      if (!entry) {
        return {
          valid: false,
          totalEntries: tail.lastSeq,
          headHash: tail.headHash,
          brokenAtSeq: seq,
          reason: `Missing audit log entry at sequence ${seq}.`,
        };
      }
      if (entry.seq !== seq) {
        return {
          valid: false,
          totalEntries: tail.lastSeq,
          headHash: tail.headHash,
          brokenAtSeq: seq,
          reason: `Sequence mismatch at ${seq}: found ${entry.seq}.`,
        };
      }
      if (entry.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          totalEntries: tail.lastSeq,
          headHash: tail.headHash,
          brokenAtSeq: seq,
          reason: `Hash chain break at seq ${seq}: prevHash ${entry.prevHash.slice(0, 12)} !== expected ${expectedPrevHash.slice(0, 12)}.`,
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
        };
      }
      expectedPrevHash = entry.entryHash;
    }

    return {
      valid: true,
      totalEntries: tail.lastSeq,
      headHash: expectedPrevHash,
    };
  }
}
