import { kvs, ForgeKvsAPIError } from '@forge/kvs';
import crypto from 'node:crypto';
import { isForgeRuntime } from './runtime';

export interface NonceRecord {
  consumedAt: number;
}

export type NonceClaimResult = 'CLAIMED' | 'REPLAY' | 'STORAGE_ERROR';

export interface NonceStore {
  get(key: string): Promise<NonceRecord | undefined>;
  set(key: string, val: NonceRecord): Promise<void>;
  delete(key: string): Promise<void>;
  claim(key: string, val: NonceRecord, ttlMs: number): Promise<boolean>;
  claimDetailed?(key: string, val: NonceRecord, ttlMs: number): Promise<NonceClaimResult>;
}

/**
 * Hashes raw nonce key strings to a fixed-length SHA-256 KVS key so arbitrary
 * characters in caller-supplied nonces never violate Forge KVS key regex rules.
 */
export function toKvsNonceKey(key: string): string {
  return `nonce:${crypto.createHash('sha256').update(key).digest('hex')}`;
}

function isNonceConflictError(err: unknown): boolean {
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

export const kvsNonceStore: NonceStore = {
  get: async (key: string): Promise<NonceRecord | undefined> => {
    return (await kvs.get(toKvsNonceKey(key))) as NonceRecord | undefined;
  },
  set: async (key: string, val: NonceRecord): Promise<void> => {
    await kvs.set(toKvsNonceKey(key), val);
  },
  delete: async (key: string): Promise<void> => {
    await kvs.delete(toKvsNonceKey(key));
  },
  claim: async (key: string, val: NonceRecord, ttlMs: number): Promise<boolean> => {
    const result = await kvsNonceStore.claimDetailed!(key, val, ttlMs);
    if (result === 'STORAGE_ERROR') {
      throw new Error('Forge KVS storage error while claiming replay-protection nonce.');
    }
    return result === 'CLAIMED';
  },
  claimDetailed: async (key: string, val: NonceRecord, ttlMs: number): Promise<NonceClaimResult> => {
    try {
      await kvs.set(toKvsNonceKey(key), val, {
        keyPolicy: 'FAIL_IF_EXISTS',
        ttl: { value: Math.max(1, Math.ceil(ttlMs / 60000)), unit: 'MINUTES' },
      });
      return 'CLAIMED';
    } catch (err) {
      if (isNonceConflictError(err)) {
        return 'REPLAY';
      }
      console.error('[MedTrace NonceStore] KVS error during nonce claim:', err);
      return 'STORAGE_ERROR';
    }
  },
};

export function createInMemoryNonceStore(): NonceStore {
  const store = new Map<string, NonceRecord>();
  return {
    get: async (key: string) => store.get(key),
    set: async (key: string, val: NonceRecord) => {
      store.set(key, val);
    },
    delete: async (key: string) => {
      store.delete(key);
    },
    claim: async (key: string, val: NonceRecord, ttlMs: number) => {
      const existing = store.get(key);
      const now = Date.now();
      if (existing && now - existing.consumedAt < ttlMs) {
        return false;
      }
      if (existing) store.delete(key);
      store.set(key, val);
      return true;
    },
    claimDetailed: async (key: string, val: NonceRecord, ttlMs: number): Promise<NonceClaimResult> => {
      const existing = store.get(key);
      const now = Date.now();
      if (existing && now - existing.consumedAt < ttlMs) {
        return 'REPLAY';
      }
      if (existing) store.delete(key);
      store.set(key, val);
      return 'CLAIMED';
    },
  };
}

let customNonceStore: NonceStore | null = null;
const defaultInMemoryStore: NonceStore = createInMemoryNonceStore();

export function setNonceStore(store: NonceStore): void {
  customNonceStore = store;
}

export function getNonceStore(): NonceStore {
  if (customNonceStore) return customNonceStore;
  return isForgeRuntime() ? kvsNonceStore : defaultInMemoryStore;
}
