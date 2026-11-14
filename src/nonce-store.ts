import { kvs } from '@forge/kvs';
import { isKvsConflictError, sha256Hex } from './crypto-utils';
import { isForgeRuntime } from './runtime';

/** Maximum accepted past age for signed webtrigger request timestamps in milliseconds. */
export const MAX_TIMESTAMP_AGE_MS = 300_000;

/** Maximum accepted future clock skew for signed webtrigger request timestamps in milliseconds. */
export const MAX_FUTURE_SKEW_MS = 30_000;

/**
 * Replay-protection nonce TTL in milliseconds (`MAX_TIMESTAMP_AGE_MS + MAX_FUTURE_SKEW_MS + 60_000`).
 * Rounds up to 7 minutes (`420s`) in Forge KVS so a future-skewed request cannot outlive its nonce.
 */
export const NONCE_TTL_MS = MAX_TIMESTAMP_AGE_MS + MAX_FUTURE_SKEW_MS + 60_000;

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
 * Hashes raw nonce key strings once to a fixed-length SHA-256 KVS key so arbitrary
 * characters or lengths in caller-supplied nonces never violate Forge KVS key regex rules.
 */
export function toKvsNonceKey(key: string): string {
  return `nonce:${sha256Hex(key)}`;
}

function assertValidTtlMs(ttlMs: number): void {
  if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new RangeError(
      `Invalid nonce ttlMs: expected a positive finite number of milliseconds, received ${String(ttlMs)}.`
    );
  }
}

function toKvsTtlMinutes(ttlMs: number): number {
  assertValidTtlMs(ttlMs);
  return Math.max(1, Math.ceil(ttlMs / 60_000));
}

/** Forge KVS-backed NonceStore using `FAIL_IF_EXISTS` conditional writes and rounded minute TTLs. */
export const kvsNonceStore: NonceStore = {
  get: async (key: string): Promise<NonceRecord | undefined> => {
    return (await kvs.get(toKvsNonceKey(key))) as NonceRecord | undefined;
  },
  set: async (key: string, val: NonceRecord): Promise<void> => {
    await kvs.set(toKvsNonceKey(key), { consumedAt: val.consumedAt });
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
    const ttlMinutes = toKvsTtlMinutes(ttlMs);
    try {
      await kvs.set(toKvsNonceKey(key), { consumedAt: val.consumedAt }, {
        keyPolicy: 'FAIL_IF_EXISTS',
        ttl: { value: ttlMinutes, unit: 'MINUTES' },
      });
      return 'CLAIMED';
    } catch (err) {
      if (isKvsConflictError(err)) {
        return 'REPLAY';
      }
      console.error('[MedTrace NonceStore] KVS error during nonce claim:', err);
      return 'STORAGE_ERROR';
    }
  },
};

/**
 * Creates an isolated in-memory NonceStore for local tests and non-Forge execution,
 * normalizing keys via `toKvsNonceKey` and lazily pruning expired entries on access.
 */
export function createInMemoryNonceStore(): NonceStore {
  const store = new Map<string, NonceRecord>();

  const claimDetailed = async (
    key: string,
    val: NonceRecord,
    ttlMs: number
  ): Promise<NonceClaimResult> => {
    assertValidTtlMs(ttlMs);
    const storageKey = toKvsNonceKey(key);
    const existing = store.get(storageKey);
    const now = Date.now();
    if (existing && now - existing.consumedAt < ttlMs) {
      return 'REPLAY';
    }
    if (existing) {
      store.delete(storageKey);
    }
    store.set(storageKey, { consumedAt: val.consumedAt });
    return 'CLAIMED';
  };

  return {
    get: async (key: string): Promise<NonceRecord | undefined> => {
      const existing = store.get(toKvsNonceKey(key));
      return existing ? { consumedAt: existing.consumedAt } : undefined;
    },
    set: async (key: string, val: NonceRecord): Promise<void> => {
      store.set(toKvsNonceKey(key), { consumedAt: val.consumedAt });
    },
    delete: async (key: string): Promise<void> => {
      store.delete(toKvsNonceKey(key));
    },
    claim: async (key: string, val: NonceRecord, ttlMs: number): Promise<boolean> => {
      return (await claimDetailed(key, val, ttlMs)) === 'CLAIMED';
    },
    claimDetailed,
  };
}

let customNonceStore: NonceStore | null = null;
const defaultInMemoryStore: NonceStore = createInMemoryNonceStore();

/** Sets (or clears with `null`) a custom NonceStore override, primarily for tests. */
export function setNonceStore(store: NonceStore | null): void {
  customNonceStore = store;
}

/** Returns the active NonceStore (custom override, Forge KVS store in runtime, or local store). */
export function getNonceStore(): NonceStore {
  if (customNonceStore) return customNonceStore;
  return isForgeRuntime() ? kvsNonceStore : defaultInMemoryStore;
}
