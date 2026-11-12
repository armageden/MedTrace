import { kvs } from '@forge/kvs';

export interface NonceRecord {
  consumedAt: number;
}

export interface NonceStore {
  get(key: string): Promise<NonceRecord | undefined>;
  set(key: string, val: NonceRecord): Promise<void>;
  delete(key: string): Promise<void>;
  claim(key: string, val: NonceRecord, ttlMs: number): Promise<boolean>;
}

export const kvsNonceStore: NonceStore = {
  get: async (key: string): Promise<NonceRecord | undefined> => {
    return (await kvs.get(key)) as NonceRecord | undefined;
  },
  set: async (key: string, val: NonceRecord): Promise<void> => {
    await kvs.set(key, val);
  },
  delete: async (key: string): Promise<void> => {
    await kvs.delete(key);
  },
  claim: async (key: string, val: NonceRecord, ttlMs: number): Promise<boolean> => {
    try {
      await kvs.set(key, val, { keyPolicy: 'FAIL_IF_EXISTS', ttl: { value: Math.max(1, Math.ceil(ttlMs / 60000)), unit: 'MINUTES' } });
      return true;
    } catch {
      return false;
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
  };
}

let activeNonceStore: NonceStore = kvsNonceStore;

export function setNonceStore(store: NonceStore): void {
  activeNonceStore = store;
}

export function getNonceStore(): NonceStore {
  return activeNonceStore;
}