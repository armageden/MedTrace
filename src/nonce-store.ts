import { kvs } from '@forge/kvs';

export interface NonceRecord {
  consumedAt: number;
}

export interface NonceStore {
  get(key: string): Promise<NonceRecord | undefined>;
  set(key: string, val: NonceRecord): Promise<void>;
  delete(key: string): Promise<void>;
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
  };
}

let activeNonceStore: NonceStore = kvsNonceStore;

export function setNonceStore(store: NonceStore): void {
  activeNonceStore = store;
}

export function getNonceStore(): NonceStore {
  return activeNonceStore;
}
