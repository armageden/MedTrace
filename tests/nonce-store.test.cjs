const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const forgeKvs = require('@forge/kvs');
const {
  MAX_TIMESTAMP_AGE_MS,
  MAX_FUTURE_SKEW_MS,
  NONCE_TTL_MS,
  toKvsNonceKey,
  kvsNonceStore,
  createInMemoryNonceStore,
  setNonceStore,
  getNonceStore,
} = require('../dist/nonce-store.js');

async function withMockedKvs({ getImpl, setImpl, deleteImpl, forgeRuntime = true }, fn) {
  const origGet = forgeKvs.kvs.get;
  const origSet = forgeKvs.kvs.set;
  const origDelete = forgeKvs.kvs.delete;
  const origRuntime = globalThis.__forge_runtime__;

  globalThis.__forge_runtime__ = forgeRuntime;
  if (getImpl) forgeKvs.kvs.get = getImpl;
  if (setImpl) forgeKvs.kvs.set = setImpl;
  if (deleteImpl) forgeKvs.kvs.delete = deleteImpl;

  try {
    return await fn();
  } finally {
    forgeKvs.kvs.get = origGet;
    forgeKvs.kvs.set = origSet;
    forgeKvs.kvs.delete = origDelete;
    if (origRuntime === undefined) {
      delete globalThis.__forge_runtime__;
    } else {
      globalThis.__forge_runtime__ = origRuntime;
    }
  }
}

async function withMockedDateNow(getNow, fn) {
  const origNow = Date.now;
  Date.now = getNow;
  try {
    return await fn();
  } finally {
    Date.now = origNow;
  }
}

async function withMutedConsoleError(fn) {
  const origError = console.error;
  const captured = [];
  console.error = (...args) => {
    captured.push(args);
  };
  try {
    return await fn(captured);
  } finally {
    console.error = origError;
  }
}

test.describe('NonceStore - replay window invariant, KVS TTL, validation & single-hash keys', () => {
  test.it('exports replay constants satisfying NONCE_TTL_MS >= MAX_TIMESTAMP_AGE_MS + MAX_FUTURE_SKEW_MS', () => {
    assert.strictEqual(MAX_TIMESTAMP_AGE_MS, 300_000);
    assert.strictEqual(MAX_FUTURE_SKEW_MS, 30_000);
    assert.strictEqual(NONCE_TTL_MS, 390_000);
    assert.ok(
      NONCE_TTL_MS >= MAX_TIMESTAMP_AGE_MS + MAX_FUTURE_SKEW_MS,
      `Expected NONCE_TTL_MS (${NONCE_TTL_MS}) >= MAX_TIMESTAMP_AGE_MS (${MAX_TIMESTAMP_AGE_MS}) + MAX_FUTURE_SKEW_MS (${MAX_FUTURE_SKEW_MS})`
    );
    const kvsTtlMinutes = Math.max(1, Math.ceil(NONCE_TTL_MS / 60_000));
    assert.strictEqual(kvsTtlMinutes, 7);
    assert.ok(kvsTtlMinutes * 60_000 >= NONCE_TTL_MS);
  });

  test.it('kvsNonceStore rounds NONCE_TTL_MS up to { value: 7, unit: "MINUTES" } (420s >= 390s)', async () => {
    const recordedSets = [];
    await withMockedKvs(
      {
        setImpl: async (key, val, opts) => {
          recordedSets.push({ key, val, opts });
        },
      },
      async () => {
        const now = 1_700_000_000_000;
        const r1 = await kvsNonceStore.claimDetailed('nonce-ttl-390s', { consumedAt: now }, NONCE_TTL_MS);
        assert.strictEqual(r1, 'CLAIMED');
        assert.deepStrictEqual(recordedSets[0].opts, {
          keyPolicy: 'FAIL_IF_EXISTS',
          ttl: { value: 7, unit: 'MINUTES' },
        });
        assert.ok(recordedSets[0].opts.ttl.value * 60 >= 390);

        // Sub-minute and exact-minute rounding checks
        await kvsNonceStore.claim('nonce-ttl-1ms', { consumedAt: now }, 1);
        assert.deepStrictEqual(recordedSets[1].opts.ttl, { value: 1, unit: 'MINUTES' });

        await kvsNonceStore.claim('nonce-ttl-60s', { consumedAt: now }, 60_000);
        assert.deepStrictEqual(recordedSets[2].opts.ttl, { value: 1, unit: 'MINUTES' });

        await kvsNonceStore.claim('nonce-ttl-60s1ms', { consumedAt: now }, 60_001);
        assert.deepStrictEqual(recordedSets[3].opts.ttl, { value: 2, unit: 'MINUTES' });
      }
    );
  });

  test.it('rejects non-positive, NaN, and non-finite ttlMs in both kvsNonceStore and createInMemoryNonceStore', async () => {
    const invalidTtls = [0, -1, -300_000, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, undefined, null, '300000'];
    const memStore = createInMemoryNonceStore();
    let kvsSetCalls = 0;

    await withMockedKvs(
      {
        setImpl: async () => {
          kvsSetCalls += 1;
        },
      },
      async () => {
        for (const badTtl of invalidTtls) {
          await assert.rejects(
            () => kvsNonceStore.claimDetailed('bad-ttl-kvs', { consumedAt: Date.now() }, badTtl),
            /ttlMs|positive|finite/i,
            `Expected kvsNonceStore.claimDetailed to reject ttlMs=${String(badTtl)}`
          );
          await assert.rejects(
            () => kvsNonceStore.claim('bad-ttl-kvs', { consumedAt: Date.now() }, badTtl),
            /ttlMs|positive|finite/i,
            `Expected kvsNonceStore.claim to reject ttlMs=${String(badTtl)}`
          );
          await assert.rejects(
            () => memStore.claimDetailed('bad-ttl-mem', { consumedAt: Date.now() }, badTtl),
            /ttlMs|positive|finite/i,
            `Expected memStore.claimDetailed to reject ttlMs=${String(badTtl)}`
          );
          await assert.rejects(
            () => memStore.claim('bad-ttl-mem', { consumedAt: Date.now() }, badTtl),
            /ttlMs|positive|finite/i,
            `Expected memStore.claim to reject ttlMs=${String(badTtl)}`
          );
        }
      }
    );

    assert.strictEqual(kvsSetCalls, 0);
    assert.strictEqual(await memStore.get('bad-ttl-mem'), undefined);
  });

  test.it('normalizes long (>64 chars) and special-character nonces with a single SHA-256 hash via toKvsNonceKey', async () => {
    const longNonce = `evt/${'a'.repeat(120)}?token=1&space=yes+plus`;
    assert.ok(longNonce.length > 64);

    const expectedSingleHash = `nonce:${crypto.createHash('sha256').update(longNonce, 'utf8').digest('hex')}`;
    const doubleHash = `nonce:${crypto.createHash('sha256').update(expectedSingleHash, 'utf8').digest('hex')}`;

    const normalized = toKvsNonceKey(longNonce);
    assert.strictEqual(normalized, expectedSingleHash);
    assert.notStrictEqual(normalized, doubleHash);
    assert.match(normalized, /^nonce:[0-9a-f]{64}$/);

    // Distinct long nonces with an identical >64-char prefix must not collide
    const prefix = 'x'.repeat(80);
    assert.notStrictEqual(toKvsNonceKey(`${prefix}-1`), toKvsNonceKey(`${prefix}-2`));

    const ops = [];
    const stored = new Map();
    await withMockedKvs(
      {
        getImpl: async (key) => {
          ops.push(['get', key]);
          return stored.get(key);
        },
        setImpl: async (key, val) => {
          ops.push(['set', key]);
          stored.set(key, val);
        },
        deleteImpl: async (key) => {
          ops.push(['delete', key]);
          stored.delete(key);
        },
      },
      async () => {
        const record = { consumedAt: 1_700_000_000_000 };
        assert.strictEqual(await kvsNonceStore.claimDetailed(longNonce, record, NONCE_TTL_MS), 'CLAIMED');
        assert.deepStrictEqual(await kvsNonceStore.get(longNonce), record);
        await kvsNonceStore.set(longNonce, { consumedAt: record.consumedAt + 1 });
        await kvsNonceStore.delete(longNonce);
        assert.strictEqual(await kvsNonceStore.get(longNonce), undefined);
      }
    );

    assert.ok(ops.length >= 5);
    for (const [, kvsKey] of ops) {
      assert.strictEqual(kvsKey, expectedSingleHash);
    }
  });

  test.it('kvsNonceStore.claimDetailed distinguishes CLAIMED, REPLAY (ForgeKvsAPIError/409), and STORAGE_ERROR', async () => {
    const kvsMap = new Map();
    let forcedError = null;

    await withMutedConsoleError(async (errorLogs) => {
      await withMockedKvs(
        {
          setImpl: async (key, val, opts) => {
            if (forcedError) throw forcedError;
            if (opts?.keyPolicy === 'FAIL_IF_EXISTS' && kvsMap.has(key)) {
              throw new forgeKvs.ForgeKvsAPIError(
                { status: 409, statusText: 'Conflict' },
                { code: 'KEY_ALREADY_EXISTS', message: 'Key already exists' }
              );
            }
            kvsMap.set(key, val);
          },
        },
        async () => {
          const now = Date.now();
          assert.strictEqual(await kvsNonceStore.claimDetailed('n-1', { consumedAt: now }, NONCE_TTL_MS), 'CLAIMED');
          assert.strictEqual(await kvsNonceStore.claimDetailed('n-1', { consumedAt: now }, NONCE_TTL_MS), 'REPLAY');
          assert.strictEqual(await kvsNonceStore.claim('n-1', { consumedAt: now }, NONCE_TTL_MS), false);

          // ForgeKvsAPIError with conflict code/message even if HTTP status differs
          forcedError = new forgeKvs.ForgeKvsAPIError(
            { status: 400, statusText: 'Bad Request' },
            { code: 'CONDITION_CONFLICT', message: 'Conditional write conflict' }
          );
          assert.strictEqual(await kvsNonceStore.claimDetailed('n-2', { consumedAt: now }, NONCE_TTL_MS), 'REPLAY');

          // Plain 409 / statusCode 409 mock errors
          forcedError = Object.assign(new Error('Conflict'), { statusCode: 409 });
          assert.strictEqual(await kvsNonceStore.claimDetailed('n-3', { consumedAt: now }, NONCE_TTL_MS), 'REPLAY');

          // ForgeKvsAPIError 503 storage outage -> STORAGE_ERROR (and claim rejects)
          forcedError = new forgeKvs.ForgeKvsAPIError(
            { status: 503, statusText: 'Service Unavailable' },
            { code: 'SERVICE_UNAVAILABLE', message: 'KVS backend unavailable' }
          );
          assert.strictEqual(await kvsNonceStore.claimDetailed('n-4', { consumedAt: now }, NONCE_TTL_MS), 'STORAGE_ERROR');
          await assert.rejects(
            () => kvsNonceStore.claim('n-4', { consumedAt: now }, NONCE_TTL_MS),
            /storage error/i
          );

          // Generic error -> STORAGE_ERROR
          forcedError = new Error('Socket hang up');
          assert.strictEqual(await kvsNonceStore.claimDetailed('n-5', { consumedAt: now }, NONCE_TTL_MS), 'STORAGE_ERROR');
        }
      );
      assert.strictEqual(errorLogs.length, 3);
    });
  });

  test.it('createInMemoryNonceStore lazily prunes expired nonces on access and blocks replay across future-skew window', async () => {
    const store = createInMemoryNonceStore();
    const T0 = 1_700_000_000_000;
    let fakeNow = T0;

    await withMockedDateNow(
      () => fakeNow,
      async () => {
        // Basic set/get/delete + clone isolation
        const initial = { consumedAt: T0 - 10_000 };
        await store.set('mutable-nonce', initial);
        initial.consumedAt = 0;
        const readBack = await store.get('mutable-nonce');
        assert.deepStrictEqual(readBack, { consumedAt: T0 - 10_000 });
        readBack.consumedAt = 123;
        assert.deepStrictEqual(await store.get('mutable-nonce'), { consumedAt: T0 - 10_000 });
        await store.delete('mutable-nonce');
        assert.strictEqual(await store.get('mutable-nonce'), undefined);

        // Request signed with ts = T0 + 29_000 (within MAX_FUTURE_SKEW_MS = 30_000) arrives at T0
        const skewNonce = `skew-nonce-${'z'.repeat(80)}`;
        assert.strictEqual(await store.claimDetailed(skewNonce, { consumedAt: fakeNow }, NONCE_TTL_MS), 'CLAIMED');

        // At T0 + 320_000, ts (T0 + 29_000) is still within MAX_TIMESTAMP_AGE_MS (291s <= 300s).
        // Because NONCE_TTL_MS = 390_000, replay MUST still be blocked.
        fakeNow = T0 + 320_000;
        assert.strictEqual(await store.claimDetailed(skewNonce, { consumedAt: fakeNow }, NONCE_TTL_MS), 'REPLAY');
        assert.strictEqual(await store.claim(skewNonce, { consumedAt: fakeNow }, NONCE_TTL_MS), false);

        // Once NONCE_TTL_MS has fully elapsed (past both future-skew and past-age windows), lazy prune allows re-claim.
        fakeNow = T0 + NONCE_TTL_MS;
        assert.strictEqual(await store.claimDetailed(skewNonce, { consumedAt: fakeNow }, NONCE_TTL_MS), 'CLAIMED');
        assert.deepStrictEqual(await store.get(skewNonce), { consumedAt: T0 + NONCE_TTL_MS });
      }
    );
  });

  test.it('getNonceStore selects in-memory outside Forge, kvsNonceStore in Forge, and honors setNonceStore', async () => {
    const origRuntime = globalThis.__forge_runtime__;
    const customStore = createInMemoryNonceStore();
    try {
      setNonceStore(null);
      delete globalThis.__forge_runtime__;
      const localStore = getNonceStore();
      assert.notStrictEqual(localStore, kvsNonceStore);

      globalThis.__forge_runtime__ = true;
      assert.strictEqual(getNonceStore(), kvsNonceStore);

      setNonceStore(customStore);
      assert.strictEqual(getNonceStore(), customStore);
    } finally {
      setNonceStore(null);
      if (origRuntime === undefined) {
        delete globalThis.__forge_runtime__;
      } else {
        globalThis.__forge_runtime__ = origRuntime;
      }
    }
  });
});
