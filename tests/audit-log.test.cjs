const test = require('node:test');
const assert = require('node:assert');
const forgeKvs = require('@forge/kvs');
const {
  AuditLogService,
  AUDIT_GENESIS_HASH,
  MAX_AUDIT_ENTRY_BYTES,
  computeAuditEntryHash,
  createInMemoryAuditStorageAdapter,
  kvsAuditStorageAdapter,
  setAuditStorageAdapter,
  resetInMemoryAuditStorage,
} = require('../dist/audit-log');
const { measureJsonBytes } = require('../dist/crypto-utils');

const { ForgeKvsAPIError } = forgeKvs;

function cloneJson(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function createMockAuditKvs(seed = {}, options = {}) {
  const store = new Map(Object.entries(seed).map(([k, v]) => [k, cloneJson(v)]));
  const calls = {
    get: [],
    set: [],
    batchGet: [],
  };
  let batchGetAttempt = 0;

  return {
    store,
    calls,
    get: async (key) => {
      calls.get.push(key);
      return cloneJson(store.get(key));
    },
    set: async (key, val, opts) => {
      calls.set.push({ key, val: cloneJson(val), opts: opts ? { ...opts } : undefined });
      if (opts && opts.keyPolicy === 'FAIL_IF_EXISTS' && store.has(key)) {
        if (options.useForgeKvsError) {
          throw new ForgeKvsAPIError(
            { status: 409, statusText: 'Conflict' },
            { code: 'KEY_ALREADY_EXISTS', message: 'Key already exists' }
          );
        }
        const err = new Error('Key already exists');
        err.status = 409;
        err.code = 'KEY_ALREADY_EXISTS';
        throw err;
      }
      const previous = store.has(key) ? cloneJson(store.get(key)) : undefined;
      store.set(key, cloneJson(val));
      if (opts && opts.keyPolicy === 'OVERRIDE' && opts.returnValue === 'PREVIOUS') {
        return previous !== undefined ? { key, value: previous } : undefined;
      }
      return undefined;
    },
    batchGet: async (items) => {
      batchGetAttempt++;
      const keys = items.map((item) => item.key);
      calls.batchGet.push(keys);
      if (typeof options.onBatchGet === 'function') {
        const override = await options.onBatchGet(items, batchGetAttempt, store);
        if (override) return override;
      }
      const successfulKeys = [];
      const failedKeys = [];
      for (const item of items) {
        if (store.has(item.key)) {
          successfulKeys.push({ key: item.key, value: cloneJson(store.get(item.key)) });
        } else {
          failedKeys.push({
            key: item.key,
            error: { code: 'KEY_NOT_FOUND', message: 'Key does not exist' },
          });
        }
      }
      return { successfulKeys, failedKeys };
    },
    resetCalls: () => {
      calls.get.length = 0;
      calls.set.length = 0;
      calls.batchGet.length = 0;
    },
  };
}

async function withMockedKvs(kvsMock, fn) {
  const origRuntime = globalThis.__forge_runtime__;
  const origKvs = {
    get: forgeKvs.kvs.get,
    set: forgeKvs.kvs.set,
    batchGet: forgeKvs.kvs.batchGet,
  };

  globalThis.__forge_runtime__ = true;
  forgeKvs.kvs.get = kvsMock.get;
  forgeKvs.kvs.set = kvsMock.set;
  forgeKvs.kvs.batchGet = kvsMock.batchGet;

  try {
    return await fn();
  } finally {
    if (origRuntime === undefined) delete globalThis.__forge_runtime__;
    else globalThis.__forge_runtime__ = origRuntime;
    forgeKvs.kvs.get = origKvs.get;
    forgeKvs.kvs.set = origKvs.set;
    forgeKvs.kvs.batchGet = origKvs.batchGet;
  }
}

function buildValidEntries(count, startSeq = 1, startPrevHash = AUDIT_GENESIS_HASH) {
  const entries = [];
  let prevHash = startPrevHash;
  for (let i = 0; i < count; i++) {
    const seq = startSeq + i;
    const base = {
      seq,
      timestamp: `2026-11-12T00:${String(Math.floor(seq / 60)).padStart(2, '0')}:${String(seq % 60).padStart(2, '0')}.000Z`,
      actorAccountId: `acc-${(seq % 5) + 1}`,
      action: 'RECORD_TEST_RESULT',
      targetKey: `TEST-${seq}`,
      details: { index: seq, status: 'PASSED' },
      prevHash,
      authMethod: 'FORGE_USER_SESSION',
    };
    const entryHash = computeAuditEntryHash(base);
    const full = { ...base, entryHash };
    entries.push(full);
    prevHash = entryHash;
  }
  return entries;
}

function seedEntriesIntoKvs(entries, headSeq = entries.length) {
  const seed = {};
  for (const e of entries) {
    seed[`medtrace:audit:entry:${e.seq}`] = e;
  }
  const headEntry = entries.find((e) => e.seq === headSeq);
  seed['medtrace:audit:head'] = headEntry
    ? { lastSeq: headEntry.seq, headHash: headEntry.entryHash }
    : { lastSeq: 0, headHash: AUDIT_GENESIS_HASH };
  return seed;
}

test.describe('AuditLogService & AuditStorageAdapters - Monotonicity, Batching & Isolation', () => {
  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
  });

  test.afterEach(() => {
    setAuditStorageAdapter(null);
    resetInMemoryAuditStorage();
  });

  test.it('enforces monotonic setHead in kvsAuditStorageAdapter using returnValue: PREVIOUS and recovers higher tail', async () => {
    const entries = buildValidEntries(12);
    const seed = seedEntriesIntoKvs(entries, 10); // head is at 10, while entries 11 and 12 also exist
    const kvsMock = createMockAuditKvs(seed);

    await withMockedKvs(kvsMock, async () => {
      // Stale writer attempts to regress head from 10 back to 5
      await kvsAuditStorageAdapter.setHead({
        lastSeq: 5,
        headHash: entries[4].entryHash,
      });

      const firstSetCall = kvsMock.calls.set[0];
      assert.deepStrictEqual(firstSetCall.opts, {
        keyPolicy: 'OVERRIDE',
        returnValue: 'PREVIOUS',
      });

      // Head must NOT regress to 5; it must recover via resolveChainTail to 12 (the true chain tail)
      const headAfter = await kvsAuditStorageAdapter.getHead();
      assert.strictEqual(headAfter.lastSeq, 12);
      assert.strictEqual(headAfter.headHash, entries[11].entryHash);

      // Attempting to regress again when no entries exist past 12 keeps head at 12
      await kvsAuditStorageAdapter.setHead({
        lastSeq: 11,
        headHash: entries[10].entryHash,
      });
      const headAfterSecond = await kvsAuditStorageAdapter.getHead();
      assert.strictEqual(headAfterSecond.lastSeq, 12);
      assert.strictEqual(headAfterSecond.headHash, entries[11].entryHash);
    });
  });

  test.it('enforces monotonic setHead in createInMemoryAuditStorageAdapter', async () => {
    const adapter = createInMemoryAuditStorageAdapter();
    await adapter.setHead({ lastSeq: 8, headHash: 'h8' });
    await adapter.setHead({ lastSeq: 4, headHash: 'h4' });
    await adapter.setHead({ lastSeq: 8, headHash: 'h8-override' });

    const head = await adapter.getHead();
    assert.deepStrictEqual(head, { lastSeq: 8, headHash: 'h8' });
  });

  test.it('resolveChainTail probes forward in batches of 10 and caps recovery at 500 hops', async () => {
    const entries25 = buildValidEntries(25);
    const seed25 = seedEntriesIntoKvs(entries25, 0); // head lags at 0 while 25 entries exist
    const kvsMock25 = createMockAuditKvs(seed25);

    await withMockedKvs(kvsMock25, async () => {
      const head = await AuditLogService.getHead();
      assert.strictEqual(head.lastSeq, 25);
      assert.strictEqual(head.headHash, entries25[24].entryHash);
      // 3 batches of 10: [1..10], [11..20], [21..30]
      assert.strictEqual(kvsMock25.calls.batchGet.length, 3);
      assert.strictEqual(kvsMock25.calls.batchGet[0].length, 10);
      assert.strictEqual(kvsMock25.calls.batchGet[1].length, 10);
      assert.strictEqual(kvsMock25.calls.batchGet[2].length, 10);
    });

    // 525 orphaned entries with head at 0 must stop at the 500-hop cap (50 batch-10 calls)
    const entries525 = buildValidEntries(525);
    const seed525 = seedEntriesIntoKvs(entries525, 0);
    const kvsMock525 = createMockAuditKvs(seed525);

    await withMockedKvs(kvsMock525, async () => {
      const cappedHead = await AuditLogService.getHead();
      assert.strictEqual(cappedHead.lastSeq, 500);
      assert.strictEqual(cappedHead.headHash, entries525[499].entryHash);
      assert.strictEqual(kvsMock525.calls.batchGet.length, 50);
    });

    // Gap stops recovery cleanly without skipping missing seq
    const gapSeed = seedEntriesIntoKvs(entries25.slice(0, 5), 0);
    delete gapSeed['medtrace:audit:entry:3'];
    const gapMock = createMockAuditKvs(gapSeed);
    await withMockedKvs(gapMock, async () => {
      const gapHead = await AuditLogService.getHead();
      assert.strictEqual(gapHead.lastSeq, 2);
      assert.strictEqual(gapHead.headHash, entries25[1].entryHash);
    });
  });

  test.it('verifyAuditChain on 35 entries uses <= 3 batchGet calls + 1 head get and detects all tamper/corruption modes', async () => {
    const entries = buildValidEntries(35);
    const seed = seedEntriesIntoKvs(entries, 35);
    const kvsMock = createMockAuditKvs(seed);

    await withMockedKvs(kvsMock, async () => {
      kvsMock.resetCalls();
      const validRes = await AuditLogService.verifyAuditChain();
      assert.strictEqual(validRes.valid, true);
      assert.strictEqual(validRes.totalEntries, 35);
      assert.strictEqual(validRes.headHash, entries[34].entryHash);
      assert.strictEqual(kvsMock.calls.get.length, 1, 'Expected exactly 1 head get call');
      assert.ok(
        kvsMock.calls.batchGet.length <= 3,
        `Expected <= 3 batchGet calls for 35 entries, got ${kvsMock.calls.batchGet.length}`
      );

      // 1. Missing entry
      const saved20 = cloneJson(kvsMock.store.get('medtrace:audit:entry:20'));
      kvsMock.store.delete('medtrace:audit:entry:20');
      const missingRes = await AuditLogService.verifyAuditChain();
      assert.strictEqual(missingRes.valid, false);
      assert.strictEqual(missingRes.brokenAtSeq, 20);
      assert.match(missingRes.reason, /Missing audit log entry at sequence 20/);
      kvsMock.store.set('medtrace:audit:entry:20', saved20);

      // 2. Sequence mismatch
      const saved12 = cloneJson(kvsMock.store.get('medtrace:audit:entry:12'));
      kvsMock.store.set('medtrace:audit:entry:12', { ...saved12, seq: 99 });
      const seqMismatchRes = await AuditLogService.verifyAuditChain();
      assert.strictEqual(seqMismatchRes.valid, false);
      assert.strictEqual(seqMismatchRes.brokenAtSeq, 12);
      assert.match(seqMismatchRes.reason, /Sequence mismatch at 12: found 99/);
      kvsMock.store.set('medtrace:audit:entry:12', saved12);

      // 3. prevHash break
      const saved28 = cloneJson(kvsMock.store.get('medtrace:audit:entry:28'));
      kvsMock.store.set('medtrace:audit:entry:28', { ...saved28, prevHash: 'f'.repeat(64) });
      const prevBreakRes = await AuditLogService.verifyAuditChain();
      assert.strictEqual(prevBreakRes.valid, false);
      assert.strictEqual(prevBreakRes.brokenAtSeq, 28);
      assert.match(prevBreakRes.reason, /Hash chain break at seq 28/);
      kvsMock.store.set('medtrace:audit:entry:28', saved28);

      // 4. Payload tampering
      const saved33 = cloneJson(kvsMock.store.get('medtrace:audit:entry:33'));
      kvsMock.store.set('medtrace:audit:entry:33', { ...saved33, details: { tampered: true } });
      const tamperRes = await AuditLogService.verifyAuditChain();
      assert.strictEqual(tamperRes.valid, false);
      assert.strictEqual(tamperRes.brokenAtSeq, 33);
      assert.match(tamperRes.reason, /Tampered payload at seq 33/);
      kvsMock.store.set('medtrace:audit:entry:33', saved33);
    });
  });

  test.it('kvsAuditStorageAdapter.getEntriesBatch retries once on transient failedKeys and fails closed if failedKeys persist', async () => {
    const entries = buildValidEntries(5);
    const seed = seedEntriesIntoKvs(entries, 5);

    // Transient failure on attempt 1, succeeds on retry
    const transientMock = createMockAuditKvs(seed, {
      onBatchGet: (items, attempt, store) => {
        if (attempt === 1) {
          const ok = items.slice(0, 3).map((i) => ({ key: i.key, value: cloneJson(store.get(i.key)) }));
          const failed = items.slice(3).map((i) => ({
            key: i.key,
            error: { code: 'TRANSIENT', message: 'Temporary error' },
          }));
          return { successfulKeys: ok, failedKeys: failed };
        }
        return null;
      },
    });

    await withMockedKvs(transientMock, async () => {
      const recovered = await kvsAuditStorageAdapter.getEntriesBatch([1, 2, 3, 4, 5]);
      assert.strictEqual(recovered.size, 5);
      assert.strictEqual(transientMock.calls.batchGet.length, 2);
      assert.deepStrictEqual(transientMock.calls.batchGet[1], [
        'medtrace:audit:entry:4',
        'medtrace:audit:entry:5',
      ]);
    });

    // Persistent failure must throw fail-closed
    const persistentMock = createMockAuditKvs(seed, {
      onBatchGet: (items) => ({
        successfulKeys: [],
        failedKeys: items.map((i) => ({
          key: i.key,
          error: { code: 'KVS_UNAVAILABLE', message: 'Persistent failure' },
        })),
      }),
    });

    await withMockedKvs(persistentMock, async () => {
      await assert.rejects(
        () => kvsAuditStorageAdapter.getEntriesBatch([1, 2]),
        /Failed to batch-read audit log entries/
      );
      assert.strictEqual(persistentMock.calls.batchGet.length, 2);
    });
  });

  test.it('getHead()/getEntriesBatch() succeed on an empty store (KEY_NOT_FOUND omitted, not fatal)', async () => {
    const emptyMock = createMockAuditKvs({});

    await withMockedKvs(emptyMock, async () => {
      const head = await AuditLogService.getHead();
      assert.deepStrictEqual(head, { lastSeq: 0, headHash: AUDIT_GENESIS_HASH });

      const batch = await kvsAuditStorageAdapter.getEntriesBatch([1, 2, 3]);
      assert.strictEqual(batch.size, 0);
      // Probes for non-existent slots must not trigger any retry batchGet
      assert.strictEqual(emptyMock.calls.batchGet.length, 2);

      const entries = await AuditLogService.getAuditLog(10);
      assert.deepStrictEqual(entries, []);
    });
  });

  test.it('getEntriesBatch filters KEY_NOT_FOUND but retries and fails closed on non-KEY_NOT_FOUND errors', async () => {
    const entries = buildValidEntries(3);
    const seed = seedEntriesIntoKvs(entries, 3);

    // Mixed missing + transient failure: KEY_NOT_FOUND must be ignored, TRANSIENT retried once
    const mixedMock = createMockAuditKvs(seed, {
      onBatchGet: (items, attempt, store) => {
        if (attempt === 1) {
          const ok = items
            .filter((i) => store.has(i.key) && i.key.endsWith(':1'))
            .map((i) => ({ key: i.key, value: cloneJson(store.get(i.key)) }));
          const failed = items
            .filter((i) => !store.has(i.key) || !i.key.endsWith(':1'))
            .map((i) => ({
              key: i.key,
              error: store.has(i.key)
                ? { code: 'TRANSIENT', message: 'Temporary error' }
                : { code: 'KEY_NOT_FOUND', message: 'Key does not exist' },
            }));
          return { successfulKeys: ok, failedKeys: failed };
        }
        return null;
      },
    });

    await withMockedKvs(mixedMock, async () => {
      const recovered = await kvsAuditStorageAdapter.getEntriesBatch([1, 2, 99]);
      assert.strictEqual(recovered.size, 2);
      assert.strictEqual(recovered.get(1).seq, 1);
      assert.strictEqual(recovered.get(2).seq, 2);
      const retried = mixedMock.calls.batchGet[1];
      assert.deepStrictEqual(retried, ['medtrace:audit:entry:2']);
    });

    // Retry returning KEY_NOT_FOUND is treated as not-present, not an error
    const notFoundOnRetryMock = createMockAuditKvs(seed, {
      onBatchGet: (items) => ({
        successfulKeys: items
          .filter((i) => i.key.endsWith(':1'))
          .map((i) => ({ key: i.key, value: cloneJson(seed[i.key]) })),
        failedKeys: items
          .filter((i) => !i.key.endsWith(':1'))
          .map((i) => ({ key: i.key, error: { code: 'KEY_NOT_FOUND', message: 'Key does not exist' } })),
      }),
    });

    await withMockedKvs(notFoundOnRetryMock, async () => {
      const batch = await kvsAuditStorageAdapter.getEntriesBatch([1, 2]);
      assert.strictEqual(batch.size, 1);
      assert.strictEqual(batch.get(1).seq, 1);
    });

    // KEY_NOT_FOUND alongside a persistent non-KEY_NOT_FOUND error still fails closed
    const mixedFatalMock = createMockAuditKvs(seed, {
      onBatchGet: (items) => ({
        successfulKeys: [],
        failedKeys: items.map((i) => ({
          key: i.key,
          error: i.key.endsWith(':1')
            ? { code: 'KEY_NOT_FOUND', message: 'Key does not exist' }
            : { code: 'QUOTA_EXCEEDED', message: 'Quota exceeded' },
        })),
      }),
    });

    await withMockedKvs(mixedFatalMock, async () => {
      await assert.rejects(
        () => kvsAuditStorageAdapter.getEntriesBatch([1, 2]),
        /Failed to batch-read audit log entries/
      );
    });
  });

  test.it('getAuditLog(limit, beforeSeq) paginates cleanly in ascending seq order', async () => {
    const entries = buildValidEntries(30);
    const seed = seedEntriesIntoKvs(entries, 30);
    const kvsMock = createMockAuditKvs(seed);

    await withMockedKvs(kvsMock, async () => {
      const page1 = await AuditLogService.getAuditLog(10);
      assert.deepStrictEqual(page1.map((e) => e.seq), [21, 22, 23, 24, 25, 26, 27, 28, 29, 30]);

      const page2 = await AuditLogService.getAuditLog(10, 21);
      assert.deepStrictEqual(page2.map((e) => e.seq), [11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);

      const page3 = await AuditLogService.getAuditLog(10, 6);
      assert.deepStrictEqual(page3.map((e) => e.seq), [1, 2, 3, 4, 5]);

      const clampedPage = await AuditLogService.getAuditLog(5, 999);
      assert.deepStrictEqual(clampedPage.map((e) => e.seq), [26, 27, 28, 29, 30]);

      const emptyPage = await AuditLogService.getAuditLog(10, 1);
      assert.deepStrictEqual(emptyPage, []);

      const zeroBefore = await AuditLogService.getAuditLog(10, 0);
      assert.deepStrictEqual(zeroBefore, []);

      // Verify batchGet was used rather than per-entry get calls
      assert.strictEqual(kvsMock.calls.get.every((k) => k === 'medtrace:audit:head'), true);
    });
  });

  test.it('append() enforces exact 220 * 1024 byte limit before writing and fails after 12 collision retries', async () => {
    const fixedTs = '2026-11-12T00:00:00.000Z';
    const baseProbe = {
      seq: 1,
      timestamp: fixedTs,
      actorAccountId: 'acc-1',
      action: 'SYNC_LIVE',
      targetKey: 'PROJ',
      details: { blob: '' },
      prevHash: AUDIT_GENESIS_HASH,
      authMethod: 'FORGE_USER_SESSION',
    };
    const probeFull = { ...baseProbe, entryHash: computeAuditEntryHash(baseProbe) };
    const overheadBytes = measureJsonBytes(probeFull);
    const maxLimit = MAX_AUDIT_ENTRY_BYTES || 220 * 1024;
    const exactAllowedBlob = 'x'.repeat(maxLimit - overheadBytes);
    const oversizedBlob = 'x'.repeat(maxLimit - overheadBytes + 1);

    let writeCount = 0;
    const backing = createInMemoryAuditStorageAdapter();
    setAuditStorageAdapter({
      getHead: () => backing.getHead(),
      setHead: (h) => backing.setHead(h),
      getEntry: (seq) => backing.getEntry(seq),
      getEntriesBatch: (seqs) => backing.getEntriesBatch(seqs),
      createEntryImmutable: async (seq, entry) => {
        writeCount++;
        return backing.createEntryImmutable(seq, entry);
      },
    });

    await assert.rejects(
      () =>
        AuditLogService.append({
          actorAccountId: 'acc-1',
          action: 'SYNC_LIVE',
          targetKey: 'PROJ',
          details: { blob: oversizedBlob },
          authMethod: 'FORGE_USER_SESSION',
          timestamp: fixedTs,
        }),
      /exceeds maximum/i
    );
    assert.strictEqual(writeCount, 0, 'Oversized entry must be rejected before any write');

    const exactOk = await AuditLogService.append({
      actorAccountId: 'acc-1',
      action: 'SYNC_LIVE',
      targetKey: 'PROJ',
      details: { blob: exactAllowedBlob },
      authMethod: 'FORGE_USER_SESSION',
      timestamp: fixedTs,
    });
    assert.strictEqual(exactOk.seq, 1);
    assert.strictEqual(measureJsonBytes(exactOk), maxLimit);
    assert.strictEqual(writeCount, 1);

    // 12-retry exhaustion
    let attempts = 0;
    setAuditStorageAdapter({
      getHead: async () => ({ lastSeq: 0, headHash: AUDIT_GENESIS_HASH }),
      setHead: async () => {},
      getEntry: async () => undefined,
      getEntriesBatch: async () => new Map(),
      createEntryImmutable: async () => {
        attempts++;
        return 'EXISTS';
      },
    });

    await assert.rejects(
      () =>
        AuditLogService.append({
          actorAccountId: 'acc-1',
          action: 'BIND_ISSUE',
          targetKey: 'HAZ-101',
          authMethod: 'FORGE_USER_SESSION',
        }),
      /Failed to append immutable audit entry after concurrency retries/
    );
    assert.strictEqual(attempts, 12);

    // KVS ForgeKvsAPIError 409 conflict during concurrent createEntryImmutable recovers via resolveChainTail to seq 2
    setAuditStorageAdapter(null);
    const firstEntry = buildValidEntries(1)[0];
    const conflictKvs = createMockAuditKvs(
      {
        'medtrace:audit:head': { lastSeq: 0, headHash: AUDIT_GENESIS_HASH },
      },
      { useForgeKvsError: true }
    );
    let injectedConcurrentEntry = false;
    const baseSet = conflictKvs.set;
    conflictKvs.set = async (key, val, opts) => {
      if (!injectedConcurrentEntry && key === 'medtrace:audit:entry:1' && opts && opts.keyPolicy === 'FAIL_IF_EXISTS') {
        injectedConcurrentEntry = true;
        conflictKvs.store.set('medtrace:audit:entry:1', cloneJson(firstEntry));
      }
      return await baseSet(key, val, opts);
    };

    await withMockedKvs(conflictKvs, async () => {
      const appended = await AuditLogService.append({
        actorAccountId: 'acc-2',
        action: 'PART11_SIGNOFF',
        targetKey: 'HAZ-101',
        authMethod: 'PART11_ATTESTATION',
      });
      assert.strictEqual(injectedConcurrentEntry, true);
      assert.strictEqual(appended.seq, 2);
      assert.strictEqual(appended.prevHash, firstEntry.entryHash);
      const head = await kvsAuditStorageAdapter.getHead();
      assert.strictEqual(head.lastSeq, 2);
      assert.strictEqual(head.headHash, appended.entryHash);
    });
  });

  test.it('createInMemoryAuditStorageAdapter deep-clones entries on write and read', async () => {
    const adapter = createInMemoryAuditStorageAdapter();
    const original = buildValidEntries(1)[0];
    original.details = { nested: { flag: false }, list: ['a'] };
    original.entryHash = computeAuditEntryHash(original);

    const status = await adapter.createEntryImmutable(1, original);
    assert.strictEqual(status, 'CREATED');

    // Mutate caller's object after write
    original.details.nested.flag = true;
    original.details.list.push('mutated-after-write');

    const read1 = await adapter.getEntry(1);
    assert.deepStrictEqual(read1.details, { nested: { flag: false }, list: ['a'] });

    // Mutate object returned from getEntry
    read1.details.nested.flag = true;
    read1.details.tampered = 'yes';

    const read2 = await adapter.getEntry(1);
    assert.deepStrictEqual(read2.details, { nested: { flag: false }, list: ['a'] });

    // Mutate object returned from getEntriesBatch
    const batch1 = await adapter.getEntriesBatch([1]);
    batch1.get(1).details.list.push('mutated-after-batch-read');

    const batch2 = await adapter.getEntriesBatch([1]);
    assert.deepStrictEqual(batch2.get(1).details, { nested: { flag: false }, list: ['a'] });
  });

  test.it('verifyAuditChain supports bounded incremental windows and detects predecessor/anchor tampering', async () => {
    const entries = buildValidEntries(35);
    const seed = seedEntriesIntoKvs(entries, 35);
    const kvsMock = createMockAuditKvs(seed);

    await withMockedKvs(kvsMock, async () => {
      const w1 = await AuditLogService.verifyAuditChain({ fromSeq: 1, maxEntries: 15 });
      assert.deepStrictEqual(w1, {
        valid: true,
        totalEntries: 35,
        headHash: entries[14].entryHash,
        verifiedFromSeq: 1,
        verifiedToSeq: 15,
        windowEntryCount: 15,
        truncated: true,
        nextFromSeq: 16,
      });

      const w2 = await AuditLogService.verifyAuditChain({
        fromSeq: w1.nextFromSeq,
        maxEntries: 15,
        expectedPrevHash: w1.headHash,
      });
      assert.deepStrictEqual(w2, {
        valid: true,
        totalEntries: 35,
        headHash: entries[29].entryHash,
        verifiedFromSeq: 16,
        verifiedToSeq: 30,
        windowEntryCount: 15,
        truncated: true,
        nextFromSeq: 31,
      });

      const w3 = await AuditLogService.verifyAuditChain({
        fromSeq: w2.nextFromSeq,
        maxEntries: 15,
        expectedPrevHash: w2.headHash,
      });
      assert.deepStrictEqual(w3, {
        valid: true,
        totalEntries: 35,
        headHash: entries[34].entryHash,
        verifiedFromSeq: 31,
        verifiedToSeq: 35,
        windowEntryCount: 5,
        truncated: false,
      });

      // Mismatched expectedPrevHash fails closed
      const badAnchor = await AuditLogService.verifyAuditChain({
        fromSeq: 16,
        maxEntries: 10,
        expectedPrevHash: '0'.repeat(64),
      });
      assert.strictEqual(badAnchor.valid, false);
      assert.strictEqual(badAnchor.brokenAtSeq, 16);
      assert.match(badAnchor.reason, /Window anchor mismatch/);

      // Tampering predecessor entry 15 fails closed when verifying window starting at 16
      const saved15 = cloneJson(kvsMock.store.get('medtrace:audit:entry:15'));
      kvsMock.store.set('medtrace:audit:entry:15', { ...saved15, details: { forged: true } });
      const badPred = await AuditLogService.verifyAuditChain({ fromSeq: 16, maxEntries: 10 });
      assert.strictEqual(badPred.valid, false);
      assert.strictEqual(badPred.brokenAtSeq, 15);
      assert.match(badPred.reason, /Tampered payload at predecessor seq 15/);
      kvsMock.store.set('medtrace:audit:entry:15', saved15);

      // Default un-optioned verifyAuditChain honors MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES bound
      const prevMaxEnv = process.env.MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES;
      process.env.MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES = '10';
      try {
        const boundedDefault = await AuditLogService.verifyAuditChain();
        assert.strictEqual(boundedDefault.valid, true);
        assert.strictEqual(boundedDefault.totalEntries, 35);
        assert.strictEqual(boundedDefault.verifiedFromSeq, 1);
        assert.strictEqual(boundedDefault.verifiedToSeq, 10);
        assert.strictEqual(boundedDefault.truncated, true);
        assert.strictEqual(boundedDefault.nextFromSeq, 11);
      } finally {
        if (prevMaxEnv === undefined) delete process.env.MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES;
        else process.env.MEDTRACE_AUDIT_VERIFY_MAX_ENTRIES = prevMaxEnv;
      }
    });
  });
});
