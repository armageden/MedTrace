const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const forgeApi = require('@forge/api');
const forgeKvs = require('@forge/kvs');
const { ComplianceEngine } = require('../dist/compliance-engine');
const { AuditLogService, setAuditStorageAdapter, resetInMemoryAuditStorage } = require('../dist/audit-log');
const { sanitizeKvsKeySegment } = require('../dist/crypto-utils');
const { PART11_ATTESTATION_PHRASE } = require('../dist/types');
const seederMod = require('../dist/seeder');
const { SeederService } = seederMod;

const { ForgeKvsAPIError } = forgeKvs;
const KVS_KEY_REGEX = /^(?!\s+$)[a-zA-Z0-9:._\s-#]+$/;

function cloneJson(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function makeJsonResponse(status, data) {
  return {
    status,
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

function createFullMockForgeKvs(seed = {}, options = {}) {
  const store = new Map(Object.entries(seed).map(([k, v]) => [k, cloneJson(v)]));
  const calls = {
    get: [],
    set: [],
    delete: [],
    batchGet: [],
    batchSet: [],
    batchDelete: [],
    transact: [],
  };
  let batchGetAttempt = 0;

  function assertValidKey(key) {
    assert.ok(typeof key === 'string' && key.length > 0 && key.length <= 500, `Invalid KVS key length: ${key}`);
    assert.match(key, KVS_KEY_REGEX, `Invalid KVS key format: ${key}`);
  }

  return {
    store,
    calls,
    get: async (key) => {
      assertValidKey(key);
      calls.get.push(key);
      return cloneJson(store.get(key));
    },
    set: async (key, val, opts) => {
      assertValidKey(key);
      calls.set.push({ key, val: cloneJson(val), opts: opts ? { ...opts } : undefined });
      if (typeof options.onSet === 'function') {
        await options.onSet(key, val, opts, store);
      }
      if (opts && opts.keyPolicy === 'FAIL_IF_EXISTS' && store.has(key)) {
        throw new ForgeKvsAPIError(
          { status: 409, statusText: 'Conflict' },
          { code: 'KEY_ALREADY_EXISTS', message: 'Key already exists' }
        );
      }
      const previous = store.has(key) ? cloneJson(store.get(key)) : undefined;
      store.set(key, cloneJson(val));
      if (opts && opts.keyPolicy === 'OVERRIDE' && opts.returnValue === 'PREVIOUS') {
        return previous !== undefined ? { key, value: previous } : undefined;
      }
      return undefined;
    },
    delete: async (key) => {
      assertValidKey(key);
      calls.delete.push(key);
      store.delete(key);
    },
    batchGet: async (items) => {
      batchGetAttempt++;
      assert.ok(items.length <= 25, `batchGet exceeded 25-item Forge ceiling: ${items.length}`);
      const keys = items.map((i) => {
        assertValidKey(i.key);
        return i.key;
      });
      calls.batchGet.push(keys);
      if (typeof options.onBatchGet === 'function') {
        const override = await options.onBatchGet(items, batchGetAttempt, store);
        if (override) return override;
      }
      const successfulKeys = [];
      for (const item of items) {
        if (store.has(item.key)) {
          successfulKeys.push({ key: item.key, value: cloneJson(store.get(item.key)) });
        }
      }
      return { successfulKeys, failedKeys: [] };
    },
    batchSet: async (items) => {
      assert.ok(items.length <= 25, `batchSet exceeded 25-item Forge ceiling: ${items.length}`);
      const keys = items.map((i) => {
        assertValidKey(i.key);
        return i.key;
      });
      calls.batchSet.push(keys);
      if (typeof options.onBatchSet === 'function') {
        const override = await options.onBatchSet(items, store);
        if (override) return override;
      }
      for (const item of items) {
        store.set(item.key, cloneJson(item.value));
      }
      return { successfulKeys: items.map((i) => ({ key: i.key })), failedKeys: [] };
    },
    batchDelete: async (items) => {
      assert.ok(items.length <= 25, `batchDelete exceeded 25-item Forge ceiling: ${items.length}`);
      const keys = items.map((i) => {
        assertValidKey(i.key);
        return i.key;
      });
      calls.batchDelete.push(keys);
      for (const item of items) {
        store.delete(item.key);
      }
      return { successfulKeys: items.map((i) => ({ key: i.key })), failedKeys: [] };
    },
    transact: () => {
      const sets = [];
      const deletes = [];
      const builder = {
        set: (key, value, entity, opts) => {
          assertValidKey(key);
          if (opts && 'keyPolicy' in opts) {
            throw new Error('TransactSet.options does not support keyPolicy in Forge KVS');
          }
          sets.push({ key, value: cloneJson(value), entity, opts });
          return builder;
        },
        delete: (key, entity) => {
          assertValidKey(key);
          deletes.push({ key, entity });
          return builder;
        },
        check: () => {
          throw new Error('transact().check() requires Custom Entities');
        },
        execute: async () => {
          const totalOps = sets.length + deletes.length;
          assert.ok(totalOps <= 25, `kvs.transact() exceeded 25-op Forge ceiling: ${totalOps}`);
          const seenKeys = new Set();
          for (const s of sets) {
            assert.ok(!seenKeys.has(s.key), `Duplicate key in transact: ${s.key}`);
            seenKeys.add(s.key);
          }
          for (const d of deletes) {
            assert.ok(!seenKeys.has(d.key), `Duplicate/overlapping key in transact: ${d.key}`);
            seenKeys.add(d.key);
          }
          calls.transact.push({
            sets: sets.map((s) => s.key),
            deletes: deletes.map((d) => d.key),
          });
          if (typeof options.onTransact === 'function') {
            await options.onTransact({ sets, deletes }, store);
          }
          for (const s of sets) {
            store.set(s.key, cloneJson(s.value));
          }
          for (const d of deletes) {
            store.delete(d.key);
          }
        },
      };
      return builder;
    },
    resetCalls: () => {
      calls.get.length = 0;
      calls.set.length = 0;
      calls.delete.length = 0;
      calls.batchGet.length = 0;
      calls.batchSet.length = 0;
      calls.batchDelete.length = 0;
      calls.transact.length = 0;
    },
  };
}

async function withForgeMocks({ kvsMock, asAppImpl, asUserImpl }, fn) {
  const origRuntime = globalThis.__forge_runtime__;
  const origKvs = {
    get: forgeKvs.kvs.get,
    set: forgeKvs.kvs.set,
    delete: forgeKvs.kvs.delete,
    batchGet: forgeKvs.kvs.batchGet,
    batchSet: forgeKvs.kvs.batchSet,
    batchDelete: forgeKvs.kvs.batchDelete,
    transact: forgeKvs.kvs.transact,
  };
  const origAsApp = forgeApi.default.asApp;
  const origAsUser = forgeApi.default.asUser;

  globalThis.__forge_runtime__ = true;
  if (kvsMock) {
    forgeKvs.kvs.get = kvsMock.get;
    forgeKvs.kvs.set = kvsMock.set;
    forgeKvs.kvs.delete = kvsMock.delete;
    forgeKvs.kvs.batchGet = kvsMock.batchGet;
    forgeKvs.kvs.batchSet = kvsMock.batchSet;
    forgeKvs.kvs.batchDelete = kvsMock.batchDelete;
    forgeKvs.kvs.transact = kvsMock.transact;
  }
  if (asAppImpl) forgeApi.default.asApp = asAppImpl;
  if (asUserImpl) forgeApi.default.asUser = asUserImpl;

  try {
    return await fn();
  } finally {
    if (origRuntime === undefined) delete globalThis.__forge_runtime__;
    else globalThis.__forge_runtime__ = origRuntime;
    forgeKvs.kvs.get = origKvs.get;
    forgeKvs.kvs.set = origKvs.set;
    forgeKvs.kvs.delete = origKvs.delete;
    forgeKvs.kvs.batchGet = origKvs.batchGet;
    forgeKvs.kvs.batchSet = origKvs.batchSet;
    forgeKvs.kvs.batchDelete = origKvs.batchDelete;
    forgeKvs.kvs.transact = origKvs.transact;
    forgeApi.default.asApp = origAsApp;
    forgeApi.default.asUser = origAsUser;
  }
}

function makeSyntheticLinks(count, opts = {}) {
  const links = [];
  for (let i = 0; i < count; i++) {
    const num = i + 1;
    const rawIdSuffix = opts.unsafeIds ? `id/${num} with spaces?param=${'x'.repeat(110)}` : `${num}`;
    const hazKey = `HAZ-${num}`;
    const specId = opts.unsafeIds ? `srs/${rawIdSuffix}` : `srs-${num}`;
    const workKey = `MED-${num}`;
    const hash = crypto.createHash('sha256').update(`spec-${num}`).digest('hex');
    const link = ComplianceEngine.evaluateTraceLink(
      {
        id: `haz-${num}`,
        key: hazKey,
        title: `Synthetic Hazard ${num}`,
        riskClass: num % 3 === 0 ? 'CLASS_C' : num % 2 === 0 ? 'CLASS_B' : 'CLASS_A',
        severity: 'CRITICAL',
        probability: 'REMOTE',
        mitigationRequirementId: specId,
        status: 'MITIGATED',
      },
      {
        id: specId,
        pageId: String(70000 + num),
        title: `SRS-${num}: Safety Spec ${num}`,
        version: 1,
        sha256Hash: hash,
        lastSignedHash: hash,
        isSignatureInvalidated: false,
        contentSnippet: `Clause ${num}`,
        lastUpdated: '2026-11-12T00:00:00Z',
      },
      {
        id: `work-${num}`,
        key: workKey,
        title: `Task ${num}`,
        status: 'Done',
        assignee: 'QA Lead',
      },
      {
        id: `test-${num}`,
        testKey: `TEST-${num}`,
        title: `Test ${num}`,
        testType: 'Integration Test',
        status: 'PASSED',
        executionDate: '2026-11-12T00:00:00Z',
        evidenceUrl: `https://ci.example.internal/runs/${num}`,
      },
      {
        id: `sig-${num}`,
        signedBy: 'QA Lead (acc-qa)',
        signedByAccountId: 'acc-qa',
        signedAt: '2026-11-12T00:00:00Z',
        role: 'Authorized Signatory',
        meaning: 'Release signoff',
        artifactSha256: hash,
        isValid: true,
      },
      undefined,
      opts.unsafeIds ? { linkId: `trace-${hazKey}--${specId}--${workKey}` } : undefined
    );
    links.push(link);
  }
  return links;
}

test.describe('Task 1B-Seeder: Cold-Start LIVE Isolation, Migration & Overwrite Guard (CS-02)', () => {
  const origPart11Secret = process.env.MEDTRACE_PART11_SECRET;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState?.();
    seederMod.setUserIdentityResolver?.(null);
    process.env.MEDTRACE_PART11_SECRET = 'test-part11-secret-2026';
  });

  test.afterEach(() => {
    seederMod.setUserIdentityResolver?.(null);
    if (origPart11Secret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
    else process.env.MEDTRACE_PART11_SECRET = origPart11Secret;
  });

  test.it('returns uninitialized LIVE suite with 0 KVS writes and 0 audit logs on cold start', async () => {
    // Non-Forge cold start
    const localCold = await SeederService.getActiveComplianceSuite();
    assert.strictEqual(localCold.datasetMode, 'LIVE');
    assert.strictEqual(localCold.initialized, false);
    assert.strictEqual(localCold.totalHazards, 0);
    assert.strictEqual(localCold.releaseBlocked, true);
    assert.strictEqual(localCold.traceLinks.length, 0);
    assert.ok(localCold.blockingReasons.length > 0);
    assert.strictEqual((await AuditLogService.getHead()).lastSeq, 0);

    // Forge KVS cold start
    const kvsMock = createFullMockForgeKvs();
    await withForgeMocks({ kvsMock }, async () => {
      const kvsCold = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(kvsCold.datasetMode, 'LIVE');
      assert.strictEqual(kvsCold.initialized, false);
      assert.strictEqual(kvsCold.totalHazards, 0);
      assert.strictEqual(kvsCold.releaseBlocked, true);
      assert.deepStrictEqual(kvsCold.traceLinks, []);
      assert.strictEqual(kvsMock.store.size, 0, 'Cold-start must perform zero KVS writes');
      assert.strictEqual(kvsMock.calls.set.length, 0);
      assert.strictEqual(kvsMock.calls.batchSet.length, 0);
      assert.strictEqual(kvsMock.calls.transact.length, 0);
      assert.strictEqual((await AuditLogService.getHead()).lastSeq, 0, 'Cold-start must create zero audit logs');

      const directUninit = await SeederService.getUninitializedLiveSuite();
      assert.strictEqual(directUninit.datasetMode, 'LIVE');
      assert.strictEqual(directUninit.initialized, false);
      assert.strictEqual(directUninit.releaseBlocked, true);
    });
  });

  test.it('migrates legacy SINGLE_KEY_V1 active_suite to SHARDED_V2 and deletes legacy key', async () => {
    const links = makeSyntheticLinks(2);
    const legacySuite = ComplianceEngine.generateComplianceReport(links, 'LIVE', 'Legacy Medical Suite');
    delete legacySuite.initialized;
    legacySuite.storageFormat = 'SINGLE_KEY_V1';

    const kvsMock = createFullMockForgeKvs({
      'medtrace:compliance:active_suite': legacySuite,
    });

    await withForgeMocks({ kvsMock }, async () => {
      const migrated = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(migrated.storageFormat, 'SHARDED_V2');
      assert.strictEqual(migrated.datasetMode, 'LIVE');
      assert.strictEqual(migrated.initialized, true);
      assert.strictEqual(migrated.totalHazards, 2);
      assert.ok(kvsMock.store.has('medtrace:compliance:suite_meta'));
      assert.strictEqual(kvsMock.store.has('medtrace:compliance:active_suite'), false, 'Legacy key must be deleted after migration');
    });
  });

  test.it('refuses to overwrite initialized LIVE suite with DEMO data without confirmOverwriteLive: true', async () => {
    const links = makeSyntheticLinks(1);
    const liveReport = ComplianceEngine.generateComplianceReport(links, 'LIVE', 'Production Project', {
      initialized: true,
    });

    await SeederService.saveComplianceSuite(liveReport, 0);

    await assert.rejects(
      () => SeederService.seedEnterpriseDemoSuite('acc-admin', 'FORGE_USER_SESSION'),
      /confirmOverwriteLive/
    );

    const allowed = await SeederService.seedEnterpriseDemoSuite('acc-admin', 'FORGE_USER_SESSION', {
      confirmOverwriteLive: true,
    });
    assert.strictEqual(allowed.success, true);
    assert.strictEqual(allowed.summary.datasetMode, 'DEMO');
    assert.strictEqual(allowed.summary.initialized, true);
    assert.match(allowed.message, /simulated/i);
  });

  test.it('remediateClassCGap requires non-empty targetHazardKey and sets simulated work Done in DEMO', async () => {
    await SeederService.seedEnterpriseDemoSuite('acc-admin', 'SYSTEM_INIT');

    for (const emptyKey of [undefined, '', '   ']) {
      await assert.rejects(
        () =>
          SeederService.remediateClassCGap(emptyKey, 'acc-admin', {
            simulate: true,
            attestationConfirmed: true,
          }),
        /targetHazardKey|required/i
      );
    }

    const remediated = await SeederService.remediateClassCGap('HAZ-101', 'acc-admin', {
      simulate: true,
      attestationConfirmed: true,
    });
    const haz101 = remediated.traceLinks.find((l) => l.hazard.key === 'HAZ-101');
    assert.strictEqual(haz101.work.status, 'Done');
    assert.strictEqual(haz101.complianceState, 'VERIFIED');
    assert.strictEqual(haz101.hazard.status, 'MITIGATED');
    assert.strictEqual(remediated.releaseBlocked, false);
  });
});

test.describe('Task 1B-Seeder: Part 11 Identity Binding, §11.200 Enforcement & HMAC Sealing (CS-03)', () => {
  const origPart11Secret = process.env.MEDTRACE_PART11_SECRET;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState?.();
    seederMod.setUserIdentityResolver?.(null);
    process.env.MEDTRACE_PART11_SECRET = 'part11-test-hmac-secret';
  });

  test.afterEach(() => {
    seederMod.setUserIdentityResolver?.(null);
    if (origPart11Secret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
    else process.env.MEDTRACE_PART11_SECRET = origPart11Secret;
  });

  test.it('enforces MEDTRACE_PART11_SECRET, passwordConfirmed, attestationConfirmed, exact phrase, and meaning length', async () => {
    await SeederService.seedEnterpriseDemoSuite('acc-init', 'SYSTEM_INIT');
    const current = await SeederService.getActiveComplianceSuite();
    current.traceLinks[0].work.status = 'Done';
    current.traceLinks[0].test.status = 'PASSED';
    await SeederService.saveComplianceSuite(current, 1);

    // 1. Missing MEDTRACE_PART11_SECRET fails closed
    delete process.env.MEDTRACE_PART11_SECRET;
    await assert.rejects(
      () =>
        SeederService.signOffPart11({
          hazardKey: 'HAZ-101',
          attestation: {
            meaning: 'Clinical safety approval',
            attestationConfirmed: true,
            passwordConfirmed: true,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
          },
          actorAccountId: 'acc-cmo',
        }),
      /MEDTRACE_PART11_SECRET/
    );
    process.env.MEDTRACE_PART11_SECRET = 'part11-test-hmac-secret';

    // 2. Missing passwordConfirmed
    await assert.rejects(
      () =>
        SeederService.signOffPart11({
          hazardKey: 'HAZ-101',
          attestation: {
            meaning: 'Clinical safety approval',
            attestationConfirmed: true,
            passwordConfirmed: false,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
          },
          actorAccountId: 'acc-cmo',
        }),
      /passwordConfirmed/
    );

    // 3. Wrong attestationPhrase
    await assert.rejects(
      () =>
        SeederService.signOffPart11({
          hazardKey: 'HAZ-101',
          attestation: {
            meaning: 'Clinical safety approval',
            attestationConfirmed: true,
            passwordConfirmed: true,
            attestationPhrase: 'WRONG PHRASE',
          },
          actorAccountId: 'acc-cmo',
        }),
      /attestationPhrase|phrase/i
    );

    // 4. Short meaning (< 5 chars)
    await assert.rejects(
      () =>
        SeederService.signOffPart11({
          hazardKey: 'HAZ-101',
          attestation: {
            meaning: 'OK',
            attestationConfirmed: true,
            passwordConfirmed: true,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
          },
          actorAccountId: 'acc-cmo',
        }),
      /meaning/
    );
  });

  test.it('ignores spoofed signedBy/role via UserIdentityResolver, seals signature, isolates composite baselines, and ensures signedAt > invalidatedAt', async () => {
    const links = [
      ...makeSyntheticLinks(1),
      ...makeSyntheticLinks(1).map((l) => ({
        ...l,
        id: ComplianceEngine.buildTraceLinkId('HAZ-99', l.spec.id, 'MED-99'),
        hazard: { ...l.hazard, id: 'haz-99', key: 'HAZ-99' },
        work: { ...l.work, id: 'work-99', key: 'MED-99' },
        signature: { ...l.signature, id: 'sig-99', isValid: false, signedBy: '', signedAt: '' },
      })),
    ];
    links[0].signature = { ...links[0].signature, isValid: false, invalidatedAt: '2026-11-12T12:00:00.000Z' };
    await SeederService.saveComplianceSuite(
      ComplianceEngine.generateComplianceReport(links, 'LIVE', 'M:N Project', { initialized: true }),
      0
    );

    seederMod.setUserIdentityResolver({
      resolveSignerIdentity: async ({ actorAccountId }) => ({
        accountId: actorAccountId,
        displayName: `Verified Signer (${actorAccountId})`,
        role: 'VP Quality Assurance',
        authSource: 'JIRA_MYSELF',
      }),
    });

    // Pin Date.now() to the exact millisecond of invalidatedAt to test strict signedAt > invalidatedAt guarantee
    const origNow = Date.now;
    Date.now = () => new Date('2026-11-12T12:00:00.000Z').getTime();
    let signed;
    try {
      signed = await SeederService.signOffPart11({
        hazardKey: 'HAZ-1',
        specId: 'srs-1',
        attestation: {
          meaning: 'Approved for clinical release',
          attestationConfirmed: true,
          passwordConfirmed: true,
          attestationPhrase: PART11_ATTESTATION_PHRASE,
          signedBy: 'Spoofed Super Admin',
          role: 'Spoofed Chief Medical Officer',
        },
        actorAccountId: 'acc-qa-1',
      });
    } finally {
      Date.now = origNow;
    }

    const link1 = signed.traceLinks.find((l) => l.hazard.key === 'HAZ-1');
    assert.strictEqual(link1.signature.signedBy, 'Verified Signer (acc-qa-1)');
    assert.strictEqual(link1.signature.signedByAccountId, 'acc-qa-1');
    assert.strictEqual(link1.signature.role, 'VP Quality Assurance');
    assert.strictEqual(link1.signature.signatureAlgorithm, 'HMAC-SHA256-SEAL-V1');
    assert.match(link1.signature.signatureSeal, /^[a-f0-9]{64}$/);
    assert.ok(
      new Date(link1.signature.signedAt).getTime() > new Date('2026-11-12T12:00:00.000Z').getTime(),
      'signedAt must strictly post-date prior invalidatedAt'
    );
    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal('HAZ-1', 'srs-1', link1.signature, 'part11-test-hmac-secret'),
      true
    );
    assert.strictEqual(link1.complianceState, 'VERIFIED');

    // Composite baseline isolation: HAZ-1 baseline must exist, HAZ-99 sharing srs-1 must NOT inherit it
    const haz1Baseline = await SeederService.getSignedSpecBaseline('srs-1', 'HAZ-1');
    assert.ok(haz1Baseline);
    assert.strictEqual(haz1Baseline.hazardKey, 'HAZ-1');
    assert.strictEqual(haz1Baseline.signatureSeal, link1.signature.signatureSeal);

    const haz99Baseline = await SeederService.getSignedSpecBaseline('srs-1', 'HAZ-99');
    assert.strictEqual(haz99Baseline, undefined, 'Baseline signed for HAZ-1 must NOT leak to HAZ-99');

    // invalidateSignedSpecBaselines persists invalidatedAt on matching baseline
    await SeederService.invalidateSignedSpecBaselines({
      hazardKey: 'HAZ-1',
      specId: 'srs-1',
      pageId: '70001',
      newHash: 'f'.repeat(64),
      reason: 'Spec edited after sign-off',
      invalidatedAt: '2026-11-12T13:00:00.000Z',
    });
    const afterInvalidation = await SeederService.getSignedSpecBaseline('srs-1', 'HAZ-1');
    assert.strictEqual(afterInvalidation.invalidatedAt, '2026-11-12T13:00:00.000Z');
    assert.strictEqual(afterInvalidation.invalidatedByHash, 'f'.repeat(64));
  });

  test.it('forgeUserIdentityResolver rejects read-only Confluence viewers and authorizes Confluence/Jira editors', async () => {
    const links = makeSyntheticLinks(1);
    await SeederService.saveComplianceSuite(
      ComplianceEngine.generateComplianceReport(links, 'LIVE', 'Conf Auth Suite', { initialized: true }),
      0
    );

    const kvsMock = createFullMockForgeKvs({
      'medtrace:compliance:suite_meta': {
        projectName: 'Conf Auth Suite',
        datasetMode: 'LIVE',
        initialized: true,
        standards: ['IEC 62304'],
        totalHazards: 1,
        classCCount: 0,
        classBCount: 0,
        classACount: 1,
        verifiedPercentage: 100,
        releaseBlocked: false,
        blockingReasons: [],
        signatureDriftCount: 0,
        lastAuditTimestamp: new Date().toISOString(),
        linkKeys: [`medtrace:compliance:link:${links[0].id}`],
        storageFormat: 'SHARDED_V2',
        version: 1,
      },
      [`medtrace:compliance:link:${links[0].id}`]: links[0],
    });

    // Read-only Confluence viewer (even with personal space write access)
    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestConfluence: async (routeObj) => {
            const r = String(routeObj?.value || routeObj);
            if (r.includes('/wiki/rest/api/user/current')) {
              return makeJsonResponse(200, { accountId: 'conf-viewer', displayName: 'Viewer Only' });
            }
            if (r.includes('/wiki/api/v2/spaces?type=global')) {
              return makeJsonResponse(200, {
                results: [
                  { id: 'global-1', type: 'global' },
                  { id: 'personal-1', type: 'personal' },
                ],
              });
            }
            if (r.includes('/wiki/api/v2/spaces/global-1/operations')) {
              return makeJsonResponse(200, {
                operations: [{ operation: 'read', targetType: 'page' }],
              });
            }
            if (r.includes('/wiki/api/v2/spaces/personal-1/operations')) {
              return makeJsonResponse(200, {
                operations: [{ operation: 'create', targetType: 'page' }],
              });
            }
            return makeJsonResponse(403, {});
          },
          requestJira: async () => makeJsonResponse(403, {}),
        }),
      },
      async () => {
        await assert.rejects(
          () =>
            SeederService.signOffPart11({
              hazardKey: 'HAZ-1',
              extensionType: 'confluence:globalPage',
              attestation: {
                meaning: 'Attempted viewer sign-off',
                attestationConfirmed: true,
                passwordConfirmed: true,
                attestationPhrase: PART11_ATTESTATION_PHRASE,
              },
              actorAccountId: 'conf-viewer',
            }),
          /Forbidden/
        );
      }
    );

    // Jira editor derives displayName & role from /myself + /mypermissions
    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async (routeObj) => {
            const r = String(routeObj?.value || routeObj);
            if (r.includes('/rest/api/3/myself')) {
              return makeJsonResponse(200, {
                accountId: 'jira-admin-1',
                displayName: 'Dr. Elena Rostova',
                active: true,
                groups: { items: [] },
              });
            }
            if (r.includes('/rest/api/3/mypermissions')) {
              return makeJsonResponse(200, {
                permissions: {
                  EDIT_ISSUES: { havePermission: true },
                  ADMINISTER_PROJECTS: { havePermission: true },
                },
              });
            }
            return makeJsonResponse(404, {});
          },
          requestConfluence: async () => makeJsonResponse(403, {}),
        }),
      },
      async () => {
        const res = await SeederService.signOffPart11({
          hazardKey: 'HAZ-1',
          extensionType: 'jira:projectPage',
          projectKey: 'MED',
          attestation: {
            meaning: 'Verified Jira admin Part 11 sign-off',
            attestationConfirmed: true,
            passwordConfirmed: true,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
            signedBy: 'Evil Spoofer',
            role: 'Evil Role',
          },
          actorAccountId: 'jira-admin-1',
        });
        const signedLink = res.traceLinks.find((l) => l.hazard.key === 'HAZ-1');
        assert.strictEqual(signedLink.signature.signedBy, 'Dr. Elena Rostova (jira-admin-1)');
        assert.strictEqual(signedLink.signature.signedByAccountId, 'jira-admin-1');
        assert.match(signedLink.signature.role, /Administrator|Approver/);
      }
    );
  });
});

test.describe('Task 1B-Seeder: Atomic KVS Transactions, 60-Link Sharding, GC, vlock & Rollback (CS-05)', () => {
  const origPart11Secret = process.env.MEDTRACE_PART11_SECRET;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState?.();
    seederMod.setUserIdentityResolver?.(null);
    process.env.MEDTRACE_PART11_SECRET = 'storage-test-part11-secret';
  });

  test.afterEach(() => {
    seederMod.setUserIdentityResolver?.(null);
    if (origPart11Secret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
    else process.env.MEDTRACE_PART11_SECRET = origPart11Secret;
  });

  test.it('commits <= 25 ops via single kvs.transact() with vlock TTL and aborts on vlock conflict', async () => {
    const kvsMock = createFullMockForgeKvs();
    const links3 = makeSyntheticLinks(3);
    const suite3 = ComplianceEngine.generateComplianceReport(links3, 'LIVE', 'Small Suite', { initialized: true });

    await withForgeMocks({ kvsMock }, async () => {
      await SeederService.saveComplianceSuite(suite3, 0);
      assert.strictEqual(kvsMock.calls.transact.length, 1, 'Small suite must commit via 1 kvs.transact() call');
      assert.strictEqual(kvsMock.calls.batchSet.length, 0);

      // vlock:1 must be written with FAIL_IF_EXISTS + 1m TTL and NOT deleted after commit
      const vlockSet = kvsMock.calls.set.find((c) => c.key === 'medtrace:compliance:vlock:1');
      assert.ok(vlockSet, 'Expected vlock:1 write');
      assert.deepStrictEqual(vlockSet.opts, {
        keyPolicy: 'FAIL_IF_EXISTS',
        ttl: { value: 1, unit: 'MINUTES' },
      });
      assert.ok(kvsMock.store.has('medtrace:compliance:vlock:1'), 'vlock must expire via TTL, not post-commit delete');

      // expectedVersion === 0 must reject when suite_meta already exists
      await assert.rejects(
        () => SeederService.saveComplianceSuite(suite3, 0),
        /Concurrent modification detected/
      );

      // Colliding on vlock:2 must abort second writer without touching suite_meta
      kvsMock.store.set('medtrace:compliance:vlock:2', { claimedAt: Date.now() });
      await assert.rejects(
        () => SeederService.saveComplianceSuite(suite3, 1),
        /Concurrent modification detected|version lock conflict/i
      );
      assert.strictEqual(kvsMock.store.get('medtrace:compliance:suite_meta').version, 1);
    });
  });

  test.it('chunks 60 links (>25 ops), sanitizes keys, shards >128 KiB metadata, GCs shrunk link:* keys, and fails closed on batchGet failedKeys', async () => {
    const kvsMock = createFullMockForgeKvs();
    const links60 = makeSyntheticLinks(60, { unsafeIds: true });
    const hugeReasons = Array.from({ length: 800 }, (_, i) => `Blocking reason ${i}: ${'R'.repeat(200)}`);
    const largeSuite = {
      ...ComplianceEngine.generateComplianceReport(links60, 'LIVE', 'Large Sharded Suite', { initialized: true }),
      blockingReasons: hugeReasons,
    };

    await withForgeMocks({ kvsMock }, async () => {
      await SeederService.saveComplianceSuite(largeSuite, 0);

      // Assert all keys conform to Forge KVS regex & <= 500 chars and batchSet chunks <= 25
      assert.ok(kvsMock.calls.batchSet.length >= 3, '60 links + meta shards must span >= 3 batchSet chunks');
      const storedMeta = kvsMock.store.get('medtrace:compliance:suite_meta');
      assert.ok(Buffer.byteLength(JSON.stringify(storedMeta), 'utf8') < 128 * 1024, 'suite_meta must stay under 128 KiB via sharding');
      assert.ok(
        Array.isArray(storedMeta.blockingReasonShardKeys) && storedMeta.blockingReasonShardKeys.length >= 1,
        'Expected >128 KiB blockingReasons to be sharded'
      );

      const loaded60 = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(loaded60.totalHazards, 60);
      assert.strictEqual(loaded60.traceLinks.length, 60);
      assert.strictEqual(loaded60.blockingReasons.length, 800);
      assert.strictEqual(loaded60.traceLinks[0].spec.id, links60[0].spec.id);

      // Shrink from 60 links down to 10 links -> obsolete link:* and meta shards GC'd via batchDelete
      kvsMock.resetCalls();
      const links10 = links60.slice(0, 10);
      const smallSuite = ComplianceEngine.generateComplianceReport(links10, 'LIVE', 'Shrunk Suite', { initialized: true });
      await SeederService.saveComplianceSuite(smallSuite, 1);

      assert.ok(kvsMock.calls.batchDelete.length >= 2, 'Shrinking 60->10 must GC obsolete keys via chunked batchDelete');
      const remainingLinkKeys = Array.from(kvsMock.store.keys()).filter((k) => k.startsWith('medtrace:compliance:link:'));
      assert.strictEqual(remainingLinkKeys.length, 10, 'Exactly 10 active link:* keys should remain after GC');

      const loaded10 = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(loaded10.traceLinks.length, 10);
    });

    // Persistent batchGet failedKeys must throw fail-closed
    const seededStore = cloneJson(Object.fromEntries(kvsMock.store.entries()));
    const failGetMock = createFullMockForgeKvs(seededStore, {
      onBatchGet: (items) => ({
        successfulKeys: [],
        failedKeys: items.map((i) => ({ key: i.key, error: { code: 'TRANSIENT_OR_DOWN' } })),
      }),
    });
    await withForgeMocks({ kvsMock: failGetMock }, async () => {
      await assert.rejects(
        () => SeederService.getActiveComplianceSuite(),
        /Failed to batch-read/
      );
      assert.strictEqual(failGetMock.calls.batchGet.length, 2, 'Should retry failedKeys once before failing closed');
    });
  });

  test.it('executes save-before-audit and performs compensating rollback (passing version+1 & restoring baselines) if AuditLogService.append fails', async () => {
    const kvsMock = createFullMockForgeKvs();
    const links = makeSyntheticLinks(2);
    links[0].signature = { ...links[0].signature, isValid: false, signedBy: '', signedAt: '' };
    const initialSuite = ComplianceEngine.generateComplianceReport(links, 'LIVE', 'Rollback Suite', { initialized: true });
    seederMod.setUserIdentityResolver({
      resolveSignerIdentity: async ({ actorAccountId }) => ({
        accountId: actorAccountId,
        displayName: `QA Signer (${actorAccountId})`,
        role: 'Quality Assurance Approver',
        authSource: 'JIRA_MYSELF',
      }),
    });

    await withForgeMocks({ kvsMock }, async () => {
      await SeederService.saveComplianceSuite(initialSuite, 0);
      const initialAuditSeq = (await AuditLogService.getHead()).lastSeq;

      // Force AuditLogService.append to throw
      const origAppend = AuditLogService.append;
      AuditLogService.append = async () => {
        throw new Error('Simulated audit ledger outage');
      };

      try {
        await assert.rejects(
          () =>
            SeederService.signOffPart11({
              hazardKey: 'HAZ-1',
              specId: 'srs-1',
              attestation: {
                meaning: 'Approval that must roll back',
                attestationConfirmed: true,
                passwordConfirmed: true,
                attestationPhrase: PART11_ATTESTATION_PHRASE,
              },
              actorAccountId: 'acc-qa-rollback',
            }),
          /Simulated audit ledger outage/
        );
      } finally {
        AuditLogService.append = origAppend;
      }

      assert.strictEqual((await AuditLogService.getHead()).lastSeq, initialAuditSeq, 'Audit head must remain unchanged');
      const afterRollback = await SeederService.getActiveComplianceSuite();
      const link1 = afterRollback.traceLinks.find((l) => l.hazard.key === 'HAZ-1');
      assert.strictEqual(link1.signature.isValid, false, 'Link signature must roll back to pre-mutation invalid state');
      assert.strictEqual(
        await SeederService.getSignedSpecBaseline('srs-1', 'HAZ-1'),
        undefined,
        'SignedSpecBaseline must roll back when AuditLogService.append fails'
      );
      assert.strictEqual(kvsMock.store.get('medtrace:compliance:suite_meta').version, 3, 'Rollback advances version atomically');
    });
  });
});

test.describe('Task 1B-Seeder: bindIssueToHazard & recordTestResult Hardening (CS-07)', () => {
  const origPart11Secret = process.env.MEDTRACE_PART11_SECRET;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState?.();
    process.env.MEDTRACE_PART11_SECRET = 'cs07-test-secret';
  });

  test.afterEach(() => {
    if (origPart11Secret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
    else process.env.MEDTRACE_PART11_SECRET = origPart11Secret;
  });

  test.it('bindIssueToHazard uses callerMode USER, clears stale prNumber/commitSha/graphMetadata, and updates hazard.status', async () => {
    await SeederService.seedEnterpriseDemoSuite('acc-init', 'SYSTEM_INIT');
    const kvsMock = createFullMockForgeKvs();
    let usedAsUser = 0;
    let usedAsApp = 0;

    await withForgeMocks(
      {
        kvsMock,
        asAppImpl: () => ({
          requestJira: async () => {
            usedAsApp++;
            return makeJsonResponse(500, {});
          },
          requestConfluence: async () => makeJsonResponse(200, { results: [] }),
        }),
        asUserImpl: () => ({
          requestJira: async (routeObj) => {
            usedAsUser++;
            const r = String(routeObj?.value || routeObj);
            assert.match(r, /\/rest\/api\/3\/issue\/MED-500/);
            return makeJsonResponse(200, {
              id: '50500',
              key: 'MED-500',
              fields: {
                summary: 'Verified Hardware Clamp',
                status: { name: 'Done', statusCategory: { name: 'Done' } },
                assignee: { displayName: 'Alice Firmware' },
              },
            });
          },
        }),
      },
      async () => {
        await SeederService.seedEnterpriseDemoSuite('acc-init', 'SYSTEM_INIT');
        const bound = await SeederService.bindIssueToHazard('HAZ-101', 'MED-500', 'acc-user', 'FORGE_USER_SESSION', {
          callerMode: 'USER',
        });
        assert.strictEqual(usedAsUser, 1);
        assert.strictEqual(usedAsApp, 0, 'User-initiated bindIssueToHazard must NOT call api.asApp()');

        const haz101 = bound.traceLinks.find((l) => l.hazard.key === 'HAZ-101');
        assert.strictEqual(haz101.work.key, 'MED-500');
        assert.strictEqual(haz101.work.status, 'Done');
        assert.strictEqual(haz101.work.prNumber, undefined, 'Stale prNumber must be cleared');
        assert.strictEqual(haz101.work.commitSha, undefined, 'Stale commitSha must be cleared');
        assert.strictEqual(haz101.graphMetadata, undefined, 'Stale graphMetadata must be cleared');
        assert.strictEqual(haz101.hazard.status, 'ACTION_REQUIRED');
      }
    );
  });

  test.it('recordTestResult validates https:// evidenceUrl, clears URL/notes on empty string, and updates hazard.status', async () => {
    const links = makeSyntheticLinks(1);
    await SeederService.saveComplianceSuite(
      ComplianceEngine.generateComplianceReport(links, 'LIVE', 'Test Evidence Suite', { initialized: true }),
      0
    );

    for (const badUrl of ['http://insecure.example.com/run/1', 'javascript:alert(1)', 'https://user:pass@ci.internal/run']) {
      await assert.rejects(
        () =>
          SeederService.recordTestResult({
            hazardKey: 'HAZ-1',
            status: 'PASSED',
            evidenceUrl: badUrl,
            actorAccountId: 'qa-1',
          }),
        /https:\/\/|Unsafe URL|credentials|Invalid URL/i
      );
    }

    const cleared = await SeederService.recordTestResult({
      hazardKey: 'HAZ-1',
      status: 'FAILED',
      evidenceUrl: '',
      notes: '',
      actorAccountId: 'qa-1',
    });
    const linkAfterFail = cleared.traceLinks[0];
    assert.strictEqual(linkAfterFail.test.status, 'FAILED');
    assert.strictEqual(linkAfterFail.test.evidenceUrl, undefined, 'Empty string must clear evidenceUrl');
    assert.strictEqual(linkAfterFail.test.notes, undefined, 'Empty string must clear notes');
    assert.strictEqual(linkAfterFail.hazard.status, 'UNVERIFIED_RISK');
  });

  test.it('reuses unchanged v<version> link shards on delta writes and serves issueKeyFilter reads in O(1) KVS reads', async () => {
    const links30 = makeSyntheticLinks(30);
    const kvsMock = createFullMockForgeKvs();

    await withForgeMocks({ kvsMock }, async () => {
      const suiteV1 = ComplianceEngine.generateComplianceReport(links30, 'LIVE', 'Delta & Index Pump', {
        initialized: true,
      });
      await SeederService.saveComplianceSuite(suiteV1, 0);

      // Modify only link #1 and shrink/preserve remaining 29 unchanged links -> v2 delta write
      const modifiedLinks = links30.map((l, idx) =>
        idx === 0
          ? {
              ...l,
              work: { ...l.work, title: 'Updated Hardware Clamp Title' },
            }
          : l
      );
      const suiteV2 = ComplianceEngine.generateComplianceReport(modifiedLinks, 'LIVE', 'Delta & Index Pump', {
        initialized: true,
      });

      kvsMock.calls.batchSet.length = 0;
      kvsMock.calls.batchDelete.length = 0;
      await SeederService.saveComplianceSuite(suiteV2, 1);

      const totalStagedWrites = kvsMock.calls.batchSet.reduce((acc, batch) => acc + batch.length, 0);
      assert.strictEqual(
        totalStagedWrites,
        1,
        `Expected delta write of 1 modified link shard (reusing 29 unchanged v1 shards), wrote ${totalStagedWrites}`
      );
      const deletedCount = kvsMock.calls.batchDelete.reduce((acc, batch) => acc + batch.length, 0);
      assert.strictEqual(deletedCount, 1, 'Expected only superseded v1 key for modified HAZ-1 to be deleted');

      // Simulate cold lambda staging failure rollback on v3: reused v1 shards must survive!
      const v3Links = modifiedLinks.map((l, idx) =>
        idx === 1 ? { ...l, work: { ...l.work, title: 'Mutate 2 Fails' } } : l
      );
      const suiteV3 = ComplianceEngine.generateComplianceReport(v3Links, 'LIVE', 'Delta & Index Pump', {
        initialized: true,
      });
      const origBatchSet = forgeKvs.kvs.batchSet;
      forgeKvs.kvs.batchSet = async () => {
        throw new Error('Injected staging failure on v3');
      };
      try {
        await assert.rejects(() => SeederService.saveComplianceSuite(suiteV3, 2), /Injected staging failure on v3/);
      } finally {
        forgeKvs.kvs.batchSet = origBatchSet;
      }

      // Fast-path O(1) lookup for linked work key MED-7 -> only 1 link shard fetched via batchGet
      kvsMock.calls.batchGet.length = 0;
      kvsMock.calls.get.length = 0;
      const fastHit = await SeederService.getActiveComplianceSuite({ issueKeyFilter: 'med-7' });
      assert.strictEqual(fastHit.totalHazards, 30);
      assert.strictEqual(fastHit.traceLinks.length, 1);
      assert.strictEqual(fastHit.traceLinks[0].work.key, 'MED-7');
      const linkBatchGetsHit = kvsMock.calls.batchGet.filter((keys) =>
        keys.some((k) => k.startsWith('medtrace:compliance:link:'))
      );
      assert.strictEqual(linkBatchGetsHit.length, 1);
      assert.strictEqual(linkBatchGetsHit[0].length, 1, 'Expected exactly 1 KVS link shard read for MED-7');

      // Fast-path O(1) lookup for unlinked issue UNLINKED-999 -> 0 link shard batchGet calls
      kvsMock.calls.batchGet.length = 0;
      const fastMiss = await SeederService.getActiveComplianceSuite({ issueKeyFilter: 'UNLINKED-999' });
      assert.strictEqual(fastMiss.initialized, true);
      assert.strictEqual(fastMiss.totalHazards, 30);
      assert.strictEqual(fastMiss.traceLinks.length, 0);
      const linkBatchGetsMiss = kvsMock.calls.batchGet.filter((keys) =>
        keys.some((k) => k.startsWith('medtrace:compliance:link:'))
      );
      assert.strictEqual(linkBatchGetsMiss.length, 0, 'Unlinked issue must require 0 link shard reads');
      assert.strictEqual(ComplianceEngine.evaluateIssueReleaseGate('UNLINKED-999', fastMiss).result, true);

      // Full read confirms all 30 links survived delta reuse & aborted v3 rollback intact
      const fullLoaded = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(fullLoaded.traceLinks.length, 30);
      assert.strictEqual(fullLoaded.traceLinks[0].work.title, 'Updated Hardware Clamp Title');
      assert.strictEqual(fullLoaded.traceLinks[1].work.title, 'Task 2');
    });
  });

  test.it('shards issueKeyIndex into meta_index:* when suite_meta exceeds 128 KiB while keeping fast-path O(1) lookup', async () => {
    const links1200 = makeSyntheticLinks(1200);
    const kvsMock = createFullMockForgeKvs();

    await withForgeMocks({ kvsMock }, async () => {
      const largeIndexSuite = ComplianceEngine.generateComplianceReport(
        links1200,
        'LIVE',
        'Sharded Meta Index Suite',
        { initialized: true }
      );
      await SeederService.saveComplianceSuite(largeIndexSuite, 0);

      const storedMeta = kvsMock.store.get('medtrace:compliance:suite_meta');
      assert.ok(
        Buffer.byteLength(JSON.stringify(storedMeta), 'utf8') <= 128 * 1024,
        'suite_meta must stay <= 128 KiB after sharding issueKeyIndex'
      );
      assert.strictEqual(storedMeta.issueKeyIndex, undefined, 'Oversized inline issueKeyIndex should move to shards');
      assert.ok(
        Array.isArray(storedMeta.issueKeyIndexShardKeys) && storedMeta.issueKeyIndexShardKeys.length >= 2,
        `Expected >= 2 meta_index shards, got ${JSON.stringify(storedMeta.issueKeyIndexShardKeys)}`
      );

      kvsMock.calls.batchGet.length = 0;
      const hit = await SeederService.getActiveComplianceSuite({ issueKeyFilter: 'MED-1150' });
      assert.strictEqual(hit.totalHazards, 1200);
      assert.strictEqual(hit.traceLinks.length, 1);
      assert.strictEqual(hit.traceLinks[0].work.key, 'MED-1150');

      const linkBatchGets = kvsMock.calls.batchGet.filter((keys) =>
        keys.some((k) => k.startsWith('medtrace:compliance:link:'))
      );
      assert.strictEqual(linkBatchGets.length, 1);
      assert.strictEqual(linkBatchGets[0].length, 1, 'Expected only 1 link shard fetch when using meta_index shards');

      const miss = await SeederService.getActiveComplianceSuite({ issueKeyFilter: 'MISSING-9999' });
      assert.strictEqual(miss.traceLinks.length, 0);

      // Re-saving shrunk suite cleans up v1 meta_index shards
      const shrunk = ComplianceEngine.generateComplianceReport(links1200.slice(0, 5), 'LIVE', 'Shrunk', {
        initialized: true,
      });
      await SeederService.saveComplianceSuite(shrunk, 1);
      const remainingIndexShards = Array.from(kvsMock.store.keys()).filter((k) =>
        k.startsWith('medtrace:compliance:meta_index:')
      );
      assert.strictEqual(remainingIndexShards.length, 0, 'Old meta_index shards must be garbage-collected');
    });
  });

  test.it('signOffPart11 accepts valid ECDSA P-256 + HMAC hybrid signatures, rejects forged keys, and clears stale ECDSA fields on HMAC-only re-sign', async () => {
    const links = makeSyntheticLinks(1);
    const target = links[0];
    await SeederService.saveComplianceSuite(
      ComplianceEngine.generateComplianceReport(links, 'LIVE', 'Hybrid ECDSA Suite', { initialized: true }),
      0
    );

    seederMod.setUserIdentityResolver({
      resolveSignerIdentity: async ({ actorAccountId }) => ({
        accountId: actorAccountId,
        displayName: `ECDSA Signer (${actorAccountId})`,
        role: 'Authorized Atlassian User',
        authSource: 'JIRA_MYSELF',
      }),
    });

    const kp = ComplianceEngine.generateEcdsaP256KeyPair();
    const otherKp = ComplianceEngine.generateEcdsaP256KeyPair();
    const challenge = ComplianceEngine.computePart11ClientChallenge({
      hazardKey: target.hazard.key,
      specId: target.spec.id,
      artifactSha256: target.spec.sha256Hash,
      meaning: 'Hybrid ECDSA P-256 clinical sign-off',
      attestationPhrase: PART11_ATTESTATION_PHRASE,
    });
    const validClientSig = ComplianceEngine.signPart11ClientChallenge(challenge, kp.privateKeyPkcs8Base64);
    const wrongClientSig = ComplianceEngine.signPart11ClientChallenge(challenge, otherKp.privateKeyPkcs8Base64);

    // Mismatched signature/keypair must fail before mutating suite or audit log
    await assert.rejects(
      () =>
        SeederService.signOffPart11({
          hazardKey: target.hazard.key,
          specId: target.spec.id,
          attestation: {
            meaning: 'Hybrid ECDSA P-256 clinical sign-off',
            attestationConfirmed: true,
            passwordConfirmed: true,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
            clientPublicKeySpki: kp.publicKeySpkiBase64,
            clientSignatureBase64: wrongClientSig,
          },
          actorAccountId: 'acc-ecdsa-signer',
        }),
      /PART11_CLIENT_SIGNATURE_INVALID/
    );

    // Valid hybrid signature succeeds and records ECDSA metadata on link, baseline, and audit log
    const hybridSigned = await SeederService.signOffPart11({
      hazardKey: target.hazard.key,
      specId: target.spec.id,
      attestation: {
        meaning: 'Hybrid ECDSA P-256 clinical sign-off',
        attestationConfirmed: true,
        passwordConfirmed: true,
        attestationPhrase: PART11_ATTESTATION_PHRASE,
        clientPublicKeySpki: kp.publicKeySpkiBase64,
        clientSignatureBase64: validClientSig,
      },
      actorAccountId: 'acc-ecdsa-signer',
    });

    const sig = hybridSigned.traceLinks[0].signature;
    assert.strictEqual(hybridSigned.traceLinks[0].complianceState, 'VERIFIED');
    assert.strictEqual(sig.signatureAlgorithm, 'ECDSA-P256-SHA256+HMAC-SEAL-V1');
    assert.strictEqual(sig.clientPublicKeySpki, kp.publicKeySpkiBase64);
    assert.strictEqual(sig.clientSignatureBase64, validClientSig);
    assert.strictEqual(sig.clientKeyFingerprint, kp.keyFingerprint);
    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal(
        target.hazard.key,
        target.spec.id,
        sig,
        process.env.MEDTRACE_PART11_SECRET
      ),
      true
    );

    const baseline = await SeederService.getSignedSpecBaseline(target.spec.id, target.hazard.key);
    assert.strictEqual(baseline.signatureAlgorithm, 'ECDSA-P256-SHA256+HMAC-SEAL-V1');
    assert.strictEqual(baseline.clientKeyFingerprint, kp.keyFingerprint);
    assert.strictEqual(baseline.clientSignatureBase64, validClientSig);

    const auditEntries = await AuditLogService.getAuditLog(10);
    const signOffAudit = auditEntries.find((e) => e.action === 'PART11_SIGNOFF');
    assert.ok(signOffAudit);
    assert.strictEqual(signOffAudit.details.signatureAlgorithm, 'ECDSA-P256-SHA256+HMAC-SEAL-V1');
    assert.strictEqual(signOffAudit.details.clientKeyFingerprint, kp.keyFingerprint);

    // Re-signing without client ECDSA fields cleanly resets to HMAC-SHA256-SEAL-V1 without stale ECDSA leftovers
    const hmacOnly = await SeederService.signOffPart11({
      hazardKey: target.hazard.key,
      specId: target.spec.id,
      attestation: {
        meaning: 'Standard HMAC re-certification',
        attestationConfirmed: true,
        passwordConfirmed: true,
        attestationPhrase: PART11_ATTESTATION_PHRASE,
      },
      actorAccountId: 'acc-hmac-signer',
    });
    const resetSig = hmacOnly.traceLinks[0].signature;
    assert.strictEqual(hmacOnly.traceLinks[0].complianceState, 'VERIFIED');
    assert.strictEqual(resetSig.signatureAlgorithm, 'HMAC-SHA256-SEAL-V1');
    assert.strictEqual(resetSig.clientSignatureBase64, undefined);
    assert.strictEqual(resetSig.clientPublicKeySpki, undefined);
    assert.strictEqual(resetSig.clientKeyFingerprint, undefined);
  });
});
