const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const forgeApi = require('@forge/api');
const forgeKvs = require('@forge/kvs');
const { ComplianceEngine } = require('../dist/compliance-engine');
const { workflowValidatorHandler } = require('../dist/workflow-validator');
const { McpToolService, rovoActionHandler } = require('../dist/mcp-server');
const indexModule = require('../dist/index');
const { SeederService } = require('../dist/seeder');
const { LiveIngestionService } = require('../dist/ingestion');
const { setAuditStorageAdapter, resetInMemoryAuditStorage } = require('../dist/audit-log');

const { mcpWebtriggerHandler, getNonceStore, setNonceStore, createInMemoryNonceStore } = indexModule;

function makeJsonResponse(status, data) {
  return {
    status,
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

function createLocalMockKvs(seed = {}) {
  const store = new Map(Object.entries(seed).map(([k, v]) => [k, JSON.parse(JSON.stringify(v))]));
  return {
    store,
    get: async (key) => {
      const val = store.get(key);
      return val === undefined ? undefined : JSON.parse(JSON.stringify(val));
    },
    set: async (key, val, opts) => {
      if (opts && opts.keyPolicy === 'FAIL_IF_EXISTS' && store.has(key)) {
        const err = new Error('Key already exists');
        err.status = 409;
        err.code = 'KEY_ALREADY_EXISTS';
        throw err;
      }
      const previous = store.has(key) ? JSON.parse(JSON.stringify(store.get(key))) : undefined;
      store.set(key, JSON.parse(JSON.stringify(val)));
      if (opts && opts.keyPolicy === 'OVERRIDE' && opts.returnValue === 'PREVIOUS') {
        return previous !== undefined ? { key, value: previous } : undefined;
      }
      return undefined;
    },
    delete: async (key) => {
      store.delete(key);
    },
    batchSet: async (items) => {
      for (const item of items) {
        store.set(item.key, JSON.parse(JSON.stringify(item.value)));
      }
      return { successfulKeys: items.map((i) => ({ key: i.key })), failedKeys: [] };
    },
    batchGet: async (items) => {
      const successfulKeys = [];
      for (const item of items) {
        if (store.has(item.key)) {
          successfulKeys.push({ key: item.key, value: JSON.parse(JSON.stringify(store.get(item.key))) });
        }
      }
      return { successfulKeys, failedKeys: [] };
    },
    batchDelete: async (items) => {
      for (const item of items) {
        store.delete(item.key);
      }
      return { successfulKeys: items.map((i) => ({ key: i.key })), failedKeys: [] };
    },
    transact: () => {
      const ops = [];
      const builder = {
        set: (key, value) => {
          ops.push({ type: 'set', key, value });
          return builder;
        },
        delete: (key) => {
          ops.push({ type: 'delete', key });
          return builder;
        },
        execute: async () => {
          for (const op of ops) {
            if (op.type === 'set') store.set(op.key, JSON.parse(JSON.stringify(op.value)));
            else store.delete(op.key);
          }
        },
      };
      return builder;
    },
  };
}

function withForgeMocks({ kvsMock, asAppImpl, asUserImpl, appContext }, fn) {
  const origRuntime = globalThis.__forge_runtime__;
  const origKvs = {
    get: forgeKvs.kvs.get,
    set: forgeKvs.kvs.set,
    delete: forgeKvs.kvs.delete,
    batchSet: forgeKvs.kvs.batchSet,
    batchGet: forgeKvs.kvs.batchGet,
    batchDelete: forgeKvs.kvs.batchDelete,
    transact: forgeKvs.kvs.transact,
  };
  const origAsApp = forgeApi.default.asApp;
  const origAsUser = forgeApi.default.asUser;
  const origGetAppContextDesc = Object.getOwnPropertyDescriptor(forgeApi, 'getAppContext');

  globalThis.__forge_runtime__ = true;
  if (kvsMock) {
    forgeKvs.kvs.get = kvsMock.get;
    forgeKvs.kvs.set = kvsMock.set;
    forgeKvs.kvs.delete = kvsMock.delete;
    forgeKvs.kvs.batchSet = kvsMock.batchSet;
    forgeKvs.kvs.batchGet = kvsMock.batchGet;
    forgeKvs.kvs.batchDelete = kvsMock.batchDelete;
    forgeKvs.kvs.transact = kvsMock.transact;
  }
  if (asAppImpl) forgeApi.default.asApp = asAppImpl;
  if (asUserImpl) forgeApi.default.asUser = asUserImpl;
  if (appContext !== undefined) {
    Object.defineProperty(forgeApi, 'getAppContext', {
      configurable: true,
      enumerable: true,
      value: () => appContext,
    });
  }

  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (origRuntime === undefined) delete globalThis.__forge_runtime__;
      else globalThis.__forge_runtime__ = origRuntime;
      forgeKvs.kvs.get = origKvs.get;
      forgeKvs.kvs.set = origKvs.set;
      forgeKvs.kvs.delete = origKvs.delete;
      forgeKvs.kvs.batchSet = origKvs.batchSet;
      forgeKvs.kvs.batchGet = origKvs.batchGet;
      forgeKvs.kvs.batchDelete = origKvs.batchDelete;
      forgeKvs.kvs.transact = origKvs.transact;
      forgeApi.default.asApp = origAsApp;
      forgeApi.default.asUser = origAsUser;
      if (origGetAppContextDesc) {
        Object.defineProperty(forgeApi, 'getAppContext', origGetAppContextDesc);
      }
    });
}

function buildSampleLinks() {
  const hashA = 'a'.repeat(64);
  const hashB = 'b'.repeat(64);
  const hashC = 'c'.repeat(64);
  const hashD = 'd'.repeat(64);

  const blockedLink = ComplianceEngine.evaluateTraceLink(
    {
      id: 'haz-101',
      key: 'HAZ-101',
      title: 'Over-Infusion Bolus Hazard',
      riskClass: 'CLASS_C',
      severity: 'CATASTROPHIC',
      probability: 'OCCASIONAL',
      mitigationRequirementId: 'srs-104',
      status: 'ACTION_REQUIRED',
    },
    {
      id: 'srs-104',
      pageId: '55104',
      title: 'SRS-104: Hardware Bolus Clamp',
      version: 3,
      sha256Hash: hashA,
      lastSignedHash: hashA,
      isSignatureInvalidated: false,
      contentSnippet: 'Hardware clamp rate limiter threshold',
      lastUpdated: '2026-10-15T10:00:00Z',
    },
    {
      id: 'med-42',
      key: 'MED-42',
      title: 'Implement Bolus Clamp Driver',
      status: 'In Progress',
      assignee: 'Dr. Sarah Lin',
    },
    {
      id: 'test-88',
      testKey: 'TEST-88',
      title: 'Bolus Clamp HIL Stress Test',
      testType: 'Automated HIL (Hardware-in-Loop)',
      status: 'UNTESTED',
    },
    {
      id: 'sig-001',
      signedBy: 'Marcus Vance, MD',
      signedAt: '2026-10-15T11:30:00Z',
      role: 'Clinical Safety Authority',
      meaning: 'Safety spec approved',
      artifactSha256: hashA,
      isValid: true,
    }
  );

  const verifiedLink = ComplianceEngine.evaluateTraceLink(
    {
      id: 'uuid-haz-102',
      key: 'HAZ-102',
      title: 'Occlusion Sensor Drift',
      riskClass: 'CLASS_B',
      severity: 'CRITICAL',
      probability: 'REMOTE',
      mitigationRequirementId: 'srs-105',
      status: 'MITIGATED',
    },
    {
      id: 'srs-105',
      pageId: '55105',
      title: 'SRS-105: Optical Droplet Calibration',
      version: 2,
      sha256Hash: hashB,
      lastSignedHash: hashB,
      isSignatureInvalidated: false,
      contentSnippet: 'Photodiode droplet stall calibration',
      lastUpdated: '2026-10-15T10:00:00Z',
    },
    {
      id: '10043',
      key: 'MED-43',
      title: 'Optical Stall Detection',
      status: 'Done',
      assignee: 'Alex Rivera',
    },
    {
      id: '10089',
      testKey: 'TEST-89',
      title: 'Optical Droplet Integration Suite',
      testType: 'Integration Test',
      status: 'PASSED',
    },
    {
      id: 'sig-002',
      signedBy: 'Marcus Vance, MD',
      signedAt: '2026-10-15T11:30:00Z',
      role: 'Clinical Safety Authority',
      meaning: 'Calibration spec approved',
      artifactSha256: hashB,
      isValid: true,
    }
  );

  const sharedVerifiedLink = ComplianceEngine.evaluateTraceLink(
    {
      id: 'haz-200',
      key: 'HAZ-200',
      title: 'Telemetry Escalation Timeout',
      riskClass: 'CLASS_C',
      severity: 'CRITICAL',
      probability: 'REMOTE',
      mitigationRequirementId: 'srs-200',
      status: 'ACTION_REQUIRED',
    },
    {
      id: 'srs-200',
      pageId: '55200',
      title: 'SRS-200: Telemetry Heartbeat Watchdog',
      version: 1,
      sha256Hash: hashC,
      lastSignedHash: hashC,
      isSignatureInvalidated: false,
      contentSnippet: 'Telemetry watchdog interval verification',
      lastUpdated: '2026-10-15T10:00:00Z',
    },
    {
      id: 'med-501',
      key: 'MED-501',
      title: 'Primary Telemetry Channel',
      status: 'Done',
      assignee: 'Jamie Chen',
    },
    {
      id: 'test-501',
      testKey: 'TEST-501',
      title: 'Primary Telemetry Heartbeat Test',
      testType: 'Integration Test',
      status: 'PASSED',
    },
    {
      id: 'sig-200',
      signedBy: 'Marcus Vance, MD',
      signedAt: '2026-10-15T11:30:00Z',
      role: 'Clinical Safety Authority',
      meaning: 'Primary telemetry approved',
      artifactSha256: hashC,
      isValid: true,
    }
  );

  const sharedBlockedSibling = ComplianceEngine.evaluateTraceLink(
    {
      id: 'haz-200',
      key: 'HAZ-200',
      title: 'Telemetry Escalation Timeout',
      riskClass: 'CLASS_C',
      severity: 'CRITICAL',
      probability: 'REMOTE',
      mitigationRequirementId: 'srs-201',
      status: 'ACTION_REQUIRED',
    },
    {
      id: 'srs-201',
      pageId: '55201',
      title: 'SRS-201: Telemetry Failover Channel',
      version: 1,
      sha256Hash: hashD,
      lastSignedHash: hashD,
      isSignatureInvalidated: false,
      contentSnippet: 'Secondary failover telemetry escalation',
      lastUpdated: '2026-10-15T10:00:00Z',
    },
    {
      id: 'med-502',
      key: 'MED-502',
      title: 'Failover Telemetry Channel',
      status: 'In Progress',
      assignee: 'Jamie Chen',
    },
    {
      id: 'test-502',
      testKey: 'TEST-502',
      title: 'Failover Telemetry Test',
      testType: 'Integration Test',
      status: 'UNTESTED',
    },
    {
      id: 'sig-201',
      signedBy: 'Marcus Vance, MD',
      signedAt: '2026-10-15T11:30:00Z',
      role: 'Clinical Safety Authority',
      meaning: 'Failover telemetry approved',
      artifactSha256: hashD,
      isValid: true,
    }
  );

  return { blockedLink, verifiedLink, sharedVerifiedLink, sharedBlockedSibling };
}

test.describe('Workflow Validator Handler - Typed Release Gate & Fail-Closed Behavior', () => {
  const originalGetSuite = SeederService.getActiveComplianceSuite;
  const originalEvaluateGate = ComplianceEngine.evaluateIssueReleaseGate;

  test.afterEach(() => {
    SeederService.getActiveComplianceSuite = originalGetSuite;
    ComplianceEngine.evaluateIssueReleaseGate = originalEvaluateGate;
  });

  test.it('exports workflowValidatorHandler and rovoActionHandler from index and dedicated modules', () => {
    assert.strictEqual(typeof workflowValidatorHandler, 'function');
    assert.strictEqual(typeof indexModule.workflowValidatorHandler, 'function');
    assert.strictEqual(typeof rovoActionHandler, 'function');
    assert.strictEqual(typeof indexModule.rovoActionHandler, 'function');
  });

  test.it('blocks tracked non-verified issues across payload.issue.key, payload.issueKey, payload.key, and hazard key', async () => {
    const { blockedLink, verifiedLink } = buildSampleLinks();
    const blockedSuite = ComplianceEngine.generateComplianceReport([blockedLink, verifiedLink], 'LIVE', 'Prod Pump');
    SeederService.getActiveComplianceSuite = async () => blockedSuite;

    for (const payload of [
      { issue: { key: 'MED-42' }, transition: { name: 'Done' } },
      { issue: { key: '  med-42  ' } },
      { issueKey: 'MED-42' },
      { key: 'MED-42' },
      { issue: { key: 'HAZ-101' } },
    ]) {
      const res = await workflowValidatorHandler(payload);
      assert.strictEqual(res.result, false);
      assert.match(res.errorMessage || '', /Human-initiated transition blocked for (MED-42|HAZ-101)/);
      assert.strictEqual('evaluatedIssueKey' in res, false);
    }
  });

  test.it('approves tracked verified issues and unsynced non-safety issues when suite is initialized, while blocking unsynced safety-labeled issues', async () => {
    const { blockedLink, verifiedLink } = buildSampleLinks();
    const blockedSuite = ComplianceEngine.generateComplianceReport([blockedLink, verifiedLink], 'LIVE', 'Prod Pump');
    SeederService.getActiveComplianceSuite = async () => blockedSuite;

    // Tracked verified Jira item and verified hazard pass even while another link in suite is blocked
    for (const payload of [
      { issue: { key: 'MED-43' }, transition: { name: 'Done' } },
      { issue: { key: 'HAZ-102' } },
      { issue: { key: 'DOCS-10' } },
      { issue: { key: 'DOCS-11', fields: { labels: ['docs'], issuetype: { name: 'Task' } } } },
    ]) {
      const res = await workflowValidatorHandler(payload);
      assert.strictEqual(res.result, true);
      assert.strictEqual(res.errorMessage, undefined);
    }

    // Inline safety label or Hazard issue type on an unsynced issue MUST fail closed
    for (const payload of [
      { issue: { key: 'MED-99', fields: { labels: ['class-c'], issuetype: { name: 'Story' } } } },
      { issue: { key: 'MED-100', fields: { labels: ['iec-62304'], issuetype: { name: 'Task' } } } },
      { issue: { key: 'MED-101', fields: { labels: [], issuetype: { name: 'Hazard' } } } },
    ]) {
      const res = await workflowValidatorHandler(payload);
      assert.strictEqual(res.result, false);
      assert.match(res.errorMessage || '', /not synced in the active compliance suite/i);
    }

    // Forge runtime Jira REST lookup blocks unsynced safety-labeled issues and fails closed on Jira errors, while passing everyday Tasks
    await withForgeMocks(
      {
        asAppImpl: () => ({
          requestJira: async (url) => {
            const urlStr = url && typeof url.value_ === 'string' ? url.value_ : String(url || '');
            if (urlStr.includes('NEW-1')) {
              return makeJsonResponse(200, {
                key: 'NEW-1',
                fields: { labels: ['class-c', 'iec-62304'], issuetype: { name: 'Story' } },
              });
            }
            if (urlStr.includes('ERR-1')) {
              return makeJsonResponse(500, { error: 'Jira unavailable' });
            }
            return makeJsonResponse(200, {
              key: 'DOCS-20',
              fields: { labels: ['chore'], issuetype: { name: 'Task' } },
            });
          },
        }),
      },
      async () => {
        const unsyncedSafetyRes = await workflowValidatorHandler({ issue: { key: 'NEW-1' } });
        assert.strictEqual(unsyncedSafetyRes.result, false);
        assert.match(unsyncedSafetyRes.errorMessage || '', /NEW-1.*not synced/i);

        const jiraErrRes = await workflowValidatorHandler({ issue: { key: 'ERR-1' } });
        assert.strictEqual(jiraErrRes.result, false);
        assert.match(jiraErrRes.errorMessage || '', /Unable to verify safety labels.*ERR-1/i);

        const everydayTaskRes = await workflowValidatorHandler({ issue: { key: 'DOCS-20' } });
        assert.strictEqual(everydayTaskRes.result, true);
      }
    );
  });

  test.it('blocks untracked and empty issue keys on uninitialized LIVE suite (fail-closed)', async () => {
    const uninitSuite = await SeederService.getUninitializedLiveSuite();
    SeederService.getActiveComplianceSuite = async () => uninitSuite;

    for (const payload of [
      { issue: { key: 'DOCS-10' } },
      { issue: { key: 'MED-43' } },
      {},
      undefined,
    ]) {
      const res = await workflowValidatorHandler(payload);
      assert.strictEqual(res.result, false);
      assert.match(res.errorMessage || '', /uninitialized/i);
    }
  });

  test.it('normalizes empty/whitespace/malformed issueKey to Global Release Gate and falls back across empty candidates', async () => {
    const { blockedLink, verifiedLink } = buildSampleLinks();
    const blockedSuite = ComplianceEngine.generateComplianceReport([blockedLink, verifiedLink], 'LIVE', 'Prod Pump');
    const cleanSuite = ComplianceEngine.generateComplianceReport([verifiedLink], 'LIVE', 'Verified Pump');

    // Empty/whitespace issueKey triggers Global Release Gate -> blocked when suite.releaseBlocked is true
    SeederService.getActiveComplianceSuite = async () => blockedSuite;
    for (const payload of [
      undefined,
      null,
      {},
      { issue: { key: '' } },
      { issue: { key: '   \t\n ' } },
      { issueKey: '   ' },
      { key: '' },
    ]) {
      const res = await workflowValidatorHandler(payload);
      assert.strictEqual(res.result, false);
      assert.match(res.errorMessage || '', /Human-initiated transition blocked!/);
    }

    // Whitespace issue.key must NOT shadow a valid fallback payload.issueKey
    const fallbackRes = await workflowValidatorHandler({
      issue: { key: '   ' },
      issueKey: 'MED-43',
      transition: { name: 'Done' },
    });
    assert.strictEqual(fallbackRes.result, true);
    assert.strictEqual(fallbackRes.errorMessage, undefined);

    // On an initialized, completely verified suite, Global Release Gate and non-string issue.key pass cleanly
    SeederService.getActiveComplianceSuite = async () => cleanSuite;
    for (const payload of [{ issue: { key: '   ' } }, {}, { issue: { key: 123 } }]) {
      const res = await workflowValidatorHandler(payload);
      assert.strictEqual(res.result, true);
      assert.strictEqual(res.errorMessage, undefined);
    }
  });

  test.it('fails closed (result: false) if suite loading, evaluation, or payload access throws', async () => {
    SeederService.getActiveComplianceSuite = async () => {
      throw new Error('KVS timeout: simulated storage failure');
    };
    const kvsFailRes = await workflowValidatorHandler({ issue: { key: 'MED-43' } });
    assert.strictEqual(kvsFailRes.result, false);
    assert.match(kvsFailRes.errorMessage || '', /Unable to verify IEC 62304 compliance integrity/);

    const { verifiedLink } = buildSampleLinks();
    SeederService.getActiveComplianceSuite = async () =>
      ComplianceEngine.generateComplianceReport([verifiedLink], 'LIVE', 'Verified Pump');
    ComplianceEngine.evaluateIssueReleaseGate = () => {
      throw new Error('Unexpected rule evaluation fault');
    };
    const evalFailRes = await workflowValidatorHandler({ issue: { key: 'MED-43' } });
    assert.strictEqual(evalFailRes.result, false);
    assert.match(evalFailRes.errorMessage || '', /Unable to verify IEC 62304 compliance integrity/);

    ComplianceEngine.evaluateIssueReleaseGate = originalEvaluateGate;
    const throwingPayload = {};
    Object.defineProperty(throwingPayload, 'issue', {
      get() {
        throw new Error('Poisoned payload property');
      },
    });
    const proxyFailRes = await workflowValidatorHandler(throwingPayload);
    assert.strictEqual(proxyFailRes.result, false);
    assert.match(proxyFailRes.errorMessage || '', /Unable to verify IEC 62304 compliance integrity/);
  });

  test.it('maintains policy parity with ComplianceEngine.evaluateIssueReleaseGate and webtrigger verify-release-gate', async () => {
    const prevSecret = process.env.MEDTRACE_MCP_SECRET;
    const prevNonceStore = getNonceStore();
    const secret = 'workflow-parity-secret-001';
    process.env.MEDTRACE_MCP_SECRET = secret;
    setNonceStore(createInMemoryNonceStore());

    const { blockedLink, verifiedLink } = buildSampleLinks();
    const mixedSuite = ComplianceEngine.generateComplianceReport([blockedLink, verifiedLink], 'LIVE', 'Parity Live');
    const uninitSuite = await SeederService.getUninitializedLiveSuite();

    try {
      for (const suite of [mixedSuite, uninitSuite]) {
        SeederService.getActiveComplianceSuite = async () => suite;
        for (const rawKey of ['MED-42', 'MED-43', 'DOCS-99', '   ', undefined]) {
          const normalizedKey = typeof rawKey === 'string' && rawKey.trim() !== '' ? rawKey.trim() : undefined;
          const engineOutcome = ComplianceEngine.evaluateIssueReleaseGate(normalizedKey, suite);
          const wfOutcome = await workflowValidatorHandler(
            rawKey !== undefined ? { issue: { key: rawKey } } : {}
          );

          assert.strictEqual(wfOutcome.result, engineOutcome.result);
          assert.strictEqual(wfOutcome.errorMessage, engineOutcome.errorMessage);

          const ts = Date.now().toString();
          const nonce = `wf-parity-${crypto.randomUUID()}`;
          const body = JSON.stringify(
            rawKey !== undefined ? { action: 'verify-release-gate', issueKey: rawKey } : { action: 'verify-release-gate' }
          );
          const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${body}`).digest('hex');
          const webResp = await mcpWebtriggerHandler({
            method: 'POST',
            headers: {
              'x-medtrace-timestamp': ts,
              'x-medtrace-nonce': nonce,
              'x-medtrace-signature': `sha256=${sig}`,
            },
            body,
          });
          const webOutcome = JSON.parse(webResp.body);
          assert.strictEqual(webOutcome.result, wfOutcome.result);
          assert.strictEqual(webOutcome.errorMessage, wfOutcome.errorMessage);
          assert.strictEqual(webResp.statusCode, wfOutcome.result ? 200 : 403);
        }
      }
    } finally {
      setNonceStore(prevNonceStore);
      if (prevSecret === undefined) delete process.env.MEDTRACE_MCP_SECRET;
      else process.env.MEDTRACE_MCP_SECRET = prevSecret;
    }
  });
});

test.describe('McpToolService & rovoActionHandler Integration Tests', () => {
  const originalGetSuite = SeederService.getActiveComplianceSuite;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState();
  });

  test.afterEach(() => {
    SeederService.getActiveComplianceSuite = originalGetSuite;
  });

  test.it('McpToolService.getHazardLineage covers summary, uninitialized LIVE, availableKeys, 9-field lookup, and M:N matches', async () => {
    const uninitSuite = await SeederService.getUninitializedLiveSuite();
    SeederService.getActiveComplianceSuite = async () => uninitSuite;

    const uninitSummary = await McpToolService.getHazardLineage();
    assert.strictEqual(uninitSummary.datasetMode, 'LIVE');
    assert.strictEqual(uninitSummary.initialized, false);
    assert.strictEqual(uninitSummary.totalHazards, 0);
    assert.strictEqual(uninitSummary.releaseBlocked, true);
    assert.deepStrictEqual(uninitSummary.traceLinks, []);

    const uninitLookup = await McpToolService.getHazardLineage({ hazardKey: 'HAZ-101' });
    assert.strictEqual(uninitLookup.found, false);
    assert.strictEqual(uninitLookup.initialized, false);
    assert.strictEqual(uninitLookup.datasetMode, 'LIVE');
    assert.deepStrictEqual(uninitLookup.availableKeys, []);

    const { blockedLink, verifiedLink, sharedVerifiedLink, sharedBlockedSibling } = buildSampleLinks();
    const liveSuite = ComplianceEngine.generateComplianceReport(
      [blockedLink, verifiedLink, sharedVerifiedLink, sharedBlockedSibling],
      'LIVE',
      'Live Infusion Suite'
    );
    SeederService.getActiveComplianceSuite = async () => liveSuite;

    // Whitespace lookupKey falls back to full project summary
    const summaryRes = await McpToolService.getHazardLineage({ issueKey: '   ' });
    assert.strictEqual(summaryRes.initialized, true);
    assert.strictEqual(summaryRes.totalHazards, 3);
    assert.strictEqual(summaryRes.traceLinks.length, 4);

    // Unknown key surfaces availableKeys
    const missingRes = await McpToolService.getHazardLineage({ issueKey: 'UNKNOWN-999' });
    assert.strictEqual(missingRes.found, false);
    assert.strictEqual(missingRes.queriedKey, 'UNKNOWN-999');
    assert.strictEqual(missingRes.availableKeys.length, 4);
    assert.deepStrictEqual(missingRes.availableKeys[0], {
      hazardKey: 'HAZ-101',
      workKey: 'MED-42',
      specId: 'srs-104',
      testKey: 'TEST-88',
    });

    // All 9 canonical fields resolve case-insensitively
    for (const q of [
      'haz-102',
      'uuid-haz-102',
      'med-43',
      '10043',
      'test-89',
      '10089',
      'srs-105',
      '55105',
      'sig-002',
    ]) {
      const foundRes = await McpToolService.getHazardLineage({ issueKey: q });
      assert.strictEqual(foundRes.found, true, `Expected lookup match for "${q}"`);
      assert.strictEqual(foundRes.hazard.key, 'HAZ-102');
      assert.strictEqual(foundRes.regulatoryStatus, 'VERIFIED');
      assert.strictEqual(foundRes.part11Valid, true);
    }

    // M:N shared hazard returns matchedLinks
    const multiMatch = await McpToolService.getHazardLineage({ hazardKey: 'HAZ-200' });
    assert.strictEqual(multiMatch.found, true);
    assert.ok(Array.isArray(multiMatch.matchedLinks));
    assert.strictEqual(multiMatch.matchedLinks.length, 2);

    // Outside Forge runtime, spec owners are never queried even when cloudId + pageId are available
    const noTwg = await McpToolService.getHazardLineage(
      { hazardKey: 'HAZ-102' },
      { cloudId: '12345678-1234-1234-1234-1234567890ab' }
    );
    assert.strictEqual(noTwg.found, true);
    assert.strictEqual(noTwg.specOwners, undefined);
    assert.strictEqual(noTwg.teamworkGraphStatus, undefined);
  });

  test.it('McpToolService.verifyIecCompliance enforces uninitialized fail-closed, multi-key contradiction fix, and LIVE keyword isolation', async () => {
    const uninitSuite = await SeederService.getUninitializedLiveSuite();
    SeederService.getActiveComplianceSuite = async () => uninitSuite;

    const uninitVerify = await McpToolService.verifyIecCompliance({ componentName: 'bolus clamp' });
    assert.strictEqual(uninitVerify.initialized, false);
    assert.strictEqual(uninitVerify.configuredChecksPassed, false);
    assert.strictEqual(uninitVerify.touchesSafetyCriticalCode, false);
    assert.strictEqual(uninitVerify.classCSummary.status, 'BLOCKED_BY_SAFETY_GATE');
    assert.strictEqual(uninitVerify.graphBlastRadius, undefined);
    assert.match(uninitVerify.activeViolations[0], /uninitialized/i);

    const { blockedLink, verifiedLink, sharedVerifiedLink, sharedBlockedSibling } = buildSampleLinks();
    const liveSuite = ComplianceEngine.generateComplianceReport(
      [blockedLink, verifiedLink, sharedVerifiedLink, sharedBlockedSibling],
      'LIVE',
      'Live Infusion Suite'
    );
    SeederService.getActiveComplianceSuite = async () => liveSuite;

    // Multi-key diff: clean link first, blocked link second -> must block without "no remediation required"
    const multiKeyRes = await McpToolService.verifyIecCompliance({ prDiff: 'diff updating MED-43 and MED-42' });
    assert.strictEqual(multiKeyRes.touchesSafetyCriticalCode, true);
    assert.strictEqual(multiKeyRes.configuredChecksPassed, false);
    assert.ok(multiKeyRes.affectedHazards.some((h) => h.includes('HAZ-101')));
    assert.ok(
      !multiKeyRes.remediationGuidance.some((g) => /no remediation required|All traversed artifacts are verified/i.test(g))
    );

    // M:N shared hazard: targeting verified MED-501 catches unverified sibling MED-502
    const sharedHazardRes = await McpToolService.verifyIecCompliance({ issueKey: 'MED-501' });
    assert.strictEqual(sharedHazardRes.touchesSafetyCriticalCode, true);
    assert.strictEqual(sharedHazardRes.configuredChecksPassed, false);
    assert.ok(sharedHazardRes.graphBlastRadius.blockedWorkItems.includes('MED-502'));
    assert.ok(
      !sharedHazardRes.remediationGuidance.some((g) => /no remediation required|All traversed artifacts are verified/i.test(g))
    );

    // Isolated verified link MED-43 remains shippable
    const cleanRes = await McpToolService.verifyIecCompliance({ issueKey: 'MED-43' });
    assert.strictEqual(cleanRes.touchesSafetyCriticalCode, true);
    assert.strictEqual(cleanRes.configuredChecksPassed, true);
    assert.deepStrictEqual(cleanRes.graphBlastRadius.blockedWorkItems, []);
    assert.match(cleanRes.remediationGuidance[0], /Configured traceability checks passed/);
    assert.doesNotMatch(cleanRes.remediationGuidance[0], /Authorized for 510\(k\)|CERTIFIED_READY/i);

    // Neither LIVE nor DEMO mode matches hardcoded keyword fallbacks ('oled', 'battery', 'voltage', 'flow', 'motor')
    const liveKeywordBlocked = await McpToolService.verifyIecCompliance({
      prDiff: 'generated oled battery spi voltage',
    });
    assert.strictEqual(liveKeywordBlocked.touchesSafetyCriticalCode, false);
    assert.strictEqual(liveKeywordBlocked.configuredChecksPassed, false);

    // Word-boundary token matching works dynamically in LIVE mode for actual spec tokens
    const tokenMatch = await McpToolService.verifyIecCompliance({
      componentName: 'photodiode calibration routine',
    });
    assert.strictEqual(tokenMatch.touchesSafetyCriticalCode, true);
    assert.strictEqual(tokenMatch.configuredChecksPassed, true);

    // DEMO mode matches only real suite artifact keys/tokens (no hardcoded DEMO_KEYWORD_FALLBACKS)
    const demoSuite = ComplianceEngine.generateComplianceReport([blockedLink, verifiedLink], 'DEMO', 'Demo Pump');
    SeederService.getActiveComplianceSuite = async () => demoSuite;
    const demoRandomWords = await McpToolService.verifyIecCompliance({
      prDiff: 'adjust battery voltage and flow motor pwm',
    });
    assert.strictEqual(demoRandomWords.touchesSafetyCriticalCode, false);
    assert.strictEqual(demoRandomWords.graphBlastRadius, undefined);

    const demoRealTokenRes = await McpToolService.verifyIecCompliance({ componentName: 'bolus clamp' });
    assert.strictEqual(demoRealTokenRes.touchesSafetyCriticalCode, true);
    assert.ok(demoRealTokenRes.graphBlastRadius);
    assert.match(demoRealTokenRes.graphBlastRadius.trigger, /SRS-104/);
  });

  test.it('rovoActionHandler enforces action allowlist, user read probes in Forge runtime, and sanitized errors', async () => {
    const unknownRes = await rovoActionHandler({ actionKey: 'delete-all' });
    assert.match(unknownRes.error, /Unknown action/);
    assert.deepStrictEqual(unknownRes.availableTools, [
      'get-hazard-lineage-action',
      'verify-iec-compliance-action',
      'create-reverification-task-action',
    ]);

    const { blockedLink, verifiedLink } = buildSampleLinks();
    const liveSuite = ComplianceEngine.generateComplianceReport([blockedLink, verifiedLink], 'LIVE', 'Prod Pump');
    SeederService.getActiveComplianceSuite = async () => liveSuite;

    // Non-Forge local dispatch supports both short & -action names and nested payload.inputs
    const lineageAliasRes = await rovoActionHandler(
      { inputs: { issueKey: 'MED-43' } },
      { moduleKey: 'get-hazard-lineage' }
    );
    assert.strictEqual(lineageAliasRes.found, true);
    assert.strictEqual(lineageAliasRes.hazard.key, 'HAZ-102');

    const verifyAliasRes = await rovoActionHandler({
      context: { moduleKey: 'verify-iec-compliance' },
      inputs: { issueKey: 'MED-42' },
    });
    assert.strictEqual(verifyAliasRes.configuredChecksPassed, false);
    assert.strictEqual(verifyAliasRes.touchesSafetyCriticalCode, true);

    const kvsMock = createLocalMockKvs();

    // Forge runtime read-probe rejections (missing accountId, empty accountId, missing BROWSE_PROJECTS, Jira 403/inactive, Confluence missing/mismatch)
    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async () =>
            makeJsonResponse(200, {
              active: true,
              permissions: { BROWSE_PROJECTS: { havePermission: false } },
            }),
          requestConfluence: async () => makeJsonResponse(200, { accountId: 'different-user' }),
        }),
      },
      async () => {
        const missingAcct = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'get-hazard-lineage-action' }
        );
        assert.match(missingAcct.error, /Unauthorized/i);

        const emptyAcct = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'get-hazard-lineage-action', accountId: '   ' }
        );
        assert.match(emptyAcct.error, /Unauthorized/i);

        const deniedJira = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'user-no-browse', extension: { type: 'jira:issuePanel' } }
        );
        assert.match(deniedJira.error, /Forbidden/i);

        const mismatchConf = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'conf-user-1', extension: { type: 'confluence:globalPage' } }
        );
        assert.match(mismatchConf.error, /Forbidden/i);
      }
    );

    // Fail closed when Jira mypermissions omits BROWSE_PROJECTS or Confluence omits accountId
    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async () => makeJsonResponse(200, { active: true, permissions: {} }),
          requestConfluence: async () => makeJsonResponse(200, {}),
        }),
      },
      async () => {
        const missingBrowseField = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-incomplete', extension: { type: 'jira:projectPage' } }
        );
        assert.match(missingBrowseField.error, /Forbidden/i);

        const missingConfAccount = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-incomplete', extension: { type: 'confluence:globalPage' } }
        );
        assert.match(missingConfAccount.error, /Forbidden/i);
      }
    );

    // Target-scoped & cross-project isolation in multi-project LIVE suite
    const alphaLink = {
      ...verifiedLink,
      id: 'link-alpha-1',
      hazard: { ...verifiedLink.hazard, id: 'haz-alpha-1', key: 'HAZ-102' },
      work: { ...verifiedLink.work, id: 'alpha-1', key: 'ALPHA-1' },
      test: { ...verifiedLink.test, id: 'test-alpha-1', testKey: 'TEST-101' },
    };
    const betaLink = {
      ...blockedLink,
      id: 'link-beta-9',
      hazard: { ...blockedLink.hazard, id: 'haz-beta-9', key: 'HAZ-202' },
      work: { ...blockedLink.work, id: 'beta-9', key: 'BETA-9' },
      test: { ...blockedLink.test, id: 'test-beta-9', testKey: 'TEST-202' },
    };
    const multiProjectSuite = ComplianceEngine.generateComplianceReport([alphaLink, betaLink], 'LIVE', 'Multi Project');
    SeederService.getActiveComplianceSuite = async () => multiProjectSuite;

    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async (url) => {
            const urlStr = url && typeof url.value_ === 'string' ? url.value_ : String(url || '');
            if (urlStr.includes('BETA')) {
              return makeJsonResponse(200, {
                active: true,
                permissions: { BROWSE_PROJECTS: { havePermission: false } },
              });
            }
            return makeJsonResponse(200, {
              active: true,
              permissions: { BROWSE_PROJECTS: { havePermission: true } },
            });
          },
          requestConfluence: async () => makeJsonResponse(200, { accountId: 'acc-alpha' }),
        }),
      },
      async () => {
        const crossProjIssue = await rovoActionHandler(
          { issueKey: 'BETA-9' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-alpha', extension: { type: 'jira:projectPage' } }
        );
        assert.match(crossProjIssue.error, /Forbidden/i);

        const crossProjHazard = await rovoActionHandler(
          { hazardKey: 'HAZ-202' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-alpha', extension: { type: 'jira:projectPage' } }
        );
        assert.match(crossProjHazard.error, /Forbidden/i);

        const crossProjDiff = await rovoActionHandler(
          { prDiff: 'diff touching BETA-9' },
          { moduleKey: 'verify-iec-compliance-action', accountId: 'acc-alpha', extension: { type: 'jira:projectPage' } }
        );
        assert.match(crossProjDiff.error, /Forbidden/i);

        const ctxMismatch = await rovoActionHandler(
          { issueKey: 'BETA-9' },
          {
            moduleKey: 'get-hazard-lineage-action',
            accountId: 'acc-alpha',
            extension: { type: 'jira:projectPage', project: { key: 'ALPHA' } },
          }
        );
        assert.match(ctxMismatch.error, /Forbidden/i);

        const scopedSummary = await rovoActionHandler(
          {},
          { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-alpha', extension: { type: 'jira:projectPage' } }
        );
        assert.strictEqual(scopedSummary.traceLinks.length, 1);
        assert.strictEqual(scopedSummary.traceLinks[0].workKey, 'ALPHA-1');

        const scopedMiss = await rovoActionHandler(
          { issueKey: 'ALPHA-999' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-alpha', extension: { type: 'jira:projectPage' } }
        );
        assert.strictEqual(scopedMiss.found, false);
        assert.strictEqual(scopedMiss.availableKeys.length, 1);
        assert.strictEqual(scopedMiss.availableKeys[0].workKey, 'ALPHA-1');

        const cleanVerify = await rovoActionHandler(
          { issueKey: 'ALPHA-1' },
          { moduleKey: 'verify-iec-compliance-action', accountId: 'acc-alpha', extension: { type: 'jira:projectPage' } }
        );
        assert.strictEqual(cleanVerify.configuredChecksPassed, true);
        assert.strictEqual(cleanVerify.classCSummary.status, 'CONFIGURED_CHECKS_PASSED');
        assert.doesNotMatch(cleanVerify.remediationGuidance.join(' '), /Authorized for 510\(k\)|CERTIFIED_READY/i);
      }
    );

    SeederService.getActiveComplianceSuite = async () => liveSuite;

    // Authorized Jira and Confluence callers succeed inside Forge runtime
    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async () =>
            makeJsonResponse(200, {
              active: true,
              permissions: { BROWSE_PROJECTS: { havePermission: true } },
            }),
          requestConfluence: async () => makeJsonResponse(200, { accountId: 'acc-authorized' }),
        }),
      },
      async () => {
        const jiraOk = await rovoActionHandler(
          { issueKey: 'MED-43' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-authorized', extension: { type: 'jira:projectPage' } }
        );
        assert.strictEqual(jiraOk.found, true);
        assert.strictEqual(jiraOk.hazard.key, 'HAZ-102');

        const confOk = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'verify-iec-compliance-action', accountId: 'acc-authorized', extension: { type: 'confluence:globalPage' } }
        );
        assert.strictEqual(confOk.configuredChecksPassed, false);
        assert.strictEqual(confOk.touchesSafetyCriticalCode, true);
      }
    );

    // Unexpected internal exceptions are sanitized before returning to Rovo
    SeederService.getActiveComplianceSuite = async () => {
      throw new Error('SECRET_INTERNAL_STACK_DETAIL');
    };
    const sanitizedErr = await rovoActionHandler(
      { issueKey: 'MED-42' },
      { moduleKey: 'get-hazard-lineage-action' }
    );
    assert.strictEqual(sanitizedErr.error, 'Unable to execute MedTrace Rovo action.');
    assert.doesNotMatch(sanitizedErr.error, /SECRET_INTERNAL_STACK_DETAIL/);
  });

  test.it('McpToolService.getHazardLineage queries Teamwork Graph for all unique matchedLinks pageIds up to cap', async () => {
    const { blockedLink, verifiedLink } = buildSampleLinks();
    const multiSpecLink1 = ComplianceEngine.evaluateTraceLink(
      { ...verifiedLink.hazard, id: 'haz-mn', key: 'HAZ-MN' },
      { ...verifiedLink.spec, id: 'srs-501', pageId: '50101', title: 'SRS-501' },
      { ...verifiedLink.work, key: 'MN-10' },
      verifiedLink.test,
      verifiedLink.signature
    );
    const multiSpecLink2 = ComplianceEngine.evaluateTraceLink(
      { ...blockedLink.hazard, id: 'haz-mn', key: 'HAZ-MN' },
      { ...verifiedLink.spec, id: 'srs-502', pageId: '50102', title: 'SRS-502' },
      { ...verifiedLink.work, key: 'MN-10' },
      verifiedLink.test,
      verifiedLink.signature
    );
    const suite = ComplianceEngine.generateComplianceReport(
      [multiSpecLink1, multiSpecLink2],
      'LIVE',
      'M:N Lineage Suite',
      { initialized: true }
    );

    const queriedAris = [];
    const origAsUser = forgeApi.default.asUser;
    const origRuntime = globalThis.__forge_runtime__;
    globalThis.__forge_runtime__ = true;
    forgeApi.default.asUser = () => ({
      requestTeamworkGraph: async (_query, variables) => {
        queriedAris.push(variables.id);
        const pid = String(variables.id).split('/').pop();
        return makeJsonResponse(200, {
          data: {
            confluencePageOwners: {
              edges: [{ node: { __typename: 'AtlassianUser', accountId: `acc-${pid}`, name: `Owner ${pid}` } }],
            },
          },
        });
      },
    });
    try {
      const res = await McpToolService.getHazardLineage(
        { hazardKey: 'HAZ-MN' },
        { suite, cloudId: '12345678-1234-1234-1234-1234567890ab' }
      );
      assert.strictEqual(res.found, true);
      assert.strictEqual(res.teamworkGraphStatus, 'OK');
      assert.deepStrictEqual(queriedAris, [
        'ari:cloud:confluence:12345678-1234-1234-1234-1234567890ab:page/50101',
        'ari:cloud:confluence:12345678-1234-1234-1234-1234567890ab:page/50102',
      ]);
      assert.deepStrictEqual(res.specOwners, [
        { pageId: '50101', accountId: 'acc-50101', name: 'Owner 50101' },
        { pageId: '50102', accountId: 'acc-50102', name: 'Owner 50102' },
      ]);
    } finally {
      forgeApi.default.asUser = origAsUser;
      if (origRuntime === undefined) delete globalThis.__forge_runtime__;
      else globalThis.__forge_runtime__ = origRuntime;
    }
  });

  test.it('rovoActionHandler supports create-reverification-task-action with CREATE_ISSUES RBAC and Jira issue linking', async () => {
    const kvsMock = createLocalMockKvs();
    const { blockedLink } = buildSampleLinks();
    const liveSuite = ComplianceEngine.generateComplianceReport([blockedLink], 'LIVE', 'Live Pump', {
      initialized: true,
    });

    const createdPayloads = [];
    const linkPayloads = [];
    let allowCreate = true;

    const asUserImpl = () => ({
      requestJira: async (routeObj, opts) => {
        const url = String(routeObj?.value_ || routeObj || '');
        if (url === '/rest/api/3/myself') {
          return makeJsonResponse(200, { accountId: 'acc-rovo-op', active: true });
        }
        if (url.startsWith('/rest/api/3/mypermissions')) {
          return makeJsonResponse(200, {
            permissions: {
              BROWSE_PROJECTS: { havePermission: true },
              EDIT_ISSUES: { havePermission: true },
              CREATE_ISSUES: { havePermission: allowCreate },
            },
          });
        }
        if (url === '/rest/api/3/issue/MED-150?fields=status,issuelinks') {
          return makeJsonResponse(200, {
            id: '50001',
            key: 'MED-150',
            fields: {
              status: { name: 'To Do', statusCategory: { key: 'new', name: 'To Do' } },
              issuelinks: [{ outwardIssue: { key: 'MED-42' } }],
            },
          });
        }
        if (url === '/rest/api/3/issue/createmeta/MED/issuetypes') {
          return makeJsonResponse(200, { issueTypes: [{ id: '10002', name: 'Task', subtask: false }] });
        }
        if (url === '/rest/api/3/issue' && opts?.method === 'POST') {
          createdPayloads.push(JSON.parse(opts.body));
          return makeJsonResponse(201, { id: '50001', key: 'MED-150' });
        }
        if (url === '/rest/api/3/issueLinkType') {
          return makeJsonResponse(200, { issueLinkTypes: [{ name: 'Relates' }] });
        }
        if (url === '/rest/api/3/issueLink' && opts?.method === 'POST') {
          linkPayloads.push(JSON.parse(opts.body));
          return makeJsonResponse(201, {});
        }
        return makeJsonResponse(404, {});
      },
    });

    await withForgeMocks({ kvsMock, asUserImpl }, async () => {
      await SeederService.saveComplianceSuite(liveSuite, 0);

      // 1. Fails closed when caller lacks CREATE_ISSUES
      allowCreate = false;
      const denied = await rovoActionHandler(
        {
          actionKey: 'create-reverification-task-action',
          inputs: { hazardKey: 'HAZ-101', issueKey: 'MED-42' },
        },
        { accountId: 'acc-rovo-op', extension: { type: 'jira:projectPage', project: { key: 'MED' } } }
      );
      assert.match(denied.error, /CREATE_ISSUES/);

      // 2. Creates and links MED-150 when authorized
      allowCreate = true;
      const created = await rovoActionHandler(
        {
          actionKey: 'create-reverification-task-action',
          inputs: { hazardKey: 'HAZ-101', issueKey: 'MED-42', reason: 'SRS-104 drift 5.0 -> 5.5' },
        },
        { accountId: 'acc-rovo-op', extension: { type: 'jira:projectPage', project: { key: 'MED' } } }
      );
      assert.strictEqual(created.success, true);
      assert.strictEqual(created.createdIssueKey, 'MED-150');
      assert.deepStrictEqual(created.linkedIssueKeys, ['MED-42']);
      assert.strictEqual(createdPayloads.length, 1);
      assert.strictEqual(linkPayloads.length, 1);

      // 3. Reuses open MED-150 idempotently on repeat invocation without creating a duplicate Jira issue
      const reused = await rovoActionHandler(
        {
          actionKey: 'create-reverification-task-action',
          inputs: { hazardKey: 'HAZ-101', issueKey: 'MED-42' },
        },
        { accountId: 'acc-rovo-op', extension: { type: 'jira:projectPage', project: { key: 'MED' } } }
      );
      assert.strictEqual(reused.success, true);
      assert.strictEqual(reused.createdIssueKey, 'MED-150');
      assert.strictEqual(reused.alreadyExisted, true);
      assert.strictEqual(createdPayloads.length, 1);
    });
  });

  test.it('rovoActionHandler blocks secondary-artifact IDOR across work/hazard/test projects and redacts restricted Confluence pages', async () => {
    const kvsMock = createLocalMockKvs();
    const { ComplianceEngine } = require('../dist/compliance-engine');

    const crossProjectLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-med-10',
        key: 'MED-10',
        title: 'Secret MED-10 Hazard',
        riskClass: 'CLASS_C',
        severity: 'CATASTROPHIC',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-999',
        status: 'ACTION_REQUIRED',
        source: 'JIRA_ISSUE',
      },
      {
        id: 'srs-999',
        pageId: '999',
        title: 'Confidential Restricted SRS-999',
        version: 3,
        sha256Hash: 'f'.repeat(64),
        lastSignedHash: 'f'.repeat(64),
        isSignatureInvalidated: false,
        contentSnippet: 'ULTRA_SECRET_CONFLUENCE_EXCERPT',
        lastUpdated: '2026-11-20T00:00:00Z',
      },
      {
        id: 'w-acme-1',
        key: 'ACME-1',
        title: 'ACME Firmware Feature',
        status: 'In Progress',
        assignee: 'Alice',
      },
      {
        id: 't-qa-11',
        testKey: 'QA-11',
        title: 'QA-11 HIL Test',
        testType: 'Automated HIL (Hardware-in-Loop)',
        status: 'UNTESTED',
        source: 'JIRA_ISSUE',
      },
      {
        id: 'sig-1',
        signedBy: '',
        signedAt: '',
        role: 'QA',
        meaning: '',
        artifactSha256: '',
        isValid: false,
      },
      undefined,
      { linkId: 'link-cross-1', requireTestEvidence: true }
    );

    const sameProjRestrictedConfLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-acme-2',
        key: 'HAZ-ACME-2',
        title: 'ACME-2 Hazard',
        riskClass: 'CLASS_A',
        severity: 'MINOR',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-999',
        status: 'UNVERIFIED_RISK',
      },
      {
        id: 'srs-999',
        pageId: '999',
        title: 'Confidential Restricted SRS-999',
        version: 3,
        sha256Hash: 'f'.repeat(64),
        lastSignedHash: 'f'.repeat(64),
        isSignatureInvalidated: false,
        contentSnippet: 'ULTRA_SECRET_CONFLUENCE_EXCERPT',
        lastUpdated: '2026-11-20T00:00:00Z',
      },
      {
        id: 'w-acme-2',
        key: 'ACME-2',
        title: 'ACME Restricted Spec Issue',
        status: 'Done',
        assignee: 'Bob',
      },
      {
        id: 't-acme-2',
        testKey: 'TEST-ACME-2',
        title: 'Test ACME-2',
        testType: 'Unit Test',
        status: 'PASSED',
        evidenceUrl: 'https://ci.example/acme-2',
        executionDate: '2026-11-20T00:00:00Z',
      },
      {
        id: 'sig-2',
        signedBy: '',
        signedAt: '',
        role: 'QA',
        meaning: '',
        artifactSha256: '',
        isValid: false,
      },
      undefined,
      { linkId: 'link-acme-2', requireTestEvidence: true }
    );

    const suite = ComplianceEngine.generateComplianceReport(
      [crossProjectLink, sameProjRestrictedConfLink],
      'LIVE',
      'Multi-Permission Suite',
      { initialized: true }
    );

    const deniedProjects = new Set(['MED', 'QA']);
    const asUserImpl = () => ({
      requestJira: async (routeObj) => {
        const url = String(routeObj?.value_ || routeObj || '');
        const match = url.match(/(?:projectKey|issueKey)=([A-Z0-9_-]+)/i);
        const keyOrProj = match ? match[1].toUpperCase().split('-')[0] : '';
        const allowed = !keyOrProj || !deniedProjects.has(keyOrProj);
        return makeJsonResponse(200, {
          active: true,
          permissions: { BROWSE_PROJECTS: { havePermission: allowed } },
        });
      },
      requestConfluence: async (routeObj) => {
        const url = String(routeObj?.value_ || routeObj || '');
        if (url === '/wiki/rest/api/user/current') {
          return makeJsonResponse(200, { accountId: 'acc-acme-only' });
        }
        if (url.includes('/wiki/api/v2/pages/999')) {
          return makeJsonResponse(403, { message: 'Forbidden page' });
        }
        return makeJsonResponse(200, {});
      },
    });

    await withForgeMocks({ kvsMock, asUserImpl }, async () => {
      await SeederService.saveComplianceSuite(suite, 0);

      // 1. Caller can browse ACME-1, but NOT linked hazard MED-10 or test QA-11 -> fails closed
      const directAcme = await rovoActionHandler(
        { issueKey: 'ACME-1' },
        { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-acme-only', extension: { type: 'jira:globalPage' } }
      );
      assert.match(directAcme.error, /Forbidden.*(?:MED-10|QA-11)/i);

      const directMedHazard = await rovoActionHandler(
        { hazardKey: 'MED-10' },
        { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-acme-only', extension: { type: 'jira:globalPage' } }
      );
      assert.match(directMedHazard.error, /Forbidden/i);

      const diffAcme = await rovoActionHandler(
        { prDiff: 'fix bug in ACME-1' },
        { moduleKey: 'verify-iec-compliance-action', accountId: 'acc-acme-only', extension: { type: 'jira:globalPage' } }
      );
      assert.match(diffAcme.error, /Forbidden/i);

      // 2. Unfiltered summary drops ACME-1 (secondary MED/QA IDOR), keeps ACME-2, AND redacts restricted page 999
      const summary = await rovoActionHandler(
        {},
        { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-acme-only', extension: { type: 'jira:globalPage' } }
      );
      assert.strictEqual(summary.traceLinks.length, 1);
      assert.strictEqual(summary.traceLinks[0].workKey, 'ACME-2');
      assert.ok(!JSON.stringify(summary).includes('ULTRA_SECRET_CONFLUENCE_EXCERPT'));
      assert.ok(!JSON.stringify(summary).includes('Confidential Restricted SRS-999'));

      const acme2Lineage = await rovoActionHandler(
        { issueKey: 'ACME-2' },
        { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-acme-only', extension: { type: 'jira:projectPage', project: { key: 'ACME' } } }
      );
      assert.strictEqual(acme2Lineage.found, true);
      assert.strictEqual(acme2Lineage.spec.specRestricted, true);
      assert.strictEqual(acme2Lineage.spec.title, 'Restricted Confluence Specification');
      assert.strictEqual(acme2Lineage.spec.sha256Hash, '');
      assert.strictEqual(acme2Lineage.signature.artifactSha256, '');
      assert.strictEqual(acme2Lineage.safetyRequirement, 'Restricted Confluence Specification');
      assert.ok(!JSON.stringify(acme2Lineage).includes('ULTRA_SECRET_CONFLUENCE_EXCERPT'));
      assert.strictEqual(acme2Lineage.specOwners, undefined);

      // Verify restricted Confluence spec does not manufacture signatureDriftDetected in verify-iec-compliance
      const acme2Verify = await rovoActionHandler(
        { issueKey: 'ACME-2' },
        { moduleKey: 'verify-iec-compliance-action', accountId: 'acc-acme-only', extension: { type: 'jira:projectPage', project: { key: 'ACME' } } }
      );
      assert.ok(!JSON.stringify(acme2Verify).includes('Confidential Restricted SRS-999'));
      assert.ok(!JSON.stringify(acme2Verify).includes('ffffff'));
    });
  });

  test.it('workflowValidatorHandler evaluates Under Review -> Done transition-aware rules and blocks incomplete sync globally', async () => {
    const prevSecret = process.env.MEDTRACE_PART11_SECRET;
    process.env.MEDTRACE_PART11_SECRET = 'wf-transition-secret-001';
    try {
      const specHash = 'e'.repeat(64);
      const signedAt = '2026-11-20T12:00:00Z';
      const validSeal = ComplianceEngine.computePart11Seal(
        {
          hazardKey: 'HAZ-REV-1',
          specId: 'srs-rev-1',
          artifactSha256: specHash,
          signedByAccountId: 'acc-qa',
          signedBy: 'Dr. QA',
          role: 'QA Lead',
          meaning: 'Approved SRS',
          signedAt,
          authMethod: 'PART11_ATTESTATION',
        },
        process.env.MEDTRACE_PART11_SECRET
      );
      const baseHazard = {
        id: 'haz-rev-1',
        key: 'HAZ-REV-1',
        title: 'Bolus Limit',
        riskClass: 'CLASS_C',
        mitigationRequirementId: 'srs-rev-1',
        status: 'ACTION_REQUIRED',
      };
      const baseSpec = {
        id: 'srs-rev-1',
        pageId: '99101',
        title: 'SRS-99101',
        version: 2,
        sha256Hash: specHash,
        lastSignedHash: specHash,
        isSignatureInvalidated: false,
        contentSnippet: 'Limit 5.0 mL/hr',
        lastUpdated: '2026-11-20T11:00:00Z',
      };
      const underReviewWork = {
        id: 'w-rev-1',
        key: 'MED-REV-1',
        title: 'Bolus Implementation',
        status: 'Under Review',
        assignee: 'Dev',
      };
      const validTest = {
        id: 't-rev-1',
        testKey: 'TEST-REV-1',
        title: 'HIL Test',
        testType: 'Automated HIL (Hardware-in-Loop)',
        status: 'PASSED',
        evidenceUrl: 'https://ci.example/runs/rev-1',
        executionDate: '2026-11-20T11:30:00Z',
      };
      const validSig = {
        id: 'sig-rev-1',
        signedBy: 'Dr. QA',
        signedByAccountId: 'acc-qa',
        signedAt,
        role: 'QA Lead',
        meaning: 'Approved SRS',
        artifactSha256: specHash,
        isValid: true,
        authMethod: 'PART11_ATTESTATION',
        signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
        signatureSeal: validSeal,
      };
      const evalOpts = {
        part11Secret: process.env.MEDTRACE_PART11_SECRET,
        requireCryptographicSeal: true,
        requireTestEvidence: true,
      };

      const compliantUnderReview = ComplianceEngine.evaluateTraceLink(
        baseHazard,
        baseSpec,
        underReviewWork,
        validTest,
        validSig,
        undefined,
        evalOpts
      );
      const missingEvidenceUnderReview = ComplianceEngine.evaluateTraceLink(
        { ...baseHazard, id: 'haz-rev-2', key: 'HAZ-REV-2' },
        baseSpec,
        { ...underReviewWork, id: 'w-rev-2', key: 'MED-REV-2' },
        { ...validTest, evidenceUrl: undefined },
        validSig,
        undefined,
        evalOpts
      );
      const invalidSigUnderReview = ComplianceEngine.evaluateTraceLink(
        { ...baseHazard, id: 'haz-rev-3', key: 'HAZ-REV-3' },
        baseSpec,
        { ...underReviewWork, id: 'w-rev-3', key: 'MED-REV-3' },
        validTest,
        { ...validSig, signatureSeal: 'bad-seal' },
        undefined,
        evalOpts
      );
      const unclassifiedSeal = ComplianceEngine.computePart11Seal(
        {
          hazardKey: 'HAZ-REV-4',
          specId: 'srs-rev-1',
          artifactSha256: specHash,
          signedByAccountId: 'acc-qa',
          signedBy: 'Dr. QA',
          role: 'QA Lead',
          meaning: 'Approved SRS',
          signedAt,
          authMethod: 'PART11_ATTESTATION',
        },
        process.env.MEDTRACE_PART11_SECRET
      );
      const unclassifiedUnderReview = ComplianceEngine.evaluateTraceLink(
        { ...baseHazard, id: 'haz-rev-4', key: 'HAZ-REV-4', safetyClassAssigned: false },
        baseSpec,
        { ...underReviewWork, id: 'w-rev-4', key: 'MED-REV-4' },
        validTest,
        { ...validSig, signatureSeal: unclassifiedSeal },
        undefined,
        evalOpts
      );

      const suite = ComplianceEngine.generateComplianceReport(
        [compliantUnderReview, missingEvidenceUnderReview, invalidSigUnderReview, unclassifiedUnderReview],
        'LIVE',
        'Transition Suite',
        { initialized: true }
      );
      SeederService.getActiveComplianceSuite = async () => suite;

      const toDonePayload = (key) => ({
        issue: { key },
        transition: {
          name: 'Done',
          from: { name: 'Under Review', statusCategory: { key: 'indeterminate' } },
          to: { name: 'Done', statusCategory: { key: 'done' } },
        },
      });

      // 1. Valid evidence + valid signature + Under Review -> Done: ALLOWED
      const allowedRes = await workflowValidatorHandler(toDonePayload('MED-REV-1'));
      assert.strictEqual(allowedRes.result, true);
      assert.strictEqual(allowedRes.errorMessage, undefined);

      // 2. Missing evidence + Under Review -> Done: BLOCKED
      const noEvRes = await workflowValidatorHandler(toDonePayload('MED-REV-2'));
      assert.strictEqual(noEvRes.result, false);
      assert.match(noEvRes.errorMessage || '', /evidenceUrl/i);

      // 3. Invalid signature + Under Review -> Done: BLOCKED
      const badSigRes = await workflowValidatorHandler(toDonePayload('MED-REV-3'));
      assert.strictEqual(badSigRes.result, false);
      assert.match(badSigRes.errorMessage || '', /Seal Violation|Part 11/i);

      // 4. Unclassified safety issue + Under Review -> Done: BLOCKED
      const unclassRes = await workflowValidatorHandler(toDonePayload('MED-REV-4'));
      assert.strictEqual(unclassRes.result, false);
      assert.match(unclassRes.errorMessage || '', /Classification Gap/i);

      // 5. Explicit non-release transitions pass instead of trapping ordinary workflow movement
      const nonReleaseRes = await workflowValidatorHandler({
        issue: { key: 'MED-REV-1' },
        transition: {
          name: 'Start Progress',
          from: { name: 'To Do', statusCategory: { key: 'new' } },
          to: { name: 'In Progress', statusCategory: { key: 'indeterminate' } },
        },
      });
      assert.strictEqual(nonReleaseRes.result, true);
      assert.strictEqual(nonReleaseRes.errorMessage, undefined);

      // 6. ID-only Forge workflowValidator payload ({ transition: { from: { id }, to: { id } } }) resolves via /rest/api/3/status/{id}
      await withForgeMocks(
        {
          asAppImpl: () => ({
            requestJira: async (routeObj) => {
              const url = String(routeObj?.value_ || routeObj || '');
              if (url === '/rest/api/3/status/10002') {
                return makeJsonResponse(200, {
                  id: '10002',
                  name: 'Done',
                  statusCategory: { key: 'done', name: 'Done' },
                });
              }
              if (url === '/rest/api/3/status/3') {
                return makeJsonResponse(200, {
                  id: '3',
                  name: 'In Progress',
                  statusCategory: { key: 'indeterminate', name: 'In Progress' },
                });
              }
              return makeJsonResponse(404, {});
            },
          }),
        },
        async () => {
          const idDoneRes = await workflowValidatorHandler({
            issue: { key: 'MED-REV-1' },
            transition: { from: { id: '10019' }, to: { id: '10002' } },
          });
          assert.strictEqual(idDoneRes.result, true);

          const idNonDoneRes = await workflowValidatorHandler({
            issue: { key: 'MED-REV-1' },
            transition: { from: { id: '10032' }, to: { id: '3' } },
          });
          assert.strictEqual(idNonDoneRes.result, true);
        }
      );

      // 7. Global release gate stays blocked while syncIncomplete === true
      const incompleteSuite = ComplianceEngine.generateComplianceReport(
        [compliantUnderReview],
        'LIVE',
        'Incomplete Sync Suite',
        { initialized: true, syncIncomplete: true }
      );
      SeederService.getActiveComplianceSuite = async () => incompleteSuite;
      const globalBlocked = await workflowValidatorHandler({});
      assert.strictEqual(globalBlocked.result, false);
      assert.match(globalBlocked.errorMessage || '', /synchronization is incomplete|Resume Sync/i);
    } finally {
      if (prevSecret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
      else process.env.MEDTRACE_PART11_SECRET = prevSecret;
    }
  });

  test.it('createReverificationTask reports failed Jira issue links honestly and checks issuelinks on reuse', async () => {
    const kvsMock = createLocalMockKvs();
    const { blockedLink } = buildSampleLinks();
    const nativeHazardLink = {
      ...blockedLink,
      id: 'link-native-haz',
      hazard: { ...blockedLink.hazard, key: 'MED-10', source: 'JIRA_ISSUE' },
      work: { ...blockedLink.work, key: 'MED-42' },
    };
    const liveSuite = ComplianceEngine.generateComplianceReport([nativeHazardLink], 'LIVE', 'Honest Link Pump', {
      initialized: true,
    });

    let failLinkForMed10 = true;
    let existingIssueLinks = [];

    const asUserImpl = () => ({
      requestJira: async (routeObj, opts) => {
        const url = String(routeObj?.value_ || routeObj || '');
        if (url === '/rest/api/3/myself') {
          return makeJsonResponse(200, { accountId: 'acc-honest-op', active: true });
        }
        if (url.startsWith('/rest/api/3/mypermissions')) {
          return makeJsonResponse(200, {
            permissions: {
              BROWSE_PROJECTS: { havePermission: true },
              EDIT_ISSUES: { havePermission: true },
              CREATE_ISSUES: { havePermission: true },
            },
          });
        }
        if (url === '/rest/api/3/issue/MED-151?fields=status,issuelinks') {
          return makeJsonResponse(200, {
            id: '50002',
            key: 'MED-151',
            fields: {
              status: { name: 'To Do', statusCategory: { key: 'new', name: 'To Do' } },
              issuelinks: existingIssueLinks,
            },
          });
        }
        if (url === '/rest/api/3/issue/createmeta/MED/issuetypes') {
          return makeJsonResponse(200, { issueTypes: [{ id: '10002', name: 'Task', subtask: false }] });
        }
        if (url === '/rest/api/3/issue' && opts?.method === 'POST') {
          return makeJsonResponse(201, { id: '50002', key: 'MED-151' });
        }
        if (url === '/rest/api/3/issueLinkType') {
          return makeJsonResponse(200, { issueLinkTypes: [{ name: 'Relates' }] });
        }
        if (url === '/rest/api/3/issueLink' && opts?.method === 'POST') {
          const payload = JSON.parse(opts.body);
          if (failLinkForMed10 && payload.outwardIssue?.key === 'MED-10') {
            return makeJsonResponse(403, { errorMessages: ['Link permission denied'] });
          }
          return makeJsonResponse(201, {});
        }
        return makeJsonResponse(404, {});
      },
    });

    await withForgeMocks({ kvsMock, asUserImpl }, async () => {
      await SeederService.saveComplianceSuite(liveSuite, 0);

      // 1. Task created, MED-42 linked, MED-10 link fails -> NOT labeled complete success; failedLinkKeys explicitly reported
      const partialRes = await rovoActionHandler(
        {
          actionKey: 'create-reverification-task-action',
          inputs: { hazardKey: 'MED-10', issueKey: 'MED-42' },
        },
        { accountId: 'acc-honest-op', extension: { type: 'jira:projectPage', project: { key: 'MED' } } }
      );
      assert.strictEqual(partialRes.success, false);
      assert.strictEqual(partialRes.partialSuccess, true);
      assert.strictEqual(partialRes.fullyLinked, false);
      assert.strictEqual(partialRes.createdIssueKey, 'MED-151');
      assert.deepStrictEqual(partialRes.linkedIssueKeys, ['MED-42']);
      assert.deepStrictEqual(partialRes.failedLinkKeys, ['MED-10']);
      assert.ok(Array.isArray(partialRes.linkErrors) && partialRes.linkErrors.length === 1);
      assert.match(partialRes.message, /failed to link: MED-10/i);

      // 2. Task reuse with empty issuelinks must NOT fabricate existing links
      existingIssueLinks = [];
      const reuseMissingLinks = await rovoActionHandler(
        {
          actionKey: 'create-reverification-task-action',
          inputs: { hazardKey: 'MED-10', issueKey: 'MED-42' },
        },
        { accountId: 'acc-honest-op', extension: { type: 'jira:projectPage', project: { key: 'MED' } } }
      );
      assert.strictEqual(reuseMissingLinks.alreadyExisted, true);
      assert.strictEqual(reuseMissingLinks.success, false);
      assert.strictEqual(reuseMissingLinks.fullyLinked, false);
      assert.strictEqual(reuseMissingLinks.linksVerified, true);
      assert.deepStrictEqual(reuseMissingLinks.linkedIssueKeys, []);
      assert.deepStrictEqual(reuseMissingLinks.missingLinkKeys, ['MED-42', 'MED-10']);
      assert.match(reuseMissingLinks.message, /missing\/unverified: MED-42, MED-10/i);
    });
  });

  test.it('rovoActionHandler GET actions stay strictly read-only on uninitialized Forge partitions', async () => {
    const { blockedLink } = buildSampleLinks();
    const syncedSuite = ComplianceEngine.generateComplianceReport([blockedLink], 'LIVE', 'MED');
    const originalSyncFromAtlassian = LiveIngestionService.syncFromAtlassian;
    const originalGetActive = SeederService.getActiveComplianceSuite;
    const syncCalls = [];
    let isSynced = false;

    SeederService.getActiveComplianceSuite = async () =>
      isSynced ? syncedSuite : SeederService.getUninitializedLiveSuite();
    LiveIngestionService.syncFromAtlassian = async (opts, actorAccountId) => {
      syncCalls.push({ opts, actorAccountId });
      isSynced = true;
      return {
        success: true,
        summary: syncedSuite,
        jiraIssuesScanned: 1,
        confluencePagesScanned: 1,
        linkedPairsFound: 1,
        driftDetectedCount: 0,
        lastSyncedAt: new Date().toISOString(),
        warnings: [],
      };
    };

    try {
      await withForgeMocks(
        {
          kvsMock: createLocalMockKvs(),
          asAppImpl: () => ({
            requestJira: async () => makeJsonResponse(404, {}),
          }),
          asUserImpl: () => ({
            requestJira: async () => makeJsonResponse(200, { active: true, permissions: { BROWSE_PROJECTS: { havePermission: true } } }),
            requestConfluence: async () => makeJsonResponse(200, { accountId: 'acc-rovo-sync' }),
          }),
        },
        async () => {
          // 1. Unscoped call without target key stays fail-closed (no sync)
          const emptyRes = await rovoActionHandler(
            { actionKey: 'get-hazard-lineage-action', inputs: {} },
            { accountId: 'acc-rovo-sync' }
          );
          assert.strictEqual(emptyRes.initialized, false);
          assert.strictEqual(syncCalls.length, 0);

          // 2. Scoped GET call by read-only user on uninitialized workspace must NOT mutate KVS via auto-sync
          const scopedRes = await rovoActionHandler(
            {
              actionKey: 'verify-iec-compliance-action',
              inputs: { hazardKey: 'HAZ-MED-42', prDiff: 'Change impacting MED-42 bolus driver' },
            },
            { accountId: 'acc-rovo-sync' }
          );
          assert.strictEqual(syncCalls.length, 0, 'GET Rovo action must not mutate KVS or audit log');
          assert.strictEqual(scopedRes.initialized, false);
          assert.strictEqual(scopedRes.configuredChecksPassed, false);
          assert.match(scopedRes.remediationGuidance.join(' '), /Sync Live Atlassian/i);
        }
      );
    } finally {
      LiveIngestionService.syncFromAtlassian = originalSyncFromAtlassian;
      SeederService.getActiveComplianceSuite = originalGetActive;
    }
  });

  test.it('workflowValidatorHandler evaluates synced safety-labeled Test issues via test.testKey', async () => {
    const prevSecret = process.env.MEDTRACE_PART11_SECRET;
    process.env.MEDTRACE_PART11_SECRET = 'wf-testkey-secret-001';
    const origGetActive = SeederService.getActiveComplianceSuite;
    const origReconcile = LiveIngestionService.reconcileConfluenceSpecs;
    const reconcileOptions = [];
    LiveIngestionService.reconcileConfluenceSpecs = async (suite, options) => {
      reconcileOptions.push(options);
      return suite;
    };
    try {
      const specHash = 'c'.repeat(64);
      const signedAt = '2026-11-20T12:00:00Z';
      const validSeal = ComplianceEngine.computePart11Seal(
        {
          hazardKey: 'HAZ-TEST-12',
          specId: 'SRS-TEST-12',
          artifactSha256: specHash,
          signedByAccountId: 'acc-qa',
          signedBy: 'Dr. QA',
          role: 'QA Lead',
          meaning: 'Approved SRS',
          signedAt,
          authMethod: 'PART11_ATTESTATION',
        },
        process.env.MEDTRACE_PART11_SECRET
      );
      const baseHazard = {
        id: 'haz-test-12',
        key: 'HAZ-TEST-12',
        title: 'Bolus Overdose Prevention',
        riskClass: 'CLASS_C',
        mitigationRequirementId: 'SRS-TEST-12',
        status: 'ACTION_REQUIRED',
      };
      const baseSpec = {
        id: 'SRS-TEST-12',
        pageId: '7712',
        title: 'Bolus Verification Spec',
        version: 2,
        sha256Hash: specHash,
        lastSignedHash: specHash,
        isSignatureInvalidated: false,
        contentSnippet: 'Verify occlusion alarm',
        lastUpdated: '2026-11-20T11:00:00Z',
      };
      const workInProgress = {
        id: 'w-42',
        key: 'MED-42',
        title: 'Bolus Driver',
        status: 'In Progress',
        assignee: 'Dev',
        labels: ['class-c', 'safety-critical'],
      };
      const validSig = {
        id: 'sig-test-12',
        signedBy: 'Dr. QA',
        signedByAccountId: 'acc-qa',
        signedAt,
        role: 'QA Lead',
        meaning: 'Approved SRS',
        artifactSha256: specHash,
        isValid: true,
        authMethod: 'PART11_ATTESTATION',
        signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
        signatureSeal: validSeal,
      };
      const evalOpts = {
        linkId: 'MED-TEST-12',
        part11Secret: process.env.MEDTRACE_PART11_SECRET,
        requireCryptographicSeal: true,
        requireTestEvidence: true,
      };
      const untestedLink = ComplianceEngine.evaluateTraceLink(
        baseHazard,
        baseSpec,
        workInProgress,
        {
          id: 't-12',
          testKey: 'MED-12',
          title: 'Pump occlusion verification',
          testType: 'Automated HIL',
          status: 'UNTESTED',
        },
        validSig,
        undefined,
        evalOpts
      );
      const passedLink = ComplianceEngine.evaluateTraceLink(
        baseHazard,
        baseSpec,
        workInProgress,
        {
          id: 't-12',
          testKey: 'MED-12',
          title: 'Pump occlusion verification',
          testType: 'Automated HIL',
          status: 'PASSED',
          executionDate: '2026-10-01T00:00:00Z',
          evidenceUrl: 'https://ci.medtrace.example/runs/12',
        },
        validSig,
        undefined,
        evalOpts
      );

      await withForgeMocks(
        {
          asAppImpl: () => ({
            requestJira: async (routeObj) => {
              const url = String(routeObj?.value_ || routeObj || '');
              if (url.includes('/rest/api/3/issue/MED-12')) {
                return makeJsonResponse(200, {
                  key: 'MED-12',
                  fields: {
                    issuetype: { name: 'Test' },
                    labels: ['class-c'],
                  },
                });
              }
              return makeJsonResponse(404, {});
            },
          }),
        },
        async () => {
          SeederService.getActiveComplianceSuite = async () =>
            ComplianceEngine.generateComplianceReport([untestedLink], 'LIVE', 'Test Key Gate Suite', {
              initialized: true,
            });
          const blockedRes = await workflowValidatorHandler({ issue: { key: 'MED-12' } });
          assert.strictEqual(blockedRes.result, false);
          assert.doesNotMatch(blockedRes.errorMessage || '', /not synced/i);
          assert.match(blockedRes.errorMessage || '', /UNTESTED|evidence|Test/i);

          SeederService.getActiveComplianceSuite = async () =>
            ComplianceEngine.generateComplianceReport([passedLink], 'LIVE', 'Test Key Gate Suite', {
              initialized: true,
            });
          const passedRes = await workflowValidatorHandler({ issue: { key: 'MED-12' } });
          assert.strictEqual(passedRes.result, true);
          assert.strictEqual(passedRes.errorMessage, undefined);
          assert.ok(
            reconcileOptions.some((options) => Array.isArray(options?.targetPageIds) && options.targetPageIds.includes('7712')),
            'test-key transitions must reconcile the linked Confluence spec page'
          );
        }
      );
    } finally {
      SeederService.getActiveComplianceSuite = origGetActive;
      LiveIngestionService.reconcileConfluenceSpecs = origReconcile;
      if (prevSecret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
      else process.env.MEDTRACE_PART11_SECRET = prevSecret;
    }
  });

  test.it('resolveTransitionToDone resolves string status IDs, transition.id, and fails closed on HTTP 500', async () => {
    const prevSecret = process.env.MEDTRACE_PART11_SECRET;
    process.env.MEDTRACE_PART11_SECRET = 'wf-probe-secret-001';
    const origGetActive = SeederService.getActiveComplianceSuite;
    try {
      const specHash = 'd'.repeat(64);
      const signedAt = '2026-11-20T12:00:00Z';
      const validSeal = ComplianceEngine.computePart11Seal(
        {
          hazardKey: 'HAZ-PROBE-1',
          specId: 'SRS-PROBE-1',
          artifactSha256: specHash,
          signedByAccountId: 'acc-qa',
          signedBy: 'Dr. QA',
          role: 'QA Lead',
          meaning: 'Approved SRS',
          signedAt,
          authMethod: 'PART11_ATTESTATION',
        },
        process.env.MEDTRACE_PART11_SECRET
      );
      const underReviewLink = ComplianceEngine.evaluateTraceLink(
        {
          id: 'haz-probe-1',
          key: 'HAZ-PROBE-1',
          title: 'Probe Hazard',
          riskClass: 'CLASS_C',
          mitigationRequirementId: 'SRS-PROBE-1',
          status: 'ACTION_REQUIRED',
        },
        {
          id: 'SRS-PROBE-1',
          pageId: '7713',
          title: 'SRS Probe',
          version: 1,
          sha256Hash: specHash,
          lastSignedHash: specHash,
          isSignatureInvalidated: false,
          contentSnippet: 'Spec',
          lastUpdated: '2026-11-20T11:00:00Z',
        },
        {
          id: 'w-42',
          key: 'MED-42',
          title: 'Probe Work',
          status: 'Under Review',
          assignee: 'Dev',
          labels: ['class-c'],
        },
        {
          id: 't-42',
          testKey: 'TEST-42',
          title: 'Probe Test',
          testType: 'Automated HIL',
          status: 'PASSED',
          executionDate: '2026-11-20T11:30:00Z',
          evidenceUrl: 'https://ci.medtrace.example/runs/42',
        },
        {
          id: 'sig-probe-1',
          signedBy: 'Dr. QA',
          signedByAccountId: 'acc-qa',
          signedAt,
          role: 'QA Lead',
          meaning: 'Approved SRS',
          artifactSha256: specHash,
          isValid: true,
          authMethod: 'PART11_ATTESTATION',
          signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
          signatureSeal: validSeal,
        },
        undefined,
        {
          linkId: 'MED-TRANS-1',
          part11Secret: process.env.MEDTRACE_PART11_SECRET,
          requireCryptographicSeal: true,
          requireTestEvidence: true,
        }
      );
      const suite = ComplianceEngine.generateComplianceReport([underReviewLink], 'LIVE', 'Transition Probe Suite', {
        initialized: true,
      });
      SeederService.getActiveComplianceSuite = async () => suite;

      await withForgeMocks(
        {
          asAppImpl: () => ({
            requestJira: async (routeObj) => {
              const url = String(routeObj?.value_ || routeObj || '');
              if (url === '/rest/api/3/status/10002') {
                return makeJsonResponse(200, {
                  id: '10002',
                  name: 'Done',
                  statusCategory: { key: 'done', name: 'Done' },
                });
              }
              if (url === '/rest/api/3/issue/MED-42/transitions') {
                return makeJsonResponse(200, {
                  transitions: [
                    {
                      id: '31',
                      name: 'Release Done',
                      to: { id: '10002', name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
                    },
                    {
                      id: '32',
                      name: 'Deploy',
                      to: { id: '10003' },
                    },
                  ],
                });
              }
              if (url === '/rest/api/3/status/500') {
                return makeJsonResponse(500, { errorMessages: ['upstream error'] });
              }
              if (url === '/rest/api/3/status/600') {
                return makeJsonResponse(200, { id: '600' });
              }
              return makeJsonResponse(404, {});
            },
          }),
        },
        async () => {
          const byStringStatusId = await workflowValidatorHandler({
            issue: { key: 'MED-42' },
            transition: { to: '10002' },
          });
          assert.strictEqual(byStringStatusId.result, true);

          const byTransitionId = await workflowValidatorHandler({
            issue: { key: 'MED-42' },
            transition: { id: '31' },
          });
          assert.strictEqual(byTransitionId.result, true);

          const failClosedOn500 = await workflowValidatorHandler({
            issue: { key: 'MED-42' },
            transition: { to: { id: '500' } },
          });
          assert.strictEqual(failClosedOn500.result, false);

          const malformedStatusStaysUnknown = await workflowValidatorHandler({
            issue: { key: 'MED-42' },
            transition: { to: { id: '600' } },
          });
          assert.strictEqual(malformedStatusStaysUnknown.result, false);

          const unresolvedNamedTransitionStaysUnknown = await workflowValidatorHandler({
            issue: { key: 'MED-42' },
            transition: { id: '32' },
          });
          assert.strictEqual(unresolvedNamedTransitionStaysUnknown.result, false);
        }
      );
    } finally {
      SeederService.getActiveComplianceSuite = origGetActive;
      if (prevSecret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
      else process.env.MEDTRACE_PART11_SECRET = prevSecret;
    }
  });

  test.it('SeederService.getActiveComplianceSuite({ issueKeyFilter }) matches test.testKey in non-Forge and filterSuiteLinksByIssueKey paths', async () => {
    SeederService.resetInMemoryState();
    const { ComplianceEngine: CE } = require('../dist/compliance-engine.js');
    const link = CE.evaluateTraceLink(
      {
        id: 'haz-t12',
        key: 'HAZ-42',
        title: 'Test Lookup Hazard',
        riskClass: 'CLASS_C',
        mitigationRequirementId: 'srs-t12',
        status: 'ACTION_REQUIRED',
      },
      {
        id: 'srs-t12',
        pageId: '7712',
        title: 'SRS 7712',
        version: 1,
        sha256Hash: 'a'.repeat(64),
        lastSignedHash: 'a'.repeat(64),
        isSignatureInvalidated: false,
        contentSnippet: 'Spec',
        lastUpdated: '2026-11-24T00:00:00Z',
      },
      {
        id: 'w-42',
        key: 'MED-42',
        title: 'Work 42',
        status: 'In Progress',
        assignee: 'Alice',
        labels: ['class-c'],
      },
      {
        id: 't-12',
        testKey: 'MED-12',
        title: 'Verification Test MED-12',
        testType: 'Automated HIL',
        status: 'UNTESTED',
        source: 'JIRA_ISSUE',
      },
      {
        id: 'sig-t12',
        signedBy: 'Alice',
        signedAt: '2026-11-24T00:00:00Z',
        role: 'QA',
        meaning: 'Approved',
        artifactSha256: 'a'.repeat(64),
        isValid: true,
      },
      undefined,
      { linkId: 'link-testkey-lookup' }
    );
    const saved = CE.generateComplianceReport([link], 'LIVE', 'Test Lookup Suite', {
      initialized: true,
    });
    await SeederService.saveComplianceSuite(saved, 0);

    // 1. Non-Forge fast-path (no projectKey)
    const fastMatch = await SeederService.getActiveComplianceSuite({ issueKeyFilter: 'MED-12' });
    assert.strictEqual(fastMatch.traceLinks.length, 1, 'non-Forge loadFastPathSuiteByIssueKey must match test.testKey');
    assert.strictEqual(fastMatch.traceLinks[0].test.testKey, 'MED-12');

    // 2. Fallback filterSuiteLinksByIssueKey path (with projectKey)
    const projMatch = await SeederService.getActiveComplianceSuite({
      projectKey: 'MED',
      issueKeyFilter: 'MED-12',
    });
    assert.strictEqual(projMatch.traceLinks.length, 1, 'filterSuiteLinksByIssueKey must match test.testKey');
    assert.strictEqual(projMatch.traceLinks[0].test.testKey, 'MED-12');
  });

  test.it('verifyIecCompliance scopes activeViolations to targeted traversal instead of leaking unrelated suite violations', async () => {
    const { blockedLink, verifiedLink, sharedVerifiedLink, sharedBlockedSibling } = buildSampleLinks();
    const liveSuite = ComplianceEngine.generateComplianceReport(
      [blockedLink, verifiedLink, sharedVerifiedLink, sharedBlockedSibling],
      'LIVE',
      'Scoped Violations Suite'
    );
    const origGet = SeederService.getActiveComplianceSuite;
    SeederService.getActiveComplianceSuite = async () => liveSuite;
    try {
      const cleanRes = await McpToolService.verifyIecCompliance({ issueKey: 'MED-43' });
      assert.strictEqual(cleanRes.configuredChecksPassed, true);
      assert.deepStrictEqual(cleanRes.activeViolations, []);

      const sharedRes = await McpToolService.verifyIecCompliance({ issueKey: 'MED-501' });
      assert.strictEqual(sharedRes.configuredChecksPassed, false);
      assert.ok(sharedRes.activeViolations.length > 0);
      assert.ok(sharedRes.activeViolations.every((v) => !v.includes('MED-42') && !v.includes('HAZ-101')));
    } finally {
      SeederService.getActiveComplianceSuite = origGet;
    }
  });

  test.it('SeederService.createReverificationTask requires EDIT_ISSUES or ADMINISTER_PROJECTS alongside CREATE_ISSUES', async () => {
    const kvsMock = createLocalMockKvs();
    const { blockedLink } = buildSampleLinks();
    const liveSuite = ComplianceEngine.generateComplianceReport([blockedLink], 'LIVE', 'RBAC Task Suite', {
      initialized: true,
    });

    let editPerm = false;
    let adminPerm = false;
    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async (routeObj, opts) => {
            const url = String(routeObj?.value_ || routeObj || '');
            if (url.startsWith('/rest/api/3/mypermissions')) {
              return makeJsonResponse(200, {
                permissions: {
                  CREATE_ISSUES: { havePermission: true },
                  EDIT_ISSUES: { havePermission: editPerm },
                  ADMINISTER_PROJECTS: { havePermission: adminPerm },
                },
              });
            }
            if (url === '/rest/api/3/issue/createmeta/MED/issuetypes') {
              return makeJsonResponse(200, { issueTypes: [{ id: '1', name: 'Task', subtask: false }] });
            }
            if (url === '/rest/api/3/issue' && opts?.method === 'POST') {
              return makeJsonResponse(201, { id: '9001', key: 'MED-901' });
            }
            if (url === '/rest/api/3/issueLinkType') {
              return makeJsonResponse(200, { issueLinkTypes: [{ name: 'Relates' }] });
            }
            if (url === '/rest/api/3/issueLink' && opts?.method === 'POST') {
              return makeJsonResponse(201, {});
            }
            return makeJsonResponse(404, {});
          },
        }),
      },
      async () => {
        await SeederService.saveComplianceSuite(liveSuite, 0);
        await assert.rejects(
          () =>
            SeederService.createReverificationTask({
              hazardKey: 'HAZ-101',
              issueKey: 'MED-42',
              actorAccountId: 'acc-create-only',
              callerMode: 'USER',
            }),
          /CREATE_ISSUES and EDIT_ISSUES/i
        );

        adminPerm = true;
        const okRes = await SeederService.createReverificationTask({
          hazardKey: 'HAZ-101',
          issueKey: 'MED-42',
          actorAccountId: 'acc-admin',
          callerMode: 'USER',
        });
        assert.strictEqual(okRes.createdIssueKey, 'MED-901');
      }
    );
  });
});
