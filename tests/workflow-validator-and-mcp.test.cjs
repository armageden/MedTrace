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

  test.it('approves tracked verified issues and untracked issues when suite is initialized', async () => {
    const { blockedLink, verifiedLink } = buildSampleLinks();
    const blockedSuite = ComplianceEngine.generateComplianceReport([blockedLink, verifiedLink], 'LIVE', 'Prod Pump');
    SeederService.getActiveComplianceSuite = async () => blockedSuite;

    // Tracked verified Jira item and verified hazard pass even while another link in suite is blocked
    for (const payload of [
      { issue: { key: 'MED-43' }, transition: { name: 'Done' } },
      { issue: { key: 'HAZ-102' } },
      { issue: { key: 'DOCS-10' } },
    ]) {
      const res = await workflowValidatorHandler(payload);
      assert.strictEqual(res.result, true);
      assert.strictEqual(res.errorMessage, undefined);
    }
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
    assert.strictEqual(summaryRes.totalHazards, 4);
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
  });

  test.it('McpToolService.verifyIecCompliance enforces uninitialized fail-closed, multi-key contradiction fix, and LIVE keyword isolation', async () => {
    const uninitSuite = await SeederService.getUninitializedLiveSuite();
    SeederService.getActiveComplianceSuite = async () => uninitSuite;

    const uninitVerify = await McpToolService.verifyIecCompliance({ componentName: 'bolus clamp', issueKey: 'MED-42' });
    assert.strictEqual(uninitVerify.initialized, false);
    assert.strictEqual(uninitVerify.canShipToClinicalProduction, false);
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
    assert.strictEqual(multiKeyRes.canShipToClinicalProduction, false);
    assert.ok(multiKeyRes.affectedHazards.some((h) => h.includes('HAZ-101')));
    assert.ok(
      !multiKeyRes.remediationGuidance.some((g) => /no remediation required|All traversed artifacts are verified/i.test(g))
    );

    // M:N shared hazard: targeting verified MED-501 catches unverified sibling MED-502
    const sharedHazardRes = await McpToolService.verifyIecCompliance({ issueKey: 'MED-501' });
    assert.strictEqual(sharedHazardRes.touchesSafetyCriticalCode, true);
    assert.strictEqual(sharedHazardRes.canShipToClinicalProduction, false);
    assert.ok(sharedHazardRes.graphBlastRadius.blockedWorkItems.includes('MED-502'));
    assert.ok(
      !sharedHazardRes.remediationGuidance.some((g) => /no remediation required|All traversed artifacts are verified/i.test(g))
    );

    // Isolated verified link MED-43 remains shippable
    const cleanRes = await McpToolService.verifyIecCompliance({ issueKey: 'MED-43' });
    assert.strictEqual(cleanRes.touchesSafetyCriticalCode, true);
    assert.strictEqual(cleanRes.canShipToClinicalProduction, true);
    assert.deepStrictEqual(cleanRes.graphBlastRadius.blockedWorkItems, []);
    assert.match(cleanRes.remediationGuidance[0], /All regulatory gates satisfied/);

    // LIVE mode disables DEMO infusion-pump fallbacks ('oled', 'droplet') and avoids substring matches ('generated' != 'rate')
    const liveKeywordBlocked = await McpToolService.verifyIecCompliance({
      prDiff: 'generated oled battery spi voltage',
    });
    assert.strictEqual(liveKeywordBlocked.touchesSafetyCriticalCode, false);
    assert.strictEqual(liveKeywordBlocked.canShipToClinicalProduction, false);

    // Word-boundary token matching works dynamically in LIVE mode for actual spec tokens
    const tokenMatch = await McpToolService.verifyIecCompliance({
      componentName: 'photodiode calibration routine',
    });
    assert.strictEqual(tokenMatch.touchesSafetyCriticalCode, true);
    assert.strictEqual(tokenMatch.canShipToClinicalProduction, true);

    // DEMO mode enables infusion-pump keyword fallback
    const demoSuite = ComplianceEngine.generateComplianceReport([blockedLink, verifiedLink], 'DEMO', 'Demo Pump');
    SeederService.getActiveComplianceSuite = async () => demoSuite;
    const demoFallbackRes = await McpToolService.verifyIecCompliance({ componentName: 'bolus motor' });
    assert.strictEqual(demoFallbackRes.touchesSafetyCriticalCode, true);
    assert.ok(demoFallbackRes.graphBlastRadius);
    assert.match(demoFallbackRes.graphBlastRadius.trigger, /SRS-104/);
  });

  test.it('rovoActionHandler enforces action allowlist, user read probes in Forge runtime, and sanitized errors', async () => {
    const unknownRes = await rovoActionHandler({ actionKey: 'delete-all' });
    assert.match(unknownRes.error, /Unknown action/);
    assert.deepStrictEqual(unknownRes.availableTools, [
      'get-hazard-lineage-action',
      'verify-iec-compliance-action',
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
    assert.strictEqual(verifyAliasRes.canShipToClinicalProduction, false);
    assert.strictEqual(verifyAliasRes.touchesSafetyCriticalCode, true);

    const kvsMock = createLocalMockKvs();

    // Forge runtime read-probe rejections (empty accountId, Jira 403/inactive, Confluence 403/mismatch)
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
        assert.strictEqual(confOk.canShipToClinicalProduction, false);
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
});
