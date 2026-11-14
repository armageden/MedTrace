const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { ComplianceEngine } = require('../dist/compliance-engine');
const { verifyHmacSignature, mcpWebtriggerHandler, workflowValidatorHandler, rovoActionHandler, setNonceStore, createInMemoryNonceStore, claimNonce } = require('../dist/index');
const { SeederService } = require('../dist/seeder');
const { McpToolService } = require('../dist/mcp-server');

test.describe('ComplianceEngine - IEC 62304 traceability & signature-fingerprint rules', () => {
  const baseHazard = {
    id: 'haz-101',
    key: 'HAZ-101',
    title: 'Over-Infusion Hazard',
    riskClass: 'CLASS_C',
    severity: 'CATASTROPHIC',
    probability: 'OCCASIONAL',
    mitigationRequirementId: 'srs-104',
    status: 'UNVERIFIED_RISK',
  };

  const baseSpec = {
    id: 'srs-104',
    title: 'SRS-104: Hardware Bolus Clamp',
    version: 3,
    sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    lastSignedHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    isSignatureInvalidated: false,
    contentSnippet: 'Clause 4.2.1: Hardware clamp',
    lastUpdated: '1 hour ago',
  };

  const baseWork = {
    id: 'med-42',
    key: 'MED-42',
    title: 'Implement Hardware Clamp',
    status: 'Done',
    assignee: 'Dr. Sarah Lin',
  };

  const baseTest = {
    id: 'test-88',
    testKey: 'TEST-88',
    title: 'Motor Stress Test',
    testType: 'Automated HIL (Hardware-in-Loop)',
    status: 'PASSED',
  };

  const baseSig = {
    id: 'sig-001',
    signedBy: 'Marcus Vance, MD',
    signedAt: '2026-10-15T11:30:00Z',
    role: 'Clinical Safety Authority',
    meaning: 'Approval',
    artifactSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    isValid: true,
  };

  test.it('evaluates fully compliant Class C hazard as VERIFIED', () => {
    const link = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, baseSig);
    assert.strictEqual(link.complianceState, 'VERIFIED');
    assert.strictEqual(link.violations.length, 0);
  });

  test.it('blocks Class C hazard when verification test is UNTESTED', () => {
    const untested = { ...baseTest, status: 'UNTESTED' };
    const link = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, untested, baseSig);
    assert.strictEqual(link.complianceState, 'SAFETY_VIOLATION');
    assert.match(link.violations[0], /IEC 62304 Critical Gap/);
  });

  test.it('flags Class B hazard as INCOMPLETE when test status is FAILED', () => {
    const classBHazard = { ...baseHazard, id: 'haz-102', key: 'HAZ-102', riskClass: 'CLASS_B', severity: 'CRITICAL' };
    const failedTest = { ...baseTest, id: 'test-89', testKey: 'TEST-89', status: 'FAILED' };
    const link = ComplianceEngine.evaluateTraceLink(classBHazard, baseSpec, baseWork, failedTest, baseSig);
    assert.strictEqual(link.complianceState, 'INCOMPLETE');
    assert.match(link.violations[0], /IEC 62304 Notice: Class B Hazard \[HAZ-102\] verification test is FAILED/);
  });

  test.it('flags signature-fingerprint drift when Confluence hash diverges', () => {
    const driftedSpec = {
      ...baseSpec,
      sha256Hash: 'divergent-sha256-hash-after-modification',
      isSignatureInvalidated: true,
    };
    const link = ComplianceEngine.evaluateTraceLink(baseHazard, driftedSpec, baseWork, baseTest, baseSig);
    assert.strictEqual(link.complianceState, 'SIGNATURE_DRIFT');
    assert.match(link.violations[0], /Cryptographic Signature Drift/);
  });

  test.it('ensures SAFETY_VIOLATION takes precedence over SIGNATURE_DRIFT on Class C hazards', () => {
    const untested = { ...baseTest, status: 'UNTESTED' };
    const driftedSpec = {
      ...baseSpec,
      sha256Hash: 'divergent-sha256-hash',
      isSignatureInvalidated: true,
    };
    const link = ComplianceEngine.evaluateTraceLink(baseHazard, driftedSpec, baseWork, untested, baseSig);
    assert.strictEqual(link.complianceState, 'SAFETY_VIOLATION');
    assert.strictEqual(link.violations.length, 2);
  });

  test.it('generates compliance report and blocks release if any violations exist', () => {
    const untested = { ...baseTest, status: 'UNTESTED' };
    const link1 = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, untested, baseSig);
    const link2 = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, baseSig);
    const report = ComplianceEngine.generateComplianceReport([link1, link2]);

    assert.strictEqual(report.totalHazards, 2);
    assert.strictEqual(report.verifiedPercentage, 50);
    assert.strictEqual(report.releaseBlocked, true);
    assert.strictEqual(report.blockingReasons.length, 1);
    assert.strictEqual(report.datasetMode, 'DEMO');

    // Supports LIVE datasetMode when evaluating live project entities
    const liveReport = ComplianceEngine.generateComplianceReport([link2], 'LIVE', 'Infusion Pump Production');
    assert.strictEqual(liveReport.datasetMode, 'LIVE');
    assert.strictEqual(liveReport.projectName, 'Infusion Pump Production');
    assert.strictEqual(liveReport.releaseBlocked, false);
  });
});

test.describe('Webtrigger Cryptographic Security - HMAC-SHA256 & Replay Protection', () => {
  const secret = 'test-secret-key-12345';
  const timestamp = Date.now().toString();
  const rawBody = JSON.stringify({ action: 'remediate', hazardKey: 'HAZ-101' });

  let inMemoryStore;
  test.beforeEach(() => {
    process.env.MEDTRACE_MCP_SECRET = secret;
    inMemoryStore = createInMemoryNonceStore();
    setNonceStore(inMemoryStore);
  });

  test.it('accepts valid HMAC-SHA256 signature bound to timestamp and body', () => {
    const validSig = crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
    const isValid = verifyHmacSignature(rawBody, timestamp, `sha256=${validSig}`, secret);
    assert.strictEqual(isValid, true);
  });

  test.it('rejects replayed request when attacker tampers with timestamp', () => {
    const validSig = crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
    const tamperedTimestamp = (Date.now() + 1000).toString();
    const isValid = verifyHmacSignature(rawBody, tamperedTimestamp, `sha256=${validSig}`, secret);
    assert.strictEqual(isValid, false);
  });

  test.it('rejects request when attacker tampers with body payload', () => {
    const validSig = crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
    const tamperedBody = JSON.stringify({ action: 'remediate', hazardKey: 'HAZ-999' });
    const isValid = verifyHmacSignature(tamperedBody, timestamp, `sha256=${validSig}`, secret);
    assert.strictEqual(isValid, false);
  });

  test.it('rejects invalid or malformed signature length', () => {
    const isValid = verifyHmacSignature(rawBody, timestamp, 'sha256=invalidhex', secret);
    assert.strictEqual(isValid, false);
  });

  test.it('rejects unauthenticated GET webtrigger requests with HTTP 401', async () => {
    const resp = await mcpWebtriggerHandler({ method: 'GET', headers: {} });
    assert.strictEqual(resp.statusCode, 401);
    assert.match(resp.body, /Unauthorized: Missing x-medtrace-timestamp header/);
  });

  test.it('accepts a validly signed GET webtrigger request with HTTP 200', async () => {
    const ts = Date.now().toString();
    const nonce = 'get-' + crypto.randomUUID();
    const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.`).digest('hex');
    const resp = await mcpWebtriggerHandler({
      method: 'GET',
      headers: {
        'x-medtrace-timestamp': ts,
        'x-medtrace-nonce': nonce,
        'x-medtrace-signature': `sha256=${sig}`,
      },
    });
    assert.strictEqual(resp.statusCode, 200);
    const parsed = JSON.parse(resp.body);
    assert.ok(parsed.traceLinks || parsed.projectName);
  });

  test.it('rejects remediation in LIVE mode with 403 and unknown DEMO hazard with 404 instead of reporting success', async () => {
    const originalGet = SeederService.getActiveComplianceSuite;
    try {
      // 1) LIVE mode blocks webtrigger auto-remediation with 403 Forbidden
      SeederService.getActiveComplianceSuite = async () => ({
        projectName: 'Live Suite',
        datasetMode: 'LIVE',
        initialized: true,
        standards: [],
        totalHazards: 1,
        classCCount: 1,
        classBCount: 0,
        classACount: 0,
        verifiedPercentage: 0,
        releaseBlocked: true,
        blockingReasons: ['HAZ-101 gap'],
        signatureDriftCount: 0,
        lastAuditTimestamp: new Date().toISOString(),
        traceLinks: [],
      });
      const tsLive = Date.now().toString();
      const nonceLive = 'rem-live-' + crypto.randomUUID();
      const bodyLive = JSON.stringify({ action: 'remediate', hazardKey: 'HAZ-999' });
      const sigLive = crypto.createHmac('sha256', secret).update(`${tsLive}.${nonceLive}.${bodyLive}`).digest('hex');
      const liveResp = await mcpWebtriggerHandler({
        method: 'POST',
        headers: {
          'x-medtrace-key': secret,
          'x-medtrace-timestamp': tsLive,
          'x-medtrace-nonce': nonceLive,
          'x-medtrace-signature': `sha256=${sigLive}`,
        },
        body: bodyLive,
      });
      assert.strictEqual(liveResp.statusCode, 403);

      // 2) DEMO mode with unknown hazard returns 404 Not Found
      SeederService.getActiveComplianceSuite = async () => ({
        projectName: 'Demo Suite',
        datasetMode: 'DEMO',
        initialized: true,
        standards: [],
        totalHazards: 0,
        classCCount: 0,
        classBCount: 0,
        classACount: 0,
        verifiedPercentage: 100,
        releaseBlocked: false,
        blockingReasons: [],
        signatureDriftCount: 0,
        lastAuditTimestamp: new Date().toISOString(),
        traceLinks: [],
      });
      const ts = Date.now().toString();
      const nonce = 'rem-' + crypto.randomUUID();
      const body = JSON.stringify({ action: 'remediate', hazardKey: 'HAZ-999' });
      const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${body}`).digest('hex');
      const resp = await mcpWebtriggerHandler({
        method: 'POST',
        headers: {
          'x-medtrace-key': secret,
          'x-medtrace-timestamp': ts,
          'x-medtrace-nonce': nonce,
          'x-medtrace-signature': `sha256=${sig}`,
        },
        body,
      });
      assert.strictEqual(resp.statusCode, 404);
      assert.match(resp.body, /not found.*nothing was remediated/i);
    } finally {
      SeederService.getActiveComplianceSuite = originalGet;
    }
  });

  test.it('rejects secrets passed in URL query parameters (header-only defense against log leakage)', async () => {
    const resp = await mcpWebtriggerHandler({ method: 'GET', headers: {}, query: { token: 'synthetic-test-fixture-secret' } });
    assert.strictEqual(resp.statusCode, 401);
  });

  test.it('rejects duplicate in-window nonce replay with HTTP 409 Conflict and unknown POST action sync-status with 400', async () => {
    const mcpSecret = process.env.MEDTRACE_MCP_SECRET || 'synthetic-test-fixture-secret';
    const testNonce = 'nonce-' + crypto.randomUUID();
    const ts = Date.now().toString();
    const body = JSON.stringify({ action: 'status' });
    const sig = crypto.createHmac('sha256', mcpSecret).update(`${ts}.${testNonce}.${body}`).digest('hex');
    const req = {
      method: 'POST',
      headers: {
        'x-medtrace-key': mcpSecret,
        'x-medtrace-timestamp': ts,
        'x-medtrace-nonce': testNonce,
        'x-medtrace-signature': `sha256=${sig}`,
      },
      body,
    };
    // First call consumes the nonce and succeeds
    const res1 = await mcpWebtriggerHandler(req);
    assert.strictEqual(res1.statusCode, 200);

    // Replayed second call with identical nonce within window
    const res2 = await mcpWebtriggerHandler(req);
    assert.strictEqual(res2.statusCode, 409);
    assert.match(res2.body, /Replay attack detected/);

    // Unknown POST action is rejected with 400 Bad Request
    const unknownNonce = 'nonce-unk-' + crypto.randomUUID();
    const unknownBody = JSON.stringify({ action: 'sync-status' });
    const unknownSig = crypto
      .createHmac('sha256', mcpSecret)
      .update(`${ts}.${unknownNonce}.${unknownBody}`)
      .digest('hex');
    const resUnknown = await mcpWebtriggerHandler({
      method: 'POST',
      headers: {
        'x-medtrace-key': mcpSecret,
        'x-medtrace-timestamp': ts,
        'x-medtrace-nonce': unknownNonce,
        'x-medtrace-signature': `sha256=${unknownSig}`,
      },
      body: unknownBody,
    });
    assert.strictEqual(resUnknown.statusCode, 400);
  });

  test.it('lazily prunes expired nonces on access and allows reuse outside TTL', async () => {
    const nonce = 'stale-nonce-123';
    // Store an expired nonce (350 seconds ago)
    await inMemoryStore.set(`nonce:${nonce}`, { consumedAt: Date.now() - 350_000 });

    // Claiming this nonce should prune the expired entry and succeed
    const claimed = await claimNonce(nonce, inMemoryStore, 300_000);
    assert.strictEqual(claimed, true);

    // The key now has the fresh timestamp
    const record = await inMemoryStore.get(`nonce:${nonce}`);
    assert.ok(Date.now() - record.consumedAt < 1000);
  });

  test.it('fails closed with HTTP 500 when MEDTRACE_MCP_SECRET is unset in environment', async () => {
    delete process.env.MEDTRACE_MCP_SECRET;
    try {
      const resp = await mcpWebtriggerHandler({ method: 'GET', headers: { 'x-medtrace-key': 'anything' } });
      assert.strictEqual(resp.statusCode, 500);
      assert.match(resp.body, /fail-closed/);
    } finally {
      process.env.MEDTRACE_MCP_SECRET = secret;
    }
  });

  test.it('allows external transition validation via webtrigger action simulate_transition', async () => {
    const ts = Date.now().toString();
    const nonce = 'val-' + crypto.randomUUID();
    const body = JSON.stringify({ action: 'simulate_transition', issueKey: 'MED-42' });
    const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${body}`).digest('hex');
    const resp = await mcpWebtriggerHandler({
      method: 'POST',
      headers: {
        'x-medtrace-key': secret,
        'x-medtrace-timestamp': ts,
        'x-medtrace-nonce': nonce,
        'x-medtrace-signature': `sha256=${sig}`,
      },
      body,
    });
    assert.strictEqual(resp.statusCode, 200);
    const parsed = JSON.parse(resp.body);
    assert.strictEqual(typeof parsed.result, 'boolean');
  });

  test.it('CI release gate action verify-release-gate returns HTTP 403 + result:false on a blocked suite', async () => {
    const originalGet = SeederService.getActiveComplianceSuite;
    SeederService.getActiveComplianceSuite = async () => ({
      projectName: 'CI Gate Suite',
      datasetMode: 'LIVE',
      initialized: true,
      standards: [],
      totalHazards: 1,
      classCCount: 1,
      classBCount: 0,
      classACount: 0,
      verifiedPercentage: 0,
      releaseBlocked: true,
      blockingReasons: ['IEC 62304 Critical Gap: HAZ-101 unverified'],
      signatureDriftCount: 0,
      lastAuditTimestamp: new Date().toISOString(),
      traceLinks: [
        {
          id: 'link-ci-blocked',
          hazard: {
            key: 'HAZ-101',
            title: 'Infusion Overdose',
            severity: 'Catastrophic',
            safetyClass: 'Class C',
            status: 'CRITICAL_GAP',
          },
          spec: { id: 'srs-1', title: 'Flow Limiter', version: '1.0', approved: true },
          work: { key: 'MED-1', summary: 'Implement limiter', status: 'In Progress' },
          test: { testKey: 'TST-1', status: 'UNTESTED', evidenceUrl: '' },
          complianceState: 'CRITICAL_GAP',
          violations: ['IEC 62304 Critical Gap: HAZ-101 unverified'],
        },
      ],
    });
    try {
      const ts = Date.now().toString();
      const nonce = 'ci-' + crypto.randomUUID();
      const body = JSON.stringify({ action: 'verify-release-gate' });
      const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${body}`).digest('hex');
      const resp = await mcpWebtriggerHandler({
        method: 'POST',
        headers: {
          'x-medtrace-key': secret,
          'x-medtrace-timestamp': ts,
          'x-medtrace-nonce': nonce,
          'x-medtrace-signature': `sha256=${sig}`,
        },
        body,
      });
      assert.strictEqual(resp.statusCode, 403);
      const parsed = JSON.parse(resp.body);
      assert.strictEqual(parsed.result, false);
      assert.match(parsed.errorMessage, /Safety Gate/);
    } finally {
      SeederService.getActiveComplianceSuite = originalGet;
    }
  });

  test.it('CI release gate action verify-release-gate returns HTTP 200 + result:true on a clean suite', async () => {
    const originalGet = SeederService.getActiveComplianceSuite;
    SeederService.getActiveComplianceSuite = async () => ({
      projectName: 'CI Gate Suite',
      datasetMode: 'LIVE',
      initialized: true,
      standards: [],
      totalHazards: 1,
      classCCount: 1,
      classBCount: 0,
      classACount: 0,
      verifiedPercentage: 100,
      releaseBlocked: false,
      blockingReasons: [],
      signatureDriftCount: 0,
      lastAuditTimestamp: new Date().toISOString(),
      traceLinks: [
        {
          id: 'link-ci-clean',
          hazard: {
            key: 'HAZ-101',
            title: 'Infusion Overdose',
            severity: 'Catastrophic',
            safetyClass: 'Class C',
            status: 'VERIFIED',
          },
          spec: { id: 'srs-1', title: 'Flow Limiter', version: '1.0', approved: true },
          work: { key: 'MED-1', summary: 'Implement limiter', status: 'Done' },
          test: {
            testKey: 'TST-1',
            status: 'PASSED',
            evidenceUrl: 'https://ci.medtrace.internal/runs/1',
          },
          complianceState: 'VERIFIED',
          violations: [],
        },
      ],
    });
    try {
      const ts = Date.now().toString();
      const nonce = 'ci-clean-' + crypto.randomUUID();
      const body = JSON.stringify({ action: 'verify-release-gate' });
      const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${body}`).digest('hex');
      const resp = await mcpWebtriggerHandler({
        method: 'POST',
        headers: {
          'x-medtrace-key': secret,
          'x-medtrace-timestamp': ts,
          'x-medtrace-nonce': nonce,
          'x-medtrace-signature': `sha256=${sig}`,
        },
        body,
      });
      assert.strictEqual(resp.statusCode, 200);
      const parsed = JSON.parse(resp.body);
      assert.strictEqual(parsed.result, true);
    } finally {
      SeederService.getActiveComplianceSuite = originalGet;
    }
  });

  test.it('CI release gate honors issueKey scoping (clean issue passes even while the suite has other gaps)', async () => {
    const originalGet = SeederService.getActiveComplianceSuite;
    SeederService.getActiveComplianceSuite = async () => ({
      projectName: 'CI Gate Suite', standards: [], totalHazards: 2, classCCount: 1, classBCount: 0, classACount: 0,
      verifiedPercentage: 50, releaseBlocked: true,
      blockingReasons: ['IEC 62304 Critical Gap: HAZ-101 unverified'],
      signatureDriftCount: 0, lastAuditTimestamp: new Date().toISOString(),
      traceLinks: [
        { work: { key: 'MED-42' }, hazard: { key: 'HAZ-101' }, complianceState: 'SAFETY_VIOLATION', violations: ['IEC 62304 Critical Gap: HAZ-101 requires verified test coverage.'] },
        { work: { key: 'MED-43' }, hazard: { key: 'HAZ-102' }, complianceState: 'VERIFIED', violations: [] },
      ],
    });
    try {
      const callGate = async (issueKey) => {
        const ts = Date.now().toString();
        const nonce = 'ci-scope-' + crypto.randomUUID();
        const body = JSON.stringify({ action: 'verify-release-gate', issueKey });
        const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${body}`).digest('hex');
        return mcpWebtriggerHandler({
          method: 'POST',
          headers: {
            'x-medtrace-key': secret,
            'x-medtrace-timestamp': ts,
            'x-medtrace-nonce': nonce,
            'x-medtrace-signature': `sha256=${sig}`,
          },
          body,
        });
      };

      const blocked = await callGate('MED-42');
      assert.strictEqual(blocked.statusCode, 403);
      assert.strictEqual(JSON.parse(blocked.body).result, false);

      const passed = await callGate('MED-43');
      assert.strictEqual(passed.statusCode, 200);
      assert.strictEqual(JSON.parse(passed.body).result, true);
    } finally {
      SeederService.getActiveComplianceSuite = originalGet;
    }
  });
});

test.describe('Rovo Action Handler - Forge rovo:action payload contract', () => {
  test.beforeEach(async () => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState();
    await SeederService.seedEnterpriseDemoSuite('acc-rovo-test', 'SYSTEM_INIT');
  });

  test.it('dispatches get-hazard-lineage from context.moduleKey with inputs spread on payload', async () => {
    const payload = { issueKey: 'MED-42', context: { moduleKey: 'get-hazard-lineage-action', cloudId: 'cloud-x' } };
    const res = await rovoActionHandler(payload, { moduleKey: 'get-hazard-lineage-action' });
    assert.strictEqual(res.found, true);
    assert.strictEqual(res.traceLink.work.key, 'MED-42');
    assert.strictEqual(res.riskClass, 'CLASS_C');
  });

  test.it('dispatches verify-iec-compliance from payload.context.moduleKey without a second context argument', async () => {
    const payload = { prDiff: 'diff --git a/pump.c b/pump.c\n+ clamp bolus motor rate 5.5', context: { moduleKey: 'verify-iec-compliance-action' } };
    const res = await rovoActionHandler(payload);
    assert.strictEqual(res.touchesSafetyCriticalCode, true);
    assert.ok(res.graphBlastRadius);
  });

  test.it('returns availableTools for an unknown moduleKey', async () => {
    const res = await rovoActionHandler({ context: { moduleKey: 'nope-action' } }, { moduleKey: 'nope-action' });
    assert.match(res.error, /Unknown action/);
    assert.ok(Array.isArray(res.availableTools));
  });
});

test.describe('McpToolService & Rovo Agent - Dynamic Graph Traversal', () => {
  test.beforeEach(async () => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState();
    await SeederService.seedEnterpriseDemoSuite('acc-mcp-test', 'SYSTEM_INIT');
  });

  test.it('extracts issue key and performs BFS blast-radius traversal on code diff', async () => {
    const res = await McpToolService.verifyIecCompliance({
      prDiff: 'diff --git a/firmware.c b/firmware.c\n+// fixes MED-42 PWM rate',
    });
    assert.strictEqual(res.touchesSafetyCriticalCode, true);
    assert.ok(res.graphBlastRadius);
    assert.strictEqual(typeof res.graphBlastRadius.executionTimeMs, 'number');
    assert.ok(res.graphBlastRadius.traversalPath.length > 0);
  });

  test.it('maps component keywords to specification nodes and executes graph traversal', async () => {
    const res = await McpToolService.verifyIecCompliance({
      componentName: 'motor bolus delivery clamp',
    });
    assert.strictEqual(res.touchesSafetyCriticalCode, true);
    assert.ok(res.graphBlastRadius);
    assert.match(res.graphBlastRadius.trigger, /SRS-104/);
  });

  test.it('blocks shipping when diff touches Class C hazard with unverified gaps', async () => {
    const res = await McpToolService.verifyIecCompliance({
      issueKey: 'MED-42',
    });
    assert.strictEqual(res.touchesSafetyCriticalCode, true);
    assert.strictEqual(res.canShipToClinicalProduction, false);
  });

  test.it('allows shipping for Class A non-critical change when suite has no blocking violations for that component', async () => {
    const originalGet = SeederService.getActiveComplianceSuite;
    SeederService.getActiveComplianceSuite = async () => ({
      standards: ['IEC 62304:2006+AMD1:2015'],
      releaseBlocked: false,
      blockingReasons: [],
      verifiedPercentage: 100,
      classCCount: 1,
      signatureDriftCount: 0,
      traceLinks: [
        {
          hazard: { key: 'HAZ-103', riskClass: 'CLASS_A', title: 'Display Transient Glitch' },
          spec: { id: 'srs-106', title: 'SRS-106', sha256Hash: 'abc', isSignatureInvalidated: false },
          work: { key: 'MED-44', status: 'Done' },
          test: { testKey: 'TEST-90', status: 'PASSED' },
          signature: { id: 'sig-003', artifactSha256: 'abc', isValid: true },
          complianceState: 'VERIFIED',
          violations: [],
        },
      ],
    });

    try {
      const res = await McpToolService.verifyIecCompliance({
        componentName: 'oled backlight display',
      });
      assert.strictEqual(res.touchesSafetyCriticalCode, true);
      assert.strictEqual(res.canShipToClinicalProduction, true);
    } finally {
      SeederService.getActiveComplianceSuite = originalGet;
    }
  });
});

test.describe('SeederService - Cryptographic Integrity & Dynamic Hashes', () => {
  test.beforeEach(async () => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState();
    await SeederService.seedEnterpriseDemoSuite('acc-hash-test', 'SYSTEM_INIT');
  });

  test.it('dynamically computes non-empty SHA-256 hashes for all specifications and signatures', async () => {
    const suite = await SeederService.getActiveComplianceSuite();
    assert.ok(suite.traceLinks.length > 0);
    for (const link of suite.traceLinks) {
      assert.strictEqual(link.spec.sha256Hash.length, 64);
      assert.notStrictEqual(link.spec.sha256Hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      assert.strictEqual(link.signature.artifactSha256.length, 64);
    }
  });
});

test.describe('Jira Workflow Validator - Scoped Release Gate', () => {
  const originalGet = SeederService.getActiveComplianceSuite;

  test.beforeEach(() => {
    SeederService.getActiveComplianceSuite = async () => ({
      releaseBlocked: true,
      blockingReasons: ['IEC 62304 Critical Gap: HAZ-101 unverified'],
      traceLinks: [
        {
          work: { key: 'MED-42' },
          hazard: { key: 'HAZ-101' },
          complianceState: 'SAFETY_VIOLATION',
          violations: ['IEC 62304 Critical Gap: HAZ-101 requires verified test coverage.'],
        },
        {
          work: { key: 'MED-43' },
          hazard: { key: 'HAZ-102' },
          complianceState: 'VERIFIED',
          violations: [],
        },
      ],
    });
  });

  test.afterEach(() => {
    SeederService.getActiveComplianceSuite = originalGet;
  });

  test.it('blocks issue transition when linked to an unverified safety hazard', async () => {
    const res = await workflowValidatorHandler({ issue: { key: 'MED-42' } });
    assert.strictEqual(res.result, false);
    assert.match(res.errorMessage, /Human-initiated transition blocked for MED-42/);
  });

  test.it('approves issue transition when issue has no safety violations', async () => {
    const res = await workflowValidatorHandler({ issue: { key: 'MED-43' } });
    assert.strictEqual(res.result, true);
    assert.strictEqual(res.errorMessage, undefined);
  });

  test.it('approves transition for unrelated everyday Jira issues not linked to hazards', async () => {
    const res = await workflowValidatorHandler({ issue: { key: 'DOCS-10' } });
    assert.strictEqual(res.result, true);
    assert.strictEqual(res.errorMessage, undefined);
  });
});

test.describe('Deterministic Regulatory Blast Radius & Transitive Impact Analyzer', () => {
  const sampleSuite = {
    projectName: 'Smart Infusion Pump Firmware v2.1',
    standards: ['IEC 62304:2006+A1:2015', 'ISO 14971:2019', 'Cryptographic Signature Fingerprinting'],
    totalHazards: 1,
    classCCount: 1,
    classBCount: 0,
    classACount: 0,
    verifiedPercentage: 0,
    releaseBlocked: true,
    blockingReasons: ['IEC 62304 Critical Gap: HAZ-101 requires verified test coverage.'],
    signatureDriftCount: 1,
    lastAuditTimestamp: new Date().toISOString(),
    traceLinks: [
      {
        id: 'trace-HAZ-101',
        complianceState: 'SAFETY_VIOLATION',
        violations: ['IEC 62304 Critical Gap: HAZ-101 requires verified test coverage.'],
        hazard: {
          id: 'haz-101',
          key: 'HAZ-101',
          title: 'Bolus Over-Infusion Hazard (> 5.0 mL/hr)',
          riskClass: 'CLASS_C',
          severity: 'CATASTROPHIC',
          probability: 'OCCASIONAL',
          mitigationRequirementId: 'srs-104',
          status: 'UNVERIFIED_RISK',
        },
        spec: {
          id: 'srs-104',
          title: 'SRS-104: Hardware Bolus Clamp',
          version: 3,
          sha256Hash: 'hash-v3-modified-content',
          lastSignedHash: 'hash-v2-signed-baseline',
          isSignatureInvalidated: true,
          contentSnippet: 'Max bolus threshold modified',
          lastUpdated: '5 minutes ago',
        },
        work: {
          id: 'med-42',
          key: 'MED-42',
          title: 'Implement Hardware Clamp',
          status: 'In Progress',
          assignee: 'Dr. Sarah Lin (Lead Firmware)',
          prNumber: '#142',
        },
        test: {
          id: 'test-88',
          testKey: 'TEST-88',
          title: 'Hardware-in-the-Loop Motor Stress Test',
          testType: 'Automated HIL (Hardware-in-Loop)',
          status: 'UNTESTED',
        },
        signature: {
          id: 'sig-001',
          signedBy: 'Marcus Vance, MD',
          signedAt: '2026-10-15T11:30:00Z',
          role: 'Chief Medical Officer',
          meaning: 'Clinical Safety Approval',
          artifactSha256: 'hash-v2-signed-baseline',
          isValid: false,
        },
      },
    ],
  };

  test.it('traverses 4-hop cascade deterministically when specification drifts', () => {
    const report = ComplianceEngine.computeBlastRadius('srs-104', sampleSuite);

    assert.strictEqual(report.triggerArtifact.id, 'srs-104');
    assert.strictEqual(report.impactSeverity, 'CRITICAL_CATASTROPHIC');
    assert.deepStrictEqual(report.affectedHazardKeys, ['HAZ-101']);
    assert.deepStrictEqual(report.blockedWorkItemKeys, ['MED-42']);
    assert.deepStrictEqual(report.invalidatedTestKeys, ['TEST-88']);
    assert.deepStrictEqual(report.invalidatedSignatureIds, ['sig-001']);

    assert.strictEqual(report.traversalPath.length, 4);
    assert.strictEqual(report.traversalPath[0].edge, 'SIGNS');
    assert.strictEqual(report.traversalPath[1].edge, 'MITIGATES');
    assert.strictEqual(report.traversalPath[2].edge, 'IMPLEMENTS');
    assert.strictEqual(report.traversalPath[3].edge, 'VERIFIES');

    assert.ok(report.executionTimeMs >= 0);
    assert.ok(report.executionTimeMs < 100, `Execution time ${report.executionTimeMs}ms exceeds 100ms threshold`);
  });

  test.it('terminates deterministically and prevents infinite loops on circular trace links', () => {
    // Construct circular trace graph link
    const circularSuite = {
      ...sampleSuite,
      traceLinks: [
        sampleSuite.traceLinks[0],
        {
          ...sampleSuite.traceLinks[0],
          id: 'trace-HAZ-101-circular',
        },
      ],
    };

    const report = ComplianceEngine.computeBlastRadius('srs-104', circularSuite);
    assert.ok(report);
    assert.strictEqual(report.affectedHazardKeys.length, 1, 'Visited set must deduplicate circular nodes');
  });

  test.it('invalidates multiple electronic signatures on one artifact when specification drifts', () => {
    const multiSigSuite = {
      ...sampleSuite,
      traceLinks: [
        {
          ...sampleSuite.traceLinks[0],
          id: 'trace-sig-1',
          signature: {
            id: 'sig-001',
            signedBy: 'Marcus Vance, MD',
            role: 'Chief Medical Officer',
            artifactSha256: 'hash-v2-signed-baseline',
            isValid: false,
          },
        },
        {
          ...sampleSuite.traceLinks[0],
          id: 'trace-sig-2',
          signature: {
            id: 'sig-002',
            signedBy: 'Claire Dupont, PhD',
            role: 'VP Regulatory Affairs',
            artifactSha256: 'hash-v2-signed-baseline',
            isValid: false,
          },
        },
      ],
    };

    const report = ComplianceEngine.computeBlastRadius('srs-104', multiSigSuite);
    assert.ok(report.invalidatedSignatureIds.includes('sig-001'), 'Must invalidate primary clinical signature');
    assert.ok(report.invalidatedSignatureIds.includes('sig-002'), 'Must invalidate regulatory affairs signature');
    assert.strictEqual(report.invalidatedSignatureIds.length, 2);
  });

  test.it('traverses both specifications when two specs are connected to one hazard', () => {
    const twoSpecSuite = {
      ...sampleSuite,
      traceLinks: [
        {
          ...sampleSuite.traceLinks[0],
          id: 'trace-link-1',
          spec: {
            id: 'srs-104',
            title: 'SRS-104: Hardware Bolus Clamp',
            sha256Hash: 'hash-srs-104-drifted',
            lastSignedHash: 'hash-srs-104-baseline',
            isSignatureInvalidated: true,
            lastUpdated: '10m ago',
          },
        },
        {
          ...sampleSuite.traceLinks[0],
          id: 'trace-link-2',
          spec: {
            id: 'srs-105',
            title: 'SRS-105: Secondary Watchdog Timer',
            sha256Hash: 'hash-srs-105-drifted',
            lastSignedHash: 'hash-srs-105-baseline',
            isSignatureInvalidated: true,
            lastUpdated: '5m ago',
          },
          work: {
            id: 'med-43',
            key: 'MED-43',
            title: 'Implement Watchdog Timer',
            status: 'In Progress',
            assignee: 'Alex Chen',
          },
          test: {
            id: 'test-89',
            testKey: 'TEST-89',
            title: 'Watchdog Timeout Test',
            testType: 'Integration Test',
            status: 'UNTESTED',
          },
        },
      ],
    };

    const report = ComplianceEngine.computeBlastRadius('haz-101', twoSpecSuite);
    assert.deepStrictEqual(report.affectedHazardKeys, ['HAZ-101']);
    // Both specs must have traversed to HAZ-101
    const mitigatesHops = report.traversalPath.filter((hop) => hop.edge === 'MITIGATES');
    assert.strictEqual(mitigatesHops.length, 2);
    assert.ok(mitigatesHops.some((h) => h.from.includes('SRS-104')));
    assert.ok(mitigatesHops.some((h) => h.from.includes('SRS-105')));
    assert.ok(report.blockedWorkItemKeys.includes('MED-42'));
    assert.ok(report.blockedWorkItemKeys.includes('MED-43'));
  });

  test.it('excludes disconnected nodes (HAZ-999) from the blast radius', () => {
    const disconnectedSuite = {
      ...sampleSuite,
      traceLinks: [
        sampleSuite.traceLinks[0],
        {
          id: 'trace-disconnected',
          complianceState: 'VERIFIED',
          violations: [],
          hazard: {
            id: 'haz-999',
            key: 'HAZ-999',
            title: 'Isolated Battery Indicator Flicker',
            riskClass: 'CLASS_A',
            severity: 'MINOR',
            probability: 'REMOTE',
            mitigationRequirementId: 'srs-999',
            status: 'MITIGATED',
          },
          spec: {
            id: 'srs-999',
            title: 'SRS-999: LED Status Indicator',
            version: 1,
            sha256Hash: 'unrelated-hash',
            lastSignedHash: 'unrelated-hash',
            isSignatureInvalidated: false,
            contentSnippet: 'LED blinks green',
            lastUpdated: '3 days ago',
          },
          work: {
            id: 'med-99',
            key: 'MED-99',
            title: 'LED driver firmware',
            status: 'Done',
            assignee: 'Jordan Lee',
          },
          test: {
            id: 'test-99',
            testKey: 'TEST-99',
            title: 'LED Blink Rate Test',
            testType: 'Unit Test',
            status: 'PASSED',
          },
          signature: {
            id: 'sig-999',
            signedBy: 'Jordan Lee',
            signedAt: '2026-10-10T10:00:00Z',
            role: 'Software Engineer',
            meaning: 'Verification Review',
            artifactSha256: 'unrelated-hash',
            isValid: true,
          },
        },
      ],
    };

    // Traversing srs-104 should only touch HAZ-101 and NOT disconnected HAZ-999
    const report1 = ComplianceEngine.computeBlastRadius('srs-104', disconnectedSuite);
    assert.strictEqual(report1.affectedHazardKeys.includes('HAZ-101'), true);
    assert.strictEqual(report1.affectedHazardKeys.includes('HAZ-999'), false);
    assert.strictEqual(report1.blockedWorkItemKeys.includes('MED-99'), false);

    // Querying an unknown / non-existent key returns clean zero-impact report
    const report2 = ComplianceEngine.computeBlastRadius('NON-EXISTENT-KEY', disconnectedSuite);
    assert.strictEqual(report2.affectedHazardKeys.length, 0);
    assert.strictEqual(report2.blockedWorkItemKeys.length, 0);
    assert.strictEqual(report2.impactSeverity, 'MINOR');
  });

  test.it('completes BFS traversal on 500-node synthetic graph benchmark in under 20ms', () => {
    // Construct 100 5-node trace links = 500 nodes
    const syntheticLinks = [];
    for (let i = 0; i < 100; i++) {
      syntheticLinks.push({
        id: `synth-link-${i}`,
        complianceState: i === 0 ? 'SAFETY_VIOLATION' : 'VERIFIED',
        violations: [],
        hazard: {
          id: `synth-haz-${i}`,
          key: `HAZ-SYNTH-${i}`,
          title: `Synthetic Hazard ${i}`,
          riskClass: i === 0 ? 'CLASS_C' : 'CLASS_A',
          severity: i === 0 ? 'CATASTROPHIC' : 'MINOR',
          probability: 'REMOTE',
          mitigationRequirementId: `srs-synth-${i}`,
          status: 'UNVERIFIED_RISK',
        },
        spec: {
          id: `srs-synth-${i}`,
          title: `SRS-SYNTH-${i}: Specification ${i}`,
          version: 1,
          sha256Hash: `hash-${i}`,
          lastSignedHash: `hash-${i}`,
          isSignatureInvalidated: i === 0,
          contentSnippet: `Specification content ${i}`,
          lastUpdated: '1m ago',
        },
        work: {
          id: `med-synth-${i}`,
          key: `MED-SYNTH-${i}`,
          title: `Task ${i}`,
          status: 'In Progress',
          assignee: `Engineer ${i}`,
        },
        test: {
          id: `test-synth-${i}`,
          testKey: `TEST-SYNTH-${i}`,
          title: `Test ${i}`,
          testType: 'Unit Test',
          status: i === 0 ? 'UNTESTED' : 'PASSED',
        },
        signature: {
          id: `sig-synth-${i}`,
          signedBy: `Auditor ${i}`,
          signedAt: new Date().toISOString(),
          role: 'Auditor',
          meaning: 'Approval',
          artifactSha256: `hash-${i}`,
          isValid: i !== 0,
        },
      });
    }

    const largeSuite = {
      projectName: 'Large Benchmark Suite (500 Nodes)',
      standards: ['IEC 62304', 'ISO 14971'],
      totalHazards: 100,
      classCCount: 1,
      classBCount: 0,
      classACount: 99,
      verifiedPercentage: 99,
      releaseBlocked: true,
      blockingReasons: [],
      signatureDriftCount: 1,
      lastAuditTimestamp: new Date().toISOString(),
      traceLinks: syntheticLinks,
    };

    const start = performance.now();
    const report = ComplianceEngine.computeBlastRadius('srs-synth-0', largeSuite);
    const totalTimeMs = performance.now() - start;

    assert.ok(report);
    assert.strictEqual(report.affectedHazardKeys.includes('HAZ-SYNTH-0'), true);
    assert.ok(totalTimeMs < 20, `500-node graph traversal took ${totalTimeMs.toFixed(2)}ms, exceeding 20ms ceiling`);
    assert.ok(report.executionTimeMs < 20, `Report internal timer ${report.executionTimeMs}ms exceeds 20ms`);
  });

  test.it('returns empty zero-impact BlastRadiusReport when the trigger is empty or whitespace', () => {
    const secondLink = {
      id: 'trace-second',
      complianceState: 'VERIFIED',
      violations: [],
      hazard: { ...sampleSuite.traceLinks[0].hazard, id: 'haz-999', key: 'HAZ-999' },
      spec: { ...sampleSuite.traceLinks[0].spec, id: 'srs-999', title: 'SRS-999: Unrelated' },
      work: { ...sampleSuite.traceLinks[0].work, id: 'med-777', key: 'MED-777' },
      test: { ...sampleSuite.traceLinks[0].test, id: 'test-777', testKey: 'TEST-777' },
      signature: { ...sampleSuite.traceLinks[0].signature, id: 'sig-777' },
    };
    const twoLinks = { ...sampleSuite, traceLinks: [sampleSuite.traceLinks[0], secondLink] };
    for (const trigger of ['', '   ']) {
      const report = ComplianceEngine.computeBlastRadius(trigger, twoLinks);
      assert.strictEqual(report.triggerArtifact.title, 'No Trigger Artifact Specified');
      assert.strictEqual(report.impactSeverity, 'MINOR');
      assert.deepStrictEqual(report.affectedHazardKeys, []);
      assert.deepStrictEqual(report.blockedWorkItemKeys, []);
      assert.deepStrictEqual(report.invalidatedTestKeys, []);
      assert.deepStrictEqual(report.invalidatedSignatureIds, []);
      assert.deepStrictEqual(report.traversalPath, []);
    }
  });

  test.it('propagates blast radius transitively to sibling links sharing the hazard node', () => {
    const linkA = { ...sampleSuite.traceLinks[0], id: 'trace-A' };
    const linkB = {
      id: 'trace-B',
      complianceState: 'VERIFIED',
      violations: [],
      hazard: { ...sampleSuite.traceLinks[0].hazard, mitigationRequirementId: 'srs-105' },
      spec: {
        id: 'srs-105',
        title: 'SRS-105: Secondary Watchdog Timer',
        version: 1,
        sha256Hash: 'hash-b-current-content',
        lastSignedHash: 'hash-b-current-content',
        isSignatureInvalidated: false,
        contentSnippet: 'Watchdog clause',
        lastUpdated: '1 day ago',
      },
      work: { id: 'med-43', key: 'MED-43', title: 'Watchdog Timer Task', status: 'Done', assignee: 'K. Patel' },
      test: { id: 'test-89', testKey: 'TEST-89', title: 'Watchdog Timeout Test', testType: 'Unit Test', status: 'PASSED' },
      signature: {
        id: 'sig-002',
        signedBy: 'R. Adams',
        signedAt: '2026-10-20T00:00:00Z',
        role: 'QA Director',
        meaning: 'Approval',
        artifactSha256: 'hash-b-current-content',
        isValid: true,
      },
    };

    const report = ComplianceEngine.computeBlastRadius('srs-104', { ...sampleSuite, traceLinks: [linkA, linkB] });

    assert.deepStrictEqual(report.affectedHazardKeys, ['HAZ-101']);
    assert.deepStrictEqual(report.blockedWorkItemKeys, ['MED-42', 'MED-43']);
    assert.deepStrictEqual(report.invalidatedTestKeys, ['TEST-88', 'TEST-89']);
    assert.deepStrictEqual(report.invalidatedSignatureIds, ['sig-001']);
    assert.strictEqual(report.traversalPath.length, 8, 'Expected 4 hops on link A + 4 hops on sibling link B including valid SIGNS hop');
    assert.ok(report.traversalPath.some((h) => h.edge === 'MITIGATES' && h.from.includes('SRS-105')), 'Sibling spec must appear as its own MITIGATES hop');
    assert.ok(report.traversalPath.some((h) => h.edge === 'SIGNS' && h.to.includes('R. Adams')), 'Valid sibling SIGNS hop must be included');
  });
});

// ============================================================================
// Comprehensive Wave 2 Test Suites (Invariants, Audit Chain, KVS Sharding,
// Live Ingestion, TWG, Resolvers + RBAC, Webtrigger/NonceStore, Stdio MCP)
// ============================================================================

const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const forgeApi = require('@forge/api');
const forgeKvs = require('@forge/kvs');
const {
  AuditLogService,
  AUDIT_GENESIS_HASH,
  computeAuditEntryHash,
  createInMemoryAuditStorageAdapter,
  setAuditStorageAdapter,
  resetInMemoryAuditStorage,
} = require('../dist/audit-log');
const { LiveIngestionService } = require('../dist/ingestion');
const { TeamworkGraphService } = require('../dist/teamwork-graph');
const { kvsNonceStore, toKvsNonceKey } = require('../dist/nonce-store');
const { resolverHandler, confluencePageUpdatedTrigger } = require('../dist/index');

function createMockForgeKvs(seed = {}) {
  const store = new Map(Object.entries(seed));
  return {
    store,
    get: async (key) => store.get(key),
    set: async (key, val, opts) => {
      if (opts && opts.keyPolicy === 'FAIL_IF_EXISTS' && store.has(key)) {
        const err = new Error('Key already exists');
        err.status = 409;
        err.code = 'KEY_ALREADY_EXISTS';
        throw err;
      }
      store.set(key, JSON.parse(JSON.stringify(val)));
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
          successfulKeys.push({ key: item.key, value: store.get(item.key) });
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
    if (kvsMock.batchDelete) forgeKvs.kvs.batchDelete = kvsMock.batchDelete;
    if (kvsMock.transact) forgeKvs.kvs.transact = kvsMock.transact;
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

function makeJsonResponse(status, data) {
  return {
    status,
    json: async () => data,
    text: async () => JSON.stringify(data),
  };
}

test.describe('ComplianceEngine - Extended Invariants, Gate Parity & Exact Blast Radius', () => {
  const baseHazard = {
    id: 'haz-101',
    key: 'HAZ-101',
    title: 'Over-Infusion Hazard',
    riskClass: 'CLASS_C',
    severity: 'CATASTROPHIC',
    probability: 'OCCASIONAL',
    mitigationRequirementId: 'srs-104',
    status: 'UNVERIFIED_RISK',
  };
  const baseSpec = {
    id: 'srs-104',
    title: 'SRS-104: Hardware Bolus Clamp',
    version: 3,
    sha256Hash: 'a'.repeat(64),
    lastSignedHash: 'a'.repeat(64),
    isSignatureInvalidated: false,
    contentSnippet: 'Clamp',
    lastUpdated: 'now',
  };
  const baseWork = {
    id: 'med-42',
    key: 'MED-42',
    title: 'Implement Hardware Clamp',
    status: 'Done',
    assignee: 'Dr. Sarah Lin',
  };
  const baseTest = {
    id: 'test-88',
    testKey: 'TEST-88',
    title: 'Motor Stress Test',
    testType: 'Automated HIL (Hardware-in-Loop)',
    status: 'PASSED',
  };
  const baseSig = {
    id: 'sig-001',
    signedBy: 'Marcus Vance, MD',
    signedAt: '2026-10-15T11:30:00Z',
    role: 'Clinical Safety Authority',
    meaning: 'Approval',
    artifactSha256: 'a'.repeat(64),
    isValid: true,
  };

  test.it('counts signatureDriftCount even when SAFETY_VIOLATION takes precedence on complianceState', () => {
    const driftedSpec = { ...baseSpec, sha256Hash: 'b'.repeat(64), isSignatureInvalidated: true };
    const untested = { ...baseTest, status: 'UNTESTED' };
    const link = ComplianceEngine.evaluateTraceLink(baseHazard, driftedSpec, baseWork, untested, baseSig);
    assert.strictEqual(link.complianceState, 'SAFETY_VIOLATION');

    const report = ComplianceEngine.generateComplianceReport([link], 'LIVE', 'Pump v2', {
      storageFormat: 'SHARDED_V2',
      auditEntryCount: 5,
      auditHeadHash: 'c'.repeat(64),
    });
    assert.strictEqual(report.signatureDriftCount, 1);
    assert.strictEqual(report.storageFormat, 'SHARDED_V2');
    assert.strictEqual(report.auditEntryCount, 5);
    assert.strictEqual(report.auditHeadHash, 'c'.repeat(64));
  });

  test.it('flags SIGNATURE_DRIFT when signature.isValid is false or signer attestation fields are missing', () => {
    const invalidFlag = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, {
      ...baseSig,
      isValid: false,
    });
    assert.strictEqual(invalidFlag.complianceState, 'SIGNATURE_DRIFT');
    assert.match(invalidFlag.violations[0], /21 CFR Part 11 Violation/);

    const missingSigner = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, {
      ...baseSig,
      signedBy: '   ',
    });
    assert.strictEqual(missingSigner.complianceState, 'SIGNATURE_DRIFT');

    const missingTimestamp = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, {
      ...baseSig,
      signedAt: '',
    });
    assert.strictEqual(missingTimestamp.complianceState, 'SIGNATURE_DRIFT');
  });

  test.it('flags CLASS_A FAILED test and missing work.key as INCOMPLETE', () => {
    const classAHazard = { ...baseHazard, key: 'HAZ-103', riskClass: 'CLASS_A', severity: 'MINOR' };
    const failedTest = { ...baseTest, testKey: 'TEST-90', status: 'FAILED' };
    const failedLink = ComplianceEngine.evaluateTraceLink(classAHazard, baseSpec, baseWork, failedTest, baseSig);
    assert.strictEqual(failedLink.complianceState, 'INCOMPLETE');
    assert.match(failedLink.violations[0], /Class A Hazard \[HAZ-103\] verification test \[TEST-90\] FAILED/);

    const missingWorkLink = ComplianceEngine.evaluateTraceLink(classAHazard, baseSpec, { ...baseWork, key: '' }, baseTest, baseSig);
    assert.strictEqual(missingWorkLink.complianceState, 'INCOMPLETE');
    assert.match(missingWorkLink.violations[0], /lacks a linked Jira implementation work item/);
  });

  test.it('enforces identical evaluateIssueReleaseGate policy across workflowValidatorHandler and webtrigger verify-release-gate', async () => {
    const secret = 'parity-secret-123';
    process.env.MEDTRACE_MCP_SECRET = secret;
    setNonceStore(createInMemoryNonceStore());
    const originalGet = SeederService.getActiveComplianceSuite;
    SeederService.getActiveComplianceSuite = async () => ({
      projectName: 'Parity Suite',
      datasetMode: 'LIVE',
      standards: [],
      totalHazards: 2,
      classCCount: 1,
      classBCount: 0,
      classACount: 1,
      verifiedPercentage: 50,
      releaseBlocked: true,
      blockingReasons: ['IEC 62304 Critical Gap: HAZ-101 unverified'],
      signatureDriftCount: 0,
      lastAuditTimestamp: new Date().toISOString(),
      traceLinks: [
        {
          id: 't1',
          hazard: { key: 'HAZ-101' },
          work: { key: 'MED-42' },
          complianceState: 'SAFETY_VIOLATION',
          violations: ['IEC 62304 Critical Gap: HAZ-101 unverified'],
        },
        {
          id: 't2',
          hazard: { key: 'HAZ-103' },
          work: { key: 'MED-44' },
          complianceState: 'VERIFIED',
          violations: [],
        },
      ],
    });

    try {
      for (const issueKey of ['MED-42', 'MED-44', 'DOCS-99', undefined]) {
        const wfOutcome = await workflowValidatorHandler(issueKey ? { issue: { key: issueKey } } : {});
        const ts = Date.now().toString();
        const nonce = 'parity-' + crypto.randomUUID();
        const body = JSON.stringify(issueKey ? { action: 'verify-release-gate', issueKey } : { action: 'verify-release-gate' });
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
        assert.strictEqual(webOutcome.result, wfOutcome.result, `Mismatch for issueKey=${issueKey}`);
        assert.strictEqual(webResp.statusCode, wfOutcome.result ? 200 : 403);
      }
    } finally {
      SeederService.getActiveComplianceSuite = originalGet;
    }
  });

  test.it('computeBlastRadius avoids substring false positives, detects WORK/TEST/SIGNATURE triggers, and preserves clean links', () => {
    const cleanLink = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, baseSig);
    const suite = ComplianceEngine.generateComplianceReport([cleanLink], 'LIVE', 'Clean Pump');

    // Short numeric substring "10" must NOT match "SRS-104"
    const nonMatch = ComplianceEngine.computeBlastRadius('10', suite);
    assert.strictEqual(nonMatch.affectedHazardKeys.length, 0);

    // WORK, TEST, and SIGNATURE trigger types
    const workBlast = ComplianceEngine.computeBlastRadius('MED-42', suite);
    assert.strictEqual(workBlast.triggerArtifact.type, 'WORK');
    assert.deepStrictEqual(workBlast.blockedWorkItemKeys, [], 'Verified Done work item without drift must not be blocked');
    assert.deepStrictEqual(workBlast.invalidatedTestKeys, [], 'Passed test without drift must not be invalidated');

    const testBlast = ComplianceEngine.computeBlastRadius('TEST-88', suite);
    assert.strictEqual(testBlast.triggerArtifact.type, 'TEST');

    const sigBlast = ComplianceEngine.computeBlastRadius('sig-001', suite);
    assert.strictEqual(sigBlast.triggerArtifact.type, 'SIGNATURE');
    assert.deepStrictEqual(sigBlast.affectedHazardKeys, ['HAZ-101']);
  });
});

test.describe('AuditLogService - Append-Only Immutability & SHA-256 Chain Verification', () => {
  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
  });

  test.afterEach(() => {
    setAuditStorageAdapter(null);
    resetInMemoryAuditStorage();
  });

  test.it('links entries with prevHash -> entryHash and verifies intact chain', async () => {
    const e1 = await AuditLogService.append({
      actorAccountId: 'acc-1',
      action: 'SEED_DEMO',
      targetKey: 'DEMO_SUITE',
      details: { b: 2, a: 1 },
      authMethod: 'FORGE_USER_SESSION',
      timestamp: '2026-11-12T00:00:00.000Z',
    });
    const e2 = await AuditLogService.append({
      actorAccountId: 'acc-2',
      action: 'RECORD_TEST_RESULT',
      targetKey: 'TEST-88',
      details: { status: 'PASSED' },
      authMethod: 'FORGE_USER_SESSION',
      timestamp: '2026-11-12T00:01:00.000Z',
    });

    assert.strictEqual(e1.seq, 1);
    assert.strictEqual(e1.prevHash, AUDIT_GENESIS_HASH);
    assert.strictEqual(e2.seq, 2);
    assert.strictEqual(e2.prevHash, e1.entryHash);
    assert.strictEqual(
      computeAuditEntryHash({ ...e1, details: { a: 1, b: 2 } }),
      e1.entryHash,
      'Canonical key sorting must yield identical SHA-256'
    );

    const log = await AuditLogService.getAuditLog(10);
    assert.strictEqual(log.length, 2);
    assert.strictEqual(log[0].seq, 1);
    assert.strictEqual(log[1].seq, 2);

    const verification = await AuditLogService.verifyAuditChain();
    assert.strictEqual(verification.valid, true);
    assert.strictEqual(verification.totalEntries, 2);
    assert.strictEqual(verification.headHash, e2.entryHash);
  });

  test.it('retries concurrency collision when FAIL_IF_EXISTS returns EXISTS and detects payload tampering', async () => {
    const backing = createInMemoryAuditStorageAdapter();
    let forcedCollision = true;
    let tamperSeq1 = false;
    const collidingAdapter = {
      getHead: () => backing.getHead(),
      setHead: (h) => backing.setHead(h),
      getEntry: async (seq) => {
        const entry = await backing.getEntry(seq);
        if (tamperSeq1 && seq === 1 && entry) {
          return { ...entry, details: { tampered: true } };
        }
        return entry;
      },
      createEntryImmutable: async (seq, entry) => {
        if (forcedCollision && seq === 1) {
          forcedCollision = false;
          await backing.createEntryImmutable(1, {
            ...entry,
            actorAccountId: 'concurrent-actor',
            entryHash: computeAuditEntryHash({ ...entry, actorAccountId: 'concurrent-actor' }),
          });
          return 'EXISTS';
        }
        return backing.createEntryImmutable(seq, entry);
      },
    };
    setAuditStorageAdapter(collidingAdapter);

    const appended = await AuditLogService.append({
      actorAccountId: 'acc-retry',
      action: 'BIND_ISSUE',
      targetKey: 'HAZ-101',
      details: { issueKey: 'MED-99' },
      authMethod: 'FORGE_USER_SESSION',
    });
    assert.strictEqual(appended.seq, 2, 'Concurrent EXISTS on seq 1 must advance safely to seq 2');

    const okCheck = await AuditLogService.verifyAuditChain();
    assert.strictEqual(okCheck.valid, true);
    assert.strictEqual(okCheck.totalEntries, 2);

    // Tamper with entry 1 payload on storage read
    tamperSeq1 = true;
    const broken = await AuditLogService.verifyAuditChain();
    assert.strictEqual(broken.valid, false);
    assert.strictEqual(broken.brokenAtSeq, 1);
    assert.match(broken.reason, /Tampered payload at seq 1/);
  });
});

test.describe('SeederService - Sharded KVS Persistence, Test Recording, Part 11 Sign-off & Simulation Guard', () => {
  const { PART11_ATTESTATION_PHRASE } = require('../dist/types');
  const origSecret = process.env.MEDTRACE_PART11_SECRET;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState();
    process.env.MEDTRACE_PART11_SECRET = 'compliance-test-part11-secret';
  });

  test.afterEach(() => {
    SeederService.resetInMemoryState();
    if (origSecret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
    else process.env.MEDTRACE_PART11_SECRET = origSecret;
  });

  test.it('persists sharded KVS suite_meta + link:* keys, detects optimistic version conflicts, and propagates batchSet errors', async () => {
    const kvsMock = createMockForgeKvs();
    await withForgeMocks({ kvsMock }, async () => {
      const seeded = await SeederService.seedEnterpriseDemoSuite('acc-admin', 'FORGE_USER_SESSION');
      assert.strictEqual(seeded.summary.storageFormat, 'SHARDED_V2');
      assert.ok(kvsMock.store.has('medtrace:compliance:suite_meta'));
      assert.ok(kvsMock.store.has('medtrace:compliance:link:trace-HAZ-101--srs-104--MED-42'));
      assert.ok(kvsMock.store.has('medtrace:audit:entry:1'));

      const loaded = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(loaded.traceLinks.length, 3);
      assert.strictEqual(loaded.storageFormat, 'SHARDED_V2');

      // Optimistic version mismatch must throw loudly
      await assert.rejects(
        () => SeederService.saveComplianceSuite(loaded, 999),
        /Concurrent modification detected/
      );

      // Failed batchSet keys must propagate inside Forge runtime (> 25 op chunked path)
      const largeLinks = Array.from({ length: 26 }, (_, i) => ({
        ...loaded.traceLinks[0],
        id: `trace-HAZ-${1000 + i}--srs-104--MED-${1000 + i}`,
        hazard: { ...loaded.traceLinks[0].hazard, id: `haz-${1000 + i}`, key: `HAZ-${1000 + i}` },
        work: { ...loaded.traceLinks[0].work, id: `med-${1000 + i}`, key: `MED-${1000 + i}` },
      }));
      const largeSuite = { ...loaded, traceLinks: largeLinks, totalHazards: largeLinks.length };
      forgeKvs.kvs.batchSet = async (items) => ({
        successfulKeys: [],
        failedKeys: [{ key: items[0].key, error: { code: 'QUOTA_EXCEEDED' } }],
      });
      await assert.rejects(
        () => SeederService.saveComplianceSuite(largeSuite),
        /Failed to persist compliance shards to Forge KVS/
      );
    });
  });

  test.it('supports bindIssueToHazard, recordTestResult, and signOffPart11 while enforcing Part 11 attestation & LIVE simulation guard', async () => {
    await SeederService.seedEnterpriseDemoSuite('acc-init', 'SYSTEM_INIT');

    // Invalid issue key rejected
    await assert.rejects(
      () => SeederService.bindIssueToHazard('HAZ-101', 'bad-key', 'acc-1'),
      /Invalid Jira issue key format/
    );

    const bound = await SeederService.bindIssueToHazard('HAZ-101', 'MED-101', 'acc-1');
    assert.strictEqual(bound.traceLinks.find((l) => l.hazard.key === 'HAZ-101').work.key, 'MED-101');

    // Transition MED-101 to Done so test pass leaves SIGNATURE_DRIFT and Part 11 signoff produces VERIFIED
    bound.traceLinks[0].work.status = 'Done';
    await SeederService.saveComplianceSuite(bound, 2);

    // Record test execution result
    const tested = await SeederService.recordTestResult({
      hazardKey: 'HAZ-101',
      status: 'PASSED',
      evidenceUrl: 'https://ci.example.internal/hil/101',
      notes: 'HIL chamber pass',
      actorAccountId: 'qa-engineer-1',
    });
    const haz101AfterTest = tested.traceLinks.find((l) => l.hazard.key === 'HAZ-101');
    assert.strictEqual(haz101AfterTest.test.status, 'PASSED');
    assert.strictEqual(haz101AfterTest.test.recordedBy, 'qa-engineer-1');
    assert.strictEqual(haz101AfterTest.complianceState, 'SIGNATURE_DRIFT', 'Still requires Part 11 re-signoff after test pass');

    // Part 11 sign-off validation guards
    await assert.rejects(
      () =>
        SeederService.signOffPart11({
          hazardKey: 'HAZ-101',
          attestation: {
            meaning: 'Approved',
            attestationConfirmed: false,
            passwordConfirmed: true,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
          },
          actorAccountId: 'cmo-1',
        }),
      /attestationConfirmed: true/
    );
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
          actorAccountId: 'cmo-1',
        }),
      /meaning/
    );

    // Valid Part 11 sign-off turns HAZ-101 VERIFIED and binds identity server-side
    const signed = await SeederService.signOffPart11({
      hazardKey: 'HAZ-101',
      attestation: {
        meaning: 'Clinical Safety Approval for v3 Bolus Clamp',
        attestationConfirmed: true,
        passwordConfirmed: true,
        attestationPhrase: PART11_ATTESTATION_PHRASE,
        signedBy: 'Spoofed Display Name',
        role: 'Spoofed Role',
      },
      actorAccountId: 'cmo-1',
    });
    const haz101Signed = signed.traceLinks.find((l) => l.hazard.key === 'HAZ-101');
    assert.strictEqual(haz101Signed.complianceState, 'VERIFIED');
    assert.strictEqual(haz101Signed.signature.isValid, true);
    assert.strictEqual(haz101Signed.signature.signedBy, 'accountId:cmo-1');
    assert.strictEqual(haz101Signed.signature.signedByAccountId, 'cmo-1');
    assert.strictEqual(signed.releaseBlocked, false);

    // Demo quick-remediate requires explicit consent and rejects LIVE mode
    await SeederService.seedEnterpriseDemoSuite('acc-init', 'SYSTEM_INIT');
    await assert.rejects(
      () => SeederService.remediateClassCGap('HAZ-101', 'acc-1', { simulate: false, attestationConfirmed: true }),
      /Explicit simulation consent/
    );
    const simulated = await SeederService.remediateClassCGap('HAZ-101', 'acc-1', {
      simulate: true,
      attestationConfirmed: true,
    });
    assert.strictEqual(simulated.releaseBlocked, false);
    const simLink = simulated.traceLinks.find((l) => l.hazard.key === 'HAZ-101');
    assert.ok(!String(simLink.test.executionDate || '').includes('120/120 Passed'));

    // Save as LIVE mode -> remediateClassCGap must reject
    await SeederService.saveComplianceSuite({ ...simulated, datasetMode: 'LIVE', initialized: true });
    await assert.rejects(
      () =>
        SeederService.remediateClassCGap('HAZ-101', 'acc-1', {
          simulate: true,
          attestationConfirmed: true,
        }),
      /disabled in LIVE dataset mode/
    );
  });
});

test.describe('LiveIngestionService & TeamworkGraphService - Mocked Atlassian Cloud & Drift Triggers', () => {
  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
  });

  test.it('syncFromAtlassian rejects non-Forge execution and ingests Jira + Confluence pages with SHA-256 drift detection in Forge runtime', async () => {
    await assert.rejects(() => LiveIngestionService.syncFromAtlassian(), /requires an active Atlassian Forge runtime/);

    const approvedBody = '<p>Clause 4.2.1: Max bolus 5.0 mL/hr</p>';
    const modifiedBody = '<p>Clause 4.2.1: Max bolus 6.0 mL/hr</p>';
    const approvedHash = crypto.createHash('sha256').update(approvedBody).digest('hex');

    const kvsMock = createMockForgeKvs({
      'medtrace:compliance:signed_spec:55001': {
        specId: 'srs-55001',
        pageId: '55001',
        sha256Hash: approvedHash,
        signedBy: 'Dr. Vance',
        signedAt: '2026-11-01T00:00:00Z',
        role: 'CMO',
        meaning: 'Approved SRS',
        authMethod: 'PART11_ATTESTATION',
      },
    });

    const mockApiClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, {
            issues: [
              {
                id: '10050',
                key: 'PUMP-10',
                fields: {
                  summary: 'Implement Bolus Clamp Firmware',
                  status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
                  assignee: { displayName: 'Dr. Sarah Lin' },
                  labels: ['class-c'],
                  priority: { name: 'Highest' },
                  project: { name: 'Infusion Pump Production' },
                },
              },
            ],
          });
        }
        if (r.includes('/rest/api/3/issue/PUMP-10/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'appId=x&pageId=55001',
              object: { title: 'SRS-55001: Bolus Clamp', url: 'https://example.atlassian.net/wiki/pages/55001' },
            },
          ]);
        }
        if (r.includes('/rest/api/3/issue/PUMP-10')) {
          return makeJsonResponse(200, {
            id: '10050',
            key: 'PUMP-10',
            self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/10050',
            fields: {
              summary: 'Implement Bolus Clamp Firmware',
              status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
              issuelinks: [],
            },
          });
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages')) {
          return makeJsonResponse(200, {
            results: [
              {
                id: '55001',
                title: 'SRS-55001: Bolus Clamp',
                version: { number: 4, createdAt: '2026-11-12T10:00:00Z' },
                body: { storage: { value: modifiedBody } },
              },
            ],
          });
        }
        return makeJsonResponse(404, {});
      },
      requestGraph: async () =>
        makeJsonResponse(200, {
          data: {
            jira: {
              issue: {
                id: 'ari:cloud:jira:11111111-2222-3333-4444-555555555555:issue/10050',
                key: 'PUMP-10',
                summary: 'Implement Bolus Clamp Firmware',
                status: { name: 'In Progress', category: 'In Progress' },
                links: [],
              },
            },
          },
        }),
    });

    await withForgeMocks(
      {
        kvsMock,
        asAppImpl: mockApiClient,
        asUserImpl: mockApiClient,
        appContext: { installation: { contexts: [{ cloudId: '11111111-2222-3333-4444-555555555555' }] } },
      },
      async () => {
        const twg = await TeamworkGraphService.queryIssueGraphContext('PUMP-10');
        assert.strictEqual(twg.source, 'JIRA_AGG_AND_REST');
        assert.strictEqual(twg.confluenceLinks[0].pageId, '55001');

        const syncRes = await LiveIngestionService.syncFromAtlassian({ projectKey: 'PUMP' }, 'acc-sync');
        assert.strictEqual(syncRes.success, true);
        assert.strictEqual(syncRes.datasetMode, 'LIVE');
        assert.strictEqual(syncRes.jiraIssuesScanned, 1);
        assert.strictEqual(syncRes.confluencePagesScanned, 1);
        assert.strictEqual(syncRes.linkedPairsFound, 1);
        assert.strictEqual(syncRes.driftDetectedCount, 1);
        assert.strictEqual(syncRes.summary.signatureDriftCount, 1);
        assert.strictEqual(syncRes.summary.traceLinks[0].spec.isSignatureInvalidated, true);
      }
    );
  });

  test.it('TeamworkGraphService falls back to JIRA_REST when AGG fails and confluencePageUpdatedTrigger revokes drifted signatures', async () => {
    const kvsMock = createMockForgeKvs();
    const fallbackClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/remotelink')) return makeJsonResponse(200, []);
        return makeJsonResponse(200, {
          id: '10042',
          key: 'MED-42',
          self: 'https://api.atlassian.com/ex/jira/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/rest/api/3/issue/10042',
          fields: { summary: 'Clamp', status: { name: 'In Progress' }, issuelinks: [] },
        });
      },
      requestConfluence: async () =>
        makeJsonResponse(200, {
          id: '98304',
          title: 'SRS-105: Modified',
          version: { number: 9 },
          body: { storage: { value: '<p>Modified spec content</p>' } },
        }),
      requestGraph: async () => makeJsonResponse(500, { errors: [{ message: 'AGG down' }] }),
    });
    await withForgeMocks(
      {
        kvsMock,
        asAppImpl: fallbackClient,
        asUserImpl: fallbackClient,
        appContext: { installation: { contexts: [{ cloudId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' }] } },
      },
      async () => {
        const twgFallback = await TeamworkGraphService.queryIssueGraphContext('MED-42');
        assert.strictEqual(twgFallback.source, 'JIRA_REST');

        // Seed suite and link srs-105 to pageId 98304 so trigger matches it
        const seeded = await SeederService.seedEnterpriseDemoSuite('acc-init', 'SYSTEM_INIT');
        seeded.summary.traceLinks[1].spec.pageId = '98304';
        await SeederService.saveComplianceSuite(seeded.summary);

        const triggerRes = await confluencePageUpdatedTrigger({
          content: { id: '98304' },
          atlassianId: 'acc-conf-editor',
        });
        assert.strictEqual(triggerRes.processed, true);
        assert.deepStrictEqual(triggerRes.affectedHazards, ['HAZ-102']);

        const afterSuite = await SeederService.getActiveComplianceSuite();
        const haz102 = afterSuite.traceLinks.find((l) => l.hazard.key === 'HAZ-102');
        assert.strictEqual(haz102.spec.isSignatureInvalidated, true);
        assert.strictEqual(haz102.signature.isValid, false);
        assert.strictEqual(haz102.complianceState, 'SIGNATURE_DRIFT');
      }
    );
  });
});

test.describe('resolverHandler & RBAC Enforcement', () => {
  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
  });

  test.it('rejects unauthenticated callers and Jira/Confluence users lacking required permissions', async () => {
    await assert.rejects(
      () => resolverHandler({ call: { functionKey: 'seedDemoSuite', payload: {} }, context: {} }, {}),
      /Unauthorized: Authenticated Atlassian accountId is required/
    );

    const kvsMock = createMockForgeKvs();
    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async () =>
            makeJsonResponse(200, {
              permissions: {
                EDIT_ISSUES: { havePermission: false },
                ADMINISTER_PROJECTS: { havePermission: false },
              },
            }),
          requestConfluence: async () => makeJsonResponse(403, {}),
        }),
      },
      async () => {
        await assert.rejects(
          () =>
            resolverHandler(
              { call: { functionKey: 'remediateGap', payload: { hazardKey: 'HAZ-101' } }, context: {} },
              { principal: { accountId: 'readonly-user' } }
            ),
          /Forbidden: Requires Jira EDIT_ISSUES or ADMINISTER_PROJECTS permission/
        );

        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'seedDemoSuite', payload: {} },
                context: { extension: { type: 'confluence:globalPage' } },
              },
              { principal: { accountId: 'conf-blocked-user' } }
            ),
          /Forbidden: Confluence user session lacks access/
        );
      }
    );
  });

  test.it('executes authorized resolvers end-to-end (seedDemoSuite, bindIssueToHazard, recordTestResult, signOffPart11, audit log & blast radius)', async () => {
    const { PART11_ATTESTATION_PHRASE } = require('../dist/types');
    const origSecret = process.env.MEDTRACE_PART11_SECRET;
    process.env.MEDTRACE_PART11_SECRET = 'resolver-e2e-part11-secret';
    SeederService.resetInMemoryState();
    try {
      const seeded = await resolverHandler(
        { call: { functionKey: 'seedDemoSuite', payload: {} }, context: {} },
        { principal: { accountId: 'operator-1' } }
      );
      assert.strictEqual(seeded.success, true);

      const bound = await resolverHandler(
        { call: { functionKey: 'bindIssueToHazard', payload: { hazardKey: 'HAZ-101', issueKey: 'MED-200' } }, context: {} },
        { principal: { accountId: 'operator-1' } }
      );
      assert.strictEqual(bound.success, true);

      const recorded = await resolverHandler(
        { call: { functionKey: 'recordTestResult', payload: { hazardKey: 'HAZ-101', status: 'PASSED' } }, context: {} },
        { principal: { accountId: 'operator-1' } }
      );
      assert.strictEqual(recorded.traceLinks[0].test.status, 'PASSED');

      // Non-Forge bindIssueToHazard does not query Jira; transition work.status -> Done before clinical release signoff
      recorded.traceLinks[0].work.status = 'Done';
      await SeederService.saveComplianceSuite(recorded);

      const signed = await resolverHandler(
        {
          call: {
            functionKey: 'signOffPart11',
            payload: {
              hazardKey: 'HAZ-101',
              meaning: 'Clinical safety release sign-off',
              attestationConfirmed: true,
              passwordConfirmed: true,
              attestationPhrase: PART11_ATTESTATION_PHRASE,
            },
          },
          context: {},
        },
        { principal: { accountId: 'operator-1' } }
      );
      assert.strictEqual(signed.releaseBlocked, false);

      const blast = await resolverHandler(
        { call: { functionKey: 'analyzeBlastRadius', payload: { triggerKey: 'srs-104' } }, context: {} },
        { principal: { accountId: 'operator-1' } }
      );
      assert.deepStrictEqual(blast.affectedHazardKeys, ['HAZ-101']);

      const auditEntries = await resolverHandler(
        { call: { functionKey: 'getAuditLog', payload: { limit: 10 } }, context: {} },
        { principal: { accountId: 'operator-1' } }
      );
      assert.ok(auditEntries.length >= 4);

      const verification = await resolverHandler(
        { call: { functionKey: 'verifyAuditChain', payload: {} }, context: {} },
        { principal: { accountId: 'operator-1' } }
      );
      assert.strictEqual(verification.valid, true);
    } finally {
      SeederService.resetInMemoryState();
      if (origSecret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
      else process.env.MEDTRACE_PART11_SECRET = origSecret;
    }
  });
});

test.describe('Webtrigger Hardening & kvsNonceStore Coverage', () => {
  const secret = 'webtrigger-hardening-secret';

  test.beforeEach(() => {
    process.env.MEDTRACE_MCP_SECRET = secret;
    setNonceStore(createInMemoryNonceStore());
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
  });

  function signHeaders(bodyStr, nonce = 'n-' + crypto.randomUUID(), ts = Date.now().toString()) {
    const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${bodyStr}`).digest('hex');
    return {
      'x-medtrace-timestamp': ts,
      'x-medtrace-nonce': nonce,
      'x-medtrace-signature': `sha256=${sig}`,
    };
  }

  test.it('returns HTTP 400 on malformed POST JSON and enforces non-spoofable service:mcp-webtrigger principal', async () => {
    const badBody = '{not-valid-json';
    const badResp = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signHeaders(badBody),
      body: badBody,
    });
    assert.strictEqual(badResp.statusCode, 400);
    assert.match(badResp.body, /Malformed JSON/);

    await SeederService.seedEnterpriseDemoSuite('acc-init', 'SYSTEM_INIT');
    const remBody = JSON.stringify({
      action: 'remediate',
      hazardKey: 'HAZ-101',
      simulate: true,
      attestationConfirmed: true,
      accountId: 'spoofed-admin-account',
    });
    const remResp = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signHeaders(remBody),
      body: remBody,
    });
    assert.strictEqual(remResp.statusCode, 200);
    const parsed = JSON.parse(remResp.body);
    const haz101 = parsed.summary.traceLinks.find((l) => l.hazard.key === 'HAZ-101');
    assert.strictEqual(haz101.signature.signedBy, 'service:mcp-webtrigger');

    const audit = await AuditLogService.getAuditLog(10);
    const lastEntry = audit[audit.length - 1];
    assert.strictEqual(lastEntry.actorAccountId, 'service:mcp-webtrigger');
  });

  test.it('toKvsNonceKey hashes arbitrary nonces and kvsNonceStore distinguishes REPLAY (409) from STORAGE_ERROR (500)', async () => {
    const hashedKey = toKvsNonceKey('nonce/with:unsafe chars?and=spaces!');
    assert.match(hashedKey, /^nonce:[0-9a-f]{64}$/);

    const kvsMock = createMockForgeKvs();
    setNonceStore(kvsNonceStore);

    await withForgeMocks({ kvsMock }, async () => {
      const first = await kvsNonceStore.claimDetailed('raw-nonce-1', { consumedAt: Date.now() }, 300_000);
      assert.strictEqual(first, 'CLAIMED');

      const replay = await kvsNonceStore.claimDetailed('raw-nonce-1', { consumedAt: Date.now() }, 300_000);
      assert.strictEqual(replay, 'REPLAY');

      // Simulate Forge KVS outage (non-conflict error)
      forgeKvs.kvs.set = async () => {
        throw new Error('KVS service unavailable');
      };
      const storageErr = await kvsNonceStore.claimDetailed('raw-nonce-2', { consumedAt: Date.now() }, 300_000);
      assert.strictEqual(storageErr, 'STORAGE_ERROR');

      const webOutageResp = await mcpWebtriggerHandler({
        method: 'GET',
        headers: signHeaders(''),
      });
      assert.strictEqual(webOutageResp.statusCode, 500);
      assert.match(webOutageResp.body, /Replay protection store unavailable/);
    });

    setNonceStore(createInMemoryNonceStore());
  });
});

test.describe('Task 1A-Engine: Compliance Rules, Cryptographic Seals, Blast Radius, McpToolService & Rovo Action Handler', () => {
  const baseHazard = {
    id: 'haz-201',
    key: 'HAZ-201',
    title: 'Class A Alert Lamp Hazard',
    riskClass: 'CLASS_A',
    severity: 'MINOR',
    probability: 'REMOTE',
    mitigationRequirementId: 'srs-201',
    status: 'UNVERIFIED_RISK',
  };
  const baseSpec = {
    id: 'srs-201',
    pageId: '55201',
    title: 'SRS-201: Alert Lamp Control',
    version: 2,
    sha256Hash: 'a'.repeat(64),
    lastSignedHash: 'a'.repeat(64),
    isSignatureInvalidated: false,
    contentSnippet: 'Alert lamp clause',
    lastUpdated: '2026-11-10T00:00:00Z',
  };
  const baseWork = {
    id: 'med-201',
    key: 'MED-201',
    title: 'Implement Alert Lamp Driver',
    status: 'Done',
    assignee: 'Alice QA',
  };
  const baseTest = {
    id: 'test-201',
    testKey: 'TEST-201',
    title: 'Alert Lamp Unit Test',
    testType: 'Unit Test',
    status: 'PASSED',
    executionDate: '2026-11-10T01:00:00Z',
    evidenceUrl: 'https://ci.example.internal/runs/201',
  };
  const baseSig = {
    id: 'sig-201',
    signedBy: 'Alice QA (acc-alice)',
    signedByAccountId: 'acc-alice',
    signedAt: '2026-11-10T02:00:00Z',
    role: 'Authorized Signatory',
    meaning: 'Release approval',
    artifactSha256: 'a'.repeat(64),
    isValid: true,
    authMethod: 'PART11_ATTESTATION',
  };

  test.it('enforces CLASS_A test status, CLASS_C missing SRS, work.status Done, evidenceUrl https://, and M:N trace link IDs', () => {
    for (const status of ['UNTESTED', 'IN_PROGRESS']) {
      const link = ComplianceEngine.evaluateTraceLink(
        baseHazard,
        baseSpec,
        baseWork,
        { ...baseTest, status },
        baseSig
      );
      assert.strictEqual(link.complianceState, 'INCOMPLETE', `CLASS_A ${status} test must be INCOMPLETE`);
    }

    const classCHazard = { ...baseHazard, key: 'HAZ-300', riskClass: 'CLASS_C', severity: 'CATASTROPHIC' };
    const missingSpecLink = ComplianceEngine.evaluateTraceLink(
      classCHazard,
      { ...baseSpec, title: '', isMissingSentinel: true },
      baseWork,
      baseTest,
      baseSig
    );
    assert.strictEqual(missingSpecLink.complianceState, 'SAFETY_VIOLATION');
    assert.match(missingSpecLink.violations[0], /ISO 14971 Violation/);

    const classCInProgressWork = ComplianceEngine.evaluateTraceLink(
      classCHazard,
      baseSpec,
      { ...baseWork, status: 'In Progress' },
      baseTest,
      baseSig
    );
    assert.strictEqual(classCInProgressWork.complianceState, 'SAFETY_VIOLATION');

    const classAUntestedWork = ComplianceEngine.evaluateTraceLink(
      baseHazard,
      baseSpec,
      { ...baseWork, status: 'Under Review' },
      baseTest,
      baseSig
    );
    assert.strictEqual(classAUntestedWork.complianceState, 'INCOMPLETE');

    const unsafeEvidence = ComplianceEngine.evaluateTraceLink(
      classCHazard,
      baseSpec,
      baseWork,
      { ...baseTest, evidenceUrl: 'javascript:alert(1)' },
      baseSig
    );
    assert.strictEqual(unsafeEvidence.complianceState, 'SAFETY_VIOLATION');
    assert.match(unsafeEvidence.violations[0], /evidenceUrl/i);

    const missingEvidence = ComplianceEngine.evaluateTraceLink(
      baseHazard,
      baseSpec,
      baseWork,
      { ...baseTest, evidenceUrl: undefined },
      baseSig,
      undefined,
      { requireTestEvidence: true }
    );
    assert.strictEqual(missingEvidence.complianceState, 'INCOMPLETE');
    assert.match(missingEvidence.violations[0], /evidenceUrl/);

    const id1 = ComplianceEngine.buildTraceLinkId('HAZ-101', 'srs-104', 'MED-42');
    const id2 = ComplianceEngine.buildTraceLinkId('HAZ-101', 'srs-105', 'MED-42');
    assert.notStrictEqual(id1, id2);
    assert.strictEqual(
      ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, baseSig).id,
      ComplianceEngine.buildTraceLinkId('HAZ-201', 'srs-201', 'MED-201')
    );
    assert.strictEqual(
      ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, baseSig, undefined, {
        linkId: 'custom-link-id',
      }).id,
      'custom-link-id'
    );

    assert.strictEqual(ComplianceEngine.deriveHazardStatus('VERIFIED'), 'MITIGATED');
    assert.strictEqual(ComplianceEngine.deriveHazardStatus('SAFETY_VIOLATION'), 'ACTION_REQUIRED');
    assert.strictEqual(ComplianceEngine.deriveHazardStatus('SIGNATURE_DRIFT'), 'ACTION_REQUIRED');
    assert.strictEqual(ComplianceEngine.deriveHazardStatus('INCOMPLETE'), 'UNVERIFIED_RISK');
  });

  test.it('computes and verifies Part 11 HMAC-SHA256 seals and detects tampering', () => {
    const secret = 'part11-unit-test-secret';
    assert.throws(() =>
      ComplianceEngine.computePart11Seal(
        {
          hazardKey: 'HAZ-201',
          specId: 'srs-201',
          artifactSha256: baseSig.artifactSha256,
          signedByAccountId: baseSig.signedByAccountId,
          signedBy: baseSig.signedBy,
          role: baseSig.role,
          meaning: baseSig.meaning,
          signedAt: baseSig.signedAt,
          authMethod: baseSig.authMethod,
        },
        ''
      )
    );

    const seal = ComplianceEngine.computePart11Seal(
      {
        hazardKey: 'HAZ-201',
        specId: 'srs-201',
        artifactSha256: baseSig.artifactSha256,
        signedByAccountId: baseSig.signedByAccountId,
        signedBy: baseSig.signedBy,
        role: baseSig.role,
        meaning: baseSig.meaning,
        signedAt: baseSig.signedAt,
        authMethod: baseSig.authMethod,
      },
      secret
    );
    const sealedSig = {
      ...baseSig,
      signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
      signatureSeal: seal,
    };

    assert.strictEqual(ComplianceEngine.verifyPart11Seal('HAZ-201', 'srs-201', sealedSig, secret), true);
    assert.strictEqual(ComplianceEngine.verifyPart11Seal('HAZ-201', 'srs-201', sealedSig, 'wrong-secret'), false);
    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal('HAZ-201', 'srs-201', { ...sealedSig, meaning: 'Tampered' }, secret),
      false
    );

    const verifiedSealed = ComplianceEngine.evaluateTraceLink(
      baseHazard,
      baseSpec,
      baseWork,
      baseTest,
      sealedSig,
      undefined,
      { part11Secret: secret, requireCryptographicSeal: true }
    );
    assert.strictEqual(verifiedSealed.complianceState, 'VERIFIED');

    const tamperedSealed = ComplianceEngine.evaluateTraceLink(
      baseHazard,
      baseSpec,
      baseWork,
      baseTest,
      { ...sealedSig, signedBy: 'Spoofed Signer' },
      undefined,
      { part11Secret: secret, requireCryptographicSeal: true }
    );
    assert.strictEqual(tamperedSealed.complianceState, 'SIGNATURE_DRIFT');
    assert.match(tamperedSealed.violations[0], /HMAC-SHA256/);
  });

  test.it('fails closed on empty/uninitialized suites in generateComplianceReport and evaluateIssueReleaseGate', () => {
    const emptyLive = ComplianceEngine.generateComplianceReport([], 'LIVE');
    assert.strictEqual(emptyLive.initialized, false);
    assert.strictEqual(emptyLive.releaseBlocked, true);
    assert.strictEqual(emptyLive.projectName, 'Atlassian Cloud Medical Project');
    assert.ok(emptyLive.blockingReasons.length > 0);

    const globalGate = ComplianceEngine.evaluateIssueReleaseGate(undefined, emptyLive);
    assert.strictEqual(globalGate.result, false);
    assert.match(globalGate.errorMessage, /uninitialized/i);

    const unrelatedIssueGate = ComplianceEngine.evaluateIssueReleaseGate('DOCS-10', emptyLive);
    assert.strictEqual(unrelatedIssueGate.result, false);

    const cleanLink = ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, baseSig);
    const initializedBlockedFalse = {
      ...ComplianceEngine.generateComplianceReport([cleanLink], 'LIVE', 'Test'),
      initialized: false,
    };
    assert.strictEqual(ComplianceEngine.evaluateIssueReleaseGate('MED-201', initializedBlockedFalse).result, false);
  });

  test.it('prevents specShortKey colon collisions, sibling tainting on shared work.key, and supports computeMultiBlastRadius', () => {
    const driftedLink = ComplianceEngine.evaluateTraceLink(
      { ...baseHazard, id: 'haz-c', key: 'HAZ-101', riskClass: 'CLASS_C', severity: 'CATASTROPHIC' },
      {
        ...baseSpec,
        id: 'srs-104',
        title: 'Overview: Bolus Clamp',
        sha256Hash: 'b'.repeat(64),
        isSignatureInvalidated: true,
      },
      { ...baseWork, id: 'med-42', key: 'MED-42', status: 'In Progress' },
      { ...baseTest, id: 'test-88', testKey: 'TEST-88', status: 'UNTESTED' },
      { ...baseSig, id: 'sig-001', artifactSha256: 'a'.repeat(64), isValid: false }
    );
    const cleanSiblingSharingWork = ComplianceEngine.evaluateTraceLink(
      { ...baseHazard, id: 'haz-202', key: 'HAZ-202', riskClass: 'CLASS_A', mitigationRequirementId: 'srs-202' },
      { ...baseSpec, id: 'srs-202', pageId: '55202', title: 'SRS-202: Watchdog Display' },
      { ...baseWork, id: 'med-42', key: 'MED-42', status: 'Done' },
      { ...baseTest, id: 'test-202', testKey: 'TEST-202', status: 'PASSED' },
      { ...baseSig, id: 'sig-202' }
    );
    const suite = ComplianceEngine.generateComplianceReport([driftedLink, cleanSiblingSharingWork], 'LIVE', 'Shared Work');

    // Colon collision guard: "Overview: Bolus Clamp" must NOT match triggerKey "Overview"
    const overviewBlast = ComplianceEngine.computeBlastRadius('Overview', suite);
    assert.deepStrictEqual(overviewBlast.affectedHazardKeys, []);

    // Sibling tainting guard: triggering drifted srs-104 must NOT taint clean srs-202 / HAZ-202 / TEST-202 / sig-202
    const srs104Blast = ComplianceEngine.computeBlastRadius('srs-104', suite);
    assert.ok(!srs104Blast.invalidatedTestKeys.includes('TEST-202'));
    assert.ok(!srs104Blast.invalidatedSignatureIds.includes('sig-202'));
    assert.ok(
      srs104Blast.traversalPath.some(
        (h) => h.edge === 'MITIGATES' && h.to.includes('HAZ-202') && h.effect.includes('Safety mitigation verified')
      ),
      'Clean sibling hazard sharing only work.key must remain verified'
    );

    // Multi-trigger blast radius across [cleanWork, dirtyWork]
    const cleanStandalone = ComplianceEngine.evaluateTraceLink(
      { ...baseHazard, id: 'haz-203', key: 'HAZ-203', mitigationRequirementId: 'srs-203' },
      { ...baseSpec, id: 'srs-203', pageId: '55203', title: 'SRS-203: Standalone' },
      { ...baseWork, id: 'med-43', key: 'MED-43', status: 'Done' },
      { ...baseTest, id: 'test-203', testKey: 'TEST-203', status: 'PASSED' },
      { ...baseSig, id: 'sig-203' }
    );
    const multiSuite = ComplianceEngine.generateComplianceReport([cleanStandalone, driftedLink], 'LIVE', 'Multi');
    const multiBlast = ComplianceEngine.computeMultiBlastRadius(['MED-43', 'MED-42'], multiSuite);
    assert.ok(multiBlast.affectedHazardKeys.includes('HAZ-203'));
    assert.ok(multiBlast.affectedHazardKeys.includes('HAZ-101'));
    assert.ok(multiBlast.blockedWorkItemKeys.includes('MED-42'));
    assert.ok(!multiBlast.blockedWorkItemKeys.includes('MED-43'));
  });

  test.it('McpToolService handles 9-field lookup, uninitialized fail-closed, multi-key diffs without contradiction, and LIVE keyword isolation', async () => {
    const originalGet = SeederService.getActiveComplianceSuite;
    try {
      // 1. Uninitialized suite fails closed
      SeederService.getActiveComplianceSuite = async () =>
        ComplianceEngine.generateComplianceReport([], 'LIVE', 'Atlassian Cloud (Uninitialized)', {
          initialized: false,
        });

      const uninitVerify = await McpToolService.verifyIecCompliance({ componentName: 'bolus clamp' });
      assert.strictEqual(uninitVerify.initialized, false);
      assert.strictEqual(uninitVerify.canShipToClinicalProduction, false);
      assert.strictEqual(uninitVerify.touchesSafetyCriticalCode, false);
      assert.match(uninitVerify.activeViolations[0], /uninitialized/i);

      const uninitLineage = await McpToolService.getHazardLineage({ hazardKey: 'HAZ-101' });
      assert.strictEqual(uninitLineage.found, false);
      assert.strictEqual(uninitLineage.initialized, false);
      assert.strictEqual(uninitLineage.datasetMode, 'LIVE');

      // 2. Multi-key diff ['MED-43', 'MED-42'] and LIVE keyword suppression
      const cleanLink = ComplianceEngine.evaluateTraceLink(
        { ...baseHazard, id: 'haz-43', key: 'HAZ-102', mitigationRequirementId: 'srs-202' },
        { ...baseSpec, id: 'srs-202', pageId: '55202', title: 'SRS-202: Clean Module' },
        { ...baseWork, id: 'med-43', key: 'MED-43', title: 'Clean Driver', status: 'Done' },
        { ...baseTest, id: 'test-89', testKey: 'TEST-89', status: 'PASSED' },
        { ...baseSig, id: 'sig-002' }
      );
      const blockedLink = ComplianceEngine.evaluateTraceLink(
        { ...baseHazard, id: 'haz-42', key: 'HAZ-101', riskClass: 'CLASS_C', severity: 'CATASTROPHIC', title: 'Rate Control' },
        { ...baseSpec, id: 'srs-104', pageId: '55104', title: 'SRS-104: Rate Limiter', contentSnippet: 'Rate limiter' },
        { ...baseWork, id: 'med-42', key: 'MED-42', title: 'Rate Implementation', status: 'In Progress' },
        { ...baseTest, id: 'test-88', testKey: 'TEST-88', status: 'UNTESTED' },
        { ...baseSig, id: 'sig-001' }
      );
      const sharedVerifiedLink = ComplianceEngine.evaluateTraceLink(
        { ...baseHazard, id: 'haz-200', key: 'HAZ-200', mitigationRequirementId: 'srs-200', title: 'Alarm Escalation' },
        { ...baseSpec, id: 'srs-200', pageId: '55200', title: 'SRS-200: Telemetry Check', contentSnippet: 'Telemetry check' },
        { ...baseWork, id: 'med-501', key: 'MED-501', title: 'Telemetry Module', status: 'Done' },
        { ...baseTest, id: 'test-501', testKey: 'TEST-501', status: 'PASSED' },
        { ...baseSig, id: 'sig-200' }
      );
      const sharedBlockedSibling = ComplianceEngine.evaluateTraceLink(
        { ...baseHazard, id: 'haz-200', key: 'HAZ-200', mitigationRequirementId: 'srs-201', title: 'Alarm Escalation' },
        { ...baseSpec, id: 'srs-201', pageId: '55201', title: 'SRS-201: Telemetry Redundancy', contentSnippet: 'Redundancy check' },
        { ...baseWork, id: 'med-502', key: 'MED-502', title: 'Telemetry Redundancy Task', status: 'In Progress' },
        { ...baseTest, id: 'test-502', testKey: 'TEST-502', status: 'UNTESTED' },
        { ...baseSig, id: 'sig-201' }
      );
      SeederService.getActiveComplianceSuite = async () =>
        ComplianceEngine.generateComplianceReport(
          [cleanLink, blockedLink, sharedVerifiedLink, sharedBlockedSibling],
          'LIVE',
          'Live Prod'
        );

      // 9-field lookup check (work.id, test.id, spec.pageId, signature.id)
      for (const q of ['med-43', 'test-89', '55202', 'sig-002']) {
        const res = await McpToolService.getHazardLineage({ issueKey: q });
        assert.strictEqual(res.found, true, `Expected 9-field lookup match for ${q}`);
        assert.strictEqual(res.datasetMode, 'LIVE');
        assert.strictEqual(res.initialized, true);
      }

      // Targeting a VERIFIED link sharing a hazard with an unverified sibling must still block when graphBlastRadius.blockedWorkItems is non-empty
      const sharedHazardRes = await McpToolService.verifyIecCompliance({
        prDiff: 'Touches MED-501 only',
      });
      assert.strictEqual(sharedHazardRes.touchesSafetyCriticalCode, true);
      assert.ok(sharedHazardRes.graphBlastRadius);
      assert.ok(sharedHazardRes.graphBlastRadius.blockedWorkItems.includes('MED-502'));
      assert.strictEqual(sharedHazardRes.canShipToClinicalProduction, false);
      assert.ok(
        !sharedHazardRes.remediationGuidance.some((g) => /no remediation required|All traversed artifacts are verified/i.test(g)),
        'Shared hazard sibling gap must never emit clean remediation guidance'
      );

      // Isolated VERIFIED link remains shippable despite unrelated blocked hazards in the suite
      const isolatedCleanRes = await McpToolService.verifyIecCompliance({
        prDiff: 'Touches MED-43 only',
      });
      assert.strictEqual(isolatedCleanRes.touchesSafetyCriticalCode, true);
      assert.deepStrictEqual(isolatedCleanRes.graphBlastRadius.blockedWorkItems, []);
      assert.strictEqual(isolatedCleanRes.canShipToClinicalProduction, true);

      // Multi-key diff with clean key first, blocked key second
      const multiDiffRes = await McpToolService.verifyIecCompliance({
        prDiff: 'Touches MED-43 and MED-42',
      });
      assert.strictEqual(multiDiffRes.canShipToClinicalProduction, false);
      assert.strictEqual(multiDiffRes.touchesSafetyCriticalCode, true);
      assert.ok(multiDiffRes.affectedHazards.some((h) => h.includes('HAZ-101')));
      assert.ok(
        !multiDiffRes.remediationGuidance.some((g) => /no remediation required|All traversed artifacts are verified/i.test(g)),
        'Must never emit contradictory clean guidance when blocking gaps exist'
      );

      // LIVE mode suppresses infusion-pump keyword fallbacks (bolus/clamp/motor/droplet/oled) and avoids substring matches ("generated" != "rate")
      const liveFallbackBlocked = await McpToolService.verifyIecCompliance({
        prDiff: 'generated bolus clamp motor flow pwm droplet sensor oled battery',
      });
      assert.strictEqual(liveFallbackBlocked.touchesSafetyCriticalCode, false);
    } finally {
      SeederService.getActiveComplianceSuite = originalGet;
    }
  });

  test.it('rovoActionHandler rejects unknown actions, empty accountId, and unauthorized Forge user read probes', async () => {
    const unknownRes = await rovoActionHandler({ actionKey: 'drop-database' });
    assert.match(unknownRes.error, /Unknown action/);
    assert.ok(Array.isArray(unknownRes.availableTools));

    const kvsMock = createMockForgeKvs();
    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async () =>
            makeJsonResponse(200, {
              permissions: { BROWSE_PROJECTS: { havePermission: false } },
            }),
          requestConfluence: async () => makeJsonResponse(403, {}),
        }),
      },
      async () => {
        const emptyAccountRes = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'get-hazard-lineage-action', accountId: '   ' }
        );
        assert.match(emptyAccountRes.error, /Unauthorized|Empty/i);

        const forbiddenJiraRes = await rovoActionHandler(
          { issueKey: 'MED-42' },
          { moduleKey: 'get-hazard-lineage-action', accountId: 'viewer-no-browse' }
        );
        assert.match(forbiddenJiraRes.error, /Forbidden/i);

        const forbiddenConfRes = await rovoActionHandler(
          { issueKey: 'MED-42' },
          {
            moduleKey: 'get-hazard-lineage-action',
            accountId: 'conf-blocked',
            extension: { type: 'confluence:globalPage' },
          }
        );
        assert.match(forbiddenConfRes.error, /Forbidden/i);
      }
    );

    const originalGet = SeederService.getActiveComplianceSuite;
    SeederService.getActiveComplianceSuite = async () =>
      ComplianceEngine.generateComplianceReport(
        [ComplianceEngine.evaluateTraceLink(baseHazard, baseSpec, baseWork, baseTest, baseSig)],
        'LIVE',
        'Live Prod'
      );
    try {
      await withForgeMocks(
        {
          kvsMock,
          asUserImpl: () => ({
            requestJira: async () =>
              makeJsonResponse(200, {
                permissions: { BROWSE_PROJECTS: { havePermission: true } },
              }),
            requestConfluence: async () => makeJsonResponse(200, { accountId: 'acc-ok' }),
          }),
        },
        async () => {
          const okRes = await rovoActionHandler(
            { issueKey: 'MED-201' },
            { moduleKey: 'get-hazard-lineage-action', accountId: 'acc-ok' }
          );
          assert.strictEqual(okRes.found, true);
          assert.strictEqual(okRes.hazard.key, 'HAZ-201');
        }
      );
    } finally {
      SeederService.getActiveComplianceSuite = originalGet;
    }
  });
});

test.describe('ComplianceEngine - Part 11 Key-Ring Rotation & Fast-Path Gate Compatibility', () => {
  const sampleHazard = {
    id: 'haz-rot-1',
    key: 'HAZ-501',
    title: 'Key Rotation Hazard',
    riskClass: 'CLASS_C',
    severity: 'CRITICAL',
    probability: 'REMOTE',
    mitigationRequirementId: 'srs-rot-1',
    status: 'VERIFIED',
  };

  const sampleSpec = {
    id: 'srs-rot-1',
    title: 'SRS-501: Key Rotation Spec',
    version: 1,
    sha256Hash: 'a'.repeat(64),
    lastSignedHash: 'a'.repeat(64),
    isSignatureInvalidated: false,
    contentSnippet: 'Spec content',
    lastUpdated: '2026-11-15T00:00:00Z',
  };

  const sampleWork = {
    id: 'work-rot-1',
    key: 'MED-501',
    title: 'Implement Spec',
    status: 'Done',
    assignee: 'Eng 1',
  };

  const sampleTest = {
    id: 'test-rot-1',
    testKey: 'TEST-501',
    status: 'PASSED',
    evidenceUrl: 'https://ci.example.com/run/501',
    executionDate: '2026-11-15T00:00:00Z',
  };

  test.it('rotates MEDTRACE_PART11_SECRET via MEDTRACE_PART11_PREVIOUS_SECRETS without rejecting valid historical seals', () => {
    const oldSecret = 'retired-part11-secret-v1';
    const newSecret = 'active-part11-secret-v2';

    const fpOld = ComplianceEngine.computePart11KeyFingerprint(oldSecret);
    const fpNew = ComplianceEngine.computePart11KeyFingerprint(newSecret);
    assert.match(fpOld, /^sha256:[0-9a-f]{12}$/);
    assert.notStrictEqual(fpOld, fpNew);
    assert.throws(() => ComplianceEngine.computePart11KeyFingerprint('   '), /non-empty/i);

    const sealPayload = {
      hazardKey: 'HAZ-501',
      specId: 'srs-rot-1',
      artifactSha256: sampleSpec.sha256Hash,
      signedByAccountId: 'acc-rot-1',
      signedBy: 'Dr. Signer',
      role: 'Clinical Safety Officer',
      meaning: 'Approved safety specification',
      signedAt: '2026-11-15T00:00:00Z',
      authMethod: 'PART11_ATTESTATION',
    };
    const legacySeal = ComplianceEngine.computePart11Seal(sealPayload, oldSecret);
    const sigObj = {
      id: 'sig-rot-1',
      signerName: 'Dr. Signer',
      signedBy: 'Dr. Signer',
      signedByAccountId: 'acc-rot-1',
      role: 'Clinical Safety Officer',
      signedAt: '2026-11-15T00:00:00Z',
      signatureHash: sampleSpec.sha256Hash,
      artifactSha256: sampleSpec.sha256Hash,
      signatureSeal: legacySeal,
      signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
      authMethod: 'PART11_ATTESTATION',
      isValid: true,
      meaning: 'Approved safety specification',
    };

    // Explicitly fails when only newSecret is provided
    assert.strictEqual(ComplianceEngine.verifyPart11Seal('HAZ-501', 'srs-rot-1', sigObj, newSecret), false);

    // Passes when previousSecretsCsv includes oldSecret
    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal('HAZ-501', 'srs-rot-1', sigObj, newSecret, `other-old, ${oldSecret}`),
      true
    );

    // Passes via environment variables when active secret matches primary
    const prevPrimary = process.env.MEDTRACE_PART11_SECRET;
    const prevRetired = process.env.MEDTRACE_PART11_PREVIOUS_SECRETS;
    try {
      process.env.MEDTRACE_PART11_SECRET = newSecret;
      process.env.MEDTRACE_PART11_PREVIOUS_SECRETS = oldSecret;

      assert.strictEqual(
        ComplianceEngine.verifyPart11Seal('HAZ-501', 'srs-rot-1', sigObj, newSecret),
        true
      );
      assert.strictEqual(
        ComplianceEngine.verifyPart11Seal('HAZ-501', 'srs-rot-1', sigObj, undefined),
        true
      );
      // Explicit mismatched negative test secret must STILL fail closed
      assert.strictEqual(
        ComplianceEngine.verifyPart11Seal('HAZ-501', 'srs-rot-1', sigObj, 'wrong-secret'),
        false
      );
    } finally {
      if (prevPrimary === undefined) delete process.env.MEDTRACE_PART11_SECRET;
      else process.env.MEDTRACE_PART11_SECRET = prevPrimary;
      if (prevRetired === undefined) delete process.env.MEDTRACE_PART11_PREVIOUS_SECRETS;
      else process.env.MEDTRACE_PART11_PREVIOUS_SECRETS = prevRetired;
    }
  });

  test.it('evaluateIssueReleaseGate allows fast-path empty issue match only on initialized populated suites', () => {
    const activeSecret = 'gate-test-secret';
    const sealPayload = {
      hazardKey: sampleHazard.key,
      specId: sampleSpec.id,
      artifactSha256: sampleSpec.sha256Hash,
      signedByAccountId: 'acc-gate-1',
      signedBy: 'Dr. Signer',
      role: 'Clinical Safety Officer',
      meaning: 'Approved',
      signedAt: '2026-11-15T00:00:00Z',
      authMethod: 'PART11_ATTESTATION',
    };
    const seal = ComplianceEngine.computePart11Seal(sealPayload, activeSecret);
    const verifiedLink = ComplianceEngine.evaluateTraceLink(
      sampleHazard,
      sampleSpec,
      sampleWork,
      sampleTest,
      {
        id: 'sig-rot-1',
        signerName: 'Dr. Signer',
        signedBy: 'Dr. Signer',
        signedByAccountId: 'acc-gate-1',
        role: 'Clinical Safety Officer',
        signedAt: '2026-11-15T00:00:00Z',
        signatureHash: sampleSpec.sha256Hash,
        artifactSha256: sampleSpec.sha256Hash,
        signatureSeal: seal,
        signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
        authMethod: 'PART11_ATTESTATION',
        isValid: true,
        meaning: 'Approved',
      },
      undefined,
      { requireTestEvidence: true, requireCryptographicSeal: true, part11Secret: activeSecret }
    );
    const fullSuite = ComplianceEngine.generateComplianceReport([verifiedLink], 'LIVE', 'Populated Suite');
    const fastPathUnlinked = { ...fullSuite, traceLinks: [] };

    // Fast-path empty result for an unlinked Jira issue in an initialized suite must PASS
    const unlinkedOutcome = ComplianceEngine.evaluateIssueReleaseGate('UNLINKED-77', fastPathUnlinked);
    assert.strictEqual(unlinkedOutcome.result, true);

    // Global gate (no issueKey) with empty traceLinks must still FAIL closed
    const globalOutcome = ComplianceEngine.evaluateIssueReleaseGate(undefined, fastPathUnlinked);
    assert.strictEqual(globalOutcome.result, false);

    // Uninitialized suite must ALWAYS fail closed even for an unlinked issueKey
    const uninitOutcome = ComplianceEngine.evaluateIssueReleaseGate('UNLINKED-77', {
      ...fastPathUnlinked,
      initialized: false,
    });
    assert.strictEqual(uninitOutcome.result, false);
  });

  test.it('supports hybrid ECDSA P-256 asymmetric + HMAC-SHA256 non-repudiation signatures and blocks server-only forgery', () => {
    const serverSecret = 'hybrid-server-secret';
    const kp1 = ComplianceEngine.generateEcdsaP256KeyPair();
    const kp2 = ComplianceEngine.generateEcdsaP256KeyPair();
    assert.match(kp1.keyFingerprint, /^ecdsa-p256:[a-f0-9]{16}$/);

    const challenge = ComplianceEngine.computePart11ClientChallenge({
      hazardKey: sampleHazard.key,
      specId: sampleSpec.id,
      artifactSha256: sampleSpec.sha256Hash,
      meaning: 'Approved for clinical safety release',
    });
    const clientSigIeee = ComplianceEngine.signPart11ClientChallenge(challenge, kp1.privateKeyPkcs8Base64);
    assert.strictEqual(Buffer.from(clientSigIeee, 'base64').length, 64, 'Expected 64-byte IEEE P1363 ECDSA signature');
    assert.strictEqual(
      ComplianceEngine.verifyPart11ClientSignature(challenge, clientSigIeee, kp1.publicKeySpkiBase64),
      true
    );

    // Also verify ASN.1 DER encoded ECDSA P-256 signatures work identically
    const privObj = crypto.createPrivateKey({
      key: Buffer.from(kp1.privateKeyPkcs8Base64, 'base64'),
      format: 'der',
      type: 'pkcs8',
    });
    const clientSigDer = crypto.sign('sha256', Buffer.from(challenge, 'utf8'), privObj).toString('base64');
    assert.strictEqual(
      ComplianceEngine.verifyPart11ClientSignature(challenge, clientSigDer, kp1.publicKeySpkiBase64),
      true
    );

    const hybridPayload = {
      hazardKey: sampleHazard.key,
      specId: sampleSpec.id,
      artifactSha256: sampleSpec.sha256Hash,
      signedByAccountId: 'acc-ecdsa-1',
      signedBy: 'Dr. Asymmetric',
      role: 'Authorized Atlassian User',
      meaning: 'Approved for clinical safety release',
      signedAt: '2026-11-15T01:00:00Z',
      authMethod: 'PART11_ATTESTATION',
      signatureAlgorithm: 'ECDSA-P256-SHA256+HMAC-SEAL-V1',
      clientPublicKeySpki: kp1.publicKeySpkiBase64,
      clientSignatureBase64: clientSigIeee,
    };
    const hybridSeal = ComplianceEngine.computePart11Seal(hybridPayload, serverSecret);
    const hybridSig = {
      id: 'sig-hybrid-1',
      signerName: 'Dr. Asymmetric',
      signedBy: 'Dr. Asymmetric',
      signedByAccountId: 'acc-ecdsa-1',
      role: 'Authorized Atlassian User',
      signedAt: '2026-11-15T01:00:00Z',
      signatureHash: sampleSpec.sha256Hash,
      artifactSha256: sampleSpec.sha256Hash,
      authMethod: 'PART11_ATTESTATION',
      isValid: true,
      meaning: 'Approved for clinical safety release',
      signatureAlgorithm: 'ECDSA-P256-SHA256+HMAC-SEAL-V1',
      signatureSeal: hybridSeal,
      clientPublicKeySpki: kp1.publicKeySpkiBase64,
      clientSignatureBase64: clientSigIeee,
      clientKeyFingerprint: kp1.keyFingerprint,
    };

    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal(sampleHazard.key, sampleSpec.id, hybridSig, serverSecret),
      true
    );

    // Server-only compromise test: recomputing HMAC with real serverSecret after changing meaning MUST FAIL
    const forgedMeaning = 'Tampered server meaning without private key';
    const serverForgedSeal = ComplianceEngine.computePart11Seal(
      { ...hybridPayload, meaning: forgedMeaning },
      serverSecret
    );
    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal(
        sampleHazard.key,
        sampleSpec.id,
        { ...hybridSig, meaning: forgedMeaning, signatureSeal: serverForgedSeal },
        serverSecret
      ),
      false
    );

    // Swapping client public key or corrupting fingerprint or stripping clientSignatureBase64 MUST FAIL
    const wrongPubSeal = ComplianceEngine.computePart11Seal(
      { ...hybridPayload, clientPublicKeySpki: kp2.publicKeySpkiBase64 },
      serverSecret
    );
    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal(
        sampleHazard.key,
        sampleSpec.id,
        {
          ...hybridSig,
          clientPublicKeySpki: kp2.publicKeySpkiBase64,
          clientKeyFingerprint: kp2.keyFingerprint,
          signatureSeal: wrongPubSeal,
        },
        serverSecret
      ),
      false
    );
    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal(
        sampleHazard.key,
        sampleSpec.id,
        { ...hybridSig, clientKeyFingerprint: kp2.keyFingerprint },
        serverSecret
      ),
      false
    );
    assert.strictEqual(
      ComplianceEngine.verifyPart11Seal(
        sampleHazard.key,
        sampleSpec.id,
        { ...hybridSig, clientSignatureBase64: undefined },
        serverSecret
      ),
      false
    );

    // evaluateTraceLink must fail closed when hybrid client fields are forged even without explicit requireCryptographicSeal
    const forgedEvaluated = ComplianceEngine.evaluateTraceLink(
      sampleHazard,
      sampleSpec,
      sampleWork,
      sampleTest,
      { ...hybridSig, meaning: forgedMeaning, signatureSeal: serverForgedSeal },
      undefined,
      { part11Secret: serverSecret }
    );
    assert.strictEqual(forgedEvaluated.complianceState, 'SIGNATURE_DRIFT');
  });
});
