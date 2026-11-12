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

  test.it('rejects remediation of an unknown hazard with HTTP 500 instead of reporting success', async () => {
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
    assert.strictEqual(resp.statusCode, 500);
    assert.match(resp.body, /not found.*nothing was remediated/i);
  });

  test.it('rejects secrets passed in URL query parameters (header-only defense against log leakage)', async () => {
    const resp = await mcpWebtriggerHandler({ method: 'GET', headers: {}, query: { token: 'medtrace-sec-2026' } });
    assert.strictEqual(resp.statusCode, 401);
  });

  test.it('rejects duplicate in-window nonce replay with HTTP 409 Conflict', async () => {
    const mcpSecret = process.env.MEDTRACE_MCP_SECRET || 'medtrace-sec-2026';
    const testNonce = 'nonce-' + crypto.randomUUID();
    const ts = Date.now().toString();
    const body = JSON.stringify({ action: 'sync-status' });
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
    // First call consumes the nonce
    const res1 = await mcpWebtriggerHandler(req);
    assert.notStrictEqual(res1.statusCode, 409);

    // Replayed second call with identical nonce within window
    const res2 = await mcpWebtriggerHandler(req);
    assert.strictEqual(res2.statusCode, 409);
    assert.match(res2.body, /Replay attack detected/);
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
      projectName: 'CI Gate Suite', standards: [], totalHazards: 1, classCCount: 1, classBCount: 0, classACount: 0,
      verifiedPercentage: 0, releaseBlocked: true,
      blockingReasons: ['IEC 62304 Critical Gap: HAZ-101 unverified'],
      signatureDriftCount: 0, lastAuditTimestamp: new Date().toISOString(),
      traceLinks: [],
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
      projectName: 'CI Gate Suite', standards: [], totalHazards: 1, classCCount: 1, classBCount: 0, classACount: 0,
      verifiedPercentage: 100, releaseBlocked: false,
      blockingReasons: [],
      signatureDriftCount: 0, lastAuditTimestamp: new Date().toISOString(),
      traceLinks: [],
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
          work: { key: 'MED-44' },
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
  test.it('dynamically computes non-empty SHA-256 hashes for all specifications and signatures', async () => {
    const suite = await SeederService.getActiveComplianceSuite();
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

  test.it('defaults to the first link when the trigger is empty or whitespace', () => {
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
      assert.deepStrictEqual(report.blockedWorkItemKeys, ['MED-42'], `Trigger "${trigger}" must not sweep the whole suite`);
      assert.strictEqual(report.triggerArtifact.id, 'srs-104');
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
    assert.strictEqual(report.traversalPath.length, 7, 'Expected 4 hops on link A + 3 newly discovered hops on sibling link B');
    assert.ok(report.traversalPath.some((h) => h.edge === 'MITIGATES' && h.from.includes('SRS-105')), 'Sibling spec must appear as its own MITIGATES hop');
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
    const collidingAdapter = {
      getHead: () => backing.getHead(),
      setHead: (h) => backing.setHead(h),
      getEntry: (seq) => backing.getEntry(seq),
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

    // Tamper directly with entry 1 payload
    const entry1 = await backing.getEntry(1);
    entry1.details = { tampered: true };
    const broken = await AuditLogService.verifyAuditChain();
    assert.strictEqual(broken.valid, false);
    assert.strictEqual(broken.brokenAtSeq, 1);
    assert.match(broken.reason, /Tampered payload at seq 1/);
  });
});

test.describe('SeederService - Sharded KVS Persistence, Test Recording, Part 11 Sign-off & Simulation Guard', () => {
  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
  });

  test.it('persists sharded KVS suite_meta + link:* keys, detects optimistic version conflicts, and propagates batchSet errors', async () => {
    const kvsMock = createMockForgeKvs();
    await withForgeMocks({ kvsMock }, async () => {
      const seeded = await SeederService.seedEnterpriseDemoSuite('acc-admin', 'FORGE_USER_SESSION');
      assert.strictEqual(seeded.summary.storageFormat, 'SHARDED_V2');
      assert.ok(kvsMock.store.has('medtrace:compliance:suite_meta'));
      assert.ok(kvsMock.store.has('medtrace:compliance:link:trace-HAZ-101'));
      assert.ok(kvsMock.store.has('medtrace:audit:entry:1'));

      const loaded = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(loaded.traceLinks.length, 3);
      assert.strictEqual(loaded.storageFormat, 'SHARDED_V2');

      // Optimistic version mismatch must throw loudly
      await assert.rejects(
        () => SeederService.saveComplianceSuite(loaded, 999),
        /Concurrent modification detected/
      );

      // Failed batchSet keys must propagate inside Forge runtime
      forgeKvs.kvs.batchSet = async (items) => ({
        successfulKeys: [],
        failedKeys: [{ key: items[0].key, error: { code: 'QUOTA_EXCEEDED' } }],
      });
      await assert.rejects(
        () => SeederService.saveComplianceSuite(loaded),
        /Failed to persist compliance trace links to Forge KVS/
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
          attestation: { meaning: 'Approved', attestationConfirmed: false },
          actorAccountId: 'cmo-1',
        }),
      /attestationConfirmed: true/
    );
    await assert.rejects(
      () =>
        SeederService.signOffPart11({
          hazardKey: 'HAZ-101',
          attestation: { meaning: 'OK', attestationConfirmed: true },
          actorAccountId: 'cmo-1',
        }),
      /meaning/
    );

    // Valid Part 11 sign-off turns HAZ-101 VERIFIED
    const signed = await SeederService.signOffPart11({
      hazardKey: 'HAZ-101',
      attestation: {
        meaning: 'Clinical Safety Approval for v3 Bolus Clamp',
        attestationConfirmed: true,
        signedBy: 'Dr. Marcus Vance',
        role: 'Chief Medical Officer',
      },
      actorAccountId: 'cmo-1',
    });
    const haz101Signed = signed.traceLinks.find((l) => l.hazard.key === 'HAZ-101');
    assert.strictEqual(haz101Signed.complianceState, 'VERIFIED');
    assert.strictEqual(haz101Signed.signature.isValid, true);
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
    await SeederService.saveComplianceSuite({ ...simulated, datasetMode: 'LIVE' });
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
        appContext: { installation: { contexts: [{ cloudId: '11111111-2222-3333-4444-555555555555' }] } },
      },
      async () => {
        const twg = await TeamworkGraphService.queryIssueGraphContext('PUMP-10');
        assert.strictEqual(twg.source, 'AGG');
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
    await withForgeMocks(
      {
        kvsMock,
        asAppImpl: () => ({
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
        }),
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

    const signed = await resolverHandler(
      {
        call: {
          functionKey: 'signOffPart11',
          payload: {
            hazardKey: 'HAZ-101',
            meaning: 'Clinical safety release sign-off',
            attestationConfirmed: true,
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

test.describe('Standalone Stdio MCP Server (mcp-server/index.mjs)', () => {
  const mcpEntry = path.resolve(__dirname, '..', 'mcp-server', 'index.mjs');

  test.it('fails closed when MEDTRACE_MCP_SECRET is missing', async () => {
    const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'medtrace-mcp-test-'));
    const tmpSub = path.join(tmpRoot, 'mcp-server');
    fs.mkdirSync(tmpSub, { recursive: true });
    const isolatedEntry = path.join(tmpSub, 'index.mjs');
    fs.copyFileSync(mcpEntry, isolatedEntry);

    try {
      const child = spawn(process.execPath, [isolatedEntry], {
        cwd: tmpSub,
        env: { PATH: process.env.PATH },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const exitCode = await new Promise((resolve) => child.on('exit', resolve));
      assert.notStrictEqual(exitCode, 0);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  test.it('handles initialize, tools/list, lineage, verify, remediate (-32602 & success), and HTTP error propagation over JSON-RPC stdio', async () => {
    const secret = 'stdio-mcp-test-secret';
    let mockMode = 'OK';
    const suite = (await SeederService.seedEnterpriseDemoSuite('acc-mcp', 'SYSTEM_INIT')).summary;

    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        if (mockMode === 'HTTP_500') {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Upstream Forge failure' }));
          return;
        }
        const raw = Buffer.concat(chunks).toString('utf8');
        if (req.method === 'GET') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(suite));
          return;
        }
        const body = JSON.parse(raw || '{}');
        if (body.action === 'verify') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ canShipToClinicalProduction: false, touchesSafetyCriticalCode: true }));
          return;
        }
        if (body.action === 'remediate') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, summary: { ...suite, releaseBlocked: false } }));
          return;
        }
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unknown action' }));
      });
    });

    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const child = spawn(process.execPath, [mcpEntry], {
      cwd: path.resolve(__dirname, '..'),
      env: {
        PATH: process.env.PATH,
        MEDTRACE_MCP_SECRET: secret,
        MEDTRACE_WEBTRIGGER_URL: `http://127.0.0.1:${port}`,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const pending = new Map();
    let buffer = '';
    child.stdout.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        const resolver = pending.get(msg.id);
        if (resolver) {
          pending.delete(msg.id);
          resolver(msg);
        }
      }
    });

    const rpc = (id, method, params) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`RPC timeout for ${method}`)), 5000);
        pending.set(id, (msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      });

    try {
      const initRes = await rpc(1, 'initialize', {});
      assert.strictEqual(initRes.result.protocolVersion, '2024-11-05');
      assert.strictEqual(initRes.result.serverInfo.name, 'medtrace-mcp-server');

      const listRes = await rpc(2, 'tools/list', {});
      assert.strictEqual(listRes.result.tools.length, 3);

      const missingKeyRes = await rpc(3, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: { hazardKey: 'UNKNOWN-999' },
      });
      const missingParsed = JSON.parse(missingKeyRes.result.content[0].text);
      assert.strictEqual(missingParsed.found, false);

      const foundKeyRes = await rpc(4, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: { hazardKey: 'HAZ-101' },
      });
      const foundParsed = JSON.parse(foundKeyRes.result.content[0].text);
      assert.strictEqual(foundParsed.found, true);
      assert.strictEqual(foundParsed.hazard.key, 'HAZ-101');

      const verifyRes = await rpc(5, 'tools/call', {
        name: 'medtrace_verify_iec_compliance',
        arguments: { issueKey: 'MED-42' },
      });
      assert.strictEqual(JSON.parse(verifyRes.result.content[0].text).canShipToClinicalProduction, false);

      const missingParamRes = await rpc(6, 'tools/call', {
        name: 'medtrace_remediate_safety_gap',
        arguments: { simulate: true, attestationConfirmed: true },
      });
      assert.strictEqual(missingParamRes.error.code, -32602);

      const remediateRes = await rpc(7, 'tools/call', {
        name: 'medtrace_remediate_safety_gap',
        arguments: { hazardKey: 'HAZ-101', simulate: true, attestationConfirmed: true },
      });
      assert.strictEqual(JSON.parse(remediateRes.result.content[0].text).remediated, true);

      mockMode = 'HTTP_500';
      const errRes = await rpc(8, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: {},
      });
      assert.strictEqual(errRes.result.isError, true);
      assert.strictEqual(JSON.parse(errRes.result.content[0].text).httpStatus, 500);
    } finally {
      child.stdin.end();
      child.kill('SIGKILL');
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
