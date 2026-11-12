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
