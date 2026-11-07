const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { ComplianceEngine } = require('../dist/compliance-engine');
const { verifyHmacSignature, mcpWebtriggerHandler, workflowValidatorHandler } = require('../dist/index');
const { SeederService } = require('../dist/seeder');

test.describe('ComplianceEngine - IEC 62304 & FDA 21 CFR Part 11 Rules', () => {
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

  test.it('flags 21 CFR Part 11 signature drift when Confluence hash diverges', () => {
    const driftedSpec = {
      ...baseSpec,
      sha256Hash: 'divergent-sha256-hash-after-modification',
      isSignatureInvalidated: true,
    };
    const link = ComplianceEngine.evaluateTraceLink(baseHazard, driftedSpec, baseWork, baseTest, baseSig);
    assert.strictEqual(link.complianceState, 'SIGNATURE_DRIFT');
    assert.match(link.violations[0], /21 CFR Part 11 Signature Drift/);
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
  });
});

test.describe('Webtrigger Cryptographic Security - HMAC-SHA256 & Replay Protection', () => {
  const secret = 'test-secret-key-12345';
  const timestamp = Date.now().toString();
  const rawBody = JSON.stringify({ action: 'remediate', hazardKey: 'HAZ-101' });

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
    assert.match(resp.body, /Unauthorized: Missing or invalid x-medtrace-key header/);
  });

  test.it('rejects secrets passed in URL query parameters (header-only defense against log leakage)', async () => {
    const resp = await mcpWebtriggerHandler({ method: 'GET', headers: {}, query: { token: 'medtrace-sec-2026' } });
    assert.strictEqual(resp.statusCode, 401);
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
    standards: ['IEC 62304:2006+A1:2015', 'ISO 14971:2019', 'FDA 21 CFR Part 11'],
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
});
