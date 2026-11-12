import api, { route } from '@forge/api';
import { kvs } from '@forge/kvs';
import crypto from 'node:crypto';
import { AuditLogService } from './audit-log';
import { ComplianceEngine } from './compliance-engine';
import { isForgeRuntime } from './runtime';
import {
  AuditAuthMethod,
  ComplianceSummary,
  ConfluenceSpec,
  GraphMetadata,
  IsoHazard,
  JiraWorkItem,
  Part11Attestation,
  Part11Signature,
  TraceLink,
  VerificationTest,
} from './types';

interface ShardedSuiteMeta {
  projectName: string;
  datasetMode: 'DEMO' | 'LIVE';
  standards: string[];
  totalHazards: number;
  classCCount: number;
  classBCount: number;
  classACount: number;
  verifiedPercentage: number;
  releaseBlocked: boolean;
  blockingReasons: string[];
  signatureDriftCount: number;
  lastAuditTimestamp: string;
  linkKeys: string[];
  storageFormat: 'SHARDED_V2';
  version: number;
}

export interface SignedSpecBaseline {
  specId: string;
  pageId?: string;
  sha256Hash: string;
  signedBy: string;
  signedAt: string;
  role: string;
  meaning: string;
  authMethod: string;
}

const SUITE_META_KEY = 'medtrace:compliance:suite_meta';
const LINK_KEY_PREFIX = 'medtrace:compliance:link:';
const SIGNED_SPEC_PREFIX = 'medtrace:compliance:signed_spec:';
const LEGACY_STORAGE_KEY = 'medtrace:compliance:active_suite';
const BATCH_CHUNK_SIZE = 25;

export class SeederService {
  private static inMemorySuite: ComplianceSummary | null = null;
  private static inMemorySignedSpecs = new Map<string, SignedSpecBaseline>();

  /**
   * Preflight check to determine if Confluence Cloud is installed and accessible.
   */
  private static async checkConfluenceAvailable(): Promise<boolean> {
    if (!isForgeRuntime()) return false;
    try {
      const resp = await api.asApp().requestConfluence(route`/wiki/api/v2/spaces?limit=1`);
      return resp.status === 200;
    } catch {
      return false;
    }
  }

  public static async getSignedSpecBaseline(specOrPageId: string): Promise<SignedSpecBaseline | undefined> {
    const cleanId = (specOrPageId || '').trim();
    if (!cleanId) return undefined;
    if (!isForgeRuntime()) {
      return this.inMemorySignedSpecs.get(cleanId);
    }
    return (await kvs.get(`${SIGNED_SPEC_PREFIX}${cleanId}`)) as SignedSpecBaseline | undefined;
  }

  public static async setSignedSpecBaseline(baseline: SignedSpecBaseline): Promise<void> {
    if (!isForgeRuntime()) {
      this.inMemorySignedSpecs.set(baseline.specId, baseline);
      if (baseline.pageId) {
        this.inMemorySignedSpecs.set(baseline.pageId, baseline);
      }
      return;
    }
    await kvs.set(`${SIGNED_SPEC_PREFIX}${baseline.specId}`, baseline);
    if (baseline.pageId && baseline.pageId !== baseline.specId) {
      await kvs.set(`${SIGNED_SPEC_PREFIX}${baseline.pageId}`, baseline);
    }
  }

  /**
   * Persists the compliance suite sharded across KVS keys (`suite_meta` + per-link keys)
   * so large suites cannot breach the 240 KiB per-key KVS ceiling.
   * Outside Forge runtime, stores in volatile memory; inside Forge runtime, KVS errors propagate loudly.
   */
  public static async saveComplianceSuite(summary: ComplianceSummary, expectedVersion?: number): Promise<ComplianceSummary> {
    const auditHead = await AuditLogService.getHead();
    const enrichedSummary: ComplianceSummary = {
      ...summary,
      storageFormat: 'SHARDED_V2',
      auditEntryCount: auditHead.lastSeq,
      auditHeadHash: auditHead.headHash,
    };

    if (!isForgeRuntime()) {
      this.inMemorySuite = enrichedSummary;
      return enrichedSummary;
    }

    const existingMeta = (await kvs.get(SUITE_META_KEY)) as ShardedSuiteMeta | undefined;
    if (typeof expectedVersion === 'number' && existingMeta && existingMeta.version !== expectedVersion) {
      throw new Error(
        `Concurrent modification detected on compliance suite (expected version ${expectedVersion}, found ${existingMeta.version}). Please retry.`
      );
    }

    const linkItems = enrichedSummary.traceLinks.map((link) => ({
      key: `${LINK_KEY_PREFIX}${link.id}`,
      value: link,
    }));

    for (let i = 0; i < linkItems.length; i += BATCH_CHUNK_SIZE) {
      const chunk = linkItems.slice(i, i + BATCH_CHUNK_SIZE);
      const batchResult = await kvs.batchSet(chunk);
      if (batchResult.failedKeys && batchResult.failedKeys.length > 0) {
        throw new Error(
          `Failed to persist compliance trace links to Forge KVS: ${batchResult.failedKeys.map((f) => `${f.key}:${f.error.code}`).join(', ')}`
        );
      }
    }

    const nextVersion = (existingMeta?.version ?? 0) + 1;
    const meta: ShardedSuiteMeta = {
      projectName: enrichedSummary.projectName,
      datasetMode: enrichedSummary.datasetMode,
      standards: enrichedSummary.standards,
      totalHazards: enrichedSummary.totalHazards,
      classCCount: enrichedSummary.classCCount,
      classBCount: enrichedSummary.classBCount,
      classACount: enrichedSummary.classACount,
      verifiedPercentage: enrichedSummary.verifiedPercentage,
      releaseBlocked: enrichedSummary.releaseBlocked,
      blockingReasons: enrichedSummary.blockingReasons,
      signatureDriftCount: enrichedSummary.signatureDriftCount,
      lastAuditTimestamp: enrichedSummary.lastAuditTimestamp,
      linkKeys: linkItems.map((item) => item.key),
      storageFormat: 'SHARDED_V2',
      version: nextVersion,
    };

    await kvs.set(SUITE_META_KEY, meta);
    return enrichedSummary;
  }

  private static async loadShardedSuiteFromKvs(): Promise<{ summary: ComplianceSummary; version: number } | undefined> {
    const meta = (await kvs.get(SUITE_META_KEY)) as ShardedSuiteMeta | undefined;
    if (!meta || !Array.isArray(meta.linkKeys)) {
      return undefined;
    }

    const linkMap = new Map<string, TraceLink>();
    for (let i = 0; i < meta.linkKeys.length; i += BATCH_CHUNK_SIZE) {
      const chunkKeys = meta.linkKeys.slice(i, i + BATCH_CHUNK_SIZE).map((key) => ({ key }));
      if (chunkKeys.length === 0) continue;
      const batchRes = await kvs.batchGet(chunkKeys);
      for (const item of batchRes.successfulKeys || []) {
        linkMap.set(item.key, item.value as TraceLink);
      }
    }

    const traceLinks: TraceLink[] = [];
    for (const key of meta.linkKeys) {
      const link = linkMap.get(key);
      if (link) traceLinks.push(link);
    }

    const auditHead = await AuditLogService.getHead();

    return {
      version: meta.version ?? 0,
      summary: {
        projectName: meta.projectName,
        datasetMode: meta.datasetMode ?? 'DEMO',
        standards: meta.standards,
        totalHazards: meta.totalHazards,
        classCCount: meta.classCCount,
        classBCount: meta.classBCount,
        classACount: meta.classACount,
        verifiedPercentage: meta.verifiedPercentage,
        releaseBlocked: meta.releaseBlocked,
        blockingReasons: meta.blockingReasons,
        signatureDriftCount: meta.signatureDriftCount,
        traceLinks,
        lastAuditTimestamp: meta.lastAuditTimestamp,
        storageFormat: 'SHARDED_V2',
        auditEntryCount: auditHead.lastSeq,
        auditHeadHash: auditHead.headHash,
      },
    };
  }

  /**
   * 1-Click Demo Dataset Seeder (explicitly labeled DEMO mode).
   */
  public static async seedEnterpriseDemoSuite(
    actorAccountId: string = 'system:demo-seeder',
    authMethod: AuditAuthMethod | string = 'SYSTEM_INIT'
  ): Promise<{
    success: boolean;
    confluenceEnabled: boolean;
    summary: ComplianceSummary;
    message: string;
  }> {
    const confluenceEnabled = await this.checkConfluenceAvailable();
    console.log(`[MedTrace Seeder] Seeding DEMO suite (Confluence available: ${confluenceEnabled})`);

    const hazards: IsoHazard[] = [
      {
        id: 'haz-101',
        key: 'HAZ-101',
        title: 'Over-Infusion Hazard: Bolus delivery exceeds 5.0 mL/hr clinical safety threshold',
        riskClass: 'CLASS_C',
        severity: 'CATASTROPHIC',
        probability: 'OCCASIONAL',
        mitigationRequirementId: 'srs-104',
        status: 'UNVERIFIED_RISK',
      },
      {
        id: 'haz-102',
        key: 'HAZ-102',
        title: 'Under-Infusion Hazard: Unintended pump stall leading to severe hypoglycemia',
        riskClass: 'CLASS_B',
        severity: 'CRITICAL',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-105',
        status: 'MITIGATED',
      },
      {
        id: 'haz-103',
        key: 'HAZ-103',
        title: 'Display Transient Glitch: OLED backlight flicker during emergency battery cutover',
        riskClass: 'CLASS_A',
        severity: 'MINOR',
        probability: 'OCCASIONAL',
        mitigationRequirementId: 'srs-106',
        status: 'MITIGATED',
      },
    ];

    const computeSha256 = (content: string): string =>
      crypto.createHash('sha256').update(content).digest('hex');

    const srs104ApprovedSnippet = 'Clause 4.2.1: Bolus delivery rate must be hardware-clamped by MCU2 with 10ms watchdog timeout at max 5.0 mL/hr.';
    const srs104CurrentSnippet = 'Clause 4.2.1: Bolus delivery rate must be hardware-clamped by MCU2 with 10ms watchdog timeout at max 5.5 mL/hr.';
    const srs105Snippet = 'Clause 4.3.5: Dual IR photodiodes calculate basal drop count every 250 milliseconds.';
    const srs106Snippet = 'Clause 6.1.2: Buck converter must maintain 3.3V bus within +/- 2% during primary cell cutover.';

    const srs104ApprovedHash = computeSha256(srs104ApprovedSnippet);
    const srs104CurrentHash = computeSha256(srs104CurrentSnippet);
    const srs105Hash = computeSha256(srs105Snippet);
    const srs106Hash = computeSha256(srs106Snippet);

    const specs: ConfluenceSpec[] = [
      {
        id: 'srs-104',
        title: 'SRS-104: Dual-Core Microcontroller Hardware Bolus Clamp (Max 5.0 mL/hr)',
        version: 3,
        sha256Hash: srs104CurrentHash,
        lastSignedHash: srs104ApprovedHash,
        isSignatureInvalidated: true,
        contentSnippet: srs104CurrentSnippet,
        lastUpdated: '10 minutes ago (Modified by engineer: changed threshold 5.0 -> 5.5 mL/hr)',
      },
      {
        id: 'srs-105',
        title: 'SRS-105: Optical Droplet Sensor Real-Time Flow Rate Verification',
        version: 2,
        sha256Hash: srs105Hash,
        lastSignedHash: srs105Hash,
        isSignatureInvalidated: false,
        contentSnippet: srs105Snippet,
        lastUpdated: '2 days ago',
      },
      {
        id: 'srs-106',
        title: 'SRS-106: Power Management Rail Glitch Filter & OLED Retention',
        version: 1,
        sha256Hash: srs106Hash,
        lastSignedHash: srs106Hash,
        isSignatureInvalidated: false,
        contentSnippet: srs106Snippet,
        lastUpdated: '1 week ago',
      },
    ];

    const workItems: JiraWorkItem[] = [
      {
        id: 'med-42',
        key: 'MED-42',
        title: 'Implement Dual-Core Hardware PWM Clamp on Infusion Motor',
        status: 'In Progress',
        assignee: 'Dr. Sarah Lin (Lead Firmware)',
        prNumber: '#142',
        commitSha: '7f9a12c',
      },
      {
        id: 'med-43',
        key: 'MED-43',
        title: 'Integrate Optical Droplet Sensor Interrupt Routine',
        status: 'Done',
        assignee: 'David Chen (Embedded Systems)',
        prNumber: '#139',
        commitSha: '3a4b981',
      },
      {
        id: 'med-44',
        key: 'MED-44',
        title: 'Calibrate OLED SPI Bus Low-Power Sleep Transitions',
        status: 'Done',
        assignee: 'Elena Rostova (Hardware QA)',
        prNumber: '#135',
        commitSha: '5c2e811',
      },
    ];

    const tests: VerificationTest[] = [
      {
        id: 'test-88',
        testKey: 'TEST-88',
        title: 'Hardware-in-the-Loop Occlusion & Over-Infusion Motor Stress Test',
        testType: 'Automated HIL (Hardware-in-Loop)',
        status: 'UNTESTED',
        executionDate: 'Pending HIL Bench Run',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/hil-88',
      },
      {
        id: 'test-89',
        testKey: 'TEST-89',
        title: 'Closed-Loop Droplet Pulse Waveform Verification',
        testType: 'Integration Test',
        status: 'PASSED',
        executionDate: 'Yesterday 14:22 UTC (48/48 Assertions Passed)',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/droplet-89',
      },
      {
        id: 'test-90',
        testKey: 'TEST-90',
        title: 'Power Rail Cutover Voltage Sag Automated Benchmark',
        testType: 'Unit Test',
        status: 'PASSED',
        executionDate: '3 days ago 09:10 UTC',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/power-90',
      },
    ];

    const signatures: Part11Signature[] = [
      {
        id: 'sig-001',
        signedBy: 'Marcus Vance, MD (Chief Medical Officer)',
        signedAt: '2026-10-15T11:30:00Z',
        role: 'Clinical Safety Authority',
        meaning: 'Approval of ISO 14971 Risk Assessment & Mitigation Architecture',
        artifactSha256: srs104ApprovedHash,
        isValid: false,
        invalidationReason: 'AUTOMATIC REVOCATION: Confluence spec modified at version 3 without clinical re-signature.',
      },
      {
        id: 'sig-002',
        signedBy: 'Rachel Adams (Director of Regulatory Affairs)',
        signedAt: '2026-10-20T16:45:00Z',
        role: 'Quality Assurance Director',
        meaning: 'IEC 62304 Software Verification Plan Approval',
        artifactSha256: srs105Hash,
        isValid: true,
      },
      {
        id: 'sig-003',
        signedBy: 'Rachel Adams (Director of Regulatory Affairs)',
        signedAt: '2026-10-21T09:15:00Z',
        role: 'Quality Assurance Director',
        meaning: 'Class A Software Verification Protocol Approval',
        artifactSha256: srs106Hash,
        isValid: true,
      },
    ];

    const graphMetadatas: GraphMetadata[] = [
      {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10042',
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-101',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98304',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'MODELED (demo lineage — live AGG query via queryGraphContext)',
      },
      {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10043',
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-102',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98305',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'MODELED (demo lineage — live AGG query via queryGraphContext)',
      },
      {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10044',
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-103',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98306',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'MODELED (demo lineage — live AGG query via queryGraphContext)',
      },
    ];

    const traceLinks = hazards.map((hazard, index) =>
      ComplianceEngine.evaluateTraceLink(
        hazard,
        specs[index],
        workItems[index],
        tests[index],
        signatures[index],
        graphMetadatas[index]
      )
    );

    await AuditLogService.append({
      actorAccountId,
      action: 'SEED_DEMO',
      targetKey: 'DEMO_SUITE',
      details: {
        hazardCount: traceLinks.length,
        confluenceEnabled,
      },
      authMethod,
    });

    const summary = ComplianceEngine.generateComplianceReport(
      traceLinks,
      'DEMO',
      'Smart Infusion Pump Firmware v2.1'
    );
    const saved = await this.saveComplianceSuite(summary);

    return {
      success: true,
      confluenceEnabled,
      summary: saved,
      message:
        'Successfully populated IEC 62304 Smart Infusion Pump Firmware DEMO dataset (3 Hazards, 3 SRS Specs, 3 Work Items, 3 Tests, 3 Signatures).',
    };
  }

  /**
   * Retrieves the active compliance suite from sharded Forge KVS (or volatile memory outside Forge).
   */
  public static async getActiveComplianceSuite(): Promise<ComplianceSummary> {
    if (!isForgeRuntime()) {
      if (this.inMemorySuite && this.inMemorySuite.traceLinks && this.inMemorySuite.traceLinks.length > 0) {
        const head = await AuditLogService.getHead();
        return {
          ...this.inMemorySuite,
          auditEntryCount: head.lastSeq,
          auditHeadHash: head.headHash,
        };
      }
      const init = await this.seedEnterpriseDemoSuite('system:auto-init', 'SYSTEM_INIT');
      return init.summary;
    }

    const sharded = await this.loadShardedSuiteFromKvs();
    if (sharded && sharded.summary.traceLinks.length > 0) {
      return sharded.summary;
    }

    // Legacy single-key migration fallback
    const legacy = (await kvs.get(LEGACY_STORAGE_KEY)) as
      | (ComplianceSummary & { datasetMode?: 'DEMO' | 'LIVE' })
      | undefined;
    if (legacy && legacy.traceLinks && legacy.traceLinks.length > 0) {
      return await this.saveComplianceSuite({ ...legacy, datasetMode: legacy.datasetMode ?? 'DEMO' });
    }

    const init = await this.seedEnterpriseDemoSuite('system:auto-init', 'SYSTEM_INIT');
    return init.summary;
  }

  private static async getSuiteWithVersion(): Promise<{ summary: ComplianceSummary; version?: number }> {
    if (!isForgeRuntime()) {
      return { summary: await this.getActiveComplianceSuite() };
    }
    const sharded = await this.loadShardedSuiteFromKvs();
    if (sharded && sharded.summary.traceLinks.length > 0) {
      return sharded;
    }
    return { summary: await this.getActiveComplianceSuite() };
  }

  /**
   * Binds a Jira issue key into a hazard's trace link work item.
   * In Forge runtime, validates the issue against Jira REST API and hydrates summary/status/assignee.
   */
  public static async bindIssueToHazard(
    hazardKey: string,
    issueKey: string,
    actorAccountId: string = 'system',
    authMethod: AuditAuthMethod | string = 'FORGE_USER_SESSION'
  ): Promise<ComplianceSummary> {
    const cleanIssueKey = (issueKey || '').trim().toUpperCase();
    if (!/^[A-Z][A-Z0-9_]+-\d+$/.test(cleanIssueKey)) {
      throw new Error(`Invalid Jira issue key format: "${issueKey}". Expected format like MED-42.`);
    }

    const { summary: current, version } = await this.getSuiteWithVersion();
    const idx = current.traceLinks.findIndex(
      (l) => l.hazard.key.toLowerCase() === (hazardKey || '').trim().toLowerCase()
    );
    if (idx < 0) {
      throw new Error(`Hazard ${hazardKey} not found in the active compliance suite.`);
    }

    const targetLink = current.traceLinks[idx];
    const previousIssueKey = targetLink.work.key;

    if (isForgeRuntime()) {
      const resp = await api
        .asApp()
        .requestJira(route`/rest/api/3/issue/${cleanIssueKey}?fields=summary,status,assignee`);
      if (resp.status !== 200) {
        throw new Error(`Jira issue ${cleanIssueKey} could not be verified (HTTP ${resp.status}).`);
      }
      const issueData = await resp.json();
      targetLink.work.id = String(issueData?.id || cleanIssueKey.toLowerCase());
      targetLink.work.key = String(issueData?.key || cleanIssueKey);
      if (issueData?.fields?.summary) {
        targetLink.work.title = issueData.fields.summary;
      }
      const statusName = issueData?.fields?.status?.name;
      if (statusName === 'Done' || statusName === 'In Progress' || statusName === 'Under Review' || statusName === 'To Do') {
        targetLink.work.status = statusName;
      }
      if (issueData?.fields?.assignee?.displayName) {
        targetLink.work.assignee = issueData.fields.assignee.displayName;
      }
    } else {
      targetLink.work.key = cleanIssueKey;
      targetLink.work.id = cleanIssueKey.toLowerCase();
    }

    current.traceLinks[idx] = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      targetLink.graphMetadata
    );

    await AuditLogService.append({
      actorAccountId,
      action: 'BIND_ISSUE',
      targetKey: targetLink.hazard.key,
      details: { previousIssueKey, newIssueKey: targetLink.work.key },
      authMethod,
    });

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'DEMO',
      current.projectName
    );
    return await this.saveComplianceSuite(updated, version);
  }

  /**
   * Records an explicit verification test execution result (real test evidence, separate from Part 11 sign-off).
   */
  public static async recordTestResult(params: {
    hazardKey?: string;
    testKey?: string;
    status: VerificationTest['status'];
    evidenceUrl?: string;
    executionDate?: string;
    notes?: string;
    actorAccountId: string;
    authMethod?: AuditAuthMethod | string;
  }): Promise<ComplianceSummary> {
    const allowedStatuses: VerificationTest['status'][] = ['PASSED', 'FAILED', 'UNTESTED', 'IN_PROGRESS'];
    if (!allowedStatuses.includes(params.status)) {
      throw new Error(`Invalid test status: ${params.status}`);
    }
    if (!params.actorAccountId || params.actorAccountId.trim() === '') {
      throw new Error('actorAccountId is required to record verification test results.');
    }

    const { summary: current, version } = await this.getSuiteWithVersion();
    const idx = current.traceLinks.findIndex(
      (l) =>
        (params.hazardKey && l.hazard.key.toLowerCase() === params.hazardKey.trim().toLowerCase()) ||
        (params.testKey && l.test.testKey.toLowerCase() === params.testKey.trim().toLowerCase())
    );
    if (idx < 0) {
      throw new Error(`Target trace link not found (${params.hazardKey || params.testKey || 'unspecified'}).`);
    }

    const targetLink = current.traceLinks[idx];
    const previousStatus = targetLink.test.status;
    targetLink.test.status = params.status;
    targetLink.test.executionDate = params.executionDate?.trim() || new Date().toISOString();
    if (params.evidenceUrl?.trim()) {
      targetLink.test.evidenceUrl = params.evidenceUrl.trim();
    }
    targetLink.test.recordedBy = params.actorAccountId;
    if (params.notes?.trim()) {
      targetLink.test.notes = params.notes.trim();
    }

    current.traceLinks[idx] = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      targetLink.graphMetadata
    );
    current.traceLinks[idx].hazard.status =
      current.traceLinks[idx].complianceState === 'VERIFIED' ? 'MITIGATED' : 'UNVERIFIED_RISK';

    await AuditLogService.append({
      actorAccountId: params.actorAccountId,
      action: 'RECORD_TEST_RESULT',
      targetKey: targetLink.test.testKey,
      details: {
        hazardKey: targetLink.hazard.key,
        previousStatus,
        newStatus: params.status,
        evidenceUrl: targetLink.test.evidenceUrl || null,
        notes: params.notes || null,
      },
      authMethod: params.authMethod || 'FORGE_USER_SESSION',
    });

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'DEMO',
      current.projectName
    );
    return await this.saveComplianceSuite(updated, version);
  }

  /**
   * Executes a 21 CFR Part 11 electronic signature sign-off on a specification artifact.
   * Requires explicit attestation confirmation, non-empty signature meaning, and authenticated actor identity.
   */
  public static async signOffPart11(params: {
    hazardKey: string;
    attestation: Part11Attestation;
    actorAccountId: string;
    authMethod?: AuditAuthMethod | string;
  }): Promise<ComplianceSummary> {
    if (!params.actorAccountId || params.actorAccountId.trim() === '') {
      throw new Error('Authenticated actorAccountId is required for 21 CFR Part 11 sign-off.');
    }
    if (!params.attestation?.attestationConfirmed) {
      throw new Error('21 CFR Part 11 Violation: Explicit attestation confirmation (attestationConfirmed: true) is required.');
    }
    if (!params.attestation.meaning || params.attestation.meaning.trim().length < 5) {
      throw new Error('21 CFR Part 11 §11.50 Violation: A non-empty signature meaning (>= 5 chars) is required.');
    }

    const { summary: current, version } = await this.getSuiteWithVersion();
    const idx = current.traceLinks.findIndex(
      (l) => l.hazard.key.toLowerCase() === (params.hazardKey || '').trim().toLowerCase()
    );
    if (idx < 0) {
      throw new Error(`Hazard ${params.hazardKey} not found in the active compliance suite.`);
    }

    const targetLink = current.traceLinks[idx];
    const signedAt = new Date().toISOString();
    const signedBy = params.attestation.signedBy?.trim() || `accountId:${params.actorAccountId}`;
    const role = params.attestation.role?.trim() || targetLink.signature.role || 'Authorized Signatory';
    const meaning = params.attestation.meaning.trim();
    const authMethod = params.authMethod || 'PART11_ATTESTATION';

    targetLink.signature.artifactSha256 = targetLink.spec.sha256Hash;
    targetLink.signature.isValid = true;
    targetLink.signature.signedAt = signedAt;
    targetLink.signature.signedBy = signedBy;
    targetLink.signature.role = role;
    targetLink.signature.meaning = meaning;
    targetLink.signature.authMethod = authMethod;
    targetLink.signature.invalidationReason = undefined;
    targetLink.spec.lastSignedHash = targetLink.spec.sha256Hash;
    targetLink.spec.isSignatureInvalidated = false;

    await this.setSignedSpecBaseline({
      specId: targetLink.spec.id,
      pageId: targetLink.spec.pageId,
      sha256Hash: targetLink.spec.sha256Hash,
      signedBy,
      signedAt,
      role,
      meaning,
      authMethod,
    });

    current.traceLinks[idx] = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      targetLink.graphMetadata
    );
    current.traceLinks[idx].hazard.status =
      current.traceLinks[idx].complianceState === 'VERIFIED' ? 'MITIGATED' : 'UNVERIFIED_RISK';

    await AuditLogService.append({
      actorAccountId: params.actorAccountId,
      action: 'PART11_SIGNOFF',
      targetKey: targetLink.hazard.key,
      details: {
        specId: targetLink.spec.id,
        artifactSha256: targetLink.spec.sha256Hash,
        signedBy,
        role,
        meaning,
      },
      authMethod,
    });

    const updated = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'DEMO',
      current.projectName
    );
    return await this.saveComplianceSuite(updated, version);
  }

  /**
   * Demo-only combined remediation flow. Disallowed in LIVE mode; in DEMO mode requires
   * explicit `simulate: true` and `attestationConfirmed: true` and logs `DEMO_SIMULATION` to the audit chain.
   */
  public static async remediateClassCGap(
    targetHazardKey: string = 'HAZ-101',
    accountId?: string,
    options?: {
      simulate?: boolean;
      attestationConfirmed?: boolean;
      meaning?: string;
      authMethod?: AuditAuthMethod | string;
    }
  ): Promise<ComplianceSummary> {
    const { summary: current, version } = await this.getSuiteWithVersion();
    const idx = current.traceLinks.findIndex(
      (l) => l.hazard.key.toLowerCase() === targetHazardKey.toLowerCase()
    );

    if (idx < 0) {
      throw new Error(`Hazard ${targetHazardKey} not found in the active compliance suite — nothing was remediated.`);
    }

    if (current.datasetMode === 'LIVE') {
      throw new Error(
        `Demo quick-remediate is disabled in LIVE dataset mode. Use recordTestResult and signOffPart11 for ${targetHazardKey}.`
      );
    }

    if (!options?.simulate || !options?.attestationConfirmed) {
      throw new Error(
        'Explicit simulation consent (simulate: true) and Part 11 attestation confirmation (attestationConfirmed: true) are required.'
      );
    }

    const actor = accountId?.trim();
    if (!actor) {
      throw new Error('Authenticated actor identity is required to remediate and attest compliance gaps.');
    }

    const targetLink = current.traceLinks[idx];
    const nowIso = new Date().toISOString();
    const authMethod = options.authMethod || 'PART11_ATTESTATION';

    targetLink.test.status = 'PASSED';
    targetLink.test.executionDate = nowIso;
    targetLink.test.recordedBy = actor;
    targetLink.test.notes = 'DEMO_SIMULATION: Operator-confirmed simulated verification run.';

    const baseMeaning = options.meaning?.trim() || targetLink.signature.meaning;
    const meaning = baseMeaning.includes('(DEMO_SIMULATION)') ? baseMeaning : `${baseMeaning} (DEMO_SIMULATION)`;

    targetLink.signature.artifactSha256 = targetLink.spec.sha256Hash;
    targetLink.signature.isValid = true;
    targetLink.signature.signedAt = nowIso;
    targetLink.signature.signedBy = actor.startsWith('service:') ? actor : `accountId:${actor}`;
    targetLink.signature.meaning = meaning;
    targetLink.signature.authMethod = authMethod;
    targetLink.signature.invalidationReason = undefined;
    targetLink.spec.lastSignedHash = targetLink.spec.sha256Hash;
    targetLink.spec.isSignatureInvalidated = false;
    targetLink.hazard.status = 'MITIGATED';

    current.traceLinks[idx] = ComplianceEngine.evaluateTraceLink(
      targetLink.hazard,
      targetLink.spec,
      targetLink.work,
      targetLink.test,
      targetLink.signature,
      targetLink.graphMetadata
    );

    await AuditLogService.append({
      actorAccountId: actor,
      action: 'DEMO_SIMULATION',
      targetKey: targetLink.hazard.key,
      details: {
        simulatedTestKey: targetLink.test.testKey,
        specId: targetLink.spec.id,
        artifactSha256: targetLink.spec.sha256Hash,
        meaning,
      },
      authMethod,
    });

    const updatedSummary = ComplianceEngine.generateComplianceReport(
      current.traceLinks,
      current.datasetMode ?? 'DEMO',
      current.projectName
    );
    return await this.saveComplianceSuite(updatedSummary, version);
  }
}
