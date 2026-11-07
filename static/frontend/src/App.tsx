import React, { useEffect, useState } from 'react';
import { invoke } from '@forge/bridge';
import { ComplianceSummary, BlastRadiusReport } from './types';
import { AuditHeader } from './components/AuditHeader';
import { LineageGraph } from './components/LineageGraph';
import { TraceMatrixTable } from './components/TraceMatrixTable';
import { InspectionDrawer } from './components/InspectionDrawer';
import { FdaExportModal } from './components/FdaExportModal';
import { TransitionModal } from './components/TransitionModal';

// Initial fallback mock data for smooth local rendering / offline previews
const fallbackSummary: ComplianceSummary = {
  projectName: 'Smart Infusion Pump Firmware v2.1',
  standards: [
    'IEC 62304:2006+A1:2015 (Medical Device Software Lifecycle)',
    'ISO 14971:2019 (Risk Management for Medical Devices)',
    'FDA 21 CFR Part 11 (Electronic Records & Signatures)',
  ],
  totalHazards: 1,
  classCCount: 1,
  classBCount: 0,
  classACount: 0,
  verifiedPercentage: 0,
  releaseBlocked: true,
  blockingReasons: [
    'IEC 62304 Critical Gap: Class C Hazard [HAZ-101] requires verified test coverage. Current test [TEST-88] status is UNTESTED.',
  ],
  signatureDriftCount: 1,
  lastAuditTimestamp: new Date().toISOString(),
  traceLinks: [
    {
      id: 'trace-HAZ-101',
      complianceState: 'SAFETY_VIOLATION',
      violations: [
        'IEC 62304 Critical Gap: Class C Hazard [HAZ-101] requires verified test coverage. Current test [TEST-88] status is UNTESTED.',
        '21 CFR Part 11 Signature Drift: Confluence Spec modified after sign-off.',
      ],
      hazard: {
        id: 'haz-101',
        key: 'HAZ-101',
        title: 'Over-Infusion Hazard: Bolus delivery exceeds 5.0 mL/hr clinical safety threshold',
        riskClass: 'CLASS_C',
        severity: 'CATASTROPHIC',
        probability: 'OCCASIONAL',
        mitigationRequirementId: 'srs-104',
        status: 'UNVERIFIED_RISK',
      },
      spec: {
        id: 'srs-104',
        title: 'SRS-104: Dual-Core Microcontroller Hardware Bolus Clamp (Max 5.0 mL/hr)',
        version: 3,
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        lastSignedHash: 'a789ef2398fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b112',
        isSignatureInvalidated: true,
        contentSnippet: 'Clause 4.2.1: Bolus rate must be hardware-clamped by MCU2 with 10ms watchdog timeout.',
        lastUpdated: '10 minutes ago (Modified by engineer: changed threshold 5.0 -> 5.5 mL/hr)',
      },
      work: {
        id: 'med-42',
        key: 'MED-42',
        title: 'Implement Dual-Core Hardware PWM Clamp on Infusion Motor',
        status: 'In Progress',
        assignee: 'Dr. Sarah Lin (Lead Firmware)',
        prNumber: '#142',
        commitSha: '7f9a12c',
      },
      test: {
        id: 'test-88',
        testKey: 'TEST-88',
        title: 'Hardware-in-the-Loop Occlusion & Over-Infusion Motor Stress Test',
        testType: 'Automated HIL (Hardware-in-Loop)',
        status: 'UNTESTED',
        executionDate: 'Pending HIL Bench Run',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/hil-88',
      },
      signature: {
        id: 'sig-001',
        signedBy: 'Marcus Vance, MD (Chief Medical Officer)',
        signedAt: '2026-10-15T11:30:00Z',
        role: 'Clinical Safety Authority',
        meaning: 'Approval of ISO 14971 Risk Assessment & Mitigation Architecture',
        artifactSha256: 'a789ef2398fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b112',
        isValid: false,
        invalidationReason: 'AUTOMATIC REVOCATION: Confluence spec modified at version 3 without clinical re-signature.',
      },
      graphMetadata: {
        entityAri: 'ari:cloud:jira:5cbf2ff9-658a-44d8-9004-dbe8a96e952b:issue/10042',
        linkedSpecAri: 'ari:cloud:confluence:d601ebde-589a-45d8-ab19-a8edfb1d5a47:page/98304',
        edgeType: 'iso14971:mitigates-hazard -> atlassian:work-item-links-page',
        aggTraversalStatus: 'TRAVERSED (AGG GraphQL Gateway 200 OK)',
      },
    },
  ],
};

export const App: React.FC = () => {
  const [summary, setSummary] = useState<ComplianceSummary>(fallbackSummary);
  const [activeView, setActiveView] = useState<'graph' | 'table'>('graph');
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>('trace-HAZ-101');
  const [isExportOpen, setIsExportOpen] = useState(false);
  const [isSeeding, setIsSeeding] = useState(false);
  const [isRemediating, setIsRemediating] = useState(false);
  const [transitionResult, setTransitionResult] = useState<{ result: boolean; errorMessage?: string } | null>(null);
  const [isTransitionModalOpen, setIsTransitionModalOpen] = useState(false);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusReport | null>(null);
  const [isAnalyzingBlastRadius, setIsAnalyzingBlastRadius] = useState(false);

  // Deterministic Regulatory Blast Radius & Transitive Impact Analyzer
  const handleAnalyzeBlastRadius = async () => {
    setIsAnalyzingBlastRadius(true);
    try {
      const report = (await invoke('analyzeBlastRadius', { triggerKey: 'srs-104' })) as BlastRadiusReport;
      if (report) {
        setBlastRadius(report);
        setSelectedLinkId('trace-HAZ-101');
      }
    } catch {
      // Offline / local preview simulation
      setBlastRadius({
        triggerArtifact: {
          type: 'SPEC',
          id: 'srs-104',
          key: 'SRS-104',
          title: 'SRS-104: Dual-Core Microcontroller Hardware Bolus Clamp',
          deltaReason: 'Content modified at v3 (changed threshold 5.0 -> 5.5 mL/hr)',
        },
        impactSeverity: 'CRITICAL_CATASTROPHIC',
        affectedHazardKeys: ['HAZ-101'],
        blockedWorkItemKeys: ['MED-42'],
        invalidatedTestKeys: ['TEST-88'],
        invalidatedSignatureIds: ['sig-001'],
        traversalPath: [
          { hop: 1, from: 'Spec [SRS-104]', edge: 'SIGNS', to: 'Signature [Marcus Vance, MD]', effect: 'Signature evidence invalidated: hash drift detected (expected a789ef23..., current e3b0c442...).' },
          { hop: 2, from: 'Spec [SRS-104]', edge: 'MITIGATES', to: 'Hazard [HAZ-101]', effect: 'Safety mitigation compromised: Bolus Over-Infusion Hazard (Class C).' },
          { hop: 3, from: 'Hazard [HAZ-101]', edge: 'IMPLEMENTS', to: 'Jira Item [MED-42]', effect: 'Human-initiated transition blocked: Firmware task assigned to Dr. Sarah Lin locked under policy gate.' },
          { hop: 4, from: 'Hazard [HAZ-101]', edge: 'VERIFIES', to: 'Test [TEST-88]', effect: 'Verification test evidence invalidated: must be executed against new specification parameters.' },
        ],
        transitiveActionPlan: [
          'Re-certify clinical sign-off with Marcus Vance, MD (Chief Medical Officer) for revised spec.',
          'Review ISO 14971 risk mitigations for HAZ-101 against revised specifications.',
          'Verify firmware implementation in MED-42 matches updated parameters.',
          'Execute automated verification run for TEST-88 (Automated HIL) to regenerate passing evidence.',
        ],
        executionTimeMs: 1.7,
      });
      setSelectedLinkId('trace-HAZ-101');
    } finally {
      setIsAnalyzingBlastRadius(false);
    }
  };

  // Test Jira Transition Validator Lockout
  const handleTestTransition = async () => {
    try {
      const res = (await invoke('simulateTransition')) as { result: boolean; errorMessage?: string };
      setTransitionResult(res);
    } catch {
      // Local preview fallback based on current state
      if (summary.releaseBlocked) {
        setTransitionResult({
          result: false,
          errorMessage:
            '❌ [MedTrace Safety Gate] Transition Blocked!\n• IEC 62304 Critical Gap: Class C Hazard [HAZ-101] requires verified test coverage (TEST-88 is UNTESTED).\n• 21 CFR Part 11 Signature Drift: Confluence Spec modified at v3 without clinical re-certification.',
        });
      } else {
        setTransitionResult({ result: true });
      }
    }
    setIsTransitionModalOpen(true);
  };

  // Load from Forge backend on mount + live background polling for Rovo Chat & MCP updates
  useEffect(() => {
    async function loadData() {
      try {
        const result = (await invoke('getComplianceSuite')) as ComplianceSummary;
        if (result && result.traceLinks) {
          setSummary(result);
        }
        // Execute real Teamwork Graph (AGG GraphQL) context query
        invoke('queryGraphContext', { issueKey: 'MED-42' }).catch(() => {});
      } catch (err) {
        console.warn('Forge bridge invoke notice (using local demo suite):', err);
      }
    }

    loadData();

    // Adaptive 8-second polling active only when tab is visible (saves Forge serverless quotas)
    const pollInterval = setInterval(async () => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      try {
        const latest = (await invoke('getComplianceSuite')) as ComplianceSummary;
        if (latest && latest.traceLinks) {
          setSummary((prev) => {
            if (
              prev.lastAuditTimestamp !== latest.lastAuditTimestamp ||
              prev.releaseBlocked !== latest.releaseBlocked ||
              prev.verifiedPercentage !== latest.verifiedPercentage
            ) {
              return latest;
            }
            return prev;
          });
        }
      } catch {}
    }, 8000);

    const onVisibilityOrFocus = () => {
      if (typeof document === 'undefined' || document.visibilityState === 'visible') {
        loadData();
      }
    };

    window.addEventListener('focus', onVisibilityOrFocus);
    document.addEventListener('visibilitychange', onVisibilityOrFocus);

    return () => {
      clearInterval(pollInterval);
      window.removeEventListener('focus', onVisibilityOrFocus);
      document.removeEventListener('visibilitychange', onVisibilityOrFocus);
    };
  }, []);

  // 1-Click Seeder Action
  const handleSeed = async () => {
    setIsSeeding(true);
    try {
      const resp = (await invoke('seedDemoSuite')) as any;
      if (resp && resp.summary) {
        setSummary(resp.summary);
      }
    } catch {
      // Local preview fallback
      setSummary({ ...fallbackSummary });
    } finally {
      setIsSeeding(false);
    }
  };

  // Remediate Class C Gap (Hero Demo Fix)
  const handleRemediate = async () => {
    setIsRemediating(true);
    try {
      const resp = (await invoke('remediateGap')) as ComplianceSummary;
      if (resp && resp.traceLinks) {
        setSummary(resp);
      }
    } catch {
      // Local preview simulation
      const updatedLinks = summary.traceLinks.map((l) => {
        if (l.hazard.key === 'HAZ-101') {
          return {
            ...l,
            complianceState: 'VERIFIED' as const,
            violations: [],
            test: {
              ...l.test,
              status: 'PASSED' as const,
              executionDate: 'Just now (Automated HIL Run: 120/120 Passed)',
            },
            spec: {
              ...l.spec,
              isSignatureInvalidated: false,
            },
            signature: {
              ...l.signature,
              artifactSha256: l.spec.sha256Hash,
              isValid: true,
              signedAt: new Date().toISOString(),
              signedBy: 'Marcus Vance, MD (Re-certified)',
              invalidationReason: undefined,
            },
          };
        }
        return l;
      });

      setSummary({
        ...summary,
        verifiedPercentage: 100,
        releaseBlocked: false,
        blockingReasons: [],
        signatureDriftCount: 0,
        traceLinks: updatedLinks,
      });
    } finally {
      setIsRemediating(false);
    }
  };

  const selectedLink = summary.traceLinks.find((l) => l.id === selectedLinkId) || null;

  return (
    <div style={{ minHeight: '100vh', background: '#f4f5f7', display: 'flex', flexDirection: 'column' }}>
      {/* Regulatory Command Header */}
      <AuditHeader
        summary={summary}
        activeView={activeView}
        onToggleView={setActiveView}
        onSeed={handleSeed}
        onOpenExport={() => setIsExportOpen(true)}
        onTestTransition={handleTestTransition}
        onAnalyzeBlastRadius={handleAnalyzeBlastRadius}
        isSeeding={isSeeding}
        isAnalyzingBlastRadius={isAnalyzingBlastRadius}
      />

      {/* Main Workspace Body */}
      <div style={{ flex: 1, padding: '20px 24px' }}>
        {activeView === 'graph' ? (
          <LineageGraph summary={summary} onSelectTraceLink={setSelectedLinkId} />
        ) : (
          <TraceMatrixTable summary={summary} onSelectTraceLink={setSelectedLinkId} />
        )}
      </div>

      {/* Slide-in Inspection Drawer */}
      <InspectionDrawer
        link={selectedLink}
        blastRadius={blastRadius}
        onClose={() => setSelectedLinkId(null)}
        onRemediate={handleRemediate}
        isRemediating={isRemediating}
      />

      {/* FDA 510(k) Export Dossier Modal */}
      {isExportOpen && (
        <FdaExportModal summary={summary} onClose={() => setIsExportOpen(false)} />
      )}

      {/* Jira Transition Safety Gate Live Intercept Modal */}
      <TransitionModal
        isOpen={isTransitionModalOpen}
        onClose={() => setIsTransitionModalOpen(false)}
        result={transitionResult}
      />
    </div>
  );
};
