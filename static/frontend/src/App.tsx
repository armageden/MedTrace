import React, { useEffect, useState } from 'react';
import { invoke } from '@forge/bridge';
import { ComplianceSummary } from './types';
import { AuditHeader } from './components/AuditHeader';
import { LineageGraph } from './components/LineageGraph';
import { TraceMatrixTable } from './components/TraceMatrixTable';
import { InspectionDrawer } from './components/InspectionDrawer';
import { FdaExportModal } from './components/FdaExportModal';

// Initial fallback mock data for smooth local rendering / offline previews
const fallbackSummary: ComplianceSummary = {
  projectName: 'Smart Infusion Pump Firmware v2.1',
  standards: [
    'IEC 62304:2006+A1:2015 (Medical Device Software Lifecycle)',
    'ISO 14971:2019 (Risk Management for Medical Devices)',
    'FDA 21 CFR Part 11 (Electronic Records & Signatures)',
  ],
  totalHazards: 3,
  classCCount: 1,
  classBCount: 1,
  classACount: 1,
  verifiedPercentage: 67,
  releaseBlocked: true,
  blockingReasons: [
    'IEC 62304 Critical Gap: Class C Hazard [HAZ-101] requires verified test coverage. Current test [TEST-88] status is UNTESTED.',
    '21 CFR Part 11 Signature Drift: Confluence Spec [SRS-104: Dual-Core Microcontroller Hardware Bolus Clamp (Max 5.0 mL/hr)] was modified after clinical sign-off.',
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
    },
    {
      id: 'trace-HAZ-102',
      complianceState: 'VERIFIED',
      violations: [],
      hazard: {
        id: 'haz-102',
        key: 'HAZ-102',
        title: 'Under-Infusion Hazard: Unintended pump stall leading to severe hypoglycemia',
        riskClass: 'CLASS_B',
        severity: 'CRITICAL',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-105',
        status: 'MITIGATED',
      },
      spec: {
        id: 'srs-105',
        title: 'SRS-105: Optical Droplet Sensor Real-Time Flow Rate Verification',
        version: 2,
        sha256Hash: 'b45c22998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b333',
        lastSignedHash: 'b45c22998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b333',
        isSignatureInvalidated: false,
        contentSnippet: 'Clause 4.3.5: Dual IR photodiodes calculate basal drop count every 250 milliseconds.',
        lastUpdated: '2 days ago',
      },
      work: {
        id: 'med-43',
        key: 'MED-43',
        title: 'Integrate Optical Droplet Sensor Interrupt Routine',
        status: 'Done',
        assignee: 'David Chen (Embedded Systems)',
        prNumber: '#139',
        commitSha: '3a4b981',
      },
      test: {
        id: 'test-89',
        testKey: 'TEST-89',
        title: 'Closed-Loop Droplet Pulse Waveform Verification',
        testType: 'Integration Test',
        status: 'PASSED',
        executionDate: 'Yesterday 14:22 UTC (48/48 Assertions Passed)',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/droplet-89',
      },
      signature: {
        id: 'sig-002',
        signedBy: 'Rachel Adams (Director of Regulatory Affairs)',
        signedAt: '2026-10-20T16:45:00Z',
        role: 'Quality Assurance Director',
        meaning: 'IEC 62304 Software Verification Plan Approval',
        artifactSha256: 'b45c22998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b333',
        isValid: true,
      },
    },
    {
      id: 'trace-HAZ-103',
      complianceState: 'VERIFIED',
      violations: [],
      hazard: {
        id: 'haz-103',
        key: 'HAZ-103',
        title: 'Display Transient Glitch: OLED backlight flicker during emergency battery cutover',
        riskClass: 'CLASS_A',
        severity: 'MINOR',
        probability: 'OCCASIONAL',
        mitigationRequirementId: 'srs-106',
        status: 'MITIGATED',
      },
      spec: {
        id: 'srs-106',
        title: 'SRS-106: Power Management Rail Glitch Filter & OLED Retention',
        version: 1,
        sha256Hash: 'c67d33998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b444',
        lastSignedHash: 'c67d33998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b444',
        isSignatureInvalidated: false,
        contentSnippet: 'Clause 6.1.2: Buck converter must maintain 3.3V bus within +/- 2% during primary cell cutover.',
        lastUpdated: '1 week ago',
      },
      work: {
        id: 'med-44',
        key: 'MED-44',
        title: 'Calibrate OLED SPI Bus Low-Power Sleep Transitions',
        status: 'Done',
        assignee: 'Elena Rostova (Hardware QA)',
        prNumber: '#135',
        commitSha: '5c2e811',
      },
      test: {
        id: 'test-90',
        testKey: 'TEST-90',
        title: 'Power Rail Cutover Voltage Sag Automated Benchmark',
        testType: 'Unit Test',
        status: 'PASSED',
        executionDate: '3 days ago 09:10 UTC',
        evidenceUrl: 'https://ci.medical-devices.internal/test-runs/power-90',
      },
      signature: {
        id: 'sig-003',
        signedBy: 'Rachel Adams (Director of Regulatory Affairs)',
        signedAt: '2026-10-21T09:15:00Z',
        role: 'Quality Assurance Director',
        meaning: 'Class A Software Verification Protocol Approval',
        artifactSha256: 'c67d33998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b444',
        isValid: true,
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

  // Load from Forge backend on mount
  useEffect(() => {
    async function loadData() {
      try {
        const result = (await invoke('getComplianceSuite')) as ComplianceSummary;
        if (result && result.traceLinks) {
          setSummary(result);
        }
      } catch (err) {
        console.warn('Forge bridge invoke notice (using local demo suite):', err);
      }
    }
    loadData();
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
        isSeeding={isSeeding}
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
        onClose={() => setSelectedLinkId(null)}
        onRemediate={handleRemediate}
        isRemediating={isRemediating}
      />

      {/* FDA 510(k) Export Dossier Modal */}
      {isExportOpen && (
        <FdaExportModal summary={summary} onClose={() => setIsExportOpen(false)} />
      )}
    </div>
  );
};
