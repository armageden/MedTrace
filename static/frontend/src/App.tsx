import React, { useEffect, useRef, useState } from 'react';
import { invoke, view } from '@forge/bridge';
import { ComplianceSummary, BlastRadiusReport } from './types';
import { AuditHeader } from './components/AuditHeader';
import { LineageGraph } from './components/LineageGraph';
import { TraceMatrixTable } from './components/TraceMatrixTable';
import { InspectionDrawer } from './components/InspectionDrawer';
import { FdaExportModal } from './components/FdaExportModal';
import { TransitionModal } from './components/TransitionModal';
import { ShieldCheck } from 'lucide-react';

// A transition-gate evaluation outcome. `evalError` marks a backend evaluation failure:
// the UI must never render a blocked/approved verdict that the validator did not actually produce.
type TransitionResult = { result: boolean; errorMessage?: string; evalError?: string };

export const App: React.FC = () => {
  // Null until the live suite arrives — no built-in fake dataset in a compliance tool.
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<'graph' | 'table'>('graph');
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [isExportOpen, setIsExportOpen] = useState(false);
  const [isSeeding, setIsSeeding] = useState(false);
  const [isRemediating, setIsRemediating] = useState(false);
  const isSeedingRef = useRef(isSeeding);
  const isRemediatingRef = useRef(isRemediating);
  useEffect(() => { isSeedingRef.current = isSeeding; }, [isSeeding]);
  useEffect(() => { isRemediatingRef.current = isRemediating; }, [isRemediating]);
  const [transitionResult, setTransitionResult] = useState<TransitionResult | null>(null);
  const [isTransitionModalOpen, setIsTransitionModalOpen] = useState(false);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusReport | null>(null);
  const [isAnalyzingBlastRadius, setIsAnalyzingBlastRadius] = useState(false);
  const [graphContext, setGraphContext] = useState<any>(null);

  // Live Teamwork Graph (AGG GraphQL) context query, fired once per mount using the current issue key
  const loadAndProbe = async () => {
    try {
      const ctx = await view.getContext();
      const issueKey = ctx?.extension?.issue?.key || 'MED-42';
      const res = await invoke('queryGraphContext', { issueKey });
      setGraphContext(res);
    } catch {
      try {
        const res = await invoke('queryGraphContext', { issueKey: 'MED-42' });
        setGraphContext(res);
      } catch {
        setGraphContext(null);
      }
    }
  };

  const loadData = async () => {
    try {
      const result = (await invoke('getComplianceSuite')) as ComplianceSummary;
      if (result && result.traceLinks) {
        setSummary(result);
        setNotice(null);
        loadAndProbe();
      }
    } catch (err) {
      console.warn('Forge bridge invoke failed:', err);
      setNotice('Live compliance suite could not be loaded from the Forge backend. Nothing is simulated in its place — retry or click "Seed Demo Suite".');
    }
  };

  // Deterministic Regulatory Blast Radius & Transitive Impact Analyzer
  const handleAnalyzeBlastRadius = async () => {
    setIsAnalyzingBlastRadius(true);
    try {
      const triggerKey = selectedLink?.spec?.id || 'srs-104';
      const report = (await invoke('analyzeBlastRadius', { triggerKey })) as BlastRadiusReport;
      if (report) {
        setBlastRadius(report);
        setSelectedLinkId(selectedLink?.id || 'trace-HAZ-101');
      }
    } catch {
      setBlastRadius(null);
      setNotice('Blast radius analysis failed on the Forge backend — no simulated report is shown.');
    } finally {
      setIsAnalyzingBlastRadius(false);
    }
  };

  // Test Jira Transition Validator Lockout
  const handleTestTransition = async () => {
    try {
      let issueKey = 'MED-42';
      try {
        const ctx = await view.getContext();
        const currentKey = ctx?.extension?.issue?.key;
        const linked = !!currentKey && !!summary?.traceLinks?.some((l) => l.work?.key === currentKey);
        issueKey = linked ? (currentKey as string) : 'MED-42';
      } catch {}
      const res = (await invoke('simulateTransition', { issueKey })) as TransitionResult;
      setTransitionResult(res);
    } catch {
      setTransitionResult({
        result: false,
        evalError: 'Forge backend could not evaluate the safety gate — no transition decision was made.',
      });
    }
    setIsTransitionModalOpen(true);
  };

  // Load from Forge backend on mount + live background polling for Rovo Chat & MCP updates
  useEffect(() => {
    loadData();

    // Adaptive 8-second polling active only when tab is visible (saves Forge serverless quotas).
    // A failed poll leaves state untouched — it never fabricates an update.
    const pollInterval = setInterval(async () => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      try {
        if (isSeedingRef.current || isRemediatingRef.current) return;
        const latest = (await invoke('getComplianceSuite')) as ComplianceSummary;
        if (latest && latest.traceLinks) {
          setSummary((prev) => {
            if (
              prev &&
              prev.lastAuditTimestamp === latest.lastAuditTimestamp &&
              prev.releaseBlocked === latest.releaseBlocked &&
              prev.verifiedPercentage === latest.verifiedPercentage
            ) {
              return prev;
            }
            return latest;
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
        setNotice(null);
        setBlastRadius(null);
      }
    } catch {
      setNotice('Seeding failed — the Forge backend is unreachable. Existing state was NOT changed.');
    } finally {
      setIsSeeding(false);
    }
  };

  // Remediate Class C Gap (Hero Demo Fix)
  const handleRemediate = async () => {
    if (!selectedLink) return;
    setIsRemediating(true);
    try {
      const resp = (await invoke('remediateGap', { hazardKey: selectedLink.hazard.key })) as ComplianceSummary;
      if (resp && resp.traceLinks) {
        setSummary(resp);
        setBlastRadius(null);
      }
    } catch {
      setNotice('Remediation failed on the Forge backend — nothing was changed. The compliance gap remains OPEN.');
    } finally {
      setIsRemediating(false);
    }
  };

  const selectedLink = summary ? summary.traceLinks.find((l) => l.id === selectedLinkId) || null : null;

  // Pre-load screen: never render a fabricated suite while the live one is unavailable
  if (!summary) {
    return (
      <div
        style={{
          minHeight: '100vh',
          background: '#f4f5f7',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 14,
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
          padding: 24,
        }}
      >
        <div style={{ background: '#0052cc', borderRadius: 10, padding: 12, display: 'flex' }}>
          <ShieldCheck size={30} color="#ffffff" />
        </div>
        <div style={{ fontSize: 16, fontWeight: 800, color: '#172b4d' }}>Loading MedTrace compliance suite…</div>
        {notice && (
          <div style={{ maxWidth: 480, fontSize: 12, color: '#de350b', textAlign: 'center', lineHeight: '18px' }}>
            {notice}
          </div>
        )}
        <button
          onClick={loadData}
          style={{
            padding: '8px 18px',
            borderRadius: 6,
            border: '1.5px solid #0052cc',
            background: '#deebff',
            color: '#0052cc',
            fontWeight: 700,
            fontSize: 12,
            cursor: 'pointer',
          }}
        >
          Retry Live Load
        </button>
      </div>
    );
  }

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

      {/* Honest-error banner: backend failures are surfaced, never papered over */}
      {notice && (
        <div
          style={{
            margin: '12px 24px 0',
            padding: '10px 14px',
            borderRadius: 6,
            background: '#ffebe6',
            border: '1px solid #ffbdad',
            color: '#bf2600',
            fontSize: 12,
            fontWeight: 600,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 12,
          }}
        >
          <span>⚠️ {notice}</span>
          <button
            onClick={() => setNotice(null)}
            style={{ border: 'none', background: 'transparent', color: '#bf2600', cursor: 'pointer', fontWeight: 700, fontSize: 13 }}
            title="Dismiss"
          >
            ✕
          </button>
        </div>
      )}

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
        graphContext={graphContext}
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
