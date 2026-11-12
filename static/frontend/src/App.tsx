import React, { useCallback, useEffect, useRef, useState } from 'react';
import { view } from '@forge/bridge';
import { invokeResolver } from './bridge';
import {
  ComplianceSummary,
  BlastRadiusReport,
  ForgePanelContext,
  SeedDemoResponse,
  LiveSyncResult,
  BindIssueResponse,
  TransitionResult,
  VerificationTest,
} from './types';
import { AuditHeader } from './components/AuditHeader';
import { LineageGraph } from './components/LineageGraph';
import { TraceMatrixTable } from './components/TraceMatrixTable';
import { InspectionDrawer } from './components/InspectionDrawer';
import { FdaExportModal } from './components/FdaExportModal';
import { TransitionModal } from './components/TransitionModal';
import { AuditLogModal } from './components/AuditLogModal';
import { ShieldCheck } from 'lucide-react';

const DEFAULT_PANEL_CONTEXT: ForgePanelContext = {
  extensionType: '',
  isCompactPanel: false,
  isConfluence: false,
};

function parseForgeContext(raw: Awaited<ReturnType<typeof view.getContext>>): ForgePanelContext {
  const ext = raw?.extension;
  const extensionType = typeof ext?.type === 'string' ? ext.type : '';
  const isCompactPanel =
    extensionType === 'jira:issuePanel' || extensionType === 'confluence:contentBylineItem';
  const isConfluence = extensionType.startsWith('confluence');
  const issueKey = typeof ext?.issue?.key === 'string' ? ext.issue.key : undefined;
  const projectKey = typeof ext?.project?.key === 'string' ? ext.project.key : undefined;
  const contentId = ext?.content?.id !== undefined ? String(ext.content.id) : undefined;
  const spaceKey = typeof ext?.space?.key === 'string' ? ext.space.key : undefined;

  return {
    extensionType,
    isCompactPanel,
    isConfluence,
    issueKey,
    projectKey,
    contentId,
    spaceKey,
  };
}

export const App: React.FC = () => {
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [panelContext, setPanelContext] = useState<ForgePanelContext>(DEFAULT_PANEL_CONTEXT);
  const [notice, setNotice] = useState<string | null>(null);
  const [isInitialLoading, setIsInitialLoading] = useState<boolean>(true);
  const [activeView, setActiveView] = useState<'graph' | 'table'>('graph');
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [isExportOpen, setIsExportOpen] = useState(false);
  const [isAuditLogOpen, setIsAuditLogOpen] = useState(false);
  const [isSeeding, setIsSeeding] = useState(false);
  const [isSyncingLive, setIsSyncingLive] = useState(false);
  const [isMutating, setIsMutating] = useState(false);
  const [transitionResult, setTransitionResult] = useState<TransitionResult | null>(null);
  const [isTransitionModalOpen, setIsTransitionModalOpen] = useState(false);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusReport | null>(null);
  const [isAnalyzingBlastRadius, setIsAnalyzingBlastRadius] = useState(false);

  const isBusyRef = useRef(false);
  const lastFocusFetchRef = useRef(0);
  const autoSelectedForContextRef = useRef(false);

  useEffect(() => {
    isBusyRef.current = isSeeding || isSyncingLive || isMutating;
  }, [isSeeding, isSyncingLive, isMutating]);

  const loadData = useCallback(async () => {
    setIsInitialLoading(true);
    try {
      const result = (await invokeResolver<ComplianceSummary | null>('getComplianceSuite')) ?? null;
      if (result && Array.isArray(result.traceLinks)) {
        setSummary(result);
        setNotice(null);
      } else {
        setNotice(
          'Forge backend returned an empty or malformed compliance suite payload. Click "Retry Live Load" to try again.'
        );
      }
    } catch (err) {
      const detail = err instanceof Error ? err.message : 'Forge bridge invoke failed';
      setNotice(`Live compliance suite could not be loaded (${detail}). Nothing is simulated in its place.`);
    } finally {
      setIsInitialLoading(false);
    }
  }, []);

  // Resolve Forge Jira/Confluence extension context once on mount
  useEffect(() => {
    let cancelled = false;
    view
      .getContext()
      .then((ctx) => {
        if (cancelled) return;
        const parsed = parseForgeContext(ctx);
        setPanelContext(parsed);
        if (parsed.isCompactPanel) {
          setActiveView('table');
        }
      })
      .catch(() => {
        // Leave default context outside Forge runtime
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Auto-select matching trace link once when opened inside a specific Jira issue or Confluence page
  useEffect(() => {
    if (!summary || autoSelectedForContextRef.current || selectedLinkId) return;
    if (panelContext.issueKey) {
      const match = summary.traceLinks.find(
        (l) => l.work.key.toUpperCase() === panelContext.issueKey!.toUpperCase()
      );
      if (match) {
        autoSelectedForContextRef.current = true;
        setSelectedLinkId(match.id);
      }
    } else if (panelContext.contentId) {
      const match = summary.traceLinks.find(
        (l) => l.spec.pageId && String(l.spec.pageId) === panelContext.contentId
      );
      if (match) {
        autoSelectedForContextRef.current = true;
        setSelectedLinkId(match.id);
      }
    }
  }, [summary, panelContext, selectedLinkId]);

  // Initial load + adaptive 8s polling + deduplicated focus/visibility refresh
  useEffect(() => {
    loadData();

    const pollInterval = setInterval(async () => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      if (isBusyRef.current) return;
      try {
        const latest = (await invokeResolver<ComplianceSummary | null>('getComplianceSuite')) ?? null;
        if (latest && Array.isArray(latest.traceLinks)) {
          setSummary((prev) => {
            if (
              prev &&
              prev.lastAuditTimestamp === latest.lastAuditTimestamp &&
              prev.releaseBlocked === latest.releaseBlocked &&
              prev.verifiedPercentage === latest.verifiedPercentage &&
              prev.signatureDriftCount === latest.signatureDriftCount &&
              prev.auditEntryCount === latest.auditEntryCount &&
              prev.auditHeadHash === latest.auditHeadHash &&
              prev.datasetMode === latest.datasetMode
            ) {
              return prev;
            }
            return latest;
          });
        }
      } catch {
        // Silent background poll preserves current verified state
      }
    }, 8000);

    const onVisibilityOrFocus = () => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      if (isBusyRef.current) return;
      const now = Date.now();
      if (now - lastFocusFetchRef.current < 1500) {
        return;
      }
      lastFocusFetchRef.current = now;
      loadData();
    };

    window.addEventListener('focus', onVisibilityOrFocus);
    document.addEventListener('visibilitychange', onVisibilityOrFocus);

    return () => {
      clearInterval(pollInterval);
      window.removeEventListener('focus', onVisibilityOrFocus);
      document.removeEventListener('visibilitychange', onVisibilityOrFocus);
    };
  }, [loadData]);

  const handleSeed = async () => {
    setIsSeeding(true);
    try {
      const resp = await invokeResolver<SeedDemoResponse>('seedDemoSuite');
      if (resp && resp.summary) {
        setSummary(resp.summary);
        setNotice(null);
        setBlastRadius(null);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Seeding failed';
      setNotice(`Seeding failed (${msg}). Existing state was NOT changed.`);
    } finally {
      setIsSeeding(false);
    }
  };

  const handleSyncLive = async () => {
    setIsSyncingLive(true);
    try {
      const resp = await invokeResolver<LiveSyncResult>('syncLiveSuite', {
        projectKey: panelContext.projectKey,
      });
      if (resp && resp.summary) {
        setSummary(resp.summary);
        setBlastRadius(null);
        if (resp.warnings && resp.warnings.length > 0) {
          setNotice(
            `Live sync scanned ${resp.jiraIssuesScanned} Jira issue(s) and ${resp.confluencePagesScanned} Confluence page(s): ${resp.warnings.join(' ')}`
          );
        } else {
          setNotice(null);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Live tenant sync failed';
      setNotice(`Live Atlassian sync failed (${msg}). Existing state was NOT changed.`);
    } finally {
      setIsSyncingLive(false);
    }
  };

  const handleAnalyzeBlastRadius = async () => {
    if (!summary) return;
    setIsAnalyzingBlastRadius(true);
    try {
      const currentSelected = summary.traceLinks.find((l) => l.id === selectedLinkId) || summary.traceLinks[0];
      const triggerKey = currentSelected?.spec?.id || currentSelected?.hazard?.key || '';
      const report = await invokeResolver<BlastRadiusReport>('analyzeBlastRadius', { triggerKey });
      if (report) {
        setBlastRadius(report);
        const firstAffected =
          report.affectedHazardKeys.length > 0
            ? summary.traceLinks.find((l) => l.hazard.key === report.affectedHazardKeys[0])
            : undefined;
        if (firstAffected) {
          setSelectedLinkId(firstAffected.id);
        } else if (currentSelected) {
          setSelectedLinkId(currentSelected.id);
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Blast radius analysis failed';
      setBlastRadius(null);
      setNotice(`Blast radius analysis failed (${msg}) — no simulated report is shown.`);
    } finally {
      setIsAnalyzingBlastRadius(false);
    }
  };

  const handleTestTransition = async () => {
    const selected = summary?.traceLinks.find((l) => l.id === selectedLinkId);
    const issueKey = panelContext.issueKey || selected?.work?.key || undefined;
    try {
      const res = await invokeResolver<TransitionResult>('simulateTransition', issueKey ? { issueKey } : {});
      setTransitionResult({
        ...res,
        evaluatedIssueKey: issueKey,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Forge backend unreachable';
      setTransitionResult({
        result: false,
        evaluatedIssueKey: issueKey,
        evalError: `Forge backend could not evaluate the safety gate (${msg}) — no transition decision was made.`,
      });
    }
    setIsTransitionModalOpen(true);
  };

  const handleBindIssue = async (hazardKey: string, issueKey: string) => {
    setIsMutating(true);
    try {
      const resp = await invokeResolver<BindIssueResponse>('bindIssueToHazard', { hazardKey, issueKey });
      if (!resp.success || !resp.summary) {
        setNotice(`Bind issue failed: ${resp.error || 'Unknown backend error'}`);
        return;
      }
      setSummary(resp.summary);
      setNotice(null);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Bind issue failed';
      setNotice(`Bind issue failed (${msg}).`);
    } finally {
      setIsMutating(false);
    }
  };

  const handleRecordTestResult = async (params: {
    hazardKey: string;
    testKey: string;
    status: VerificationTest['status'];
    evidenceUrl?: string;
    notes?: string;
  }) => {
    setIsMutating(true);
    try {
      const updated = await invokeResolver<ComplianceSummary>('recordTestResult', params);
      if (updated && updated.traceLinks) {
        setSummary(updated);
        setBlastRadius(null);
        setNotice(null);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to record test result';
      setNotice(`Recording test result failed (${msg}).`);
    } finally {
      setIsMutating(false);
    }
  };

  const handleSignOffPart11 = async (params: {
    hazardKey: string;
    meaning: string;
    role?: string;
    attestationConfirmed: boolean;
    attestationPhrase?: string;
  }) => {
    setIsMutating(true);
    try {
      const updated = await invokeResolver<ComplianceSummary>('signOffPart11', params);
      if (updated && updated.traceLinks) {
        setSummary(updated);
        setBlastRadius(null);
        setNotice(null);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : '21 CFR Part 11 sign-off failed';
      setNotice(`Part 11 electronic signature failed (${msg}).`);
    } finally {
      setIsMutating(false);
    }
  };

  const handleRemediateDemo = async (hazardKey: string, meaning: string) => {
    setIsMutating(true);
    try {
      const updated = await invokeResolver<ComplianceSummary>('remediateGap', {
        hazardKey,
        simulate: true,
        attestationConfirmed: true,
        meaning,
      });
      if (updated && updated.traceLinks) {
        setSummary(updated);
        setBlastRadius(null);
        setNotice(null);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Demo remediation failed';
      setNotice(`Simulated remediation failed (${msg}). Compliance gap remains OPEN.`);
    } finally {
      setIsMutating(false);
    }
  };

  const selectedLink = summary ? summary.traceLinks.find((l) => l.id === selectedLinkId) || null : null;

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
          padding: 24,
        }}
      >
        <div style={{ background: '#0052cc', borderRadius: 10, padding: 12, display: 'flex' }}>
          <ShieldCheck size={30} color="#ffffff" />
        </div>
        <div style={{ fontSize: 16, fontWeight: 800, color: '#172b4d' }}>
          {isInitialLoading ? 'Loading MedTrace compliance suite…' : 'MedTrace compliance suite unavailable'}
        </div>
        {notice && (
          <div style={{ maxWidth: 480, fontSize: 12, color: '#bf2600', textAlign: 'center', lineHeight: '18px' }}>
            {notice}
          </div>
        )}
        <button
          type="button"
          onClick={loadData}
          disabled={isInitialLoading}
          className="mt-btn"
          style={{
            padding: '8px 18px',
            border: '1.5px solid #0052cc',
            background: '#deebff',
            color: '#0052cc',
          }}
        >
          {isInitialLoading ? 'Loading…' : 'Retry Live Load'}
        </button>
      </div>
    );
  }

  return (
    <div className={`mt-app ${panelContext.isCompactPanel ? 'mt-panel-compact' : ''}`}>
      <AuditHeader
        summary={summary}
        panelContext={panelContext}
        activeView={activeView}
        onToggleView={setActiveView}
        onSeed={handleSeed}
        onSyncLive={handleSyncLive}
        onOpenAuditLog={() => setIsAuditLogOpen(true)}
        onOpenExport={() => setIsExportOpen(true)}
        onTestTransition={handleTestTransition}
        onAnalyzeBlastRadius={handleAnalyzeBlastRadius}
        isSeeding={isSeeding}
        isSyncingLive={isSyncingLive}
        isAnalyzingBlastRadius={isAnalyzingBlastRadius}
      />

      {notice && (
        <div
          className="no-print"
          role="status"
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
          <span>{notice}</span>
          <button
            type="button"
            onClick={() => setNotice(null)}
            aria-label="Dismiss notification"
            className="mt-icon-btn"
            style={{ color: '#bf2600', fontWeight: 700, fontSize: 13 }}
          >
            ✕
          </button>
        </div>
      )}

      <main className="mt-main no-print">
        {activeView === 'graph' ? (
          <LineageGraph
            summary={summary}
            compact={panelContext.isCompactPanel}
            onSelectTraceLink={setSelectedLinkId}
          />
        ) : (
          <TraceMatrixTable summary={summary} onSelectTraceLink={setSelectedLinkId} />
        )}
      </main>

      <InspectionDrawer
        link={selectedLink}
        datasetMode={summary.datasetMode}
        panelContext={panelContext}
        blastRadius={blastRadius}
        onClose={() => setSelectedLinkId(null)}
        onBindIssue={handleBindIssue}
        onRecordTestResult={handleRecordTestResult}
        onSignOffPart11={handleSignOffPart11}
        onRemediateDemo={handleRemediateDemo}
        isMutating={isMutating}
      />

      {isExportOpen && <FdaExportModal summary={summary} onClose={() => setIsExportOpen(false)} />}

      <AuditLogModal isOpen={isAuditLogOpen} onClose={() => setIsAuditLogOpen(false)} />

      <TransitionModal
        isOpen={isTransitionModalOpen}
        onClose={() => setIsTransitionModalOpen(false)}
        result={transitionResult}
        summary={summary}
      />
    </div>
  );
};
