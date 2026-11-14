import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { FullContext } from '@forge/bridge';
import { enableForgeTheme, getForgeContext, invokeResolver } from './bridge';
import {
  BlastRadiusReport,
  ClientTransitionResult,
  ComplianceSummary,
  ForgePanelContext,
  LiveSyncOptions,
  UiNotice,
  VerificationTest,
} from './types';
import { AuditHeader } from './components/AuditHeader';
import { LineageGraph } from './components/LineageGraph';
import { TraceMatrixTable } from './components/TraceMatrixTable';
import { InspectionDrawer } from './components/InspectionDrawer';
import { FdaExportModal } from './components/FdaExportModal';
import { TransitionModal } from './components/TransitionModal';
import { AuditLogModal } from './components/AuditLogModal';
import { ConfirmSeedModal } from './components/ConfirmSeedModal';
import { ShieldCheck } from 'lucide-react';

const DEFAULT_PANEL_CONTEXT: ForgePanelContext = {
  extensionType: '',
  isCompactPanel: false,
  isConfluence: false,
};

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isComplianceSummary(value: unknown): value is ComplianceSummary {
  return (
    isPlainRecord(value) &&
    Array.isArray(value.traceLinks) &&
    typeof value.datasetMode === 'string' &&
    typeof value.totalHazards === 'number'
  );
}

function extractErrorMessage(value: unknown): string | null {
  if (!isPlainRecord(value)) return null;
  if (typeof value.error === 'string' && value.error.trim().length > 0) {
    return value.error.trim();
  }
  if (typeof value.message === 'string' && value.message.trim().length > 0) {
    return value.message.trim();
  }
  if (Array.isArray(value.warnings)) {
    const warnings = value.warnings.filter(
      (item): item is string => typeof item === 'string' && item.trim().length > 0
    );
    if (warnings.length > 0) {
      return warnings.join(' ');
    }
  }
  return null;
}

type MutationSummaryOutcome =
  | { ok: true; summary: ComplianceSummary }
  | { ok: false; error: string };

function resolveMutationSummaryResponse(
  raw: unknown,
  actionLabel: string
): MutationSummaryOutcome {
  if (!isPlainRecord(raw)) {
    return { ok: false, error: `${actionLabel} returned an empty or malformed response.` };
  }
  if (raw.success === false) {
    return {
      ok: false,
      error: extractErrorMessage(raw) || `${actionLabel} failed.`,
    };
  }
  if (raw.success === true && isComplianceSummary(raw.summary)) {
    return { ok: true, summary: raw.summary };
  }
  if (isComplianceSummary(raw)) {
    return { ok: true, summary: raw };
  }
  return { ok: false, error: `${actionLabel} returned a malformed compliance suite payload.` };
}

function parseForgeContext(raw: FullContext | null): ForgePanelContext {
  const ext = isPlainRecord(raw?.extension) ? raw.extension : undefined;
  const extensionType = typeof ext?.type === 'string' ? ext.type : '';
  const isCompactPanel =
    extensionType === 'jira:issuePanel' || extensionType === 'confluence:contentBylineItem';
  const isConfluence = extensionType.startsWith('confluence');
  const issueObj = isPlainRecord(ext?.issue) ? ext.issue : undefined;
  const projectObj = isPlainRecord(ext?.project) ? ext.project : undefined;
  const contentObj = isPlainRecord(ext?.content) ? ext.content : undefined;
  const issueKey = typeof issueObj?.key === 'string' ? issueObj.key : undefined;
  const projectKey = typeof projectObj?.key === 'string' ? projectObj.key : undefined;
  const contentId =
    contentObj?.id !== undefined && contentObj?.id !== null ? String(contentObj.id) : undefined;

  return {
    extensionType,
    isCompactPanel,
    isConfluence,
    issueKey,
    projectKey,
    contentId,
  };
}

function getNoticeVisualStyle(kind: UiNotice['kind']): {
  background: string;
  border: string;
  color: string;
} {
  if (kind === 'error') {
    return {
      background: 'var(--mt-danger-bg, #ffebe6)',
      border: '1px solid var(--mt-danger-border, #ffbdad)',
      color: 'var(--mt-danger-text, #bf2600)',
    };
  }
  if (kind === 'warning') {
    return {
      background: 'var(--mt-warning-bg, #fffae6)',
      border: '1px solid var(--mt-warning-border, #ffe380)',
      color: 'var(--mt-warning-text, #974f0c)',
    };
  }
  if (kind === 'success') {
    return {
      background: 'var(--mt-success-bg, #e3fcef)',
      border: '1px solid var(--mt-success-border, #abf5d1)',
      color: 'var(--mt-success-text, #006644)',
    };
  }
  return {
    background: 'var(--mt-brand-subtle-bg, #deebff)',
    border: '1px solid var(--mt-brand-bg, #0052cc)',
    color: 'var(--mt-brand-text, #0052cc)',
  };
}

export const App: React.FC = () => {
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [panelContext, setPanelContext] = useState<ForgePanelContext>(DEFAULT_PANEL_CONTEXT);
  const [notice, setNotice] = useState<UiNotice | null>(null);
  const [isInitialLoading, setIsInitialLoading] = useState<boolean>(true);
  const [activeView, setActiveView] = useState<'graph' | 'table'>('graph');
  const [selectedLinkId, setSelectedLinkId] = useState<string | null>(null);
  const [isExportOpen, setIsExportOpen] = useState(false);
  const [isAuditLogOpen, setIsAuditLogOpen] = useState(false);
  const [isConfirmSeedOpen, setIsConfirmSeedOpen] = useState(false);
  const [isSeeding, setIsSeeding] = useState(false);
  const [isSyncingLive, setIsSyncingLive] = useState(false);
  const [isMutating, setIsMutating] = useState(false);
  const [transitionResult, setTransitionResult] = useState<ClientTransitionResult | null>(null);
  const [isTransitionModalOpen, setIsTransitionModalOpen] = useState(false);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusReport | null>(null);
  const [isAnalyzingBlastRadius, setIsAnalyzingBlastRadius] = useState(false);

  const summaryRef = useRef<ComplianceSummary | null>(null);
  const activeMutationRef = useRef(false);
  const mutationEpochRef = useRef(0);
  const suiteRequestSeqRef = useRef(0);
  const activeTransitionRef = useRef(false);
  const activeBlastRef = useRef(false);
  const lastFocusFetchRef = useRef(0);
  const autoSelectedForContextRef = useRef(false);

  const commitSummary = useCallback((next: ComplianceSummary) => {
    summaryRef.current = next;
    setSummary(next);
  }, []);

  const fetchAndApplySuite = useCallback(
    async (mode: 'initial' | 'poll' | 'focus') => {
      if (mode !== 'initial' && activeMutationRef.current) {
        return;
      }

      const reqSeq = ++suiteRequestSeqRef.current;
      const mutEpoch = mutationEpochRef.current;
      if (mode === 'initial') {
        setIsInitialLoading(true);
      }

      try {
        const result: unknown = (await invokeResolver('getComplianceSuite')) ?? null;
        if (
          reqSeq !== suiteRequestSeqRef.current ||
          mutEpoch !== mutationEpochRef.current ||
          activeMutationRef.current
        ) {
          return;
        }

        if (isComplianceSummary(result)) {
          if (mode === 'poll') {
            const prev = summaryRef.current;
            if (!prev || JSON.stringify(prev) !== JSON.stringify(result)) {
              commitSummary(result);
            }
            return;
          }

          commitSummary(result);
          setNotice((prev) => (prev?.source === 'load' ? null : prev));
          return;
        }

        if (mode === 'poll') {
          return;
        }

        if (summaryRef.current !== null) {
          setNotice({
            kind: 'warning',
            source: 'load',
            message:
              'Live refresh returned an unexpected response; showing last verified compliance state.',
            retryable: true,
          });
        } else {
          setNotice({
            kind: 'error',
            source: 'load',
            message:
              'Forge backend returned an empty or malformed compliance suite payload. Click "Retry Live Load" to try again.',
          });
        }
      } catch (err) {
        if (
          reqSeq !== suiteRequestSeqRef.current ||
          mutEpoch !== mutationEpochRef.current ||
          activeMutationRef.current
        ) {
          return;
        }
        if (mode === 'poll') {
          // Silent background poll preserves current verified state and any active error notices
          return;
        }
        const detail = err instanceof Error ? err.message : 'Forge bridge invoke failed';
        if (summaryRef.current !== null) {
          setNotice({
            kind: 'warning',
            source: 'load',
            message: `Live refresh failed (${detail}); showing last verified compliance state.`,
            retryable: true,
          });
        } else {
          setNotice({
            kind: 'error',
            source: 'load',
            message: `Live compliance suite could not be loaded (${detail}). Nothing is simulated in its place.`,
          });
        }
      } finally {
        if (mode === 'initial') {
          setIsInitialLoading(false);
        }
      }
    },
    [commitSummary]
  );

  // Enable Forge design tokens and resolve Jira/Confluence extension context safely on mount
  useEffect(() => {
    let cancelled = false;
    void enableForgeTheme();

    getForgeContext()
      .then((ctx) => {
        if (cancelled || !ctx) return;
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
    void fetchAndApplySuite('initial');

    const pollInterval = setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      if (activeMutationRef.current) return;
      void fetchAndApplySuite('poll');
    }, 8000);

    const onVisibilityOrFocus = () => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      if (activeMutationRef.current) return;
      const now = Date.now();
      if (now - lastFocusFetchRef.current < 1500) {
        return;
      }
      lastFocusFetchRef.current = now;
      void fetchAndApplySuite('focus');
    };

    window.addEventListener('focus', onVisibilityOrFocus);
    document.addEventListener('visibilitychange', onVisibilityOrFocus);

    return () => {
      clearInterval(pollInterval);
      window.removeEventListener('focus', onVisibilityOrFocus);
      document.removeEventListener('visibilitychange', onVisibilityOrFocus);
    };
  }, [fetchAndApplySuite]);

  const executeSeed = async (confirmOverwriteLive: boolean): Promise<boolean> => {
    if (activeMutationRef.current) return false;
    activeMutationRef.current = true;
    mutationEpochRef.current += 1;
    suiteRequestSeqRef.current += 1;
    setIsSeeding(true);

    try {
      const resp: unknown = await invokeResolver(
        'seedDemoSuite',
        confirmOverwriteLive ? { confirmOverwriteLive: true } : undefined
      );
      if (isPlainRecord(resp) && resp.success !== false && isComplianceSummary(resp.summary)) {
        suiteRequestSeqRef.current += 1;
        commitSummary(resp.summary);
        setSelectedLinkId(null);
        setBlastRadius(null);
        setNotice(null);
        return true;
      }
      const detail = extractErrorMessage(resp) || 'Malformed or unsuccessful backend response';
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Seeding failed (${detail}). Existing state was NOT changed.`,
      });
      return false;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Seeding failed';
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Seeding failed (${msg}). Existing state was NOT changed.`,
      });
      return false;
    } finally {
      activeMutationRef.current = false;
      setIsSeeding(false);
      setIsConfirmSeedOpen(false);
    }
  };

  const handleSeed = () => {
    if (activeMutationRef.current) return;
    if (summaryRef.current?.datasetMode === 'LIVE') {
      setIsConfirmSeedOpen(true);
      return;
    }
    void executeSeed(false);
  };

  const handleSyncLive = async (options?: {
    includeUntaggedIssues?: boolean;
  }): Promise<boolean> => {
    if (activeMutationRef.current) return false;
    activeMutationRef.current = true;
    mutationEpochRef.current += 1;
    suiteRequestSeqRef.current += 1;
    setIsSyncingLive(true);

    try {
      const payload: Omit<LiveSyncOptions, 'callerMode'> = {
        projectKey: panelContext.projectKey,
        ...(typeof options?.includeUntaggedIssues === 'boolean'
          ? { includeUntaggedIssues: options.includeUntaggedIssues }
          : {}),
      };
      const resp: unknown = await invokeResolver('syncLiveSuite', payload);
      if (isPlainRecord(resp) && resp.success !== false && isComplianceSummary(resp.summary)) {
        const nextSummary = resp.summary;
        suiteRequestSeqRef.current += 1;
        commitSummary(nextSummary);
        setBlastRadius(null);
        setSelectedLinkId((prev) =>
          prev && nextSummary.traceLinks.some((l) => l.id === prev) ? prev : null
        );

        const warnings = Array.isArray(resp.warnings)
          ? resp.warnings.filter(
              (item): item is string => typeof item === 'string' && item.trim().length > 0
            )
          : [];
        const jiraIssuesScanned =
          typeof resp.jiraIssuesScanned === 'number' ? resp.jiraIssuesScanned : 0;
        const confluencePagesScanned =
          typeof resp.confluencePagesScanned === 'number' ? resp.confluencePagesScanned : 0;
        const skippedUntaggedCount =
          typeof resp.skippedUntaggedCount === 'number' ? resp.skippedUntaggedCount : 0;

        if (warnings.length > 0 || resp.truncated === true) {
          setNotice({
            kind: 'warning',
            source: 'sync',
            message: `Live sync scanned ${jiraIssuesScanned} Jira issue(s) and ${confluencePagesScanned} Confluence page(s): ${
              warnings.join(' ') || 'Results truncated.'
            }`,
          });
        } else if (skippedUntaggedCount > 0) {
          setNotice({
            kind: 'info',
            source: 'sync',
            message: `Live sync scanned ${jiraIssuesScanned} Jira issue(s) and ${confluencePagesScanned} Confluence page(s) (${skippedUntaggedCount} untagged issue(s) skipped).`,
          });
        } else {
          setNotice(null);
        }
        return true;
      }

      const detail =
        extractErrorMessage(resp) || 'Backend returned an unsuccessful or malformed sync response';
      setNotice({
        kind: 'error',
        source: 'sync',
        message: `Live Atlassian sync failed (${detail}). Existing state was NOT changed.`,
      });
      return false;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Live tenant sync failed';
      setNotice({
        kind: 'error',
        source: 'sync',
        message: `Live Atlassian sync failed (${msg}). Existing state was NOT changed.`,
      });
      return false;
    } finally {
      activeMutationRef.current = false;
      setIsSyncingLive(false);
    }
  };

  const handleAnalyzeBlastRadius = async () => {
    const currentSummary = summaryRef.current;
    if (!currentSummary || activeMutationRef.current || activeBlastRef.current) return;
    if (currentSummary.traceLinks.length === 0) {
      setNotice({
        kind: 'warning',
        source: 'info',
        message:
          'No trace links configured for blast radius analysis. Sync Live Atlassian or seed a dataset first.',
      });
      return;
    }

    activeBlastRef.current = true;
    setIsAnalyzingBlastRadius(true);
    try {
      const currentSelected =
        currentSummary.traceLinks.find((l) => l.id === selectedLinkId) ||
        currentSummary.traceLinks[0];
      const triggerKey = currentSelected?.spec?.id || currentSelected?.hazard?.key || '';
      const report: unknown = await invokeResolver('analyzeBlastRadius', { triggerKey });
      if (isPlainRecord(report) && Array.isArray(report.affectedHazardKeys)) {
        const typedReport = report as unknown as BlastRadiusReport;
        setBlastRadius(typedReport);
        const firstAffected =
          typedReport.affectedHazardKeys.length > 0
            ? currentSummary.traceLinks.find(
                (l) => l.hazard.key === typedReport.affectedHazardKeys[0]
              )
            : undefined;
        if (firstAffected) {
          setSelectedLinkId(firstAffected.id);
        } else if (currentSelected) {
          setSelectedLinkId(currentSelected.id);
        }
      } else {
        setBlastRadius(null);
        setNotice({
          kind: 'error',
          source: 'info',
          message:
            'Blast radius analysis failed (malformed backend response) — no simulated report is shown.',
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Blast radius analysis failed';
      setBlastRadius(null);
      setNotice({
        kind: 'error',
        source: 'info',
        message: `Blast radius analysis failed (${msg}) — no simulated report is shown.`,
      });
    } finally {
      activeBlastRef.current = false;
      setIsAnalyzingBlastRadius(false);
    }
  };

  const handleTestTransition = async () => {
    if (activeMutationRef.current || activeTransitionRef.current) return;
    activeTransitionRef.current = true;
    const currentSummary = summaryRef.current;
    const selected = currentSummary?.traceLinks.find((l) => l.id === selectedLinkId) ?? null;
    const issueKey = selected
      ? selected.work?.key?.trim() || undefined
      : panelContext.issueKey?.trim() || undefined;

    try {
      const res: unknown = await invokeResolver(
        'simulateTransition',
        issueKey ? { issueKey, scope: 'issue' } : { scope: 'global' }
      );
      if (isPlainRecord(res) && typeof res.result === 'boolean') {
        const evaluatedIssueKey =
          typeof res.evaluatedIssueKey === 'string' && res.evaluatedIssueKey.trim().length > 0
            ? res.evaluatedIssueKey
            : issueKey;
        const errorMessage = typeof res.errorMessage === 'string' ? res.errorMessage : undefined;
        const evalError = typeof res.evalError === 'string' ? res.evalError : undefined;
        setTransitionResult({
          result: res.result,
          errorMessage,
          evaluatedIssueKey,
          evalError,
        });
      } else {
        setTransitionResult({
          result: false,
          evaluatedIssueKey: issueKey,
          evalError:
            'Forge backend returned an unexpected safety gate payload — no transition decision was made.',
        });
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Forge backend unreachable';
      setTransitionResult({
        result: false,
        evaluatedIssueKey: issueKey,
        evalError: `Forge backend could not evaluate the safety gate (${msg}) — no transition decision was made.`,
      });
    } finally {
      activeTransitionRef.current = false;
      setIsTransitionModalOpen(true);
    }
  };

  const handleBindIssue = async (
    hazardKey: string,
    issueKey: string,
    linkId?: string
  ): Promise<boolean> => {
    if (activeMutationRef.current) return false;
    activeMutationRef.current = true;
    mutationEpochRef.current += 1;
    suiteRequestSeqRef.current += 1;
    setIsMutating(true);

    try {
      const resp: unknown = await invokeResolver('bindIssueToHazard', {
        hazardKey,
        issueKey,
        linkId,
      });
      if (isPlainRecord(resp) && resp.success === true && isComplianceSummary(resp.summary)) {
        suiteRequestSeqRef.current += 1;
        commitSummary(resp.summary);
        setBlastRadius(null);
        setNotice(null);
        return true;
      }
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Bind issue failed: ${extractErrorMessage(resp) || 'Unknown backend error'}`,
      });
      return false;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Bind issue failed';
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Bind issue failed (${msg}).`,
      });
      return false;
    } finally {
      activeMutationRef.current = false;
      setIsMutating(false);
    }
  };

  const handleRecordTestResult = async (params: {
    hazardKey: string;
    linkId?: string;
    testKey: string;
    status: VerificationTest['status'];
    evidenceUrl: string;
    notes: string;
  }): Promise<boolean> => {
    if (activeMutationRef.current) return false;
    activeMutationRef.current = true;
    mutationEpochRef.current += 1;
    suiteRequestSeqRef.current += 1;
    setIsMutating(true);

    try {
      const raw: unknown = await invokeResolver('recordTestResult', params);
      const outcome = resolveMutationSummaryResponse(raw, 'Recording test result');
      if (outcome.ok) {
        suiteRequestSeqRef.current += 1;
        commitSummary(outcome.summary);
        setBlastRadius(null);
        setNotice(null);
        return true;
      }
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Recording test result failed (${outcome.error}).`,
      });
      return false;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to record test result';
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Recording test result failed (${msg}).`,
      });
      return false;
    } finally {
      activeMutationRef.current = false;
      setIsMutating(false);
    }
  };

  const handleSignOffPart11 = async (params: {
    hazardKey: string;
    linkId?: string;
    specId?: string;
    meaning: string;
    attestationConfirmed: boolean;
    passwordConfirmed: boolean;
    attestationPhrase: string;
  }): Promise<boolean> => {
    if (activeMutationRef.current) return false;
    activeMutationRef.current = true;
    mutationEpochRef.current += 1;
    suiteRequestSeqRef.current += 1;
    setIsMutating(true);

    try {
      const raw: unknown = await invokeResolver('signOffPart11', params);
      const outcome = resolveMutationSummaryResponse(raw, 'Part 11 electronic signature');
      if (outcome.ok) {
        suiteRequestSeqRef.current += 1;
        commitSummary(outcome.summary);
        setBlastRadius(null);
        setNotice(null);
        return true;
      }
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Part 11 electronic signature failed (${outcome.error}).`,
      });
      return false;
    } catch (err) {
      const msg = err instanceof Error ? err.message : '21 CFR Part 11 sign-off failed';
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Part 11 electronic signature failed (${msg}).`,
      });
      return false;
    } finally {
      activeMutationRef.current = false;
      setIsMutating(false);
    }
  };

  const handleRemediateDemo = async (hazardKey: string, meaning: string): Promise<boolean> => {
    if (activeMutationRef.current) return false;
    activeMutationRef.current = true;
    mutationEpochRef.current += 1;
    suiteRequestSeqRef.current += 1;
    setIsMutating(true);

    try {
      const raw: unknown = await invokeResolver('remediateGap', {
        hazardKey,
        simulate: true,
        attestationConfirmed: true,
        meaning,
      });
      const outcome = resolveMutationSummaryResponse(raw, 'Simulated remediation');
      if (outcome.ok) {
        suiteRequestSeqRef.current += 1;
        commitSummary(outcome.summary);
        setBlastRadius(null);
        setNotice(null);
        return true;
      }
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Simulated remediation failed (${outcome.error}). Compliance gap remains OPEN.`,
      });
      return false;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Demo remediation failed';
      setNotice({
        kind: 'error',
        source: 'mutation',
        message: `Simulated remediation failed (${msg}). Compliance gap remains OPEN.`,
      });
      return false;
    } finally {
      activeMutationRef.current = false;
      setIsMutating(false);
    }
  };

  const isAnyMutationBusy = isSeeding || isSyncingLive || isMutating;
  const isBusy = isAnyMutationBusy || isAnalyzingBlastRadius;
  const selectedLink = summary
    ? summary.traceLinks.find((l) => l.id === selectedLinkId) || null
    : null;

  if (!summary) {
    return (
      <div
        style={{
          minHeight: '100vh',
          background: 'var(--mt-bg-page, #f4f5f7)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 14,
          padding: 24,
        }}
      >
        <div
          style={{
            background: 'var(--mt-brand-bg, #0052cc)',
            borderRadius: 10,
            padding: 12,
            display: 'flex',
          }}
        >
          <ShieldCheck size={30} color="var(--ds-text-inverse, #ffffff)" />
        </div>
        <div
          style={{
            fontSize: 16,
            fontWeight: 800,
            color: 'var(--mt-text-primary, #172b4d)',
          }}
        >
          {isInitialLoading
            ? 'Loading MedTrace compliance suite…'
            : 'MedTrace compliance suite unavailable'}
        </div>
        {notice && (
          <div
            role={notice.kind === 'error' ? 'alert' : 'status'}
            style={{
              maxWidth: 480,
              fontSize: 12,
              color: 'var(--mt-danger-text, #bf2600)',
              textAlign: 'center',
              lineHeight: '18px',
            }}
          >
            {notice.message}
          </div>
        )}
        <button
          type="button"
          onClick={() => {
            void fetchAndApplySuite('initial');
          }}
          disabled={isInitialLoading}
          className="mt-btn"
          style={{
            padding: '8px 18px',
            border: '1.5px solid var(--mt-brand-bg, #0052cc)',
            background: 'var(--mt-brand-subtle-bg, #deebff)',
            color: 'var(--mt-brand-text, #0052cc)',
          }}
        >
          {isInitialLoading ? 'Loading…' : 'Retry Live Load'}
        </button>
      </div>
    );
  }

  const noticeStyle = notice ? getNoticeVisualStyle(notice.kind) : undefined;

  return (
    <div className={`mt-app ${panelContext.isCompactPanel ? 'mt-panel-compact' : ''}`}>
      <AuditHeader
        summary={summary}
        panelContext={panelContext}
        activeView={activeView}
        onToggleView={setActiveView}
        onSeed={handleSeed}
        onSyncLive={() => {
          void handleSyncLive();
        }}
        onOpenAuditLog={() => setIsAuditLogOpen(true)}
        onOpenExport={() => setIsExportOpen(true)}
        onTestTransition={() => {
          void handleTestTransition();
        }}
        onAnalyzeBlastRadius={() => {
          void handleAnalyzeBlastRadius();
        }}
        isSeeding={isSeeding}
        isSyncingLive={isSyncingLive}
        isAnalyzingBlastRadius={isAnalyzingBlastRadius}
        isMutating={isMutating}
        isBusy={isBusy}
      />

      {notice && noticeStyle && (
        <div
          className="no-print"
          role={notice.kind === 'error' ? 'alert' : 'status'}
          style={{
            margin: '12px 24px 0',
            padding: '10px 14px',
            borderRadius: 6,
            background: noticeStyle.background,
            border: noticeStyle.border,
            color: noticeStyle.color,
            fontSize: 12,
            fontWeight: 600,
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 12,
            flexWrap: 'wrap',
          }}
        >
          <span>{notice.message}</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {notice.retryable && (
              <button
                type="button"
                onClick={() => {
                  void fetchAndApplySuite('focus');
                }}
                disabled={isAnyMutationBusy}
                className="mt-btn"
                style={{
                  padding: '4px 10px',
                  border: '1px solid currentColor',
                  background: 'var(--mt-bg-surface, #ffffff)',
                  color: 'inherit',
                }}
              >
                Refresh Now
              </button>
            )}
            <button
              type="button"
              onClick={() => setNotice(null)}
              aria-label="Dismiss notification"
              className="mt-icon-btn"
              style={{ color: noticeStyle.color, fontWeight: 700, fontSize: 13 }}
            >
              ✕
            </button>
          </div>
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
        isGlobalBusy={isSeeding || isSyncingLive || isAnalyzingBlastRadius}
      />

      <ConfirmSeedModal
        isOpen={isConfirmSeedOpen}
        currentMode={summary.datasetMode}
        linkCount={summary.traceLinks.length}
        isSubmitting={isSeeding}
        isBusy={isBusy}
        onConfirm={() => {
          void executeSeed(true);
        }}
        onCancel={() => {
          if (!activeMutationRef.current) {
            setIsConfirmSeedOpen(false);
          }
        }}
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
