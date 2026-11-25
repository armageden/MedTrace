import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { FullContext } from '@forge/bridge';
import { enableForgeTheme, getForgeContext, invokeResolver } from './bridge';
import { getErrorMessage, isPlainRecord } from './utils';
import {
  BlastRadiusReport,
  ComplianceSummary,
  ForgePanelContext,
  LiveSyncOptions,
  TransitionResult,
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
  actionLabel: string,
  acceptWarningWithSummary = false
): MutationSummaryOutcome {
  if (!isPlainRecord(raw)) {
    return { ok: false, error: `${actionLabel} returned an empty or malformed response.` };
  }
  if (raw.success === false) {
    if (
      (raw.partialSuccess === true || (acceptWarningWithSummary && typeof raw.error !== 'string')) &&
      isComplianceSummary(raw.summary)
    ) {
      return { ok: true, summary: raw.summary };
    }
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
  const spaceObj = isPlainRecord(ext?.space) ? ext.space : undefined;
  const issueKey = typeof issueObj?.key === 'string' ? issueObj.key : undefined;
  const projectKey = typeof projectObj?.key === 'string' ? projectObj.key : undefined;
  const spaceId =
    spaceObj?.id !== undefined && spaceObj?.id !== null ? String(spaceObj.id) : undefined;
  const contentId =
    contentObj?.id !== undefined && contentObj?.id !== null ? String(contentObj.id) : undefined;

  return {
    extensionType,
    isCompactPanel,
    isConfluence,
    issueKey,
    projectKey,
    spaceId,
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
  const [isCreatingLiveProof, setIsCreatingLiveProof] = useState(false);
  const [isMutating, setIsMutating] = useState(false);
  const [isTestingTransition, setIsTestingTransition] = useState(false);
  const [transitionResult, setTransitionResult] = useState<TransitionResult | null>(null);
  const [isTransitionModalOpen, setIsTransitionModalOpen] = useState(false);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusReport | null>(null);
  const [isAnalyzingBlastRadius, setIsAnalyzingBlastRadius] = useState(false);

  const summaryRef = useRef<ComplianceSummary | null>(null);
  const activeMutationRef = useRef(false);
  const initialInFlightRef = useRef(false);
  const suitePollInFlightRef = useRef(false);
  const mutationEpochRef = useRef(0);
  const suiteRequestSeqRef = useRef(0);
  const activeTransitionRef = useRef(false);
  const activeBlastRef = useRef(false);
  const lastFocusFetchRef = useRef(0);
  const autoSelectedForContextRef = useRef(false);
  const userToggledViewRef = useRef(false);
  const pollPausedRef = useRef(false);
  const LARGE_WORKSPACE_MATRIX_THRESHOLD = 25;

  const commitSummary = useCallback((next: ComplianceSummary) => {
    summaryRef.current = next;
    setSummary(next);
    if (!userToggledViewRef.current && next.traceLinks.length >= LARGE_WORKSPACE_MATRIX_THRESHOLD) {
      setActiveView('table');
    }
  }, []);

  const handleToggleView = useCallback((view: 'graph' | 'table') => {
    userToggledViewRef.current = true;
    setActiveView(view);
  }, []);

  const fetchAndApplySuite = useCallback(
    async (mode: 'initial' | 'poll' | 'focus') => {
      if (
        mode !== 'initial' &&
        (activeMutationRef.current || initialInFlightRef.current || suitePollInFlightRef.current)
      ) {
        return;
      }

      const reqSeq = ++suiteRequestSeqRef.current;
      const mutEpoch = mutationEpochRef.current;
      if (mode === 'initial') {
        initialInFlightRef.current = true;
        pollPausedRef.current = false;
        setIsInitialLoading(true);
      } else {
        suitePollInFlightRef.current = true;
      }

      try {
        const result: unknown =
          (await (mode === 'poll' || mode === 'focus'
            ? invokeResolver('getComplianceSuite', { skipReconcile: true })
            : invokeResolver('getComplianceSuite'))) ?? null;
        if (
          reqSeq !== suiteRequestSeqRef.current ||
          mutEpoch !== mutationEpochRef.current ||
          activeMutationRef.current
        ) {
          return;
        }

        if (isComplianceSummary(result)) {
          pollPausedRef.current = false;
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
        const detail = getErrorMessage(err, 'Forge bridge invoke failed');
        const isAuthLike = /auth|consent|401|403|token|session|expired|unauthor/i.test(detail);
        if (summaryRef.current === null || isAuthLike) {
          pollPausedRef.current = true;
        }
        if (mode === 'poll') {
          if (isAuthLike && summaryRef.current !== null) {
            setNotice((prev) => {
              if (prev && prev.source !== 'load') return prev;
              return {
                kind: 'warning',
                source: 'load',
                message: `Live refresh paused (${detail}); showing last verified compliance state.`,
                retryable: true,
              };
            });
          }
          return;
        }
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
          initialInFlightRef.current = false;
          if (reqSeq === suiteRequestSeqRef.current) {
            setIsInitialLoading(false);
          }
        } else {
          suitePollInFlightRef.current = false;
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
        if (parsed.isCompactPanel && !userToggledViewRef.current) {
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

  // Initial load + adaptive 30s cache-only polling + deduplicated focus/visibility refresh
  useEffect(() => {
    void fetchAndApplySuite('initial');

    const pollInterval = setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      if (activeMutationRef.current || pollPausedRef.current) return;
      void fetchAndApplySuite('poll');
    }, 30000);

    const onVisibilityOrFocus = () => {
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return;
      }
      if (activeMutationRef.current || pollPausedRef.current) return;
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

  const runSummaryMutation = async (opts: {
    setBusy: (busy: boolean) => void;
    actionLabel: string;
    noticeSource?: UiNotice['source'];
    acceptWarningWithSummary?: boolean;
    invoke: () => Promise<unknown>;
    onSuccess?: (raw: unknown, nextSummary: ComplianceSummary) => void;
    formatError: (detail: string, threw: boolean) => string;
    onFinally?: () => void;
  }): Promise<boolean> => {
    if (activeMutationRef.current) return false;
    activeMutationRef.current = true;
    mutationEpochRef.current += 1;
    suiteRequestSeqRef.current += 1;
    opts.setBusy(true);

    try {
      const raw: unknown = await opts.invoke();
      const outcome = resolveMutationSummaryResponse(
        raw,
        opts.actionLabel,
        opts.acceptWarningWithSummary === true
      );
      if (outcome.ok) {
        suiteRequestSeqRef.current += 1;
        commitSummary(outcome.summary);
        setBlastRadius(null);
        setNotice(null);
        opts.onSuccess?.(raw, outcome.summary);
        return true;
      }
      setNotice({
        kind: 'error',
        source: opts.noticeSource ?? 'mutation',
        message: opts.formatError(outcome.error, false),
      });
      return false;
    } catch (err) {
      const msg = getErrorMessage(err, `${opts.actionLabel} failed`);
      setNotice({
        kind: 'error',
        source: opts.noticeSource ?? 'mutation',
        message: opts.formatError(msg, true),
      });
      return false;
    } finally {
      activeMutationRef.current = false;
      opts.setBusy(false);
      opts.onFinally?.();
    }
  };

  const executeSeed = async (confirmOverwriteLive: boolean): Promise<boolean> =>
    runSummaryMutation({
      setBusy: setIsSeeding,
      actionLabel: 'Seeding',
      invoke: () =>
        invokeResolver(
          'seedDemoSuite',
          confirmOverwriteLive ? { confirmOverwriteLive: true } : undefined
        ),
      onSuccess: () => setSelectedLinkId(null),
      formatError: (detail) => `Seeding failed (${detail}). Existing state was NOT changed.`,
      onFinally: () => setIsConfirmSeedOpen(false),
    });

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
    resumeFromCursor?: boolean;
  }): Promise<boolean> =>
    runSummaryMutation({
      setBusy: setIsSyncingLive,
      actionLabel: options?.resumeFromCursor ? 'Resume Live Atlassian sync' : 'Live Atlassian sync',
      noticeSource: 'sync',
      acceptWarningWithSummary: true,
      invoke: () => {
        const payload: Omit<LiveSyncOptions, 'callerMode'> = {
          projectKey: panelContext.projectKey,
          ...(panelContext.spaceId ? { spaceId: panelContext.spaceId } : {}),
          ...(typeof options?.includeUntaggedIssues === 'boolean'
            ? { includeUntaggedIssues: options.includeUntaggedIssues }
            : {}),
          ...(options?.resumeFromCursor === true ? { resumeFromCursor: true } : {}),
        };
        return invokeResolver('syncLiveSuite', payload);
      },
      onSuccess: (resp, nextSummary) => {
        setSelectedLinkId((prev) =>
          prev && nextSummary.traceLinks.some((l) => l.id === prev) ? prev : null
        );
        if (!isPlainRecord(resp)) return;

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

        if (warnings.length > 0 || resp.truncated === true || nextSummary.syncIncomplete === true) {
          setNotice({
            kind: 'warning',
            source: 'sync',
            message: `Live sync scanned ${jiraIssuesScanned} Jira issue(s) and ${confluencePagesScanned} Confluence page(s): ${
              warnings.join(' ') || 'Results truncated; click Resume Sync to finish.'
            }`,
          });
        } else if (skippedUntaggedCount > 0) {
          setNotice({
            kind: 'info',
            source: 'sync',
            message: `Live sync scanned ${jiraIssuesScanned} Jira issue(s) and ${confluencePagesScanned} Confluence page(s) (${skippedUntaggedCount} untagged issue(s) skipped).`,
          });
        }
      },
      formatError: (detail) =>
        `Live Atlassian sync failed (${detail}). Existing state was NOT changed.`,
    });

  const handleCreateLiveProof = async (): Promise<boolean> =>
    runSummaryMutation({
      setBusy: setIsCreatingLiveProof,
      actionLabel: 'Live proof chain creation',
      noticeSource: 'sync',
      invoke: () =>
        invokeResolver('createLiveProofScenario', {
          ...(panelContext.projectKey ? { projectKey: panelContext.projectKey } : {}),
          ...(panelContext.spaceId ? { spaceId: panelContext.spaceId } : {}),
        }),
      onSuccess: (raw, nextSummary) => {
        if (!isPlainRecord(raw)) return;
        const createdWorkKey = typeof raw.workIssueKey === 'string' ? raw.workIssueKey.trim().toUpperCase() : '';
        const createdLink = createdWorkKey
          ? nextSummary.traceLinks.find((link) => link.work.key.trim().toUpperCase() === createdWorkKey)
          : undefined;
        if (createdLink) setSelectedLinkId(createdLink.id);
        const hazardIssueKey = typeof raw.hazardIssueKey === 'string' ? raw.hazardIssueKey : 'unknown hazard';
        const workIssueKey = typeof raw.workIssueKey === 'string' ? raw.workIssueKey : 'unknown work item';
        const testIssueKey = typeof raw.testIssueKey === 'string' ? raw.testIssueKey : 'unknown test';
        const pageId = typeof raw.pageId === 'string' ? raw.pageId : 'unknown page';
        const warnings = Array.isArray(raw.warnings)
          ? raw.warnings.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
          : [];
        setNotice({
          kind: warnings.length > 0 ? 'warning' : 'success',
          source: 'sync',
          message: `Created live proof chain: Confluence page ${pageId}, hazard ${hazardIssueKey}, work ${workIssueKey}, and verification test ${testIssueKey}. Next: record HTTPS test evidence and sign off, then edit the requirement from 5.0 to 5.5 mL/hr.${
            warnings.length > 0 ? ` ${warnings.join(' ')}` : ''
          }`,
        });
      },
      formatError: (detail) =>
        `Live proof chain creation failed (${detail}). Any artifacts listed in the error were real Atlassian records and were not deleted automatically.`,
    });

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
    const mutEpoch = mutationEpochRef.current;
    setIsAnalyzingBlastRadius(true);
    try {
      const currentSelected =
        currentSummary.traceLinks.find((l) => l.id === selectedLinkId) ||
        currentSummary.traceLinks[0];
      const triggerKey = currentSelected?.spec?.id || currentSelected?.hazard?.key || '';
      const report: unknown = await invokeResolver('analyzeBlastRadius', { triggerKey });
      if (mutEpoch !== mutationEpochRef.current || activeMutationRef.current) {
        return;
      }
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
      if (mutEpoch !== mutationEpochRef.current || activeMutationRef.current) {
        return;
      }
      const msg = getErrorMessage(err, 'Blast radius analysis failed');
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
    const mutEpoch = mutationEpochRef.current;
    setIsTestingTransition(true);
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
      if (mutEpoch !== mutationEpochRef.current || activeMutationRef.current) {
        return;
      }
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
      setIsTransitionModalOpen(true);
    } catch (err) {
      if (mutEpoch !== mutationEpochRef.current || activeMutationRef.current) {
        return;
      }
      const msg = getErrorMessage(err, 'Forge backend unreachable');
      setTransitionResult({
        result: false,
        evaluatedIssueKey: issueKey,
        evalError: `Forge backend could not evaluate the safety gate (${msg}) — no transition decision was made.`,
      });
      setIsTransitionModalOpen(true);
    } finally {
      activeTransitionRef.current = false;
      setIsTestingTransition(false);
    }
  };

  const handleBindIssue = async (
    hazardKey: string,
    issueKey: string,
    linkId?: string
  ): Promise<boolean> =>
    runSummaryMutation({
      setBusy: setIsMutating,
      actionLabel: 'Bind issue',
      invoke: () => invokeResolver('bindIssueToHazard', { hazardKey, issueKey, linkId }),
      formatError: (detail, threw) =>
        threw ? `Bind issue failed (${detail}).` : `Bind issue failed: ${detail}`,
    });

  const handleRecordTestResult = async (params: {
    hazardKey: string;
    linkId?: string;
    testKey: string;
    status: VerificationTest['status'];
    evidenceUrl: string;
    notes: string;
  }): Promise<boolean> =>
    runSummaryMutation({
      setBusy: setIsMutating,
      actionLabel: 'Recording test result',
      invoke: () => invokeResolver('recordTestResult', params),
      formatError: (detail) => `Recording test result failed (${detail}).`,
    });

  const handleSignOffPart11 = async (params: {
    hazardKey: string;
    linkId?: string;
    specId?: string;
    meaning: string;
    attestationConfirmed: boolean;
    attestationChecked: boolean;
    attestationPhrase: string;
  }): Promise<boolean> =>
    runSummaryMutation({
      setBusy: setIsMutating,
      actionLabel: 'Electronic attestation',
      invoke: () => invokeResolver('signOffPart11', params),
      formatError: (detail) => `Electronic attestation failed (${detail}).`,
    });

  const handleRemediateDemo = async (hazardKey: string, meaning: string): Promise<boolean> =>
    runSummaryMutation({
      setBusy: setIsMutating,
      actionLabel: 'Simulated remediation',
      invoke: () =>
        invokeResolver('remediateGap', {
          hazardKey,
          simulate: true,
          attestationConfirmed: true,
          meaning,
        }),
      formatError: (detail) =>
        `Simulated remediation failed (${detail}). Compliance gap remains OPEN.`,
    });

  const handleCreateReverificationTask = async (params: {
    hazardKey?: string;
    linkId?: string;
    issueKey?: string;
    reason?: string;
  }): Promise<boolean> =>
    runSummaryMutation({
      setBusy: setIsMutating,
      actionLabel: 'Create re-verification task',
      invoke: () => invokeResolver('createReverificationTask', params),
      onSuccess: (raw) => {
        if (isPlainRecord(raw) && typeof raw.createdIssueKey === 'string') {
          const linked = Array.isArray(raw.linkedIssueKeys)
            ? raw.linkedIssueKeys.filter((k): k is string => typeof k === 'string')
            : [];
          const failed = Array.isArray(raw.failedLinkKeys)
            ? raw.failedLinkKeys.filter((k): k is string => typeof k === 'string')
            : [];
          const missing = Array.isArray(raw.missingLinkKeys)
            ? raw.missingLinkKeys.filter((k): k is string => typeof k === 'string')
            : [];
          if (failed.length > 0) {
            setNotice({
              kind: 'warning',
              source: 'mutation',
              message: `Created Jira re-verification task ${raw.createdIssueKey}, but failed to link: ${failed.join(', ')}.${
                linked.length > 0 ? ` Linked: ${linked.join(', ')}.` : ''
              }`,
            });
          } else if (raw.alreadyExisted === true) {
            if (missing.length > 0 || raw.linksVerified === false) {
              setNotice({
                kind: 'warning',
                source: 'mutation',
                message: `Found existing open Jira re-verification task ${raw.createdIssueKey}; verified links: ${
                  linked.join(', ') || 'none'
                } (missing/unverified: ${missing.join(', ') || 'unknown'}).`,
              });
            } else {
              setNotice({
                kind: 'info',
                source: 'mutation',
                message: `Found existing open Jira re-verification task ${raw.createdIssueKey}${
                  linked.length > 0 ? ` linked to ${linked.join(', ')}` : ''
                }.`,
              });
            }
          } else if (linked.length === 0) {
            setNotice({
              kind: 'info',
              source: 'mutation',
              message: `Created Jira re-verification task ${raw.createdIssueKey} (no native Jira issues were linked).`,
            });
          } else {
            setNotice({
              kind: 'success',
              source: 'mutation',
              message: `Created Jira re-verification task ${raw.createdIssueKey} linked to ${linked.join(', ')}.`,
            });
          }
        }
      },
      formatError: (detail) => `Failed to create re-verification Jira task (${detail}).`,
    });

  const isAnyMutationBusy = isSeeding || isSyncingLive || isCreatingLiveProof || isMutating;
  const isBusy = isAnyMutationBusy || isAnalyzingBlastRadius;
  const selectedLink = summary
    ? summary.traceLinks.find((l) => l.id === selectedLinkId) || null
    : null;

  if (!summary) {
    return (
      <div
        role="status"
        aria-busy={isInitialLoading || undefined}
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
          <ShieldCheck size={30} color="var(--ds-text-inverse, #ffffff)" aria-hidden="true" />
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
        onToggleView={handleToggleView}
        onSeed={handleSeed}
        onSyncLive={() => {
          void handleSyncLive();
        }}
        onResumeSync={() => {
          void handleSyncLive({ resumeFromCursor: true });
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
        isTestingTransition={isTestingTransition}
        isMutating={isMutating}
        isBusy={isBusy}
      />

      {notice && noticeStyle && (
        <div
          className="no-print"
          role={notice.kind === 'error' ? 'alert' : 'status'}
          style={{
            margin: panelContext.isCompactPanel ? '10px 14px 0' : '12px 24px 0',
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
                  pollPausedRef.current = false;
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
            onSyncLive={() => {
              void handleSyncLive();
            }}
            onSeedDemo={handleSeed}
            onCreateLiveProof={() => {
              void handleCreateLiveProof();
            }}
            canCreateLiveProof={Boolean(panelContext.projectKey)}
            isBusy={isBusy}
          />
        ) : (
          <TraceMatrixTable
            summary={summary}
            onSelectTraceLink={setSelectedLinkId}
            onSyncLive={() => {
              void handleSyncLive();
            }}
            onSeedDemo={handleSeed}
            onCreateLiveProof={() => {
              void handleCreateLiveProof();
            }}
            canCreateLiveProof={Boolean(panelContext.projectKey)}
            isBusy={isBusy}
          />
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
        onCreateReverificationTask={handleCreateReverificationTask}
        isMutating={isMutating}
        isGlobalBusy={isSeeding || isSyncingLive || isCreatingLiveProof || isAnalyzingBlastRadius}
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

      {isExportOpen && (
        <FdaExportModal
          summary={summary}
          projectKey={panelContext.projectKey}
          onClose={() => setIsExportOpen(false)}
        />
      )}

      <AuditLogModal
        isOpen={isAuditLogOpen}
        projectKey={panelContext.projectKey}
        datasetMode={summary.datasetMode}
        onClose={() => setIsAuditLogOpen(false)}
      />

      <TransitionModal
        isOpen={isTransitionModalOpen}
        onClose={() => setIsTransitionModalOpen(false)}
        result={transitionResult}
        summary={summary}
      />
    </div>
  );
};
