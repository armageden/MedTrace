import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { FullContext } from '@forge/bridge';
import { App } from '../App';
import { AuditHeader } from '../components/AuditHeader';
import * as bridgeModule from '../bridge';
import {
  ComplianceSummary,
  PART11_ATTESTATION_PHRASE,
  TraceLink,
} from '../types';

vi.mock('@xyflow/react', () => ({
  ReactFlow: ({ children }: { children?: React.ReactNode }) => (
    <div data-testid="mock-react-flow">{children}</div>
  ),
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  MarkerType: { ArrowClosed: 'arrowclosed' },
  useViewport: () => ({ x: 0, y: 0, zoom: 1 }),
}));

vi.mock('../bridge', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../bridge')>();
  return {
    ...actual,
    getForgeContext: vi.fn(),
    enableForgeTheme: vi.fn(),
    invokeResolver: vi.fn(),
  };
});

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function makeTraceLink(overrides: {
  id?: string;
  hazardKey?: string;
  workKey?: string;
  sigValid?: boolean;
  testStatus?: TraceLink['test']['status'];
  complianceState?: TraceLink['complianceState'];
}): TraceLink {
  const id = overrides.id ?? 'link-1';
  const hazardKey = overrides.hazardKey ?? 'HAZ-101';
  const workKey = overrides.workKey ?? 'MED-43';
  const sigValid = overrides.sigValid ?? false;
  const testStatus = overrides.testStatus ?? 'PASSED';
  const complianceState = overrides.complianceState ?? (sigValid ? 'VERIFIED' : 'SIGNATURE_DRIFT');

  return {
    id,
    hazard: {
      id: `haz-${id}`,
      key: hazardKey,
      title: `Hazard for ${hazardKey}`,
      riskClass: 'CLASS_C',
      severity: 'CRITICAL',
      probability: 'REMOTE',
      mitigationRequirementId: 'SRS-1',
      status: complianceState === 'VERIFIED' ? 'MITIGATED' : 'ACTION_REQUIRED',
    },
    spec: {
      id: `spec-${id}`,
      pageId: `page-${id}`,
      title: 'SRS-201: Basal Rate Safety Guard',
      version: 3,
      sha256Hash: 'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff66667777888899990000',
      lastSignedHash: sigValid
        ? 'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff66667777888899990000'
        : '0000',
      isSignatureInvalidated: !sigValid,
      contentSnippet: 'Safety requirement snippet',
      lastUpdated: '2026-01-10T00:00:00.000Z',
    },
    work: {
      id: workKey ? `work-${id}` : '',
      key: workKey,
      title: workKey ? `Implement ${workKey}` : 'Unbound work item',
      status: workKey ? 'Done' : 'To Do',
      assignee: workKey ? 'Alice Engineer' : '',
    },
    test: {
      id: `test-${id}`,
      testKey: `TEST-${id}`,
      title: 'HIL safety verification',
      testType: 'Automated HIL (Hardware-in-Loop)',
      status: testStatus,
      evidenceUrl: 'https://ci.example.com/builds/42',
    },
    signature: {
      id: `sig-${id}`,
      signedBy: sigValid ? 'Alice QA' : '',
      signedAt: sigValid ? '2026-01-11T00:00:00.000Z' : '',
      role: 'QA Lead',
      meaning: 'Safety verification sign-off',
      artifactSha256: 'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff66667777888899990000',
      isValid: sigValid,
    },
    complianceState,
    violations: complianceState === 'VERIFIED' ? [] : ['Signature invalid or drifted'],
  };
}

function makeSuite(overrides?: Partial<ComplianceSummary>): ComplianceSummary {
  const traceLinks = overrides?.traceLinks ?? [
    makeTraceLink({ id: 'link-1', hazardKey: 'HAZ-101', workKey: 'MED-43', sigValid: false }),
  ];
  const verifiedCount = traceLinks.filter((l) => l.complianceState === 'VERIFIED').length;
  const totalHazards = overrides?.totalHazards ?? traceLinks.length;
  const releaseBlocked =
    overrides?.releaseBlocked ?? (totalHazards === 0 || verifiedCount < totalHazards);

  return {
    projectName: 'PumpGuard Live',
    datasetMode: 'LIVE',
    initialized: true,
    standards: ['IEC 62304:2006+A1:2015', 'ISO 14971:2019', 'FDA 21 CFR Part 11'],
    totalHazards,
    classCCount: totalHazards,
    classBCount: 0,
    classACount: 0,
    verifiedPercentage: totalHazards === 0 ? 0 : Math.round((verifiedCount / totalHazards) * 100),
    releaseBlocked,
    blockingReasons: releaseBlocked ? ['Unverified trace link present'] : [],
    signatureDriftCount: traceLinks.filter((l) => l.spec.isSignatureInvalidated).length,
    traceLinks,
    lastAuditTimestamp: '2026-01-11T00:00:00.000Z',
    auditEntryCount: 5,
    auditHeadHash: 'headhash1234567890',
    ...overrides,
  };
}

function makeFullContext(extension: FullContext['extension']): FullContext {
  return {
    accountId: 'acc-1',
    cloudId: 'cloud-1',
    extension,
    environmentId: 'env-1',
    environmentType: 'DEVELOPMENT',
    localId: 'local-1',
    locale: 'en-US',
    moduleKey: 'medtrace-panel',
    siteUrl: 'https://example.atlassian.net',
    timezone: 'UTC',
  };
}

describe('FE-01..FE-04 & FE-07: App races, bridge errors, confirm seed, and transition precedence', () => {
  const mockedGetForgeContext = vi.mocked(bridgeModule.getForgeContext);
  const mockedEnableForgeTheme = vi.mocked(bridgeModule.enableForgeTheme);
  const mockedInvokeResolver = vi.mocked(bridgeModule.invokeResolver);

  beforeEach(() => {
    vi.clearAllMocks();
    mockedGetForgeContext.mockResolvedValue(
      makeFullContext({ type: 'jira:projectPage', project: { key: 'MED' } })
    );
    mockedEnableForgeTheme.mockResolvedValue(true);
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'visible',
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('renders role="alert" and Retry Live Load outside Forge without simulating data', async () => {
    mockedGetForgeContext.mockResolvedValue(null);
    mockedEnableForgeTheme.mockResolvedValue(false);
    mockedInvokeResolver
      .mockRejectedValueOnce(new bridgeModule.BridgeUnavailableError())
      .mockResolvedValueOnce(makeSuite());

    render(<App />);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/could not be loaded/i);
    expect(screen.getByText('MedTrace compliance suite unavailable')).toBeInTheDocument();

    const retryBtn = screen.getByRole('button', { name: 'Retry Live Load' });
    await userEvent.click(retryBtn);

    await waitFor(() => {
      expect(screen.getByText('PumpGuard Live')).toBeInTheDocument();
    });
    expect(mockedEnableForgeTheme).toHaveBeenCalledTimes(1);
  });

  it('discards stale in-flight poll responses that resolve after a mutation (mutationEpochRef)', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });

    const staleSuite = makeSuite({
      traceLinks: [makeTraceLink({ id: 'link-1', hazardKey: 'HAZ-101', workKey: 'MED-43', sigValid: false })],
      lastAuditTimestamp: '2026-01-11T00:00:00.000Z',
    });
    const signedSuite = makeSuite({
      traceLinks: [
        makeTraceLink({
          id: 'link-1',
          hazardKey: 'HAZ-101',
          workKey: 'MED-43',
          sigValid: true,
          complianceState: 'VERIFIED',
        }),
      ],
      lastAuditTimestamp: '2026-01-11T00:05:00.000Z',
    });

    const deferredPoll = createDeferred<ComplianceSummary>();
    let getSuiteCount = 0;

    mockedInvokeResolver.mockImplementation(async (key) => {
      if (key === 'getComplianceSuite') {
        getSuiteCount += 1;
        if (getSuiteCount === 1) return staleSuite;
        return deferredPoll.promise;
      }
      if (key === 'queryGraphContext') return null;
      if (key === 'signOffPart11') return signedSuite;
      throw new Error(`Unexpected resolver ${key}`);
    });

    render(<App />);
    await screen.findByText('PumpGuard Live');

    // Switch to table view and open drawer
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    await user.click(screen.getByRole('button', { name: /matrix/i }));
    await user.click(screen.getByRole('button', { name: 'Inspect HAZ-101 lineage' }));

    // Trigger 8s poll while drawer is open
    await act(async () => {
      vi.advanceTimersByTime(8000);
    });
    expect(getSuiteCount).toBe(2);

    // Execute Part 11 sign-off while slow poll is still pending
    await user.type(
      screen.getByLabelText(/Required Attestation Phrase/i),
      PART11_ATTESTATION_PHRASE
    );
    await user.click(
      screen.getByLabelText(/I confirm my active Atlassian user session re-attestation/i)
    );
    await user.click(
      screen.getByLabelText(/I attest under 21 CFR Part 11/i)
    );
    await user.click(screen.getByRole('button', { name: /Sign Off Spec/i }));

    await waitFor(() => {
      expect(screen.getByText('VALID SIGNATURE')).toBeInTheDocument();
    });

    // Now resolve stale poll; UI MUST NOT revert to SIGNATURE REVOKED
    await act(async () => {
      deferredPoll.resolve(staleSuite);
      await deferredPoll.promise;
    });

    expect(screen.getByText('VALID SIGNATURE')).toBeInTheDocument();
    expect(screen.queryByText('SIGNATURE REVOKED')).not.toBeInTheDocument();
  });

  it('preserves mutation error notices across focus refreshes and shows Refresh Now on malformed focus refresh', async () => {
    const suite = makeSuite();
    let nowMs = 10_000;
    const dateNowSpy = vi.spyOn(Date, 'now').mockImplementation(() => nowMs);
    let suiteCalls = 0;

    mockedInvokeResolver.mockImplementation(async (key) => {
      if (key === 'getComplianceSuite') {
        suiteCalls += 1;
        if (suiteCalls <= 2) return suite;
        if (suiteCalls === 3) return null as unknown as ComplianceSummary;
        return suite;
      }
      if (key === 'queryGraphContext') return null;
      if (key === 'bindIssueToHazard') {
        return { success: false, error: 'Forbidden: Jira issue belongs to another project' };
      }
      throw new Error(`Unexpected resolver ${key}`);
    });

    try {
      render(<App />);
      await screen.findByText('PumpGuard Live');

      const user = userEvent.setup();
      await user.click(screen.getByRole('button', { name: /matrix/i }));
      await user.click(screen.getByRole('button', { name: 'Inspect HAZ-101 lineage' }));
      await user.click(screen.getByRole('button', { name: /Bind/i }));

      const mutAlert = await screen.findByRole('alert');
      expect(mutAlert).toHaveTextContent(/Forbidden: Jira issue belongs to another project/i);

      // Focus refresh succeeds — mutation error notice must NOT be wiped
      nowMs += 2000;
      await act(async () => {
        fireEvent(window, new Event('focus'));
      });
      await waitFor(() => expect(suiteCalls).toBe(2));
      expect(screen.getByRole('alert')).toHaveTextContent(
        /Forbidden: Jira issue belongs to another project/i
      );

      // Dismiss mutation error, then trigger focus returning null -> Refresh Now warning
      await user.click(screen.getByRole('button', { name: 'Dismiss notification' }));
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();

      nowMs += 2000;
      await act(async () => {
        fireEvent(window, new Event('focus'));
      });

      await waitFor(() => {
        expect(screen.getByRole('status')).toHaveTextContent(/showing last verified compliance state/i);
      });
      const refreshNowBtn = screen.getByRole('button', { name: 'Refresh Now' });
      await user.click(refreshNowBtn);

      await waitFor(() => {
        expect(screen.queryByRole('button', { name: 'Refresh Now' })).not.toBeInTheDocument();
      });
    } finally {
      dateNowSpy.mockRestore();
    }
  });

  it('prevents synchronous double-submit, disables cross-buttons while busy, and surfaces signOffPart11 null/false errors without clearing attestation', async () => {
    const suite = makeSuite();
    const deferredSync = createDeferred<Awaited<ReturnType<typeof bridgeModule.invokeResolver<'syncLiveSuite'>>>>();
    let syncCallCount = 0;

    mockedInvokeResolver.mockImplementation(async (key) => {
      if (key === 'getComplianceSuite') return suite;
      if (key === 'queryGraphContext') return null;
      if (key === 'syncLiveSuite') {
        syncCallCount += 1;
        return deferredSync.promise;
      }
      if (key === 'signOffPart11') {
        return null as unknown as ComplianceSummary;
      }
      throw new Error(`Unexpected resolver ${key}`);
    });

    render(<App />);
    await screen.findByText('PumpGuard Live');

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /matrix/i }));
    await user.click(screen.getByRole('button', { name: 'Inspect HAZ-101 lineage' }));

    const syncBtn = screen.getByRole('button', { name: /Sync Live Atlassian/i });
    const seedBtn = screen.getByRole('button', { name: /Seed Demo Suite/i });
    const testGateBtn = screen.getByRole('button', { name: /Test Human Gate/i });
    const blastBtn = screen.getByRole('button', { name: /Blast Radius/i });

    // Synchronous double-click before re-render
    fireEvent.click(syncBtn);
    fireEvent.click(syncBtn);
    expect(syncCallCount).toBe(1);

    await waitFor(() => {
      expect(syncBtn).toBeDisabled();
      expect(seedBtn).toBeDisabled();
      expect(testGateBtn).toBeDisabled();
      expect(blastBtn).toBeDisabled();
      expect(screen.getByRole('button', { name: /Bind/i })).toBeDisabled();
      expect(screen.getByRole('button', { name: /Record Test Result/i })).toBeDisabled();
    });

    await act(async () => {
      deferredSync.resolve({
        success: false,
        datasetMode: 'LIVE',
        jiraIssuesScanned: 4,
        confluencePagesScanned: 2,
        linkedPairsFound: 0,
        driftDetectedCount: 0,
        warnings: ['No safety-tracked Jira issues matched the live sync query.'],
        summary: suite,
      });
    });

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(
        /No safety-tracked Jira issues matched the live sync query/i
      );
      expect(syncBtn).toBeEnabled();
    });

    // Test signOffPart11 returning null retains drawer attestation inputs
    const phraseInput = screen.getByLabelText(/Required Attestation Phrase/i);
    const pwdBox = screen.getByLabelText(/I confirm my active Atlassian user session re-attestation/i);
    const attBox = screen.getByLabelText(/I attest under 21 CFR Part 11/i);

    await user.type(phraseInput, PART11_ATTESTATION_PHRASE);
    await user.click(pwdBox);
    await user.click(attBox);
    await user.click(screen.getByRole('button', { name: /Sign Off Spec/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/Part 11 electronic signature/i);
    });
    expect(phraseInput).toHaveValue(PART11_ATTESTATION_PHRASE);
    expect(pwdBox).toBeChecked();
    expect(attBox).toBeChecked();
  });

  it('gates LIVE Seed Demo Suite behind ConfirmSeedModal and passes confirmOverwriteLive: true on confirm', async () => {
    const liveSuite = makeSuite({ datasetMode: 'LIVE' });
    const demoSuite = makeSuite({ datasetMode: 'DEMO' });

    mockedInvokeResolver.mockImplementation(async (key) => {
      if (key === 'getComplianceSuite') return liveSuite;
      if (key === 'seedDemoSuite') {
        return {
          success: true,
          confluenceEnabled: true,
          summary: demoSuite,
          message: 'Seeded demo suite',
        };
      }
      throw new Error(`Unexpected resolver ${key}`);
    });

    render(<App />);
    await screen.findByText('LIVE ATLASSIAN DATA');

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /Seed Demo Suite/i }));

    const confirmDialog = await screen.findByRole('alertdialog');
    expect(confirmDialog).toHaveTextContent(/Overwrite Initialized LIVE Data with DEMO Suite/i);
    expect(mockedInvokeResolver).not.toHaveBeenCalledWith('seedDemoSuite', expect.anything());

    await user.click(within(confirmDialog).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(mockedInvokeResolver).not.toHaveBeenCalledWith('seedDemoSuite', expect.anything());

    await user.click(screen.getByRole('button', { name: /Seed Demo Suite/i }));
    const reopened = await screen.findByRole('alertdialog');
    await user.click(
      within(reopened).getByRole('button', { name: /Confirm Overwrite & Seed Demo/i })
    );

    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('seedDemoSuite', {
        confirmOverwriteLive: true,
      });
      expect(screen.getByText('DEMO DATASET — MODELED RECORDS')).toBeInTheDocument();
    });
  });

  it('computes handleTestTransition precedence cleanly across global, panel issueKey, bound row, and unbound row', async () => {
    // 1. Outside issuePanel with no row selected -> { scope: 'global' }
    const suiteOutside = makeSuite({
      traceLinks: [
        makeTraceLink({ id: 'link-bound', hazardKey: 'HAZ-101', workKey: 'MED-43' }),
        makeTraceLink({ id: 'link-unbound', hazardKey: 'HAZ-102', workKey: '' }),
      ],
    });
    mockedInvokeResolver.mockImplementation(async (key) => {
      if (key === 'getComplianceSuite') return suiteOutside;
      if (key === 'queryGraphContext') return null;
      if (key === 'simulateTransition') {
        return { result: false, errorMessage: 'Blocked' };
      }
      throw new Error(`Unexpected resolver ${key}`);
    });

    const user = userEvent.setup();
    const { unmount } = render(<App />);
    await screen.findByText('PumpGuard Live');

    await user.click(screen.getByRole('button', { name: /Test Human Gate/i }));
    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('simulateTransition', {
        scope: 'global',
      });
    });
    unmount();

    // 2. Inside jira:issuePanel (MED-10) -> MED-10 when unselected, MED-43 when bound row selected, global when unbound row selected
    vi.clearAllMocks();
    mockedEnableForgeTheme.mockResolvedValue(true);
    mockedGetForgeContext.mockResolvedValue(
      makeFullContext({
        type: 'jira:issuePanel',
        issue: { key: 'MED-10' },
        project: { key: 'MED' },
      })
    );
    mockedInvokeResolver.mockImplementation(async (key, payload) => {
      if (key === 'getComplianceSuite') return suiteOutside;
      if (key === 'queryGraphContext') return null;
      if (key === 'simulateTransition') {
        const p = payload as { issueKey?: string; scope?: string } | undefined;
        return {
          result: p?.scope === 'issue',
          evaluatedIssueKey: p?.issueKey,
        };
      }
      throw new Error(`Unexpected resolver ${key}`);
    });

    render(<App />);
    await screen.findByText(/Jira Issue: MED-10/i);

    await user.click(screen.getByRole('button', { name: /Test Human Gate/i }));
    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('simulateTransition', {
        issueKey: 'MED-10',
        scope: 'issue',
      });
    });
    await user.click(screen.getByRole('button', { name: 'Close Intercept Dialog' }));

    // Select bound row HAZ-101 (MED-43)
    await user.click(screen.getByRole('button', { name: 'Inspect HAZ-101 lineage' }));
    await user.click(screen.getByRole('button', { name: /Test Human Gate/i }));
    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('simulateTransition', {
        issueKey: 'MED-43',
        scope: 'issue',
      });
    });
    await user.click(screen.getByRole('button', { name: 'Close Intercept Dialog' }));

    // Select unbound row HAZ-102 (workKey = '') inside MED-10 panel -> MUST send { scope: 'global' }
    await user.click(screen.getByRole('button', { name: 'Inspect HAZ-102 lineage' }));
    await user.click(screen.getByRole('button', { name: /Test Human Gate/i }));
    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenLastCalledWith('simulateTransition', {
        scope: 'global',
      });
    });
  });

  it('renders UNINITIALIZED (NO DATA) and No Records for 0-hazard suites and avoids All Valid on unsigned suites', () => {
    const emptySuite = makeSuite({
      initialized: false,
      totalHazards: 0,
      classCCount: 0,
      traceLinks: [],
      releaseBlocked: true,
      blockingReasons: ['Suite uninitialized'],
    });
    const noop = () => {};

    const { rerender } = render(
      <AuditHeader
        summary={emptySuite}
        panelContext={{ extensionType: 'jira:projectPage', isCompactPanel: false, isConfluence: false }}
        activeView="graph"
        onToggleView={noop}
        onSeed={noop}
        onSyncLive={noop}
        onOpenAuditLog={noop}
        onOpenExport={noop}
        onTestTransition={noop}
        onAnalyzeBlastRadius={noop}
        isSeeding={false}
        isSyncingLive={false}
        isAnalyzingBlastRadius={false}
      />
    );

    expect(screen.getAllByText('UNINITIALIZED (NO DATA)').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('No Records')).toBeInTheDocument();
    expect(screen.queryByText('All Valid')).not.toBeInTheDocument();
    expect(screen.queryByText('AUDIT READY (ZERO GAPS)')).not.toBeInTheDocument();

    const unsignedSuite = makeSuite({
      signatureDriftCount: 0,
      traceLinks: [makeTraceLink({ id: 'link-u', sigValid: false })],
    });
    unsignedSuite.traceLinks[0].spec.isSignatureInvalidated = false;

    rerender(
      <AuditHeader
        summary={unsignedSuite}
        panelContext={{ extensionType: 'jira:projectPage', isCompactPanel: false, isConfluence: false }}
        activeView="graph"
        onToggleView={noop}
        onSeed={noop}
        onSyncLive={noop}
        onOpenAuditLog={noop}
        onOpenExport={noop}
        onTestTransition={noop}
        onAnalyzeBlastRadius={noop}
        isSeeding={false}
        isSyncingLive={false}
        isAnalyzingBlastRadius={false}
      />
    );

    expect(screen.getByText('1 Unsigned / Invalid')).toBeInTheDocument();
    expect(screen.queryByText('All Valid')).not.toBeInTheDocument();
  });

  it('forwards linkId, specId, cleared test strings, and Part 11 attestation fields through App handlers', async () => {
    const initial = makeSuite();
    const updated = makeSuite({
      traceLinks: [
        makeTraceLink({
          id: 'link-1',
          hazardKey: 'HAZ-101',
          workKey: 'MED-43',
          sigValid: true,
          complianceState: 'VERIFIED',
        }),
      ],
    });

    mockedInvokeResolver.mockImplementation(async (key) => {
      if (key === 'getComplianceSuite') return initial;
      if (key === 'queryGraphContext') return null;
      if (key === 'bindIssueToHazard') return { success: true, summary: initial };
      if (key === 'recordTestResult') return updated;
      if (key === 'signOffPart11') return updated;
      throw new Error(`Unexpected resolver ${key}`);
    });

    render(<App />);
    await screen.findByText('PumpGuard Live');

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /matrix/i }));
    await user.click(screen.getByRole('button', { name: 'Inspect HAZ-101 lineage' }));

    const bindInput = screen.getByLabelText(/Bind Jira Issue Key/i);
    await user.clear(bindInput);
    await user.type(bindInput, 'MED-99');
    await user.click(screen.getByRole('button', { name: /Bind/i }));

    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('bindIssueToHazard', {
        hazardKey: 'HAZ-101',
        issueKey: 'MED-99',
        linkId: 'link-1',
      });
    });

    await user.clear(screen.getByLabelText('Evidence URL'));
    await user.clear(screen.getByLabelText('Test execution notes'));
    await user.click(screen.getByRole('button', { name: /Record Test Result/i }));

    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('recordTestResult', {
        hazardKey: 'HAZ-101',
        linkId: 'link-1',
        testKey: 'TEST-link-1',
        status: 'PASSED',
        evidenceUrl: '',
        notes: '',
      });
    });

    await user.type(
      screen.getByLabelText(/Required Attestation Phrase/i),
      PART11_ATTESTATION_PHRASE
    );
    await user.click(
      screen.getByLabelText(/I confirm my active Atlassian user session re-attestation/i)
    );
    await user.click(screen.getByLabelText(/I attest under 21 CFR Part 11/i));
    await user.click(screen.getByRole('button', { name: /Sign Off Spec/i }));

    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('signOffPart11', {
        hazardKey: 'HAZ-101',
        linkId: 'link-1',
        specId: 'spec-link-1',
        meaning: 'Safety verification sign-off',
        attestationConfirmed: true,
        passwordConfirmed: true,
        attestationPhrase: PART11_ATTESTATION_PHRASE,
      });
    });
  });
});
