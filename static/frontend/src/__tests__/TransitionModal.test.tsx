import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TransitionModal } from '../components/TransitionModal';
import { ComplianceSummary, TraceLink } from '../types';

function makeLink(workKey: string, complianceState: TraceLink['complianceState']): TraceLink {
  return {
    id: `link-${workKey}`,
    hazard: {
      id: 'haz-1',
      key: 'HAZ-101',
      title: 'Hazard 101',
      riskClass: 'CLASS_C',
      severity: 'CRITICAL',
      probability: 'REMOTE',
      mitigationRequirementId: 'SRS-1',
      status: complianceState === 'VERIFIED' ? 'MITIGATED' : 'ACTION_REQUIRED',
    },
    spec: {
      id: 'spec-1',
      title: 'SRS-1',
      version: 1,
      sha256Hash: 'abc',
      lastSignedHash: 'abc',
      isSignatureInvalidated: false,
      contentSnippet: 'Spec',
      lastUpdated: '2026-01-01T00:00:00.000Z',
    },
    work: {
      id: 'work-1',
      key: workKey,
      title: 'Task',
      status: 'Done',
      assignee: 'Alice',
    },
    test: {
      id: 'test-1',
      testKey: 'TEST-1',
      title: 'Test',
      testType: 'Unit Test',
      status: complianceState === 'VERIFIED' ? 'PASSED' : 'FAILED',
    },
    signature: {
      id: 'sig-1',
      signedBy: 'Alice',
      signedAt: '2026-01-01T00:00:00.000Z',
      role: 'QA',
      meaning: 'Approved',
      artifactSha256: 'abc',
      isValid: complianceState === 'VERIFIED',
    },
    complianceState,
    violations: complianceState === 'VERIFIED' ? [] : ['Safety violation'],
  };
}

function makeSummary(overrides?: Partial<ComplianceSummary>): ComplianceSummary {
  return {
    projectName: 'PumpGuard Live',
    datasetMode: 'LIVE',
    initialized: true,
    standards: ['IEC 62304'],
    totalHazards: 1,
    classCCount: 1,
    classBCount: 0,
    classACount: 0,
    verifiedPercentage: 100,
    releaseBlocked: false,
    blockingReasons: [],
    signatureDriftCount: 0,
    traceLinks: [makeLink('MED-42', 'VERIFIED')],
    lastAuditTimestamp: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('FE-04: TransitionModal global vs issue gate and fail-closed empty suite', () => {
  it('renders No Trace Links Configured and stays blocked for 0-hazard / uninitialized global gate even if result=true', () => {
    const emptySummary = makeSummary({
      initialized: false,
      totalHazards: 0,
      classCCount: 0,
      verifiedPercentage: 0,
      traceLinks: [],
      releaseBlocked: true,
      blockingReasons: ['Suite uninitialized'],
    });

    render(
      <TransitionModal
        isOpen={true}
        onClose={() => {}}
        result={{ result: true }}
        summary={emptySummary}
      />
    );

    expect(screen.getByText(/GLOBAL RELEASE GATE/)).toBeInTheDocument();
    expect(screen.getByText('Transition to "Done" Blocked')).toBeInTheDocument();
    expect(
      screen.getByText(
        'No Trace Links Configured — Sync Live Atlassian artifacts or seed a dataset before release'
      )
    ).toBeInTheDocument();
    expect(screen.queryByText(/All 0 hazard trace links verified/i)).not.toBeInTheDocument();
  });

  it('renders evalError cleanly when backend is unreachable', () => {
    render(
      <TransitionModal
        isOpen={true}
        onClose={() => {}}
        result={{
          result: false,
          evaluatedIssueKey: 'MED-42',
          evalError: 'Forge backend unreachable',
        }}
        summary={makeSummary()}
      />
    );

    expect(screen.getByText(/ISSUE MED-42/)).toBeInTheDocument();
    expect(screen.getByText('Gate Evaluation Failed')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Forge backend unreachable');
  });

  it('distinguishes unlinked permitted issue from verified linked issue and global gate', () => {
    const blockedSummary = makeSummary({
      releaseBlocked: true,
      blockingReasons: ['HAZ-101 requires review'],
      traceLinks: [makeLink('MED-42', 'SAFETY_VIOLATION')],
    });

    const { rerender } = render(
      <TransitionModal
        isOpen={true}
        onClose={() => {}}
        result={{ result: true, evaluatedIssueKey: 'MED-999' }}
        summary={blockedSummary}
      />
    );

    expect(screen.getByText(/ISSUE MED-999/)).toBeInTheDocument();
    expect(screen.getByText('Unlinked Issue Permitted:')).toBeInTheDocument();
    expect(screen.getByText(/Global release remains blocked/i)).toBeInTheDocument();

    rerender(
      <TransitionModal
        isOpen={true}
        onClose={() => {}}
        result={{ result: true, evaluatedIssueKey: 'MED-42' }}
        summary={makeSummary()}
      />
    );

    expect(screen.getByText('Linked Hazard Verification Satisfied (MED-42):')).toBeInTheDocument();
    expect(screen.getByText('Transition to "Done" Authorized')).toBeInTheDocument();
  });
});
