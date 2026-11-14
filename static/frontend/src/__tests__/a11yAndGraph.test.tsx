import React, { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Edge, Node, NodeProps, NodeTypes } from '@xyflow/react';
import { InspectionDrawer } from '../components/InspectionDrawer';
import { FdaExportModal } from '../components/FdaExportModal';
import { ConfirmSeedModal } from '../components/ConfirmSeedModal';
import { TransitionModal } from '../components/TransitionModal';
import { TraceMatrixTable } from '../components/TraceMatrixTable';
import { LineageGraph } from '../components/LineageGraph';
import type { FlowNodePayload } from '../components/CustomNodes';
import * as bridgeModule from '../bridge';
import { ComplianceSummary, TraceLink } from '../types';

let mockViewport = { x: 0, y: 0, zoom: 1 };
let lastRenderedEdges: Edge[] = [];
let lastRenderedNodes: Node[] = [];

vi.mock('@xyflow/react', () => ({
  Position: { Left: 'left', Right: 'right', Top: 'top', Bottom: 'bottom' },
  MarkerType: { ArrowClosed: 'arrowclosed' },
  Handle: () => null,
  Background: () => null,
  Controls: () => null,
  MiniMap: () => null,
  useViewport: () => mockViewport,
  ReactFlow: ({
    nodes = [],
    edges = [],
    nodeTypes = {},
    children,
  }: {
    nodes?: Node[];
    edges?: Edge[];
    nodeTypes?: NodeTypes;
    children?: React.ReactNode;
  }) => {
    lastRenderedNodes = nodes;
    lastRenderedEdges = edges;
    return (
      <div data-testid="react-flow-canvas">
        {children}
        {nodes.map((node) => {
          const Comp = (nodeTypes as Record<string, React.ComponentType<NodeProps<Node>>>)[
            node.type || ''
          ];
          if (!Comp) return null;
          return (
            <div key={node.id} data-testid={node.id}>
              <Comp
                id={node.id}
                type={node.type || 'default'}
                data={node.data}
                selected={Boolean(node.selected)}
                isConnectable={false}
                zIndex={0}
                positionAbsoluteX={node.position.x}
                positionAbsoluteY={node.position.y}
                dragging={false}
                draggable={false}
                selectable={true}
                deletable={false}
              />
            </div>
          );
        })}
      </div>
    );
  },
}));

vi.mock('../bridge', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../bridge')>();
  return {
    ...actual,
    invokeResolver: vi.fn(),
  };
});

function makeLink(overrides?: Partial<TraceLink> & { id?: string }): TraceLink {
  const id = overrides?.id ?? 'link-1';
  return {
    id,
    hazard: {
      id: `haz-${id}`,
      key: `HAZ-${id}`,
      title: `Hazard ${id}`,
      riskClass: 'CLASS_C',
      severity: 'CRITICAL',
      probability: 'REMOTE',
      mitigationRequirementId: `SRS-${id}`,
      status: 'ACTION_REQUIRED',
      ...overrides?.hazard,
    },
    spec: {
      id: `spec-${id}`,
      pageId: `page-${id}`,
      title: 'SRS-301: Oxygen Concentration Alarm',
      version: 2,
      sha256Hash: 'abc12345',
      lastSignedHash: '',
      isSignatureInvalidated: true,
      contentSnippet: 'Monitor O2 percentage.',
      lastUpdated: '2026-01-01T00:00:00.000Z',
      ...overrides?.spec,
    },
    work: {
      id: `work-${id}`,
      key: `PUMP-${id}`,
      title: 'Implement O2 alarm',
      status: 'In Progress',
      assignee: 'Alice',
      ...overrides?.work,
    },
    test: {
      id: `test-${id}`,
      testKey: `TEST-${id}`,
      title: 'O2 sensor HIL test',
      testType: 'Automated HIL (Hardware-in-Loop)',
      status: 'FAILED',
      ...overrides?.test,
    },
    signature: {
      id: `sig-${id}`,
      signedBy: '',
      signedAt: '',
      role: 'QA Lead',
      meaning: 'Safety approval',
      artifactSha256: 'abc12345',
      isValid: false,
      ...overrides?.signature,
    },
    complianceState: overrides?.complianceState ?? 'SAFETY_VIOLATION',
    violations: overrides?.violations ?? ['Failed test'],
  };
}

function makeSummary(links: TraceLink[], mode: 'DEMO' | 'LIVE' = 'LIVE'): ComplianceSummary {
  return {
    projectName: 'OxyGuard Live',
    datasetMode: mode,
    initialized: true,
    standards: ['IEC 62304'],
    totalHazards: links.length,
    classCCount: links.length,
    classBCount: 0,
    classACount: 0,
    verifiedPercentage: 0,
    releaseBlocked: true,
    blockingReasons: ['Gap present'],
    signatureDriftCount: 0,
    traceLinks: links,
    lastAuditTimestamp: '2026-01-01T00:00:00.000Z',
  };
}

describe('FE-08..FE-10: Dialog a11y stack/focus trap/restore, table semantics, and graph node/zoom fixes', () => {
  const mockedInvokeResolver = vi.mocked(bridgeModule.invokeResolver);

  beforeEach(() => {
    vi.clearAllMocks();
    mockViewport = { x: 0, y: 0, zoom: 1 };
    lastRenderedEdges = [];
    lastRenderedNodes = [];
    mockedInvokeResolver.mockImplementation(async (key) => {
      if (key === 'queryGraphContext') return null;
      if (key === 'verifyAuditChain') {
        return { valid: true, totalEntries: 0, headHash: 'GENESIS' };
      }
      if (key === 'getAuditLog') return [];
      return null;
    });
  });

  it('closes only top-most dialog per Escape press (LIFO stack)', async () => {
    const link = makeLink({ id: '1' });
    const summary = makeSummary([link], 'LIVE');
    const onCloseDrawer = vi.fn();
    const onCloseExport = vi.fn();

    const { rerender } = render(
      <>
        <InspectionDrawer
          link={link}
          datasetMode="LIVE"
          blastRadius={null}
          onClose={onCloseDrawer}
          onBindIssue={async () => true}
          onRecordTestResult={async () => true}
          onSignOffPart11={async () => true}
          onRemediateDemo={async () => true}
          isMutating={false}
        />
        <FdaExportModal summary={summary} onClose={onCloseExport} isOpen={true} />
      </>
    );

    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('queryGraphContext', {
        issueKey: 'PUMP-1',
      });
      expect(mockedInvokeResolver).toHaveBeenCalledWith('getAuditLog', { limit: 200 });
    });

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCloseExport).toHaveBeenCalledTimes(1);
    expect(onCloseDrawer).not.toHaveBeenCalled();

    rerender(
      <>
        <InspectionDrawer
          link={link}
          datasetMode="LIVE"
          blastRadius={null}
          onClose={onCloseDrawer}
          onBindIssue={async () => true}
          onRecordTestResult={async () => true}
          onSignOffPart11={async () => true}
          onRemediateDemo={async () => true}
          isMutating={false}
        />
        <FdaExportModal summary={summary} onClose={onCloseExport} isOpen={false} />
      </>
    );

    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onCloseDrawer).toHaveBeenCalledTimes(1);
  });

  it('traps Tab and Shift+Tab focus inside ConfirmSeedModal and restores focus on close', async () => {
    const Harness: React.FC = () => {
      const [open, setOpen] = useState(false);
      return (
        <div>
          <button type="button" onClick={() => setOpen(true)}>
            Open Confirm
          </button>
          <ConfirmSeedModal
            isOpen={open}
            currentMode="LIVE"
            linkCount={3}
            onConfirm={() => setOpen(false)}
            onCancel={() => setOpen(false)}
          />
        </div>
      );
    };

    render(<Harness />);
    const triggerBtn = screen.getByRole('button', { name: 'Open Confirm' });
    triggerBtn.focus();
    expect(document.activeElement).toBe(triggerBtn);

    const user = userEvent.setup();
    await user.click(triggerBtn);

    const cancelBtn = screen.getByRole('button', { name: 'Cancel' });
    const closeIconBtn = screen.getByRole('button', {
      name: 'Close overwrite confirmation dialog',
    });
    const confirmBtn = screen.getByRole('button', { name: 'Confirm Overwrite & Seed Demo' });

    // ConfirmSeedModal sets initialFocusRef to Cancel
    expect(document.activeElement).toBe(cancelBtn);

    // Shift+Tab from Cancel wraps to Confirm (or if closeIconBtn is first in DOM, Tab wraps from last to first)
    confirmBtn.focus();
    expect(document.activeElement).toBe(confirmBtn);
    fireEvent.keyDown(window, { key: 'Tab', shiftKey: false });
    expect(document.activeElement).toBe(closeIconBtn);

    fireEvent.keyDown(window, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(confirmBtn);

    await user.click(cancelBtn);
    await waitFor(() => {
      expect(document.activeElement).toBe(triggerBtn);
    });
  });

  it('restores focus when TransitionModal closes', async () => {
    const summary = makeSummary([makeLink({ id: '1' })], 'LIVE');
    const TransitionHarness: React.FC = () => {
      const [open, setOpen] = useState(false);
      return (
        <div>
          <button type="button" onClick={() => setOpen(true)}>
            Launch Gate Modal
          </button>
          <TransitionModal
            isOpen={open}
            onClose={() => setOpen(false)}
            result={{ result: false, evaluatedIssueKey: 'PUMP-1', errorMessage: 'Blocked' }}
            summary={summary}
          />
        </div>
      );
    };

    render(<TransitionHarness />);
    const launchBtn = screen.getByRole('button', { name: 'Launch Gate Modal' });
    const user = userEvent.setup();
    await user.click(launchBtn);

    const closeBtn = screen.getByRole('button', { name: 'Close transition gate dialog' });
    expect(document.activeElement).toBe(closeBtn);

    await user.click(closeBtn);
    expect(document.activeElement).toBe(launchBtn);
  });

  it('renders native table rows with inspect button, accessible search input, full spec title, and clean LIVE empty-search copy', async () => {
    const link = makeLink({ id: '301' });
    const summary = makeSummary([link], 'LIVE');
    const onSelect = vi.fn();

    const { container } = render(
      <TraceMatrixTable summary={summary} onSelectTraceLink={onSelect} />
    );

    const rows = Array.from(container.querySelectorAll('tbody tr'));
    expect(rows).toHaveLength(1);
    expect(rows[0]).not.toHaveAttribute('role', 'button');
    expect(rows[0]).not.toHaveAttribute('tabindex');

    const inspectBtn = screen.getByRole('button', { name: 'Inspect HAZ-301 lineage' });
    const user = userEvent.setup();
    await user.click(inspectBtn);
    expect(onSelect).toHaveBeenCalledWith('301');

    const searchInput = screen.getByLabelText('Filter traceability matrix');
    expect(searchInput).toHaveClass('mt-search-input');
    expect((searchInput as HTMLInputElement).style.outline).not.toBe('none');

    // Full spec title with colon is unclipped
    expect(screen.getByText('SRS-301: Oxygen Concentration Alarm')).toBeInTheDocument();

    // LIVE empty-search copy omits DEMO fixture keys
    await user.type(searchInput, 'zzz-nomatch');
    const emptyText = screen.getByText(/No matching traceability records found/i).parentElement
      ?.textContent;
    expect(emptyText).not.toContain('HAZ-101');
    expect(emptyText).not.toContain('SRS-104');
    expect(emptyText).not.toContain('MED-42');
    expect(emptyText).not.toContain('TEST-88');
  });

  it('creates distinct unbound graph nodes, supports keyboard node activation, omits inline TestNode animation, respects reduced motion, and prevents low-zoom header overlap', async () => {
    mockViewport = { x: 0, y: 0, zoom: 0.25 };

    // Simulate prefers-reduced-motion: reduce
    const originalMatchMedia = window.matchMedia;
    window.matchMedia = vi.fn().mockImplementation((query: string) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }));

    try {
      const unboundA = makeLink({
        id: 'a',
        hazard: {
          id: 'haz-a',
          key: 'HAZ-A',
          title: 'Unbound A',
          riskClass: 'CLASS_C',
          severity: 'CRITICAL',
          probability: 'REMOTE',
          mitigationRequirementId: 'SRS-A',
          status: 'ACTION_REQUIRED',
        },
        spec: {
          id: '',
          title: '',
          version: 0,
          sha256Hash: '',
          lastSignedHash: '',
          isSignatureInvalidated: false,
          isMissingSentinel: true,
          contentSnippet: '',
          lastUpdated: '',
        },
        work: { id: '', key: '', title: '', status: 'To Do', assignee: '' },
        test: { id: '', testKey: 'TEST-A', title: 'Test A', testType: 'Unit Test', status: 'FAILED' },
        signature: {
          id: '',
          signedBy: '',
          signedAt: '',
          role: 'QA',
          meaning: '',
          artifactSha256: '',
          isValid: false,
        },
      });
      const unboundB = makeLink({
        id: 'b',
        hazard: {
          id: 'haz-b',
          key: 'HAZ-B',
          title: 'Unbound B',
          riskClass: 'CLASS_B',
          severity: 'SERIOUS',
          probability: 'OCCASIONAL',
          mitigationRequirementId: 'SRS-B',
          status: 'ACTION_REQUIRED',
        },
        spec: {
          id: '',
          title: '',
          version: 0,
          sha256Hash: '',
          lastSignedHash: '',
          isSignatureInvalidated: false,
          isMissingSentinel: true,
          contentSnippet: '',
          lastUpdated: '',
        },
        work: { id: '', key: '', title: '', status: 'To Do', assignee: '' },
        test: { id: '', testKey: 'TEST-B', title: 'Test B', testType: 'Unit Test', status: 'PASSED' },
        signature: {
          id: '',
          signedBy: '',
          signedAt: '',
          role: 'QA',
          meaning: '',
          artifactSha256: '',
          isValid: false,
        },
      });

      const onSelect = vi.fn();
      const summary = makeSummary([unboundA, unboundB], 'LIVE');

      render(<LineageGraph summary={summary} onSelectTraceLink={onSelect} />);

      // Distinct unbound IDs prevent node collisions across all unbound stages
      expect(screen.getByTestId('node-work-unbound-a')).toBeInTheDocument();
      expect(screen.getByTestId('node-work-unbound-b')).toBeInTheDocument();
      expect(screen.getByTestId('node-spec-unbound-a')).toBeInTheDocument();
      expect(screen.getByTestId('node-spec-unbound-b')).toBeInTheDocument();
      expect(screen.getByTestId('node-test-unbound-a')).toBeInTheDocument();
      expect(screen.getByTestId('node-test-unbound-b')).toBeInTheDocument();
      expect(screen.getByTestId('node-sig-unbound-a')).toBeInTheDocument();
      expect(screen.getByTestId('node-sig-unbound-b')).toBeInTheDocument();
      expect(lastRenderedNodes).toHaveLength(10);

      // prefers-reduced-motion disables edge animation
      expect(lastRenderedEdges.every((e) => e.animated === false)).toBe(true);

      // TestNode uses CSS class mt-node-test--alert without inline animation
      const failingTestBtn = screen.getByRole('button', {
        name: /IEC 62304 Verification TEST-A/i,
      });
      expect(failingTestBtn).toHaveClass('mt-node-test--alert');
      expect((failingTestBtn as HTMLDivElement).style.animation).toBe('');

      // Keyboard Enter & Space activation on custom node
      const hazABtn = screen.getByRole('button', { name: /ISO 14971 Hazard HAZ-A/i });
      expect(hazABtn).toHaveAttribute('tabindex', '0');
      fireEvent.keyDown(hazABtn, { key: 'Enter' });
      expect(onSelect).toHaveBeenCalledWith('a');

      const hazBBtn = screen.getByRole('button', { name: /ISO 14971 Hazard HAZ-B/i });
      fireEvent.keyDown(hazBBtn, { key: ' ' });
      expect(onSelect).toHaveBeenCalledWith('b');

      // StageHeaderOverlay headers do not overlap at zoom = 0.25
      const headerEls = [
        screen.getByText('1. ISO 14971 HAZARD'),
        screen.getByText('2. CONFLUENCE SRS SPEC'),
        screen.getByText('3. JIRA WORK & PR'),
        screen.getByText('4. IEC 62304 VERIFICATION'),
        screen.getByText('5. 21 CFR PART 11 SIGN-OFF'),
      ];
      for (let i = 0; i < headerEls.length - 1; i++) {
        const curLeft = parseFloat((headerEls[i] as HTMLElement).style.left);
        const curWidth = parseFloat((headerEls[i] as HTMLElement).style.width);
        const nextLeft = parseFloat((headerEls[i + 1] as HTMLElement).style.left);
        expect(curLeft + curWidth).toBeLessThanOrEqual(nextLeft);
      }

      // Also verify shared node opens ambiguousRefs dialog and Escape closes it
      const sharedA = makeLink({ id: 's1' });
      const sharedB = makeLink({
        id: 's2',
        hazard: { ...sharedA.hazard, id: 'haz-shared', key: 'HAZ-SHARED' },
        work: { ...sharedA.work, key: 'PUMP-2' },
      });
      sharedA.hazard = sharedB.hazard;
      const sharedSummary = makeSummary([sharedA, sharedB], 'LIVE');
      render(<LineageGraph summary={sharedSummary} onSelectTraceLink={onSelect} />);

      const sharedNode = lastRenderedNodes.find((n) => n.id === 'node-haz-haz-shared');
      expect((sharedNode?.data as FlowNodePayload<unknown>)?.linkRefs).toHaveLength(2);
      const sharedBtns = screen.getAllByRole('button', {
        name: /ISO 14971 Hazard HAZ-SHARED/i,
      });
      fireEvent.keyDown(sharedBtns[sharedBtns.length - 1], { key: 'Enter' });

      const popover = await screen.findByRole('dialog', {
        name: 'Select trace link for shared node',
      });
      expect(popover).toBeInTheDocument();
      fireEvent.keyDown(window, { key: 'Escape' });
      await waitFor(() => {
        expect(
          screen.queryByRole('dialog', { name: 'Select trace link for shared node' })
        ).not.toBeInTheDocument();
      });
    } finally {
      window.matchMedia = originalMatchMedia;
    }
  });
});
