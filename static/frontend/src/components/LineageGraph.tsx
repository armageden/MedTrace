import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  NodeTypes,
  MarkerType,
  useViewport,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { HazardNode, SpecNode, WorkNode, TestNode, SignatureNode, FlowLinkRef, FlowNodePayload } from './CustomNodes';
import { ComplianceSummary } from '../types';
import { useDialogA11y } from '../hooks/useDialogA11y';

interface LineageGraphProps {
  summary: ComplianceSummary;
  compact?: boolean;
  onSelectTraceLink: (linkId: string) => void;
}

const nodeTypes: NodeTypes = {
  hazard: HazardNode,
  spec: SpecNode,
  work: WorkNode,
  test: TestNode,
  signature: SignatureNode,
};

const STAGE_COLUMNS = [
  { key: 'hazard', label: '1. ISO 14971 HAZARD', x: 40, width: 220 },
  { key: 'spec', label: '2. CONFLUENCE SRS SPEC', x: 340, width: 220 },
  { key: 'work', label: '3. JIRA WORK & PR', x: 640, width: 210 },
  { key: 'test', label: '4. IEC 62304 VERIFICATION', x: 920, width: 220 },
  { key: 'signature', label: '5. 21 CFR PART 11 SIGN-OFF', x: 1210, width: 220 },
] as const;

function minimapNodeColor(node: Node): string {
  if (node.type === 'hazard') return '#de350b';
  if (node.type === 'test') return '#ff8b00';
  return '#0052cc';
}

function getPrefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return false;
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function usePrefersReducedMotion(): boolean {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState<boolean>(getPrefersReducedMotion);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mediaQuery.matches);

    const handleChange = (event: MediaQueryListEvent) => {
      setPrefersReducedMotion(event.matches);
    };

    if (typeof mediaQuery.addEventListener === 'function') {
      mediaQuery.addEventListener('change', handleChange);
      return () => mediaQuery.removeEventListener('change', handleChange);
    }
    if (typeof mediaQuery.addListener === 'function') {
      mediaQuery.addListener(handleChange);
      return () => mediaQuery.removeListener(handleChange);
    }
    return undefined;
  }, []);

  return prefersReducedMotion;
}

const StageHeaderOverlay: React.FC = () => {
  const { x, zoom } = useViewport();

  return (
    <div
      style={{
        position: 'absolute',
        top: 10,
        left: 0,
        right: 0,
        height: 32,
        overflow: 'hidden',
        zIndex: 10,
        pointerEvents: 'none',
      }}
    >
      {STAGE_COLUMNS.map((col, idx) => {
        const nextCol = STAGE_COLUMNS[idx + 1];
        const maxNonOverlappingWidth = nextCol ? (nextCol.x - col.x) * zoom - 6 : col.width * zoom;
        const scaledWidth = Math.min(col.width * zoom, maxNonOverlappingWidth);
        const headerWidth =
          maxNonOverlappingWidth >= 40 ? Math.max(40, scaledWidth) : Math.max(0, maxNonOverlappingWidth);

        return (
          <div
            key={col.key}
            title={col.label}
            style={{
              position: 'absolute',
              top: 0,
              left: x + col.x * zoom,
              width: headerWidth,
              fontSize: 10,
              fontWeight: 800,
              letterSpacing: '0.6px',
              color: 'var(--mt-text-secondary, #42526e)',
              background: 'var(--mt-bg-overlay, rgba(255, 255, 255, 0.94))',
              padding: '4px 8px',
              borderRadius: 4,
              boxShadow: '0 1px 3px rgba(9, 30, 66, 0.08)',
              border: '1px solid var(--mt-border, #dfe1e6)',
              textAlign: 'center',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {col.label}
          </div>
        );
      })}
    </div>
  );
};

export const LineageGraph: React.FC<LineageGraphProps> = ({ summary, compact = false, onSelectTraceLink }) => {
  const [ambiguousRefs, setAmbiguousRefs] = useState<FlowLinkRef[] | null>(null);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const prefersReducedMotion = usePrefersReducedMotion();

  const isPopoverOpen = Boolean(ambiguousRefs && ambiguousRefs.length > 1);
  const closePopover = useCallback(() => {
    setAmbiguousRefs(null);
  }, []);

  useDialogA11y({
    isOpen: isPopoverOpen,
    onClose: closePopover,
    containerRef: popoverRef,
  });

  const handleActivateRefs = useCallback(
    (refs: FlowLinkRef[]) => {
      if (refs.length === 1) {
        setAmbiguousRefs(null);
        onSelectTraceLink(refs[0].id);
      } else if (refs.length > 1) {
        setAmbiguousRefs(refs);
      }
    },
    [onSelectTraceLink]
  );

  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      const payload = node.data as FlowNodePayload<unknown> | undefined;
      handleActivateRefs(payload?.linkRefs || []);
    },
    [handleActivateRefs]
  );

  const handleEdgeClick = useCallback(
    (_event: React.MouseEvent, edge: Edge) => {
      const linkId = (edge.data as { linkId?: string } | undefined)?.linkId;
      if (linkId) {
        setAmbiguousRefs(null);
        onSelectTraceLink(linkId);
      }
    },
    [onSelectTraceLink]
  );

  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map<string, Node<FlowNodePayload<unknown>>>();
    const calculatedEdges: Edge[] = [];

    const colX = {
      hazard: 40,
      spec: 340,
      work: 640,
      test: 920,
      signature: 1210,
    };

    const upsertNode = (
      id: string,
      type: 'hazard' | 'spec' | 'work' | 'test' | 'signature',
      position: { x: number; y: number },
      item: unknown,
      linkRef: FlowLinkRef
    ) => {
      const existing = nodeMap.get(id);
      if (existing) {
        if (!existing.data.linkRefs.some((r) => r.id === linkRef.id)) {
          existing.data.linkRefs.push(linkRef);
        }
        return;
      }
      nodeMap.set(id, {
        id,
        type,
        position,
        data: { item, linkRefs: [linkRef], onActivate: handleActivateRefs },
      });
    };

    summary.traceLinks.forEach((link, idx) => {
      const yPos = 72 + idx * 160;
      const isBroken = link.complianceState !== 'VERIFIED';
      const edgeColor = isBroken ? '#de350b' : '#00875a';
      const linkRef: FlowLinkRef = {
        id: link.id,
        hazardKey: link.hazard.key,
        workKey: link.work.key,
      };

      const hazNodeId = link.hazard.id ? `node-haz-${link.hazard.id}` : `node-haz-unbound-${link.id}`;
      const specNodeId =
        link.spec.id && !link.spec.isMissingSentinel
          ? `node-spec-${link.spec.id}`
          : `node-spec-unbound-${link.id}`;
      const workNodeId =
        link.work.id && link.work.key ? `node-work-${link.work.id}` : `node-work-unbound-${link.id}`;
      const testNodeId = link.test.id ? `node-test-${link.test.id}` : `node-test-unbound-${link.id}`;
      const sigNodeId = link.signature.id ? `node-sig-${link.signature.id}` : `node-sig-unbound-${link.id}`;

      upsertNode(hazNodeId, 'hazard', { x: colX.hazard, y: yPos }, link.hazard, linkRef);
      upsertNode(specNodeId, 'spec', { x: colX.spec, y: yPos }, link.spec, linkRef);
      upsertNode(workNodeId, 'work', { x: colX.work, y: yPos }, link.work, linkRef);
      upsertNode(testNodeId, 'test', { x: colX.test, y: yPos }, link.test, linkRef);
      upsertNode(sigNodeId, 'signature', { x: colX.signature, y: yPos }, link.signature, linkRef);

      const baseEdge = {
        type: 'smoothstep' as const,
        animated: isBroken && !prefersReducedMotion,
        style: { stroke: edgeColor, strokeWidth: isBroken ? 2.5 : 2, cursor: 'pointer' },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor },
        data: { linkId: link.id },
      };

      calculatedEdges.push(
        { id: `e-haz-spec-${link.id}`, source: hazNodeId, target: specNodeId, ...baseEdge },
        { id: `e-spec-work-${link.id}`, source: specNodeId, target: workNodeId, ...baseEdge },
        { id: `e-work-test-${link.id}`, source: workNodeId, target: testNodeId, ...baseEdge },
        { id: `e-test-sig-${link.id}`, source: testNodeId, target: sigNodeId, ...baseEdge }
      );
    });

    return { nodes: Array.from(nodeMap.values()), edges: calculatedEdges };
  }, [summary, handleActivateRefs, prefersReducedMotion]);

  return (
    <div
      style={{
        height: compact ? '380px' : 'calc(100vh - 230px)',
        minHeight: compact ? '340px' : '540px',
        width: '100%',
        position: 'relative',
        background: 'var(--mt-bg-surface-subtle, #fafbfc)',
        borderRadius: 8,
        border: '1px solid var(--mt-border-subtle, #ebecf0)',
      }}
    >
      {isPopoverOpen && ambiguousRefs && (
        <div
          ref={popoverRef}
          role="dialog"
          aria-modal="true"
          aria-label="Select trace link for shared node"
          style={{
            position: 'absolute',
            top: 52,
            left: '50%',
            transform: 'translateX(-50%)',
            zIndex: 30,
            background: 'var(--mt-bg-overlay, #ffffff)',
            border: '1px solid var(--mt-border, #dfe1e6)',
            borderRadius: 8,
            padding: '10px 12px',
            boxShadow: '0 4px 16px rgba(9, 30, 66, 0.2)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
          }}
        >
          <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--mt-text-primary, #172b4d)' }}>
            Shared node — choose lineage to inspect:
          </span>
          {ambiguousRefs.map((ref) => (
            <button
              key={ref.id}
              type="button"
              className="mt-btn"
              onClick={() => {
                setAmbiguousRefs(null);
                onSelectTraceLink(ref.id);
              }}
              style={{
                padding: '4px 10px',
                border: '1px solid var(--mt-brand-bg, #0052cc)',
                background: 'var(--mt-brand-subtle-bg, #deebff)',
                color: 'var(--mt-brand-text, #0052cc)',
              }}
            >
              {ref.hazardKey} ({ref.workKey || 'Unbound'})
            </button>
          ))}
          <button
            type="button"
            className="mt-icon-btn"
            aria-label="Dismiss link selector"
            onClick={closePopover}
            style={{ fontSize: 12, fontWeight: 700 }}
          >
            ✕
          </button>
        </div>
      )}

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        nodesDraggable={false}
        nodesConnectable={false}
        fitView
        onNodeClick={handleNodeClick}
        onEdgeClick={handleEdgeClick}
      >
        <StageHeaderOverlay />
        <Background color="#dfe1e6" gap={20} size={1} />
        <Controls />
        {!compact && <MiniMap nodeColor={minimapNodeColor} style={{ height: 100, width: 140 }} />}
      </ReactFlow>
    </div>
  );
};
