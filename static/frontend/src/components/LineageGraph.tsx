import React, { useMemo, useState } from 'react';
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
      {STAGE_COLUMNS.map((col) => (
        <div
          key={col.key}
          style={{
            position: 'absolute',
            top: 0,
            left: x + col.x * zoom,
            width: Math.max(110, col.width * zoom),
            fontSize: 10,
            fontWeight: 800,
            letterSpacing: '0.6px',
            color: '#42526e',
            background: 'rgba(255, 255, 255, 0.94)',
            padding: '4px 8px',
            borderRadius: 4,
            boxShadow: '0 1px 3px rgba(9, 30, 66, 0.08)',
            border: '1px solid #dfe1e6',
            textAlign: 'center',
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {col.label}
        </div>
      ))}
    </div>
  );
};

export const LineageGraph: React.FC<LineageGraphProps> = ({ summary, compact = false, onSelectTraceLink }) => {
  const [ambiguousRefs, setAmbiguousRefs] = useState<FlowLinkRef[] | null>(null);

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
        data: { item, linkRefs: [linkRef] },
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

      const hazNodeId = `node-haz-${link.hazard.id}`;
      const specNodeId = `node-spec-${link.spec.id}`;
      const workNodeId = `node-work-${link.work.id}`;
      const testNodeId = `node-test-${link.test.id}`;
      const sigNodeId = `node-sig-${link.signature.id}`;

      upsertNode(hazNodeId, 'hazard', { x: colX.hazard, y: yPos }, link.hazard, linkRef);
      upsertNode(specNodeId, 'spec', { x: colX.spec, y: yPos }, link.spec, linkRef);
      upsertNode(workNodeId, 'work', { x: colX.work, y: yPos }, link.work, linkRef);
      upsertNode(testNodeId, 'test', { x: colX.test, y: yPos }, link.test, linkRef);
      upsertNode(sigNodeId, 'signature', { x: colX.signature, y: yPos }, link.signature, linkRef);

      const baseEdge = {
        animated: isBroken,
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
  }, [summary]);

  return (
    <div
      style={{
        height: compact ? '380px' : 'calc(100vh - 230px)',
        minHeight: compact ? '340px' : '540px',
        width: '100%',
        position: 'relative',
        background: '#fafbfc',
        borderRadius: 8,
        border: '1px solid #ebecf0',
      }}
    >
      {ambiguousRefs && ambiguousRefs.length > 1 && (
        <div
          role="dialog"
          aria-label="Select trace link for shared node"
          style={{
            position: 'absolute',
            top: 52,
            left: '50%',
            transform: 'translateX(-50%)',
            zIndex: 30,
            background: '#ffffff',
            border: '1px solid #dfe1e6',
            borderRadius: 8,
            padding: '10px 12px',
            boxShadow: '0 4px 16px rgba(9, 30, 66, 0.2)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
          }}
        >
          <span style={{ fontSize: 11, fontWeight: 700, color: '#172b4d' }}>
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
                border: '1px solid #0052cc',
                background: '#deebff',
                color: '#0052cc',
              }}
            >
              {ref.hazardKey} ({ref.workKey})
            </button>
          ))}
          <button
            type="button"
            className="mt-icon-btn"
            aria-label="Dismiss link selector"
            onClick={() => setAmbiguousRefs(null)}
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
        onNodeClick={(_, node) => {
          const payload = node.data as FlowNodePayload<unknown> | undefined;
          const refs = payload?.linkRefs || [];
          if (refs.length === 1) {
            setAmbiguousRefs(null);
            onSelectTraceLink(refs[0].id);
          } else if (refs.length > 1) {
            setAmbiguousRefs(refs);
          }
        }}
        onEdgeClick={(_, edge) => {
          const linkId = (edge.data as { linkId?: string } | undefined)?.linkId;
          if (linkId) {
            setAmbiguousRefs(null);
            onSelectTraceLink(linkId);
          }
        }}
      >
        <StageHeaderOverlay />
        <Background color="#dfe1e6" gap={20} size={1} />
        <Controls />
        {!compact && (
          <MiniMap
            nodeColor={(n) => {
              if (n.type === 'hazard') return '#de350b';
              if (n.type === 'test') return '#ff8b00';
              return '#0052cc';
            }}
            style={{ height: 100, width: 140 }}
          />
        )}
      </ReactFlow>
    </div>
  );
};
