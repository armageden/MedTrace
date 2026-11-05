import React, { useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { HazardNode, SpecNode, WorkNode, TestNode, SignatureNode } from './CustomNodes';
import { ComplianceSummary } from '../types';

interface LineageGraphProps {
  summary: ComplianceSummary;
  onSelectTraceLink: (linkId: string) => void;
}

const nodeTypes = {
  hazard: HazardNode,
  spec: SpecNode,
  work: WorkNode,
  test: TestNode,
  signature: SignatureNode,
};

export const LineageGraph: React.FC<LineageGraphProps> = ({ summary, onSelectTraceLink }) => {
  const { nodes, edges } = useMemo(() => {
    const calculatedNodes: Node[] = [];
    const calculatedEdges: Edge[] = [];

    const colX = {
      hazard: 40,
      spec: 340,
      work: 640,
      test: 920,
      signature: 1210,
    };

    summary.traceLinks.forEach((link, idx) => {
      const yPos = 80 + idx * 160;
      const isBroken = link.complianceState !== 'VERIFIED';
      const edgeColor = isBroken ? '#de350b' : '#00875a';

      // 1. Hazard Node
      calculatedNodes.push({
        id: `node-${link.hazard.id}`,
        type: 'hazard',
        position: { x: colX.hazard, y: yPos },
        data: link.hazard,
      });

      // 2. Confluence Spec Node
      calculatedNodes.push({
        id: `node-${link.spec.id}`,
        type: 'spec',
        position: { x: colX.spec, y: yPos },
        data: link.spec,
      });

      // 3. Jira Work Item Node
      calculatedNodes.push({
        id: `node-${link.work.id}`,
        type: 'work',
        position: { x: colX.work, y: yPos },
        data: link.work,
      });

      // 4. Verification Test Node
      calculatedNodes.push({
        id: `node-${link.test.id}`,
        type: 'test',
        position: { x: colX.test, y: yPos },
        data: link.test,
      });

      // 5. 21 CFR Part 11 Signature Node
      calculatedNodes.push({
        id: `node-${link.signature.id}`,
        type: 'signature',
        position: { x: colX.signature, y: yPos },
        data: link.signature,
      });

      // Edges connecting the 5 stages
      // Hazard -> Spec
      calculatedEdges.push({
        id: `e-haz-spec-${link.id}`,
        source: `node-${link.hazard.id}`,
        target: `node-${link.spec.id}`,
        animated: isBroken,
        style: { stroke: edgeColor, strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor },
      });

      // Spec -> Work
      calculatedEdges.push({
        id: `e-spec-work-${link.id}`,
        source: `node-${link.spec.id}`,
        target: `node-${link.work.id}`,
        animated: isBroken,
        style: { stroke: edgeColor, strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor },
      });

      // Work -> Test
      calculatedEdges.push({
        id: `e-work-test-${link.id}`,
        source: `node-${link.work.id}`,
        target: `node-${link.test.id}`,
        animated: isBroken,
        style: { stroke: edgeColor, strokeWidth: isBroken ? 2.5 : 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor },
      });

      // Test -> Signature
      calculatedEdges.push({
        id: `e-test-sig-${link.id}`,
        source: `node-${link.test.id}`,
        target: `node-${link.signature.id}`,
        animated: isBroken,
        style: { stroke: edgeColor, strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor },
      });
    });

    return { nodes: calculatedNodes, edges: calculatedEdges };
  }, [summary]);

  return (
    <div style={{ height: 'calc(100vh - 220px)', minHeight: '580px', width: '100%', position: 'relative', background: '#fafbfc', borderRadius: 8, border: '1px solid #ebecf0' }}>
      {/* Column Stage Headers */}
      <div
        style={{
          position: 'absolute',
          top: 12,
          left: 0,
          right: 0,
          display: 'flex',
          justifyContent: 'space-between',
          padding: '0 60px 0 50px',
          zIndex: 10,
          pointerEvents: 'none',
        }}
      >
        <div style={headerStyle}>1. ISO 14971 HAZARD ANALYSIS</div>
        <div style={headerStyle}>2. CONFLUENCE SRS SPEC</div>
        <div style={headerStyle}>3. JIRA WORK & PR</div>
        <div style={headerStyle}>4. IEC 62304 VERIFICATION</div>
        <div style={headerStyle}>5. 21 CFR PART 11 SIGN-OFF</div>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        onNodeClick={(_, node) => {
          const rawId = node.id.replace('node-', '');
          const match = summary.traceLinks.find(
            (l) =>
              l.hazard.id === rawId ||
              l.spec.id === rawId ||
              l.work.id === rawId ||
              l.test.id === rawId ||
              l.signature.id === rawId
          );
          if (match) {
            onSelectTraceLink(match.id);
          }
        }}
      >
        <Background color="#dfe1e6" gap={20} size={1} />
        <Controls />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === 'hazard') return '#de350b';
            if (n.type === 'test') return '#ff8b00';
            return '#0052cc';
          }}
          style={{ height: 100, width: 140 }}
        />
      </ReactFlow>
    </div>
  );
};

const headerStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: '0.8px',
  color: '#5e6c84',
  background: 'rgba(255, 255, 255, 0.9)',
  padding: '4px 10px',
  borderRadius: 4,
  boxShadow: '0 1px 3px rgba(9, 30, 66, 0.08)',
  border: '1px solid #dfe1e6',
};
