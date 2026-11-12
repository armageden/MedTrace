import React from 'react';
import { Handle, Node, NodeProps, Position } from '@xyflow/react';
import { ShieldAlert, FileText, AlertOctagon, Lock, Unlock, GitPullRequest, Activity } from 'lucide-react';
import { IsoHazard, ConfluenceSpec, JiraWorkItem, VerificationTest, Part11Signature } from '../types';

export interface FlowLinkRef {
  id: string;
  hazardKey: string;
  workKey: string;
}

export type FlowNodePayload<T> = {
  item: T;
  linkRefs: FlowLinkRef[];
};

const clampTextStyle: React.CSSProperties = {
  fontSize: 12,
  color: '#42526e',
  lineHeight: '16px',
  display: '-webkit-box',
  WebkitLineClamp: 2,
  WebkitBoxOrient: 'vertical',
  overflow: 'hidden',
};

const SharedCountBadge: React.FC<{ count: number }> = ({ count }) => {
  if (count <= 1) return null;
  return (
    <span
      style={{
        fontSize: 9,
        fontWeight: 800,
        padding: '1px 5px',
        borderRadius: 10,
        background: '#eae6ff',
        color: '#403294',
      }}
      title={`Shared across ${count} trace links — click to choose a link`}
    >
      {count} links
    </span>
  );
};

export const HazardNode: React.FC<NodeProps<Node<FlowNodePayload<IsoHazard>>>> = ({ data, selected }) => {
  const hazard = data.item;
  const isClassC = hazard.riskClass === 'CLASS_C';
  const badgeColor = isClassC ? '#bf2600' : hazard.riskClass === 'CLASS_B' ? '#974f0c' : '#0052cc';
  const badgeBg = isClassC ? '#ffebe6' : hazard.riskClass === 'CLASS_B' ? '#fff0b3' : '#deebff';

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: '#ffffff',
        border: selected ? '2px solid #0052cc' : `1.5px solid ${isClassC ? '#de350b' : '#dfe1e6'}`,
        boxShadow: isClassC ? '0 0 12px rgba(222, 53, 11, 0.25)' : '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 220,
        cursor: 'pointer',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ShieldAlert size={16} color={badgeColor} />
          <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>{hazard.key}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              padding: '2px 6px',
              borderRadius: 4,
              background: badgeBg,
              color: badgeColor,
            }}
          >
            {hazard.riskClass.replace('_', ' ')}
          </span>
        </div>
      </div>
      <div style={clampTextStyle}>{hazard.title}</div>
      <div style={{ marginTop: 6, fontSize: 10, color: '#505f79', display: 'flex', justifyContent: 'space-between' }}>
        <span>
          Sev: <b>{hazard.severity}</b>
        </span>
        <span>
          Prob: <b>{hazard.probability}</b>
        </span>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: '#0052cc', width: 8, height: 8 }} />
    </div>
  );
};

export const SpecNode: React.FC<NodeProps<Node<FlowNodePayload<ConfluenceSpec>>>> = ({ data, selected }) => {
  const spec = data.item;
  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: '#ffffff',
        border: selected ? '2px solid #0052cc' : spec.isSignatureInvalidated ? '1.5px solid #ff8b00' : '1.5px solid #dfe1e6',
        boxShadow: spec.isSignatureInvalidated ? '0 0 10px rgba(255, 139, 0, 0.2)' : '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 220,
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#0052cc', width: 8, height: 8 }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <FileText size={16} color="#0052cc" />
          <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>Confluence SRS</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: '#deebff', color: '#0052cc' }}>
            v{spec.version}
          </span>
        </div>
      </div>
      <div style={clampTextStyle}>{spec.title}</div>
      {spec.isSignatureInvalidated && (
        <div style={{ marginTop: 6, fontSize: 10, fontWeight: 600, color: '#bf2600', display: 'flex', alignItems: 'center', gap: 4 }}>
          <AlertOctagon size={12} /> Spec drift vs. Part 11 sign-off
        </div>
      )}
      <Handle type="source" position={Position.Right} style={{ background: '#0052cc', width: 8, height: 8 }} />
    </div>
  );
};

export const WorkNode: React.FC<NodeProps<Node<FlowNodePayload<JiraWorkItem>>>> = ({ data, selected }) => {
  const work = data.item;
  const firstAssignee = (work.assignee || 'Unassigned').split(' ')[0];
  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: '#ffffff',
        border: selected ? '2px solid #0052cc' : '1.5px solid #dfe1e6',
        boxShadow: '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 210,
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#0052cc', width: 8, height: 8 }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <GitPullRequest size={15} color="#006644" />
          <span style={{ fontWeight: 700, fontSize: 13, color: '#0052cc' }}>{work.key}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              padding: '2px 6px',
              borderRadius: 4,
              background: work.status === 'Done' ? '#e3fcef' : '#eae6ff',
              color: work.status === 'Done' ? '#006644' : '#403294',
            }}
          >
            {work.status}
          </span>
        </div>
      </div>
      <div style={clampTextStyle}>{work.title}</div>
      <div style={{ marginTop: 6, fontSize: 10, color: '#505f79' }}>
        <span>
          Assignee: {firstAssignee} {work.prNumber || ''}
        </span>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: '#0052cc', width: 8, height: 8 }} />
    </div>
  );
};

export const TestNode: React.FC<NodeProps<Node<FlowNodePayload<VerificationTest>>>> = ({ data, selected }) => {
  const test = data.item;
  const isFailingOrUntested = test.status !== 'PASSED';

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: isFailingOrUntested ? '#fff5f5' : '#ffffff',
        border: selected ? '2px solid #0052cc' : isFailingOrUntested ? '2px solid #de350b' : '1.5px solid #00875a',
        boxShadow: isFailingOrUntested ? '0 0 14px rgba(222, 53, 11, 0.35)' : '0 2px 6px rgba(0, 135, 90, 0.1)',
        width: 220,
        cursor: 'pointer',
        animation: isFailingOrUntested ? 'pulseBorder 2s infinite' : 'none',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#0052cc', width: 8, height: 8 }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Activity size={16} color={isFailingOrUntested ? '#bf2600' : '#006644'} />
          <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>{test.testKey}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          <span
            style={{
              fontSize: 10,
              fontWeight: 800,
              padding: '2px 8px',
              borderRadius: 4,
              background: isFailingOrUntested ? '#de350b' : '#e3fcef',
              color: isFailingOrUntested ? '#ffffff' : '#006644',
              letterSpacing: '0.5px',
            }}
          >
            {test.status}
          </span>
        </div>
      </div>
      <div style={clampTextStyle}>{test.title}</div>
      <div style={{ marginTop: 6, fontSize: 10, color: '#505f79' }}>
        <span>{test.testType}</span>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: '#0052cc', width: 8, height: 8 }} />
    </div>
  );
};

export const SignatureNode: React.FC<NodeProps<Node<FlowNodePayload<Part11Signature>>>> = ({ data, selected }) => {
  const sig = data.item;
  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: '#ffffff',
        border: selected ? '2px solid #0052cc' : sig.isValid ? '1.5px solid #00875a' : '2px solid #de350b',
        boxShadow: sig.isValid ? '0 2px 6px rgba(0, 135, 90, 0.1)' : '0 0 12px rgba(222, 53, 11, 0.3)',
        width: 220,
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#0052cc', width: 8, height: 8 }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {sig.isValid ? <Lock size={15} color="#006644" /> : <Unlock size={15} color="#bf2600" />}
          <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>21 CFR Part 11</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          <span
            style={{
              fontSize: 10,
              fontWeight: 800,
              padding: '2px 6px',
              borderRadius: 4,
              background: sig.isValid ? '#e3fcef' : '#ffebe6',
              color: sig.isValid ? '#006644' : '#bf2600',
            }}
          >
            {sig.isValid ? 'CERTIFIED' : 'INVALIDATED'}
          </span>
        </div>
      </div>
      <div style={{ fontSize: 11, color: '#172b4d', fontWeight: 600 }}>{sig.signedBy || 'Unsigned'}</div>
      <div style={{ fontSize: 10, color: '#505f79', marginTop: 2 }}>{sig.role}</div>
      <div style={{ fontSize: 10, color: '#505f79', marginTop: 4, fontFamily: 'monospace' }}>
        SHA: {(sig.artifactSha256 || '').slice(0, 12)}...
      </div>
    </div>
  );
};
