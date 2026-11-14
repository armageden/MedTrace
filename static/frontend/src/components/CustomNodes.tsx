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
  onActivate?: (refs: FlowLinkRef[]) => void;
};

const clampTextStyle: React.CSSProperties = {
  fontSize: 12,
  color: 'var(--mt-text-secondary, #42526e)',
  lineHeight: '16px',
  display: '-webkit-box',
  WebkitLineClamp: 2,
  WebkitBoxOrient: 'vertical',
  overflow: 'hidden',
};

const handleStyle: React.CSSProperties = {
  background: 'var(--mt-brand-bg, #0052cc)',
  width: 8,
  height: 8,
};

function handleNodeKeyDown<T>(
  event: React.KeyboardEvent<HTMLDivElement>,
  data: FlowNodePayload<T>
): void {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    event.stopPropagation();
    data.onActivate?.(data.linkRefs);
  }
}

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

const HazardNodeInner: React.FC<NodeProps<Node<FlowNodePayload<IsoHazard>>>> = ({ data, selected }) => {
  const hazard = data.item;
  const isClassC = hazard.riskClass === 'CLASS_C';
  const badgeColor = isClassC
    ? 'var(--mt-danger-text, #bf2600)'
    : hazard.riskClass === 'CLASS_B'
    ? 'var(--mt-warning-text, #974f0c)'
    : 'var(--mt-brand-text, #0052cc)';
  const badgeBg = isClassC
    ? 'var(--mt-danger-bg, #ffebe6)'
    : hazard.riskClass === 'CLASS_B'
    ? 'var(--mt-warning-bg, #fff0b3)'
    : 'var(--mt-brand-subtle-bg, #deebff)';

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`ISO 14971 Hazard ${hazard.key}: ${hazard.title} (${hazard.riskClass.replace('_', ' ')})`}
      onKeyDown={(e) => handleNodeKeyDown(e, data)}
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: 'var(--mt-bg-surface, #ffffff)',
        border: selected
          ? '2px solid var(--mt-brand-bg, #0052cc)'
          : `1.5px solid ${isClassC ? 'var(--mt-danger-bold, #de350b)' : 'var(--mt-border, #dfe1e6)'}`,
        boxShadow: isClassC
          ? '0 0 12px rgba(222, 53, 11, 0.25)'
          : '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 220,
        cursor: 'pointer',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ShieldAlert size={16} color={badgeColor} aria-hidden="true" />
          <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-text-primary, #172b4d)' }}>
            {hazard.key}
          </span>
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
      <div
        style={{
          marginTop: 6,
          fontSize: 10,
          color: 'var(--mt-text-muted, #505f79)',
          display: 'flex',
          justifyContent: 'space-between',
        }}
      >
        <span>
          Sev: <b>{hazard.severity}</b>
        </span>
        <span>
          Prob: <b>{hazard.probability}</b>
        </span>
      </div>
      <Handle type="source" position={Position.Right} style={handleStyle} />
    </div>
  );
};

export const HazardNode = React.memo(HazardNodeInner);
HazardNode.displayName = 'HazardNode';

const SpecNodeInner: React.FC<NodeProps<Node<FlowNodePayload<ConfluenceSpec>>>> = ({ data, selected }) => {
  const spec = data.item;
  const specTitle = spec.title && !spec.isMissingSentinel ? spec.title : 'Unlinked (No SRS)';

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`Confluence SRS ${specTitle} (v${spec.version}${spec.isSignatureInvalidated ? ', spec drift detected' : ''})`}
      onKeyDown={(e) => handleNodeKeyDown(e, data)}
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: 'var(--mt-bg-surface, #ffffff)',
        border: selected
          ? '2px solid var(--mt-brand-bg, #0052cc)'
          : spec.isSignatureInvalidated
          ? '1.5px solid #ff8b00'
          : '1.5px solid var(--mt-border, #dfe1e6)',
        boxShadow: spec.isSignatureInvalidated
          ? '0 0 10px rgba(255, 139, 0, 0.2)'
          : '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 220,
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <FileText size={16} color="var(--mt-brand-text, #0052cc)" aria-hidden="true" />
          <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-text-primary, #172b4d)' }}>
            Confluence SRS
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          {spec.version > 0 && (
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                padding: '2px 6px',
                borderRadius: 4,
                background: 'var(--mt-brand-subtle-bg, #deebff)',
                color: 'var(--mt-brand-text, #0052cc)',
              }}
            >
              v{spec.version}
            </span>
          )}
        </div>
      </div>
      <div style={clampTextStyle}>{specTitle}</div>
      {spec.isSignatureInvalidated && (
        <div
          style={{
            marginTop: 6,
            fontSize: 10,
            fontWeight: 600,
            color: 'var(--mt-danger-text, #bf2600)',
            display: 'flex',
            alignItems: 'center',
            gap: 4,
          }}
        >
          <AlertOctagon size={12} aria-hidden="true" /> Spec drift vs. Part 11 sign-off
        </div>
      )}
      <Handle type="source" position={Position.Right} style={handleStyle} />
    </div>
  );
};

export const SpecNode = React.memo(SpecNodeInner);
SpecNode.displayName = 'SpecNode';

const WorkNodeInner: React.FC<NodeProps<Node<FlowNodePayload<JiraWorkItem>>>> = ({ data, selected }) => {
  const work = data.item;
  const firstAssignee = (work.assignee || 'Unassigned').split(' ')[0];
  const workKeyLabel = work.key || 'Unbound';
  const workTitleLabel = work.title || 'Unbound Jira issue';

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`Jira Work Item ${workKeyLabel}: ${workTitleLabel} (${work.status})`}
      onKeyDown={(e) => handleNodeKeyDown(e, data)}
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: 'var(--mt-bg-surface, #ffffff)',
        border: selected
          ? '2px solid var(--mt-brand-bg, #0052cc)'
          : '1.5px solid var(--mt-border, #dfe1e6)',
        boxShadow: '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 210,
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <GitPullRequest size={15} color="var(--mt-success-text, #006644)" aria-hidden="true" />
          <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-brand-text, #0052cc)' }}>
            {workKeyLabel}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              padding: '2px 6px',
              borderRadius: 4,
              background: work.status === 'Done' ? 'var(--mt-success-bg, #e3fcef)' : '#eae6ff',
              color: work.status === 'Done' ? 'var(--mt-success-text, #006644)' : '#403294',
            }}
          >
            {work.status}
          </span>
        </div>
      </div>
      <div style={clampTextStyle}>{workTitleLabel}</div>
      <div style={{ marginTop: 6, fontSize: 10, color: 'var(--mt-text-muted, #505f79)' }}>
        <span>
          Assignee: {firstAssignee} {work.prNumber || ''}
        </span>
      </div>
      <Handle type="source" position={Position.Right} style={handleStyle} />
    </div>
  );
};

export const WorkNode = React.memo(WorkNodeInner);
WorkNode.displayName = 'WorkNode';

const TestNodeInner: React.FC<NodeProps<Node<FlowNodePayload<VerificationTest>>>> = ({ data, selected }) => {
  const test = data.item;
  const isFailingOrUntested = test.status !== 'PASSED';

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`IEC 62304 Verification ${test.testKey}: ${test.title} (${test.status})`}
      onKeyDown={(e) => handleNodeKeyDown(e, data)}
      className={isFailingOrUntested ? 'mt-node-test--alert' : undefined}
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: isFailingOrUntested
          ? 'var(--mt-danger-row-bg, #fff5f5)'
          : 'var(--mt-bg-surface, #ffffff)',
        border: selected
          ? '2px solid var(--mt-brand-bg, #0052cc)'
          : isFailingOrUntested
          ? '2px solid var(--mt-danger-bold, #de350b)'
          : '1.5px solid var(--mt-success-bold, #00875a)',
        boxShadow: isFailingOrUntested
          ? '0 0 14px rgba(222, 53, 11, 0.35)'
          : '0 2px 6px rgba(0, 135, 90, 0.1)',
        width: 220,
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Activity
            size={16}
            color={isFailingOrUntested ? 'var(--mt-danger-text, #bf2600)' : 'var(--mt-success-text, #006644)'}
            aria-hidden="true"
          />
          <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-text-primary, #172b4d)' }}>
            {test.testKey}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          <span
            style={{
              fontSize: 10,
              fontWeight: 800,
              padding: '2px 8px',
              borderRadius: 4,
              background: isFailingOrUntested
                ? 'var(--mt-danger-bold, #de350b)'
                : 'var(--mt-success-bg, #e3fcef)',
              color: isFailingOrUntested ? '#ffffff' : 'var(--mt-success-text, #006644)',
              letterSpacing: '0.5px',
            }}
          >
            {test.status}
          </span>
        </div>
      </div>
      <div style={clampTextStyle}>{test.title}</div>
      <div style={{ marginTop: 6, fontSize: 10, color: 'var(--mt-text-muted, #505f79)' }}>
        <span>{test.testType}</span>
      </div>
      <Handle type="source" position={Position.Right} style={handleStyle} />
    </div>
  );
};

export const TestNode = React.memo(TestNodeInner);
TestNode.displayName = 'TestNode';

const SignatureNodeInner: React.FC<NodeProps<Node<FlowNodePayload<Part11Signature>>>> = ({ data, selected }) => {
  const sig = data.item;
  const signerLabel = sig.signedBy || 'Unsigned';

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={`21 CFR Part 11 Signature: ${sig.isValid ? 'Certified' : 'Invalidated'} by ${signerLabel}`}
      onKeyDown={(e) => handleNodeKeyDown(e, data)}
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: 'var(--mt-bg-surface, #ffffff)',
        border: selected
          ? '2px solid var(--mt-brand-bg, #0052cc)'
          : sig.isValid
          ? '1.5px solid var(--mt-success-bold, #00875a)'
          : '2px solid var(--mt-danger-bold, #de350b)',
        boxShadow: sig.isValid
          ? '0 2px 6px rgba(0, 135, 90, 0.1)'
          : '0 0 12px rgba(222, 53, 11, 0.3)',
        width: 220,
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6, gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {sig.isValid ? (
            <Lock size={15} color="var(--mt-success-text, #006644)" aria-hidden="true" />
          ) : (
            <Unlock size={15} color="var(--mt-danger-text, #bf2600)" aria-hidden="true" />
          )}
          <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-text-primary, #172b4d)' }}>
            21 CFR Part 11
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <SharedCountBadge count={data.linkRefs.length} />
          <span
            style={{
              fontSize: 10,
              fontWeight: 800,
              padding: '2px 6px',
              borderRadius: 4,
              background: sig.isValid ? 'var(--mt-success-bg, #e3fcef)' : 'var(--mt-danger-bg, #ffebe6)',
              color: sig.isValid ? 'var(--mt-success-text, #006644)' : 'var(--mt-danger-text, #bf2600)',
            }}
          >
            {sig.isValid ? 'CERTIFIED' : 'INVALIDATED'}
          </span>
        </div>
      </div>
      <div style={{ fontSize: 11, color: 'var(--mt-text-primary, #172b4d)', fontWeight: 600 }}>
        {signerLabel}
      </div>
      <div style={{ fontSize: 10, color: 'var(--mt-text-muted, #505f79)', marginTop: 2 }}>{sig.role}</div>
      <div
        style={{
          fontSize: 10,
          color: 'var(--mt-text-muted, #505f79)',
          marginTop: 4,
          fontFamily: 'monospace',
        }}
      >
        SHA: {(sig.artifactSha256 || '').slice(0, 12)}...
      </div>
    </div>
  );
};

export const SignatureNode = React.memo(SignatureNodeInner);
SignatureNode.displayName = 'SignatureNode';
