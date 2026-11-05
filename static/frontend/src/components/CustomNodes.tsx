import React from 'react';
import { Handle, Position } from '@xyflow/react';
import { ShieldAlert, FileText, CheckCircle2, AlertOctagon, Lock, Unlock, GitPullRequest, Activity } from 'lucide-react';
import { IsoHazard, ConfluenceSpec, JiraWorkItem, VerificationTest, Part11Signature } from '../types';

interface NodeProps<T> {
  data: T;
  selected?: boolean;
}

export const HazardNode: React.FC<NodeProps<IsoHazard>> = ({ data, selected }) => {
  const isClassC = data.riskClass === 'CLASS_C';
  const badgeColor = isClassC ? '#de350b' : data.riskClass === 'CLASS_B' ? '#ff8b00' : '#0052cc';
  const badgeBg = isClassC ? '#ffebe6' : data.riskClass === 'CLASS_B' ? '#fff0b3' : '#deebff';

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: '#ffffff',
        border: selected ? '2px solid #0052cc' : `1.5px solid ${isClassC ? '#de350b' : '#dfe1e6'}`,
        boxShadow: isClassC ? '0 0 12px rgba(222, 53, 11, 0.25)' : '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 220,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        cursor: 'pointer',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ShieldAlert size={16} color={badgeColor} />
          <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>{data.key}</span>
        </div>
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
          {data.riskClass.replace('_', ' ')}
        </span>
      </div>
      <div
        style={{
          fontSize: 12,
          color: '#42526e',
          lineHeight: '16px',
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
      >
        {data.title}
      </div>
      <div style={{ marginTop: 6, fontSize: 10, color: '#6b778c', display: 'flex', justifyContent: 'space-between' }}>
        <span>Sev: <b>{data.severity}</b></span>
        <span>Prob: <b>{data.probability}</b></span>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: '#0052cc', width: 8, height: 8 }} />
    </div>
  );
};

export const SpecNode: React.FC<NodeProps<ConfluenceSpec>> = ({ data, selected }) => {
  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: '#ffffff',
        border: selected ? '2px solid #0052cc' : data.isSignatureInvalidated ? '1.5px solid #ff8b00' : '1.5px solid #dfe1e6',
        boxShadow: data.isSignatureInvalidated ? '0 0 10px rgba(255, 139, 0, 0.2)' : '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 220,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#0052cc', width: 8, height: 8 }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <FileText size={16} color="#0052cc" />
          <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>Confluence SRS</span>
        </div>
        <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: '#deebff', color: '#0052cc' }}>
          v{data.version}
        </span>
      </div>
      <div
        style={{
          fontSize: 12,
          color: '#42526e',
          lineHeight: '16px',
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
      >
        {data.title}
      </div>
      {data.isSignatureInvalidated && (
        <div style={{ marginTop: 6, fontSize: 10, fontWeight: 600, color: '#de350b', display: 'flex', alignItems: 'center', gap: 4 }}>
          <AlertOctagon size={12} /> Spec drift vs. Part 11 sign-off
        </div>
      )}
      <Handle type="source" position={Position.Right} style={{ background: '#0052cc', width: 8, height: 8 }} />
    </div>
  );
};

export const WorkNode: React.FC<NodeProps<JiraWorkItem>> = ({ data, selected }) => {
  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: '#ffffff',
        border: selected ? '2px solid #0052cc' : '1.5px solid #dfe1e6',
        boxShadow: '0 2px 6px rgba(9, 30, 66, 0.08)',
        width: 210,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#0052cc', width: 8, height: 8 }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <GitPullRequest size={15} color="#00875a" />
          <span style={{ fontWeight: 700, fontSize: 13, color: '#0052cc' }}>{data.key}</span>
        </div>
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            padding: '2px 6px',
            borderRadius: 4,
            background: data.status === 'Done' ? '#e3fcef' : '#eae6ff',
            color: data.status === 'Done' ? '#00875a' : '#403294',
          }}
        >
          {data.status}
        </span>
      </div>
      <div
        style={{
          fontSize: 12,
          color: '#42526e',
          lineHeight: '16px',
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
      >
        {data.title}
      </div>
      <div style={{ marginTop: 6, fontSize: 10, color: '#6b778c' }}>
        <span>Assignee: {data.assignee.split(' ')[0]} {data.prNumber}</span>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: '#0052cc', width: 8, height: 8 }} />
    </div>
  );
};

export const TestNode: React.FC<NodeProps<VerificationTest>> = ({ data, selected }) => {
  const isUntested = data.status === 'UNTESTED';

  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: isUntested ? '#fff5f5' : '#ffffff',
        border: selected ? '2px solid #0052cc' : isUntested ? '2px solid #de350b' : '1.5px solid #00875a',
        boxShadow: isUntested ? '0 0 14px rgba(222, 53, 11, 0.35)' : '0 2px 6px rgba(0, 135, 90, 0.1)',
        width: 220,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        cursor: 'pointer',
        animation: isUntested ? 'pulseBorder 2s infinite' : 'none',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#0052cc', width: 8, height: 8 }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Activity size={16} color={isUntested ? '#de350b' : '#00875a'} />
          <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>{data.testKey}</span>
        </div>
        <span
          style={{
            fontSize: 10,
            fontWeight: 800,
            padding: '2px 8px',
            borderRadius: 4,
            background: isUntested ? '#de350b' : '#e3fcef',
            color: isUntested ? '#ffffff' : '#00875a',
            letterSpacing: '0.5px',
          }}
        >
          {data.status}
        </span>
      </div>
      <div
        style={{
          fontSize: 12,
          color: '#42526e',
          lineHeight: '16px',
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
      >
        {data.title}
      </div>
      <div style={{ marginTop: 6, fontSize: 10, color: '#6b778c' }}>
        <span>{data.testType}</span>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: '#0052cc', width: 8, height: 8 }} />
    </div>
  );
};

export const SignatureNode: React.FC<NodeProps<Part11Signature>> = ({ data, selected }) => {
  return (
    <div
      style={{
        padding: '12px 14px',
        borderRadius: 8,
        background: '#ffffff',
        border: selected ? '2px solid #0052cc' : data.isValid ? '1.5px solid #00875a' : '2px solid #de350b',
        boxShadow: data.isValid ? '0 2px 6px rgba(0, 135, 90, 0.1)' : '0 0 12px rgba(222, 53, 11, 0.3)',
        width: 220,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: '#0052cc', width: 8, height: 8 }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {data.isValid ? <Lock size={15} color="#00875a" /> : <Unlock size={15} color="#de350b" />}
          <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>21 CFR Part 11</span>
        </div>
        <span
          style={{
            fontSize: 10,
            fontWeight: 800,
            padding: '2px 6px',
            borderRadius: 4,
            background: data.isValid ? '#e3fcef' : '#ffebe6',
            color: data.isValid ? '#00875a' : '#de350b',
          }}
        >
          {data.isValid ? 'CERTIFIED' : 'INVALIDATED'}
        </span>
      </div>
      <div style={{ fontSize: 11, color: '#172b4d', fontWeight: 600 }}>{data.signedBy}</div>
      <div style={{ fontSize: 10, color: '#6b778c', marginTop: 2 }}>{data.role}</div>
      <div style={{ fontSize: 9, color: '#8993a4', marginTop: 4, fontFamily: 'monospace' }}>
        SHA: {data.artifactSha256.slice(0, 12)}...
      </div>
    </div>
  );
};
