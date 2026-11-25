import React from 'react';
import { Clock, Zap } from 'lucide-react';
import { BlastRadiusReport } from '../types';

export interface BlastRadiusCardProps {
  blastRadius: BlastRadiusReport;
}

export const BlastRadiusCard: React.FC<BlastRadiusCardProps> = ({ blastRadius }) => (
  <div
    style={{
      marginBottom: 16,
      padding: '14px 16px',
      borderRadius: 8,
      background: 'var(--mt-warning-bg)',
      border: '1.5px solid var(--mt-warning-border)',
      boxShadow: '0 2px 6px rgba(255, 171, 0, 0.15)',
    }}
  >
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 6,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          color: 'var(--mt-warning-text)',
          fontWeight: 800,
          fontSize: 13,
        }}
      >
        <Zap size={16} /> Transitive Regulatory Blast Radius
      </div>
      <span
        style={{
          fontSize: 10,
          fontFamily: 'monospace',
          background: 'var(--mt-bg-surface)',
          padding: '2px 6px',
          borderRadius: 4,
          border: '1px solid var(--mt-warning-border)',
          color: 'var(--mt-text-secondary)',
          display: 'flex',
          alignItems: 'center',
          gap: 4,
        }}
      >
        <Clock size={11} /> {blastRadius.executionTimeMs} ms
      </span>
    </div>

    <div style={{ fontSize: 11, color: 'var(--mt-text-primary)', marginBottom: 8 }}>
      Trigger: <b>{blastRadius.triggerArtifact.title}</b> ({blastRadius.triggerArtifact.deltaReason})
    </div>

    <div
      style={{
        background: 'var(--mt-bg-surface)',
        borderRadius: 6,
        padding: '8px 10px',
        border: '1px solid var(--mt-border-subtle)',
        marginBottom: 10,
      }}
    >
      <div
        style={{
          fontSize: 10,
          fontWeight: 700,
          color: 'var(--mt-text-muted)',
          textTransform: 'uppercase',
          marginBottom: 4,
        }}
      >
        Deterministic Graph Traversal (BFS):
      </div>
      {blastRadius.traversalPath.map((hop, idx) => (
        <div key={idx} style={{ fontSize: 11, lineHeight: '16px', marginTop: 4, display: 'flex', gap: 6 }}>
          <span style={{ fontWeight: 700, color: 'var(--mt-brand-text)', minWidth: 40 }}>
            Hop {hop.hop}:
          </span>
          <span style={{ color: 'var(--mt-text-secondary)' }}>
            <span style={{ fontWeight: 600, color: 'var(--mt-text-primary)' }}>{hop.edge}</span> →{' '}
            {hop.effect}
          </span>
        </div>
      ))}
    </div>

    <div>
      <div
        style={{
          fontSize: 10,
          fontWeight: 700,
          color: 'var(--mt-text-muted)',
          textTransform: 'uppercase',
          marginBottom: 4,
        }}
      >
        Mandatory Re-audit Actions:
      </div>
      {blastRadius.transitiveActionPlan.map((action, idx) => (
        <div key={idx} style={{ fontSize: 11, color: 'var(--mt-text-primary)', lineHeight: '16px', marginTop: 3 }}>
          • {action}
        </div>
      ))}
    </div>
  </div>
);
