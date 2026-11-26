import React from 'react';
import { RefreshCw, ShieldCheck, Sparkles, Zap } from 'lucide-react';

export interface LiveOnboardingCardProps {
  onSyncLive?: () => void;
  onSeedDemo?: () => void;
  onCreateLiveProof?: () => void;
  canCreateLiveProof?: boolean;
  isBusy?: boolean;
}

const ONBOARDING_STEPS = [
  'Create Live Proof Chain creates a real Confluence SRS page plus linked native Jira hazard, implementation, and verification-test issues.',
  'Record HTTPS test verification evidence and execute 21 CFR Part 11 electronic attestation sign-off to establish the compliant baseline.',
  'Edit the Confluence requirement from 5.0 to 5.5 mL/hr to prove hash drift, stale approval invalidation, impact analysis, and release blocking.',
  'Manual path: label safety-critical Jira issues with class-a, class-b, or class-c, link implementation work to SRS pages and Hazard / Test issues, then click Sync Live Atlassian.',
];

export const LiveOnboardingCard: React.FC<LiveOnboardingCardProps> = ({
  onSyncLive,
  onSeedDemo,
  onCreateLiveProof,
  canCreateLiveProof = true,
  isBusy = false,
}) => (
  <div
    style={{
      maxWidth: 680,
      margin: '0 auto',
      padding: '24px 28px',
      textAlign: 'left',
      background: 'var(--mt-bg-surface, #ffffff)',
      border: '1px solid var(--mt-border, #dfe1e6)',
      borderRadius: 10,
      boxShadow: '0 2px 8px rgba(9, 30, 66, 0.06)',
    }}
  >
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
      <div
        style={{
          width: 34,
          height: 34,
          borderRadius: 8,
          background: 'var(--mt-brand-subtle-bg, #deebff)',
          color: 'var(--mt-brand-text, #0052cc)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0,
        }}
      >
        <ShieldCheck size={18} aria-hidden="true" />
      </div>
      <div>
        <div
          style={{
            fontSize: 15,
            fontWeight: 800,
            color: 'var(--mt-text-primary, #172b4d)',
          }}
        >
          Connect Your Live Jira &amp; Confluence Artifacts
        </div>
        <div style={{ fontSize: 12, color: 'var(--mt-text-muted, #505f79)', marginTop: 2 }}>
          LIVE mode starts empty and fails closed until safety-classified issues are synchronized.
        </div>
      </div>
    </div>

    <ol
      style={{
        margin: '14px 0 0',
        paddingLeft: 20,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        fontSize: 12,
        lineHeight: '18px',
        color: 'var(--mt-text-primary, #172b4d)',
      }}
    >
      {ONBOARDING_STEPS.map((step, idx) => (
        <li key={idx}>{step}</li>
      ))}
    </ol>

    <div style={{ fontSize: 12, color: 'var(--mt-text-muted, #505f79)', marginTop: 10 }}>
      In the matrix or graph, click a row or node to open the inspection drawer, where you record
      evidence, sign off, and create re-verification tasks.
    </div>

    {(onSyncLive || onSeedDemo || onCreateLiveProof) && (
      <div style={{ marginTop: 18, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {onCreateLiveProof && (
          <button
            type="button"
            disabled={isBusy || !canCreateLiveProof}
            onClick={onCreateLiveProof}
            className="mt-btn"
            title={
              canCreateLiveProof
                ? 'Creates one real SRS page and three linked native Jira issues. Evidence and approval remain explicit user actions.'
                : 'Open MedTrace from a Jira project page to create the live proof chain.'
            }
            style={{
              padding: '8px 14px',
              border: 'none',
              background: 'var(--mt-success-bg, #006644)',
              color: 'var(--ds-text-inverse, #ffffff)',
            }}
          >
            <Zap size={14} aria-hidden="true" /> Create Live Proof Chain
          </button>
        )}
        {onSyncLive && (
          <button
            type="button"
            disabled={isBusy}
            onClick={onSyncLive}
            className="mt-btn"
            style={{
              padding: '8px 14px',
              border: 'none',
              background: 'var(--mt-brand-bg, #0052cc)',
              color: 'var(--ds-text-inverse, #ffffff)',
            }}
          >
            <RefreshCw size={14} aria-hidden="true" /> Sync Live Atlassian
          </button>
        )}
        {onSeedDemo && (
          <button
            type="button"
            disabled={isBusy}
            onClick={onSeedDemo}
            className="mt-btn"
            style={{
              padding: '8px 14px',
              border: '1px solid var(--mt-border, #dfe1e6)',
              background: 'var(--mt-bg-page, #f4f5f7)',
              color: 'var(--mt-text-primary, #172b4d)',
            }}
          >
            <Sparkles size={14} aria-hidden="true" /> Explore Demo Suite
          </button>
        )}
      </div>
    )}
  </div>
);
