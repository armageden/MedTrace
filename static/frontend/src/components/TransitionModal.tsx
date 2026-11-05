import React from 'react';
import { X, ShieldAlert, ShieldCheck } from 'lucide-react';

interface TransitionModalProps {
  isOpen: boolean;
  onClose: () => void;
  result: { result: boolean; errorMessage?: string } | null;
}

export const TransitionModal: React.FC<TransitionModalProps> = ({ isOpen, onClose, result }) => {
  if (!isOpen || !result) return null;

  const isBlocked = !result.result;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(9, 30, 66, 0.54)',
        zIndex: 2500,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      }}
    >
      <div
        style={{
          background: '#ffffff',
          borderRadius: 8,
          width: '100%',
          maxWidth: 540,
          boxShadow: '0 8px 32px rgba(9, 30, 66, 0.3)',
          overflow: 'hidden',
          borderTop: `6px solid ${isBlocked ? '#de350b' : '#00875a'}`,
        }}
      >
        <div style={{ padding: '20px 24px', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {isBlocked ? (
              <div style={{ background: '#ffebe6', borderRadius: '50%', padding: 10, display: 'flex' }}>
                <ShieldAlert size={28} color="#de350b" />
              </div>
            ) : (
              <div style={{ background: '#e3fcef', borderRadius: '50%', padding: 10, display: 'flex' }}>
                <ShieldCheck size={28} color="#00875a" />
              </div>
            )}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#6b778c', textTransform: 'uppercase' }}>
                Jira Workflow Validator Live Intercept
              </div>
              <div style={{ fontSize: 17, fontWeight: 800, color: '#172b4d', marginTop: 2 }}>
                {isBlocked ? 'Transition to "Done" Blocked' : 'Transition to "Done" Authorized'}
              </div>
            </div>
          </div>
          <button onClick={onClose} style={{ border: 'none', background: 'transparent', cursor: 'pointer', color: '#6b778c' }}>
            <X size={20} />
          </button>
        </div>

        <div style={{ padding: '0 24px 20px 24px' }}>
          {isBlocked ? (
            <div style={{ background: '#fff5f5', border: '1px solid #ffbdad', borderRadius: 6, padding: '14px 16px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#bf2600', marginBottom: 6 }}>
                MedTrace IEC 62304 Safety Gate Lockout:
              </div>
              <div style={{ fontSize: 12, color: '#42526e', whiteSpace: 'pre-line', lineHeight: '18px' }}>
                {result.errorMessage || 'Class C Hazard lacks verified test coverage or has an invalidated 21 CFR Part 11 signature.'}
              </div>
            </div>
          ) : (
            <div style={{ background: '#e3fcef', border: '1px solid #abf5d1', borderRadius: 6, padding: '14px 16px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#006644', marginBottom: 6 }}>
                All Regulatory Criteria Satisfied:
              </div>
              <div style={{ fontSize: 12, color: '#42526e', lineHeight: '18px' }}>
                ✓ ISO 14971 Class C hazards verified with passing automated test execution.<br />
                ✓ 21 CFR Part 11 electronic signatures validated against Confluence SHA-256 digests.<br />
                ✓ Issue transition to <b>Done / Released</b> is safely permitted.
              </div>
            </div>
          )}
        </div>

        <div style={{ padding: '12px 24px', background: '#fafbfc', borderTop: '1px solid #ebecf0', display: 'flex', justifyContent: 'flex-end' }}>
          <button
            onClick={onClose}
            style={{
              padding: '8px 16px',
              borderRadius: 4,
              border: 'none',
              background: '#0052cc',
              color: '#ffffff',
              fontWeight: 700,
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            Close Intercept Dialog
          </button>
        </div>
      </div>
    </div>
  );
};
