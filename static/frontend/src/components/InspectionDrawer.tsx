import React from 'react';
import { TraceLink } from '../types';
import { X, ShieldAlert, FileText, GitPullRequest, Activity, Lock, AlertOctagon, CheckCircle2, Zap } from 'lucide-react';

interface InspectionDrawerProps {
  link: TraceLink | null;
  onClose: () => void;
  onRemediate: () => void;
  isRemediating: boolean;
}

export const InspectionDrawer: React.FC<InspectionDrawerProps> = ({ link, onClose, onRemediate, isRemediating }) => {
  if (!link) return null;

  const isClassC = link.hazard.riskClass === 'CLASS_C';
  const isBroken = link.complianceState !== 'VERIFIED';

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        right: 0,
        bottom: 0,
        width: 440,
        background: '#ffffff',
        boxShadow: '-4px 0 24px rgba(9, 30, 66, 0.15)',
        zIndex: 1000,
        display: 'flex',
        flexDirection: 'column',
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      }}
    >
      {/* Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid #ebecf0', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#fafbfc' }}>
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#6b778c', textTransform: 'uppercase' }}>Regulatory Trace Inspection</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: '#172b4d' }}>{link.hazard.key} Lineage</div>
        </div>
        <button
          onClick={onClose}
          style={{ border: 'none', background: 'transparent', cursor: 'pointer', padding: 4, borderRadius: 4, color: '#6b778c' }}
        >
          <X size={18} />
        </button>
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
        {/* Violations Alert Banner */}
        {link.violations.length > 0 && (
          <div style={{ marginBottom: 16, padding: '12px 14px', borderRadius: 6, background: '#ffebe6', border: '1px solid #ffbdad' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#de350b', fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
              <AlertOctagon size={16} /> Regulatory Safety Gate Lockout
            </div>
            {link.violations.map((v, i) => (
              <div key={i} style={{ fontSize: 11, color: '#bf2600', lineHeight: '16px', marginTop: 4 }}>
                • {v}
              </div>
            ))}
          </div>
        )}

        {/* Stage 1: ISO 14971 Hazard */}
        <div style={sectionStyle}>
          <div style={sectionHeader}>
            <ShieldAlert size={15} color={isClassC ? '#de350b' : '#0052cc'} />
            <span>1. ISO 14971 Risk Classification</span>
          </div>
          <div style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>{link.hazard.title}</div>
          <div style={{ marginTop: 6, display: 'flex', gap: 8, fontSize: 11 }}>
            <span style={pillStyle('#ffebe6', '#de350b')}>{link.hazard.riskClass.replace('_', ' ')}</span>
            <span style={pillStyle('#f4f5f7', '#42526e')}>Severity: {link.hazard.severity}</span>
            <span style={pillStyle('#f4f5f7', '#42526e')}>Prob: {link.hazard.probability}</span>
          </div>
        </div>

        {/* Stage 2: Confluence SRS Spec */}
        <div style={sectionStyle}>
          <div style={sectionHeader}>
            <FileText size={15} color="#0052cc" />
            <span>2. Confluence Safety Spec (SRS)</span>
          </div>
          <div style={{ fontWeight: 600, fontSize: 13, color: '#172b4d' }}>{link.spec.title}</div>
          <div style={{ fontSize: 11, color: '#5e6c84', marginTop: 4, background: '#f4f5f7', padding: '6px 8px', borderRadius: 4 }}>
            "{link.spec.contentSnippet}"
          </div>
          <div style={{ marginTop: 6, fontSize: 10, color: '#6b778c' }}>
            <span>Revision: <b>v{link.spec.version}</b></span> | <span>Last: {link.spec.lastUpdated}</span>
          </div>
          <div style={{ marginTop: 4, fontSize: 9, fontFamily: 'monospace', color: link.spec.isSignatureInvalidated ? '#de350b' : '#6b778c' }}>
            SHA-256: {link.spec.sha256Hash}
          </div>
        </div>

        {/* Stage 3: Jira Implementation */}
        <div style={sectionStyle}>
          <div style={sectionHeader}>
            <GitPullRequest size={15} color="#00875a" />
            <span>3. Jira Work Item & Pull Request</span>
          </div>
          <div style={{ fontWeight: 700, fontSize: 13, color: '#0052cc' }}>{link.work.key}: {link.work.title}</div>
          <div style={{ marginTop: 6, fontSize: 11, color: '#42526e', display: 'flex', gap: 12 }}>
            <span>Status: <b>{link.work.status}</b></span>
            <span>PR: <b>{link.work.prNumber}</b></span>
            <span>Assignee: <b>{link.work.assignee}</b></span>
          </div>
        </div>

        {/* Stage 4: IEC 62304 Verification Test */}
        <div style={sectionStyle}>
          <div style={sectionHeader}>
            <Activity size={15} color={link.test.status === 'PASSED' ? '#00875a' : '#de350b'} />
            <span>4. IEC 62304 Verification Evidence</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>{link.test.testKey}: {link.test.title}</span>
            <span style={pillStyle(link.test.status === 'PASSED' ? '#e3fcef' : '#ffebe6', link.test.status === 'PASSED' ? '#00875a' : '#de350b')}>
              {link.test.status}
            </span>
          </div>
          <div style={{ fontSize: 11, color: '#6b778c', marginTop: 4 }}>Type: {link.test.testType}</div>
          <div style={{ fontSize: 11, color: '#5e6c84', marginTop: 2 }}>Execution: {link.test.executionDate}</div>
        </div>

        {/* Stage 5: 21 CFR Part 11 Electronic Signature */}
        <div style={sectionStyle}>
          <div style={sectionHeader}>
            <Lock size={15} color={link.signature.isValid ? '#00875a' : '#de350b'} />
            <span>5. FDA 21 CFR Part 11 Audit Trail</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 700, fontSize: 12, color: '#172b4d' }}>{link.signature.signedBy}</span>
            <span style={pillStyle(link.signature.isValid ? '#e3fcef' : '#ffebe6', link.signature.isValid ? '#00875a' : '#de350b')}>
              {link.signature.isValid ? 'VALID SIGNATURE' : 'SIGNATURE REVOKED'}
            </span>
          </div>
          <div style={{ fontSize: 11, color: '#6b778c', marginTop: 2 }}>Role: {link.signature.role}</div>
          <div style={{ fontSize: 11, color: '#5e6c84', marginTop: 2 }}>Meaning: "{link.signature.meaning}"</div>
          {link.signature.invalidationReason && (
            <div style={{ fontSize: 10, color: '#de350b', fontWeight: 600, marginTop: 4 }}>
              {link.signature.invalidationReason}
            </div>
          )}
        </div>
      </div>

      {/* Footer / Remediate Action */}
      <div style={{ padding: '16px 20px', borderTop: '1px solid #ebecf0', background: '#fafbfc' }}>
        {isBroken ? (
          <button
            onClick={onRemediate}
            disabled={isRemediating}
            style={{
              width: '100%',
              padding: '10px 16px',
              borderRadius: 6,
              border: 'none',
              background: '#0052cc',
              color: '#ffffff',
              fontWeight: 700,
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 8,
              boxShadow: '0 2px 6px rgba(0, 82, 204, 0.3)',
            }}
          >
            <Zap size={16} />
            {isRemediating ? 'Executing Automated HIL Test & Re-signing...' : '⚡ Remediate Class C Gap & Re-certify Gate'}
          </button>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, color: '#00875a', fontWeight: 700, fontSize: 13 }}>
            <CheckCircle2 size={16} /> Unbroken IEC 62304 Regulatory Compliance
          </div>
        )}
      </div>
    </div>
  );
};

const sectionStyle: React.CSSProperties = {
  marginBottom: 16,
  padding: '12px 14px',
  borderRadius: 6,
  border: '1px solid #ebecf0',
  background: '#ffffff',
};

const sectionHeader: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 6,
  fontSize: 11,
  fontWeight: 700,
  color: '#5e6c84',
  textTransform: 'uppercase',
  marginBottom: 6,
};

const pillStyle = (bg: string, color: string): React.CSSProperties => ({
  fontSize: 10,
  fontWeight: 700,
  padding: '2px 6px',
  borderRadius: 4,
  background: bg,
  color: color,
});
