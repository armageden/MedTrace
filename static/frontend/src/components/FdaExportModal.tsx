import React from 'react';
import { ComplianceSummary } from '../types';
import { X, Printer, ShieldCheck } from 'lucide-react';

interface FdaExportModalProps {
  summary: ComplianceSummary;
  onClose: () => void;
}

export const FdaExportModal: React.FC<FdaExportModalProps> = ({ summary, onClose }) => {
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(9, 30, 66, 0.54)',
        zIndex: 2000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      }}
    >
      <div
        style={{
          background: '#ffffff',
          borderRadius: 8,
          width: '100%',
          maxWidth: 820,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          boxShadow: '0 8px 32px rgba(9, 30, 66, 0.25)',
          overflow: 'hidden',
        }}
      >
        {/* Modal Topbar */}
        <div style={{ padding: '14px 20px', borderBottom: '1px solid #ebecf0', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#fafbfc' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={18} color="#0052cc" />
            <span style={{ fontWeight: 700, fontSize: 14, color: '#172b4d' }}>FDA 510(k) Section 16 Software Traceability Dossier</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              onClick={() => window.print()}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 12px',
                borderRadius: 4,
                border: '1px solid #dfe1e6',
                background: '#ffffff',
                fontWeight: 600,
                fontSize: 12,
                cursor: 'pointer',
                color: '#172b4d',
              }}
            >
              <Printer size={14} /> Print / Save PDF
            </button>
            <button onClick={onClose} style={{ border: 'none', background: 'transparent', cursor: 'pointer', color: '#6b778c' }}>
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Dossier Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px' }}>
          {/* FDA Header */}
          <div style={{ borderBottom: '2px solid #172b4d', paddingBottom: 16, marginBottom: 20 }}>
            <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: '1px', color: '#5e6c84', textTransform: 'uppercase' }}>
              U.S. Food & Drug Administration | CDRH Regulatory Submission
            </div>
            <div style={{ fontSize: 20, fontWeight: 800, color: '#172b4d', marginTop: 4 }}>
              Software System Traceability & Hazard Mitigation Matrix
            </div>
            <div style={{ fontSize: 12, color: '#42526e', marginTop: 4 }}>
              Device: <b>{summary.projectName}</b> | Classification: <b>IEC 62304 Class C (Life-Critical)</b> | Generated: {new Date(summary.lastAuditTimestamp).toLocaleString()}
            </div>
          </div>

          {/* Regulatory Standards Compliance Statement */}
          <div style={{ background: '#f4f5f7', padding: '12px 16px', borderRadius: 6, marginBottom: 20 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#172b4d', marginBottom: 6 }}>REGULATORY GOVERNANCE STANDARDS:</div>
            {summary.standards.map((s, idx) => (
              <div key={idx} style={{ fontSize: 11, color: '#42526e', lineHeight: '18px' }}>
                ✓ {s}
              </div>
            ))}
          </div>

          {/* Traceability Table */}
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, marginBottom: 24 }}>
            <thead>
              <tr style={{ background: '#ebecf0', color: '#172b4d', textAlign: 'left', borderBottom: '2px solid #c1c7d0' }}>
                <th style={{ padding: '8px 10px' }}>ISO 14971 Hazard ID</th>
                <th style={{ padding: '8px 10px' }}>Risk Class</th>
                <th style={{ padding: '8px 10px' }}>SRS Specification</th>
                <th style={{ padding: '8px 10px' }}>Jira Implementation</th>
                <th style={{ padding: '8px 10px' }}>Verification Test</th>
                <th style={{ padding: '8px 10px' }}>Part 11 Signature</th>
              </tr>
            </thead>
            <tbody>
              {summary.traceLinks.map((link) => (
                <tr key={link.id} style={{ borderBottom: '1px solid #dfe1e6' }}>
                  <td style={{ padding: '8px 10px', fontWeight: 700 }}>{link.hazard.key}</td>
                  <td style={{ padding: '8px 10px' }}>{link.hazard.riskClass}</td>
                  <td style={{ padding: '8px 10px' }}>{link.spec.title.split(':')[0]} (v{link.spec.version})</td>
                  <td style={{ padding: '8px 10px' }}>{link.work.key} ({link.work.status})</td>
                  <td style={{ padding: '8px 10px', fontWeight: 700, color: link.test.status === 'PASSED' ? '#00875a' : '#de350b' }}>
                    {link.test.testKey}: {link.test.status}
                  </td>
                  <td style={{ padding: '8px 10px', color: link.signature.isValid ? '#00875a' : '#de350b' }}>
                    {link.signature.isValid ? 'VALID' : 'REVOKED (DRIFT)'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Electronic Signatures Log (21 CFR Part 11) */}
          <div style={{ borderTop: '1px solid #dfe1e6', paddingTop: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#172b4d', marginBottom: 10 }}>
              FDA 21 CFR Part 11 Electronic Signature Audit Certification
            </div>
            {summary.traceLinks.map((link) => (
              <div key={link.signature.id} style={{ fontSize: 10, color: '#5e6c84', marginBottom: 8, padding: '6px 10px', background: '#fafbfc', borderRadius: 4 }}>
                <b>{link.signature.signedBy}</b> ({link.signature.role}) — Timestamp: {link.signature.signedAt}
                <br />
                Meaning: "{link.signature.meaning}" | Hash: <span style={{ fontFamily: 'monospace' }}>{link.signature.artifactSha256}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
