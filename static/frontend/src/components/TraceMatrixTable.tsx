import React, { useState } from 'react';
import { ComplianceSummary, TraceLink } from '../types';
import { Search, AlertTriangle, CheckCircle2, AlertOctagon, ExternalLink } from 'lucide-react';

interface TraceMatrixTableProps {
  summary: ComplianceSummary;
  onSelectTraceLink: (linkId: string) => void;
}

export const TraceMatrixTable: React.FC<TraceMatrixTableProps> = ({ summary, onSelectTraceLink }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredLinks = summary.traceLinks.filter((link) => {
    const text = `${link.hazard.key} ${link.hazard.title} ${link.spec.title} ${link.work.key} ${link.test.testKey}`.toLowerCase();
    return text.includes(searchTerm.toLowerCase());
  });

  return (
    <div style={{ background: '#ffffff', borderRadius: 8, border: '1px solid #ebecf0', overflow: 'hidden' }}>
      {/* Search Bar */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid #ebecf0', display: 'flex', alignItems: 'center', gap: 10 }}>
        <Search size={16} color="#6b778c" />
        <input
          type="text"
          placeholder="Filter by Hazard ID, Requirement, Jira Key, or Test..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{
            border: 'none',
            outline: 'none',
            fontSize: 13,
            width: '100%',
            color: '#172b4d',
            fontFamily: 'inherit',
          }}
        />
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13, fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif' }}>
          <thead>
            <tr style={{ background: '#f4f5f7', color: '#5e6c84', borderBottom: '1px solid #dfe1e6', fontSize: 11, fontWeight: 700, letterSpacing: '0.5px' }}>
              <th style={{ padding: '10px 14px' }}>ISO 14971 HAZARD</th>
              <th style={{ padding: '10px 14px' }}>SAFETY CLASS</th>
              <th style={{ padding: '10px 14px' }}>CONFLUENCE SRS SPEC</th>
              <th style={{ padding: '10px 14px' }}>JIRA WORK ITEM</th>
              <th style={{ padding: '10px 14px' }}>IEC 62304 VERIFICATION</th>
              <th style={{ padding: '10px 14px' }}>21 CFR PART 11 STATUS</th>
              <th style={{ padding: '10px 14px' }}>AUDIT STATE</th>
            </tr>
          </thead>
          <tbody>
            {filteredLinks.map((link) => {
              const isClassC = link.hazard.riskClass === 'CLASS_C';
              const isBroken = link.complianceState !== 'VERIFIED';

              return (
                <tr
                  key={link.id}
                  onClick={() => onSelectTraceLink(link.id)}
                  style={{
                    borderBottom: '1px solid #ebecf0',
                    cursor: 'pointer',
                    background: isBroken ? '#fffbfa' : '#ffffff',
                    transition: 'background 0.15s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.background = '#f4f5f7')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = isBroken ? '#fffbfa' : '#ffffff')}
                >
                  {/* Hazard */}
                  <td style={{ padding: '12px 14px', maxWidth: 200 }}>
                    <div style={{ fontWeight: 700, color: '#172b4d' }}>{link.hazard.key}</div>
                    <div style={{ fontSize: 11, color: '#6b778c', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {link.hazard.title}
                    </div>
                  </td>

                  {/* Safety Class */}
                  <td style={{ padding: '12px 14px' }}>
                    <span
                      style={{
                        fontSize: 10,
                        fontWeight: 800,
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: isClassC ? '#ffebe6' : link.hazard.riskClass === 'CLASS_B' ? '#fff0b3' : '#deebff',
                        color: isClassC ? '#de350b' : link.hazard.riskClass === 'CLASS_B' ? '#ff8b00' : '#0052cc',
                      }}
                    >
                      {link.hazard.riskClass.replace('_', ' ')}
                    </span>
                  </td>

                  {/* Confluence Spec */}
                  <td style={{ padding: '12px 14px', maxWidth: 220 }}>
                    <div style={{ fontWeight: 600, color: '#0052cc', display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span>v{link.spec.version}</span>
                      <span style={{ fontSize: 12, color: '#172b4d' }}>{link.spec.title.split(':')[0]}</span>
                    </div>
                    {link.spec.isSignatureInvalidated ? (
                      <div style={{ fontSize: 10, color: '#de350b', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 3 }}>
                        <AlertOctagon size={11} /> Spec Drift Detected
                      </div>
                    ) : (
                      <div style={{ fontSize: 10, color: '#6b778c' }}>SHA: {link.spec.sha256Hash.slice(0, 8)}...</div>
                    )}
                  </td>

                  {/* Jira Task */}
                  <td style={{ padding: '12px 14px' }}>
                    <div style={{ fontWeight: 700, color: '#0052cc' }}>{link.work.key}</div>
                    <div style={{ fontSize: 11, color: '#6b778c' }}>{link.work.assignee.split(' ')[0]}</div>
                  </td>

                  {/* Verification Test */}
                  <td style={{ padding: '12px 14px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 800,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: link.test.status === 'PASSED' ? '#e3fcef' : '#ffebe6',
                          color: link.test.status === 'PASSED' ? '#00875a' : '#de350b',
                        }}
                      >
                        {link.test.status}
                      </span>
                      <span style={{ fontSize: 11, fontWeight: 600, color: '#42526e' }}>{link.test.testKey}</span>
                    </div>
                  </td>

                  {/* 21 CFR Part 11 */}
                  <td style={{ padding: '12px 14px' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: link.signature.isValid ? '#00875a' : '#de350b' }}>
                      {link.signature.isValid ? '✓ Validated' : '✗ Revoked Drift'}
                    </div>
                    <div style={{ fontSize: 10, color: '#6b778c' }}>{link.signature.signedBy.split('(')[0]}</div>
                  </td>

                  {/* Audit State */}
                  <td style={{ padding: '12px 14px' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 4,
                        fontSize: 11,
                        fontWeight: 700,
                        padding: '3px 8px',
                        borderRadius: 4,
                        background: link.complianceState === 'VERIFIED' ? '#e3fcef' : '#ffebe6',
                        color: link.complianceState === 'VERIFIED' ? '#00875a' : '#de350b',
                      }}
                    >
                      {link.complianceState === 'VERIFIED' ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
                      {link.complianceState.replace('_', ' ')}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
