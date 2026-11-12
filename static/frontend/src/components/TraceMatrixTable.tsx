import React, { useState } from 'react';
import { ComplianceSummary } from '../types';
import { Search, AlertTriangle, CheckCircle2, AlertOctagon, X } from 'lucide-react';

interface TraceMatrixTableProps {
  summary: ComplianceSummary;
  onSelectTraceLink: (linkId: string) => void;
}

export const TraceMatrixTable: React.FC<TraceMatrixTableProps> = ({ summary, onSelectTraceLink }) => {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredLinks = summary.traceLinks.filter((link) => {
    const text = [
      link.hazard.key,
      link.hazard.title,
      link.hazard.riskClass,
      link.spec.title,
      link.work.key,
      link.work.title,
      link.work.assignee,
      link.test.testKey,
      link.signature.signedBy,
      link.complianceState,
    ]
      .join(' ')
      .toLowerCase();
    return text.includes(searchTerm.toLowerCase());
  });

  return (
    <div style={{ background: '#ffffff', borderRadius: 8, border: '1px solid #ebecf0', overflow: 'hidden' }}>
      {/* Search Bar */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid #ebecf0', display: 'flex', alignItems: 'center', gap: 10 }}>
        <Search size={16} color="#505f79" aria-hidden="true" />
        <input
          type="text"
          aria-label="Filter traceability matrix"
          placeholder="Filter by Hazard ID, Requirement, Jira Key, Assignee, Signer, or Test..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{
            border: 'none',
            outline: 'none',
            fontSize: 13,
            width: '100%',
            color: '#172b4d',
          }}
        />
        {searchTerm && (
          <button
            type="button"
            onClick={() => setSearchTerm('')}
            aria-label="Clear search"
            title="Clear search"
            className="mt-icon-btn"
          >
            <X size={14} />
          </button>
        )}
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: 13 }}>
          <thead>
            <tr style={{ background: '#f4f5f7', color: '#42526e', borderBottom: '1px solid #dfe1e6', fontSize: 11, fontWeight: 700, letterSpacing: '0.5px' }}>
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
            {filteredLinks.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '48px 24px', textAlign: 'center' }}>
                  <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
                    <div style={{ width: 44, height: 44, borderRadius: 22, background: '#f4f5f7', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#505f79' }}>
                      <Search size={22} />
                    </div>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: '#172b4d' }}>
                        No matching traceability records found
                      </div>
                      <div style={{ fontSize: 12, color: '#505f79', marginTop: 4, maxWidth: 440 }}>
                        No records matched <strong style={{ color: '#0052cc' }}>&ldquo;{searchTerm}&rdquo;</strong>. Try filtering by Hazard ID (e.g. HAZ-101), Confluence requirement (SRS-104), Jira issue (MED-42), or test key (TEST-88).
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setSearchTerm('')}
                      className="mt-btn"
                      style={{
                        marginTop: 4,
                        padding: '6px 14px',
                        background: '#f4f5f7',
                        border: '1px solid #dfe1e6',
                        color: '#0052cc',
                      }}
                    >
                      Clear search filter
                    </button>
                  </div>
                </td>
              </tr>
            ) : (
              filteredLinks.map((link) => {
                const isClassC = link.hazard.riskClass === 'CLASS_C';
                const isBroken = link.complianceState !== 'VERIFIED';

                return (
                  <tr
                    key={link.id}
                    tabIndex={0}
                    role="button"
                    aria-label={`Inspect ${link.hazard.key} lineage`}
                    className={`mt-table-row ${isBroken ? 'mt-table-row--broken' : ''}`}
                    onClick={() => onSelectTraceLink(link.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectTraceLink(link.id);
                      }
                    }}
                  >
                    {/* Hazard */}
                    <td style={{ padding: '12px 14px', maxWidth: 200 }}>
                      <div style={{ fontWeight: 700, color: '#172b4d' }}>{link.hazard.key}</div>
                      <div style={{ fontSize: 11, color: '#505f79', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
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
                          color: isClassC ? '#bf2600' : link.hazard.riskClass === 'CLASS_B' ? '#974f0c' : '#0052cc',
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
                        <div style={{ fontSize: 10, color: '#bf2600', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 3 }}>
                          <AlertOctagon size={11} /> Spec Drift Detected
                        </div>
                      ) : (
                        <div style={{ fontSize: 10, color: '#505f79' }}>SHA: {link.spec.sha256Hash.slice(0, 8)}...</div>
                      )}
                    </td>

                    {/* Jira Task */}
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ fontWeight: 700, color: '#0052cc' }}>{link.work.key || 'Unbound'}</div>
                      <div style={{ fontSize: 11, color: '#505f79' }}>{(link.work.assignee || 'Unassigned').split(' ')[0]}</div>
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
                            color: link.test.status === 'PASSED' ? '#006644' : '#bf2600',
                          }}
                        >
                          {link.test.status}
                        </span>
                        <span style={{ fontSize: 11, fontWeight: 600, color: '#42526e' }}>{link.test.testKey}</span>
                      </div>
                    </td>

                    {/* 21 CFR Part 11 */}
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: link.signature.isValid ? '#006644' : '#bf2600' }}>
                        {link.signature.isValid ? '✓ Validated' : '✗ Invalidated Drift'}
                      </div>
                      <div style={{ fontSize: 10, color: '#505f79' }}>{(link.signature.signedBy || 'Unsigned').split('(')[0]}</div>
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
                          color: link.complianceState === 'VERIFIED' ? '#006644' : '#bf2600',
                        }}
                      >
                        {link.complianceState === 'VERIFIED' ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
                        {link.complianceState.replace('_', ' ')}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
