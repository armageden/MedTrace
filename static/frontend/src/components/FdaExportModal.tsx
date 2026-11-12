import React, { useEffect } from 'react';
import { ComplianceSummary } from '../types';
import { X, Printer, ShieldCheck, FileJson, FileSpreadsheet } from 'lucide-react';

interface FdaExportModalProps {
  summary: ComplianceSummary;
  onClose: () => void;
}

function formatSafeTimestamp(iso?: string): string {
  if (!iso) return 'Unknown timestamp';
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleString();
}

function getDynamicClassification(summary: ComplianceSummary): string {
  if (summary.classCCount > 0) {
    return `IEC 62304 Class C (Highest Severity Present; C:${summary.classCCount}, B:${summary.classBCount}, A:${summary.classACount})`;
  }
  if (summary.classBCount > 0) {
    return `IEC 62304 Class B (B:${summary.classBCount}, A:${summary.classACount})`;
  }
  if (summary.classACount > 0) {
    return `IEC 62304 Class A (A:${summary.classACount})`;
  }
  return 'IEC 62304 Unclassified (0 hazards)';
}

function escapeCsvCell(value: string | number | boolean | undefined): string {
  const str = String(value ?? '');
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function triggerDownload(filename: string, content: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export const FdaExportModal: React.FC<FdaExportModalProps> = ({ summary, onClose }) => {
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  const handleDownloadJson = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      classificationSummary: getDynamicClassification(summary),
      ...summary,
    };
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    triggerDownload(`medtrace-fda-dossier-${stamp}.json`, JSON.stringify(payload, null, 2), 'application/json');
  };

  const handleDownloadCsv = () => {
    const headers = [
      'Hazard Key',
      'Hazard Title',
      'Risk Class',
      'SRS Spec',
      'Spec Version',
      'Spec SHA-256',
      'Jira Key',
      'Jira Status',
      'Test Key',
      'Test Status',
      'Signature Valid',
      'Signed By',
      'Signed At',
      'Signature Meaning',
      'Compliance State',
    ];
    const rows = summary.traceLinks.map((link) =>
      [
        link.hazard.key,
        link.hazard.title,
        link.hazard.riskClass,
        link.spec.title,
        link.spec.version,
        link.spec.sha256Hash,
        link.work.key,
        link.work.status,
        link.test.testKey,
        link.test.status,
        link.signature.isValid,
        link.signature.signedBy,
        link.signature.signedAt,
        link.signature.meaning,
        link.complianceState,
      ]
        .map(escapeCsvCell)
        .join(',')
    );
    const csv = [headers.map(escapeCsvCell).join(','), ...rows].join('\n');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    triggerDownload(`medtrace-trace-matrix-${stamp}.csv`, csv, 'text/csv;charset=utf-8');
  };

  return (
    <div
      id="fda-export-backdrop"
      className="mt-modal-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="fda-export-modal-title"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div id="fda-export-printable" className="mt-modal-card" style={{ maxWidth: 860 }}>
        {/* Modal Topbar (hidden when printing) */}
        <div
          className="no-print"
          style={{
            padding: '14px 20px',
            borderBottom: '1px solid #ebecf0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 10,
            background: '#fafbfc',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={18} color="#0052cc" />
            <span id="fda-export-modal-title" style={{ fontWeight: 700, fontSize: 14, color: '#172b4d' }}>
              FDA 510(k) eSTAR Software Documentation Traceability Package
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={handleDownloadJson}
              className="mt-btn"
              style={{
                padding: '6px 10px',
                borderRadius: 4,
                border: '1px solid #dfe1e6',
                background: '#ffffff',
                color: '#172b4d',
              }}
            >
              <FileJson size={14} /> Download JSON
            </button>
            <button
              type="button"
              onClick={handleDownloadCsv}
              className="mt-btn"
              style={{
                padding: '6px 10px',
                borderRadius: 4,
                border: '1px solid #dfe1e6',
                background: '#ffffff',
                color: '#172b4d',
              }}
            >
              <FileSpreadsheet size={14} /> Download CSV
            </button>
            <button
              type="button"
              onClick={() => window.print()}
              className="mt-btn"
              style={{
                padding: '6px 10px',
                borderRadius: 4,
                border: '1px solid #0052cc',
                background: '#deebff',
                color: '#0052cc',
              }}
            >
              <Printer size={14} /> Print / Save PDF
            </button>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close FDA export modal"
              className="mt-icon-btn"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Dossier Content */}
        <div className="fda-export-scroll" style={{ flex: 1, overflowY: 'auto', padding: '24px 32px' }}>
          <div style={{ borderBottom: '2px solid #172b4d', paddingBottom: 16, marginBottom: 20 }}>
            <div style={{ fontSize: 10, fontWeight: 800, letterSpacing: '1px', color: '#42526e', textTransform: 'uppercase' }}>
              Software System Lifecycle & Traceability Audit Evidence ({summary.datasetMode} Dataset)
            </div>
            <div style={{ fontSize: 20, fontWeight: 800, color: '#172b4d', marginTop: 4 }}>
              Software Lifecycle Traceability & Hazard Mitigation Evidence Package
            </div>
            <div style={{ fontSize: 12, color: '#42526e', marginTop: 6, lineHeight: '18px' }}>
              Device: <b>{summary.projectName}</b> | Classification: <b>{getDynamicClassification(summary)}</b>
              <br />
              Generated: {formatSafeTimestamp(summary.lastAuditTimestamp)} | Audit Ledger Entries:{' '}
              <b>{summary.auditEntryCount ?? 0}</b>
              {summary.auditHeadHash ? (
                <span>
                  {' '}
                  | Head Hash: <code>{summary.auditHeadHash.slice(0, 16)}...</code>
                </span>
              ) : null}
            </div>
          </div>

          <div style={{ background: '#f4f5f7', padding: '12px 16px', borderRadius: 6, marginBottom: 20 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#172b4d', marginBottom: 6 }}>
              REGULATORY GOVERNANCE STANDARDS:
            </div>
            {summary.standards.map((s, idx) => (
              <div key={idx} style={{ fontSize: 11, color: '#42526e', lineHeight: '18px' }}>
                ✓ {s}
              </div>
            ))}
          </div>

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
                  <td style={{ padding: '8px 10px' }}>
                    {link.spec.title.split(':')[0]} (v{link.spec.version})
                  </td>
                  <td style={{ padding: '8px 10px' }}>
                    {link.work.key || 'Unbound'} ({link.work.status})
                  </td>
                  <td
                    style={{
                      padding: '8px 10px',
                      fontWeight: 700,
                      color: link.test.status === 'PASSED' ? '#006644' : '#bf2600',
                    }}
                  >
                    {link.test.testKey}: {link.test.status}
                  </td>
                  <td style={{ padding: '8px 10px', color: link.signature.isValid ? '#006644' : '#bf2600' }}>
                    {link.signature.isValid ? 'VALID' : 'INVALIDATED (DRIFT)'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div style={{ borderTop: '1px solid #dfe1e6', paddingTop: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#172b4d', marginBottom: 10 }}>
              FDA 21 CFR Part 11 Electronic Signature Audit Certification
            </div>
            {summary.traceLinks.map((link) => (
              <div
                key={link.signature.id}
                className="fda-sig-card"
                style={{ fontSize: 10, color: '#42526e', marginBottom: 8, padding: '6px 10px', background: '#fafbfc', borderRadius: 4 }}
              >
                <b>{link.signature.signedBy || 'Unsigned'}</b> ({link.signature.role}) — Timestamp:{' '}
                {link.signature.signedAt || 'Pending'}
                {link.signature.authMethod ? ` — Method: ${link.signature.authMethod}` : ''}
                <br />
                Meaning: &ldquo;{link.signature.meaning}&rdquo; | Hash:{' '}
                <span style={{ fontFamily: 'monospace' }}>{link.signature.artifactSha256}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
