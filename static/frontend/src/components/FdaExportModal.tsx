import React, { useEffect, useRef, useState } from 'react';
import { invokeResolver } from '../bridge';
import { verifyAuditChainBounded } from '../auditVerify';
import { useDialogA11y } from '../hooks/useDialogA11y';
import { AuditChainVerification, AuditLogEntry, ComplianceSummary } from '../types';
import {
  X,
  Printer,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FileJson,
  FileSpreadsheet,
} from 'lucide-react';

interface FdaExportModalProps {
  summary: ComplianceSummary;
  onClose: () => void;
  isOpen?: boolean;
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

function getSafeHttpsUrl(rawUrl?: string): string | null {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return null;
  }
  const trimmed = rawUrl.trim();
  if (!/^https:\/\//.test(trimmed)) {
    return null;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
      return null;
    }
    return trimmed;
  } catch {
    return null;
  }
}

/**
 * Neutralizes spreadsheet formula injection (CWE-1236) and applies RFC 4180 CSV quoting.
 */
export function escapeCsvCell(value: string | number | boolean | null | undefined): string {
  const raw = String(value ?? '');
  const neutralized = /^[=+\-@\t\r]|^\s+[=+\-@]/.test(raw) ? `'${raw}` : raw;
  if (/[",\n\r]/.test(neutralized)) {
    return `"${neutralized.replace(/"/g, '""')}"`;
  }
  return neutralized;
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

export const FdaExportModal: React.FC<FdaExportModalProps> = ({
  summary,
  onClose,
  isOpen = true,
}) => {
  const dialogRef = useRef<HTMLDivElement>(null);
  const [auditVerification, setAuditVerification] = useState<AuditChainVerification | null>(null);
  const [auditLogEntries, setAuditLogEntries] = useState<AuditLogEntry[]>([]);
  const [isLoadingAudit, setIsLoadingAudit] = useState<boolean>(false);
  const [auditLoadError, setAuditLoadError] = useState<string | null>(null);

  useDialogA11y({ isOpen, onClose, containerRef: dialogRef });

  useEffect(() => {
    if (!isOpen) return;

    let cancelled = false;
    setIsLoadingAudit(true);
    setAuditLoadError(null);

    Promise.all([
      verifyAuditChainBounded(() => cancelled),
      invokeResolver('getAuditLog', { limit: 200 }),
    ])
      .then(([verifyRes, logRes]) => {
        if (cancelled) return;
        setAuditVerification(verifyRes ?? null);
        setAuditLogEntries(Array.isArray(logRes) ? logRes : []);
      })
      .catch((err) => {
        if (cancelled) return;
        setAuditVerification(null);
        setAuditLogEntries([]);
        setAuditLoadError(
          err instanceof Error
            ? err.message
            : 'Failed to retrieve audit chain verification and ledger entries.'
        );
      })
      .finally(() => {
        if (!cancelled) {
          setIsLoadingAudit(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const modePrefix = summary.datasetMode.toLowerCase();
  const auditTotalEntries =
    auditVerification?.totalEntries ?? summary.auditEntryCount ?? auditLogEntries.length;
  const auditLedgerTruncated = Boolean(
    auditVerification && auditVerification.totalEntries > auditLogEntries.length
  );

  const handleDownloadJson = () => {
    const verificationSnapshot =
      auditVerification ?? (auditLoadError ? { error: auditLoadError } : null);
    const payload = {
      exportMetadata: {
        exportedAt: new Date().toISOString(),
        datasetMode: summary.datasetMode,
        releaseBlocked: summary.releaseBlocked,
        blockingReasons: summary.blockingReasons,
        auditEntriesIncluded: auditLogEntries.length,
        auditTotalEntries,
        auditLedgerTruncated,
        clientGeneratedNotice:
          'Client-assembled export snapshot of Forge KVS compliance and audit state; verify chain integrity independently before regulatory reliance.',
      },
      classificationSummary: getDynamicClassification(summary),
      ...summary,
      auditVerification: verificationSnapshot,
      verifyAuditChain: verificationSnapshot,
      auditLogEntries,
    };
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    triggerDownload(
      `${modePrefix}-medtrace-fda-dossier-${stamp}.json`,
      JSON.stringify(payload, null, 2),
      'application/json'
    );
  };

  const handleDownloadCsv = () => {
    const auditChainStatus = auditLoadError
      ? `ERROR: ${auditLoadError}`
      : auditVerification
        ? String(auditVerification.valid)
        : isLoadingAudit
          ? 'LOADING'
          : 'UNKNOWN';
    const auditHeadHash = auditVerification?.headHash ?? summary.auditHeadHash ?? '';
    const blockingReasonsText = (summary.blockingReasons || []).join('; ');
    const auditLogSummaryText = auditLogEntries
      .map((entry) => `#${entry.seq}:${entry.action}:${entry.targetKey}`)
      .join('; ');

    const headers = [
      'Dataset Mode',
      'Release Blocked',
      'Blocking Reasons',
      'Hazard Key',
      'Hazard Title',
      'Risk Class',
      'SRS Spec',
      'Spec Version',
      'Spec SHA-256',
      'Jira Key',
      'Jira Status',
      'Commit SHA',
      'Test Key',
      'Test Status',
      'Evidence URL',
      'Signature Valid',
      'Signed By',
      'Signed At',
      'Signature Meaning',
      'Compliance State',
      'Violations',
      'Audit Chain Valid',
      'Audit Total Entries',
      'Audit Entries Included',
      'Audit Head Hash',
      'Audit Log Entries',
    ];

    const rows = summary.traceLinks.map((link) =>
      [
        summary.datasetMode,
        summary.releaseBlocked,
        blockingReasonsText,
        link.hazard.key,
        link.hazard.title,
        link.hazard.riskClass,
        link.spec.title || 'Unlinked (No SRS)',
        link.spec.version,
        link.spec.sha256Hash,
        link.work.key,
        link.work.status,
        link.work.commitSha ?? '',
        link.test.testKey,
        link.test.status,
        link.test.evidenceUrl ?? '',
        link.signature.isValid,
        link.signature.signedBy,
        link.signature.signedAt,
        link.signature.meaning,
        link.complianceState,
        (link.violations || []).join('; '),
        auditChainStatus,
        auditTotalEntries,
        auditLogEntries.length,
        auditHeadHash,
        auditLogSummaryText,
      ]
        .map(escapeCsvCell)
        .join(',')
    );

    const csv = [headers.map(escapeCsvCell).join(','), ...rows].join('\n');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    triggerDownload(
      `${modePrefix}-medtrace-trace-matrix-${stamp}.csv`,
      csv,
      'text/csv;charset=utf-8'
    );
  };

  return (
    <div
      id="fda-export-backdrop"
      className="mt-modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        id="fda-export-printable"
        ref={dialogRef}
        className="mt-modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="fda-export-modal-title"
        style={{ maxWidth: 920 }}
      >
        {/* Modal Topbar (hidden when printing) */}
        <div
          className="no-print"
          style={{
            padding: '14px 20px',
            borderBottom: '1px solid var(--mt-border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 10,
            background: 'var(--mt-bg-surface-subtle)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={18} color="var(--mt-brand-text)" />
            <span
              id="fda-export-modal-title"
              style={{ fontWeight: 700, fontSize: 14, color: 'var(--mt-text-primary)' }}
            >
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
                border: '1px solid var(--mt-border)',
                background: 'var(--mt-bg-surface)',
                color: 'var(--mt-text-primary)',
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
                border: '1px solid var(--mt-border)',
                background: 'var(--mt-bg-surface)',
                color: 'var(--mt-text-primary)',
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
                border: '1px solid var(--mt-brand-bg)',
                background: 'var(--mt-brand-subtle-bg)',
                color: 'var(--mt-brand-text)',
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
        <div
          className="fda-export-scroll"
          style={{ flex: 1, overflowY: 'auto', padding: '24px 32px', position: 'relative' }}
        >
          {summary.datasetMode === 'DEMO' && (
            <div
              role="status"
              style={{
                marginBottom: 16,
                padding: '10px 14px',
                borderRadius: 6,
                background: 'var(--mt-warning-bg)',
                border: '2px dashed var(--mt-warning-border)',
                color: 'var(--mt-warning-text)',
                fontSize: 12,
                fontWeight: 800,
                letterSpacing: '0.6px',
                textAlign: 'center',
                textTransform: 'uppercase',
              }}
            >
              DEMO DATASET — NON-CLINICAL / NOT FOR REGULATORY SUBMISSION
            </div>
          )}

          {summary.releaseBlocked && (
            <div
              role="alert"
              style={{
                marginBottom: 16,
                padding: '12px 14px',
                borderRadius: 6,
                background: 'var(--mt-danger-bg)',
                border: '1px solid var(--mt-danger-border)',
                color: 'var(--mt-danger-text)',
                fontSize: 12,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 800 }}>
                <AlertTriangle size={16} />
                <span>RELEASE BLOCKED — UNRESOLVED COMPLIANCE GAPS PRESENT</span>
              </div>
              {summary.blockingReasons.length > 0 && (
                <ul style={{ margin: '6px 0 0 22px', padding: 0, lineHeight: '18px' }}>
                  {summary.blockingReasons.map((reason, idx) => (
                    <li key={`${idx}-${reason}`}>{reason}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          <div
            style={{
              borderBottom: '2px solid var(--mt-text-primary)',
              paddingBottom: 16,
              marginBottom: 20,
            }}
          >
            <div
              style={{
                fontSize: 10,
                fontWeight: 800,
                letterSpacing: '1px',
                color: 'var(--mt-text-secondary)',
                textTransform: 'uppercase',
              }}
            >
              Software System Lifecycle &amp; Traceability Audit Evidence ({summary.datasetMode}{' '}
              Dataset)
            </div>
            <div
              style={{
                fontSize: 20,
                fontWeight: 800,
                color: 'var(--mt-text-primary)',
                marginTop: 4,
              }}
            >
              Software Lifecycle Traceability &amp; Hazard Mitigation Evidence Package
            </div>
            <div
              style={{
                fontSize: 12,
                color: 'var(--mt-text-secondary)',
                marginTop: 6,
                lineHeight: '18px',
              }}
            >
              Device: <b>{summary.projectName}</b> | Classification:{' '}
              <b>{getDynamicClassification(summary)}</b>
              <br />
              Generated: {formatSafeTimestamp(summary.lastAuditTimestamp)} | Audit Ledger Entries:{' '}
              <b>{auditTotalEntries}</b>
              {(auditVerification?.headHash || summary.auditHeadHash) && (
                <span>
                  {' '}
                  | Head Hash:{' '}
                  <code>{(auditVerification?.headHash ?? summary.auditHeadHash ?? '').slice(0, 16)}...</code>
                </span>
              )}
            </div>
          </div>

          <div
            style={{
              background: 'var(--mt-bg-page)',
              padding: '12px 16px',
              borderRadius: 6,
              marginBottom: 20,
            }}
          >
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: 'var(--mt-text-primary)',
                marginBottom: 6,
              }}
            >
              REGULATORY GOVERNANCE STANDARDS:
            </div>
            {summary.standards.map((s, idx) => (
              <div
                key={`${idx}-${s}`}
                style={{ fontSize: 11, color: 'var(--mt-text-secondary)', lineHeight: '18px' }}
              >
                ✓ {s}
              </div>
            ))}
          </div>

          {/* Audit Chain Integrity Snapshot */}
          <div style={{ marginBottom: 20 }}>
            <div
              style={{
                fontSize: 12,
                fontWeight: 700,
                color: 'var(--mt-text-primary)',
                marginBottom: 8,
              }}
            >
              SHA-256 Audit Chain Verification (Forge KVS)
            </div>
            {isLoadingAudit && (
              <div style={{ fontSize: 11, color: 'var(--mt-text-secondary)', marginBottom: 8 }}>
                Verifying SHA-256 audit hash chain and loading ledger entries...
              </div>
            )}
            {auditLoadError && (
              <div
                role="alert"
                style={{
                  padding: '10px 12px',
                  borderRadius: 6,
                  background: 'var(--mt-danger-bg)',
                  border: '1px solid var(--mt-danger-border)',
                  color: 'var(--mt-danger-text)',
                  fontSize: 11,
                  fontWeight: 600,
                }}
              >
                Audit verification error: {auditLoadError}
              </div>
            )}
            {auditVerification && (
              <div
                style={{
                  padding: '10px 12px',
                  borderRadius: 6,
                  background: auditVerification.valid
                    ? 'var(--mt-success-bg)'
                    : 'var(--mt-danger-bg)',
                  border: `1px solid ${
                    auditVerification.valid ? 'var(--mt-success-border)' : 'var(--mt-danger-border)'
                  }`,
                  color: auditVerification.valid
                    ? 'var(--mt-success-text)'
                    : 'var(--mt-danger-text)',
                  fontSize: 11,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: 8,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700 }}>
                  {auditVerification.valid ? <ShieldCheck size={15} /> : <ShieldAlert size={15} />}
                  <span>
                    {auditVerification.valid
                      ? `HASH CHAIN VERIFIED (${auditVerification.totalEntries} entries)`
                      : `CHAIN INTEGRITY FAILURE${
                          auditVerification.brokenAtSeq
                            ? ` AT SEQ #${auditVerification.brokenAtSeq}`
                            : ''
                        }`}
                  </span>
                </div>
                <span style={{ fontFamily: 'monospace', fontSize: 10 }}>
                  Head: {auditVerification.headHash.slice(0, 20)}...
                </span>
                {auditVerification.reason && (
                  <div style={{ width: '100%', fontSize: 11 }}>{auditVerification.reason}</div>
                )}
              </div>
            )}
            {auditLedgerTruncated && auditVerification && (
              <div
                role="status"
                style={{
                  marginTop: 8,
                  padding: '8px 10px',
                  borderRadius: 4,
                  background: 'var(--mt-warning-bg)',
                  border: '1px solid var(--mt-warning-border)',
                  color: 'var(--mt-warning-text)',
                  fontSize: 11,
                  fontWeight: 600,
                }}
              >
                Export includes the most recent {auditLogEntries.length} of{' '}
                {auditVerification.totalEntries} audit entries. Hash-chain verification above covers
                all {auditVerification.totalEntries} entries.
              </div>
            )}
          </div>

          <table
            style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, marginBottom: 24 }}
          >
            <thead>
              <tr
                style={{
                  background: 'var(--mt-bg-neutral)',
                  color: 'var(--mt-text-primary)',
                  textAlign: 'left',
                  borderBottom: '2px solid var(--mt-border-input)',
                }}
              >
                <th style={{ padding: '8px 10px' }}>ISO 14971 Hazard ID</th>
                <th style={{ padding: '8px 10px' }}>Risk Class</th>
                <th style={{ padding: '8px 10px' }}>SRS Specification</th>
                <th style={{ padding: '8px 10px' }}>Jira Implementation</th>
                <th style={{ padding: '8px 10px' }}>Verification Test</th>
                <th style={{ padding: '8px 10px' }}>Part 11 Signature</th>
              </tr>
            </thead>
            <tbody>
              {summary.traceLinks.map((link) => {
                const safeEvidenceUrl = getSafeHttpsUrl(link.test.evidenceUrl);
                return (
                  <tr key={link.id} style={{ borderBottom: '1px solid var(--mt-border)' }}>
                    <td style={{ padding: '8px 10px', fontWeight: 700 }}>
                      <div>{link.hazard.key}</div>
                      {link.violations.length > 0 && (
                        <div
                          style={{
                            fontSize: 10,
                            fontWeight: 500,
                            color: 'var(--mt-danger-text)',
                            marginTop: 2,
                          }}
                        >
                          {link.violations.join('; ')}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '8px 10px' }}>{link.hazard.riskClass}</td>
                    <td style={{ padding: '8px 10px' }}>
                      {link.spec.title
                        ? `${link.spec.title} (v${link.spec.version})`
                        : 'Unlinked (No SRS)'}
                    </td>
                    <td style={{ padding: '8px 10px' }}>
                      <div>
                        {link.work.key || 'Unbound'} ({link.work.status})
                      </div>
                      {link.work.commitSha && (
                        <div
                          style={{
                            fontSize: 10,
                            fontFamily: 'monospace',
                            color: 'var(--mt-text-secondary)',
                            marginTop: 2,
                          }}
                        >
                          Commit: {link.work.commitSha}
                        </div>
                      )}
                    </td>
                    <td
                      style={{
                        padding: '8px 10px',
                        fontWeight: 700,
                        color:
                          link.test.status === 'PASSED'
                            ? 'var(--mt-success-text)'
                            : 'var(--mt-danger-text)',
                      }}
                    >
                      <div>
                        {link.test.testKey}: {link.test.status}
                      </div>
                      {link.test.evidenceUrl && (
                        <div style={{ fontSize: 10, fontWeight: 400, marginTop: 2 }}>
                          {safeEvidenceUrl ? (
                            <a
                              href={safeEvidenceUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              style={{ color: 'var(--mt-brand-text)' }}
                            >
                              {safeEvidenceUrl}
                            </a>
                          ) : (
                            <span style={{ color: 'var(--mt-text-secondary)' }}>
                              {link.test.evidenceUrl} (non-HTTPS link disabled)
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                    <td
                      style={{
                        padding: '8px 10px',
                        color: link.signature.isValid
                          ? 'var(--mt-success-text)'
                          : 'var(--mt-danger-text)',
                      }}
                    >
                      {link.signature.isValid ? 'VALID' : 'INVALIDATED (DRIFT)'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          <div
            style={{
              borderTop: '1px solid var(--mt-border)',
              paddingTop: 16,
              marginBottom: 20,
            }}
          >
            <div
              style={{
                fontSize: 12,
                fontWeight: 700,
                color: 'var(--mt-text-primary)',
                marginBottom: 10,
              }}
            >
              FDA 21 CFR Part 11 Electronic Signature Audit Certification
            </div>
            {summary.traceLinks.map((link) => (
              <div
                key={link.id}
                className="fda-sig-card"
                style={{
                  fontSize: 10,
                  color: 'var(--mt-text-secondary)',
                  marginBottom: 8,
                  padding: '6px 10px',
                  background: 'var(--mt-bg-surface-subtle)',
                  borderRadius: 4,
                }}
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

          <div style={{ borderTop: '1px solid var(--mt-border)', paddingTop: 16 }}>
            <div
              style={{
                fontSize: 12,
                fontWeight: 700,
                color: 'var(--mt-text-primary)',
                marginBottom: 8,
              }}
            >
              Audit Ledger Trail ({auditLogEntries.length} entries included)
            </div>
            {auditLogEntries.length === 0 ? (
              <div style={{ fontSize: 11, color: 'var(--mt-text-secondary)' }}>
                No audit log entries recorded.
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                <thead>
                  <tr
                    style={{
                      background: 'var(--mt-bg-page)',
                      color: 'var(--mt-text-secondary)',
                      textAlign: 'left',
                      borderBottom: '1px solid var(--mt-border)',
                    }}
                  >
                    <th style={{ padding: '6px 8px' }}>Seq</th>
                    <th style={{ padding: '6px 8px' }}>Timestamp</th>
                    <th style={{ padding: '6px 8px' }}>Action</th>
                    <th style={{ padding: '6px 8px' }}>Target</th>
                    <th style={{ padding: '6px 8px' }}>Actor</th>
                    <th style={{ padding: '6px 8px' }}>Entry Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {[...auditLogEntries].reverse().map((entry) => (
                    <tr key={entry.seq} style={{ borderBottom: '1px solid var(--mt-border-subtle)' }}>
                      <td style={{ padding: '6px 8px', fontWeight: 700 }}>#{entry.seq}</td>
                      <td style={{ padding: '6px 8px', whiteSpace: 'nowrap' }}>{entry.timestamp}</td>
                      <td style={{ padding: '6px 8px', fontWeight: 700 }}>{entry.action}</td>
                      <td style={{ padding: '6px 8px' }}>{entry.targetKey}</td>
                      <td style={{ padding: '6px 8px', fontFamily: 'monospace' }}>
                        {entry.actorAccountId}
                      </td>
                      <td style={{ padding: '6px 8px', fontFamily: 'monospace' }}>
                        {entry.entryHash.slice(0, 12)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
