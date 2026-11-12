import React, { useCallback, useEffect, useState } from 'react';
import { invokeResolver } from '../bridge';
import { AuditChainVerification, AuditLogEntry } from '../types';
import { X, ShieldCheck, ShieldAlert, RefreshCw, ScrollText } from 'lucide-react';

interface AuditLogModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AuditLogModal: React.FC<AuditLogModalProps> = ({ isOpen, onClose }) => {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [verification, setVerification] = useState<AuditChainVerification | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadLedger = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [logRes, verifyRes] = await Promise.all([
        invokeResolver<AuditLogEntry[]>('getAuditLog', { limit: 100 }),
        invokeResolver<AuditChainVerification>('verifyAuditChain'),
      ]);
      setEntries(Array.isArray(logRes) ? [...logRes].reverse() : []);
      setVerification(verifyRes || null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load immutable audit ledger from Forge backend.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    loadLedger();
  }, [isOpen, loadLedger]);

  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="mt-modal-backdrop no-print"
      role="dialog"
      aria-modal="true"
      aria-labelledby="audit-log-modal-title"
      style={{ zIndex: 2300 }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="mt-modal-card" style={{ maxWidth: 920 }}>
        <div
          style={{
            padding: '14px 20px',
            borderBottom: '1px solid #ebecf0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: '#fafbfc',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ScrollText size={18} color="#0052cc" />
            <span id="audit-log-modal-title" style={{ fontWeight: 700, fontSize: 14, color: '#172b4d' }}>
              Immutable SHA-256 Hash-Chained Audit Ledger
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              type="button"
              onClick={loadLedger}
              disabled={isLoading}
              className="mt-btn"
              style={{
                padding: '6px 10px',
                borderRadius: 4,
                border: '1px solid #dfe1e6',
                background: '#ffffff',
                color: '#172b4d',
              }}
            >
              <RefreshCw size={14} /> {isLoading ? 'Verifying...' : 'Verify Hash Chain'}
            </button>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close audit log modal"
              className="mt-icon-btn"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          {error && (
            <div style={{ marginBottom: 14, padding: '10px 12px', borderRadius: 6, background: '#ffebe6', border: '1px solid #ffbdad', color: '#bf2600', fontSize: 12, fontWeight: 600 }}>
              {error}
            </div>
          )}

          {verification && (
            <div
              style={{
                marginBottom: 16,
                padding: '12px 14px',
                borderRadius: 6,
                background: verification.valid ? '#e3fcef' : '#ffebe6',
                border: `1px solid ${verification.valid ? '#abf5d1' : '#ffbdad'}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 10,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {verification.valid ? <ShieldCheck size={18} color="#006644" /> : <ShieldAlert size={18} color="#bf2600" />}
                <div>
                  <div style={{ fontSize: 13, fontWeight: 800, color: verification.valid ? '#006644' : '#bf2600' }}>
                    {verification.valid
                      ? `HASH CHAIN VERIFIED (${verification.totalEntries} immutable entries)`
                      : `CHAIN INTEGRITY FAILURE${verification.brokenAtSeq ? ` AT SEQ #${verification.brokenAtSeq}` : ''}`}
                  </div>
                  {verification.reason && (
                    <div style={{ fontSize: 11, color: '#bf2600', marginTop: 2 }}>{verification.reason}</div>
                  )}
                </div>
              </div>
              <div style={{ fontSize: 10, fontFamily: 'monospace', color: '#42526e' }}>
                Head: {verification.headHash.slice(0, 20)}...
              </div>
            </div>
          )}

          {entries.length === 0 && !isLoading ? (
            <div style={{ padding: 32, textAlign: 'center', color: '#505f79', fontSize: 13 }}>
              No audit log entries recorded yet.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: '#f4f5f7', color: '#42526e', borderBottom: '1px solid #dfe1e6' }}>
                    <th style={{ padding: '8px 10px' }}>Seq</th>
                    <th style={{ padding: '8px 10px' }}>Timestamp</th>
                    <th style={{ padding: '8px 10px' }}>Action</th>
                    <th style={{ padding: '8px 10px' }}>Target</th>
                    <th style={{ padding: '8px 10px' }}>Actor</th>
                    <th style={{ padding: '8px 10px' }}>Auth Method</th>
                    <th style={{ padding: '8px 10px' }}>Entry Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => (
                    <tr key={entry.seq} style={{ borderBottom: '1px solid #ebecf0', verticalAlign: 'top' }}>
                      <td style={{ padding: '8px 10px', fontWeight: 700 }}>#{entry.seq}</td>
                      <td style={{ padding: '8px 10px', whiteSpace: 'nowrap', color: '#505f79' }}>{entry.timestamp}</td>
                      <td style={{ padding: '8px 10px', fontWeight: 700, color: '#0052cc' }}>
                        {entry.action}
                        {Object.keys(entry.details || {}).length > 0 && (
                          <div style={{ fontSize: 10, fontWeight: 400, color: '#505f79', marginTop: 2, maxWidth: 220, wordBreak: 'break-word' }}>
                            {JSON.stringify(entry.details)}
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '8px 10px', fontWeight: 600 }}>{entry.targetKey}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', fontSize: 10 }}>{entry.actorAccountId}</td>
                      <td style={{ padding: '8px 10px', fontSize: 10 }}>{entry.authMethod}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', fontSize: 10 }}>
                        <div title={entry.entryHash}>cur: {entry.entryHash.slice(0, 12)}...</div>
                        <div title={entry.prevHash} style={{ color: '#505f79' }}>
                          prev: {entry.prevHash.slice(0, 12)}...
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
