import React, { useCallback, useEffect, useRef, useState } from 'react';
import { invokeResolver } from '../bridge';
import { verifyAuditChainBounded } from '../auditVerify';
import { useDialogA11y } from '../hooks/useDialogA11y';
import { AuditChainVerification, AuditLogEntry } from '../types';
import { X, ShieldCheck, ShieldAlert, RefreshCw, ScrollText } from 'lucide-react';

interface AuditLogModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const AUDIT_PAGE_SIZE = 100;

export const AuditLogModal: React.FC<AuditLogModalProps> = ({ isOpen, onClose }) => {
  const dialogRef = useRef<HTMLDivElement>(null);
  const requestSeqRef = useRef(0);

  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [verification, setVerification] = useState<AuditChainVerification | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [hasExhaustedOlder, setHasExhaustedOlder] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useDialogA11y({ isOpen, onClose, containerRef: dialogRef });

  const loadLedger = useCallback(async () => {
    const reqId = ++requestSeqRef.current;
    setIsLoading(true);
    setError(null);
    setHasExhaustedOlder(false);
    try {
      const [logRes, verifyRes] = await Promise.all([
        invokeResolver('getAuditLog', { limit: AUDIT_PAGE_SIZE }),
        verifyAuditChainBounded(() => reqId !== requestSeqRef.current),
      ]);
      if (reqId !== requestSeqRef.current) return;
      const newestFirst = Array.isArray(logRes) ? [...logRes].reverse() : [];
      setEntries(newestFirst);
      setVerification(verifyRes || null);
    } catch (err) {
      if (reqId !== requestSeqRef.current) return;
      setError(
        err instanceof Error ? err.message : 'Failed to load audit ledger from Forge backend.'
      );
    } finally {
      if (reqId === requestSeqRef.current) {
        setIsLoading(false);
      }
    }
  }, []);

  const loadOlderEntries = useCallback(async () => {
    if (entries.length === 0 || isLoading || isLoadingMore) return;
    const oldestLoadedSeq = entries.reduce(
      (min, item) => Math.min(min, item.seq),
      entries[0].seq
    );
    if (oldestLoadedSeq <= 1) {
      setHasExhaustedOlder(true);
      return;
    }

    const reqId = ++requestSeqRef.current;
    setIsLoadingMore(true);
    setError(null);
    try {
      // Backend returns entries strictly older than beforeSeq in ascending seq order.
      const olderAsc = await invokeResolver('getAuditLog', {
        limit: AUDIT_PAGE_SIZE,
        beforeSeq: oldestLoadedSeq,
      });
      if (reqId !== requestSeqRef.current) return;

      const olderNewestFirst = Array.isArray(olderAsc) ? [...olderAsc].reverse() : [];
      if (olderNewestFirst.length === 0) {
        setHasExhaustedOlder(true);
        return;
      }

      setEntries((prev) => {
        const seen = new Set(prev.map((item) => item.seq));
        const uniqueOlder = olderNewestFirst.filter((item) => !seen.has(item.seq));
        return [...prev, ...uniqueOlder];
      });
    } catch (err) {
      if (reqId !== requestSeqRef.current) return;
      setError(
        err instanceof Error ? err.message : 'Failed to load older audit ledger entries.'
      );
    } finally {
      if (reqId === requestSeqRef.current) {
        setIsLoadingMore(false);
      }
    }
  }, [entries, isLoading, isLoadingMore]);

  useEffect(() => {
    if (!isOpen) return;
    loadLedger();
    return () => {
      // Invalidate any in-flight fetch if modal closes before completion.
      requestSeqRef.current += 1;
    };
  }, [isOpen, loadLedger]);

  if (!isOpen) return null;

  const oldestLoadedSeq =
    entries.length > 0 ? entries.reduce((min, item) => Math.min(min, item.seq), entries[0].seq) : null;
  const isTruncated = Boolean(verification && verification.totalEntries > entries.length);
  const canLoadOlder =
    isTruncated && !hasExhaustedOlder && oldestLoadedSeq !== null && oldestLoadedSeq > 1;

  return (
    <div
      className="mt-modal-backdrop no-print"
      style={{ zIndex: 2300 }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="mt-modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="audit-log-modal-title"
        style={{ maxWidth: 920 }}
      >
        <div
          style={{
            padding: '14px 20px',
            borderBottom: '1px solid var(--mt-border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--mt-bg-surface-subtle)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ScrollText size={18} color="var(--mt-brand-text)" />
            <span
              id="audit-log-modal-title"
              style={{ fontWeight: 700, fontSize: 14, color: 'var(--mt-text-primary)' }}
            >
              SHA-256 Hash-Chained Audit Ledger (Forge KVS)
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              type="button"
              onClick={loadLedger}
              disabled={isLoading || isLoadingMore}
              className="mt-btn"
              style={{
                padding: '6px 10px',
                borderRadius: 4,
                border: '1px solid var(--mt-border)',
                background: 'var(--mt-bg-surface)',
                color: 'var(--mt-text-primary)',
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
            <div
              role="alert"
              style={{
                marginBottom: 14,
                padding: '10px 12px',
                borderRadius: 6,
                background: 'var(--mt-danger-bg)',
                border: '1px solid var(--mt-danger-border)',
                color: 'var(--mt-danger-text)',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {error}
            </div>
          )}

          {verification && (
            <div
              style={{
                marginBottom: 16,
                padding: '12px 14px',
                borderRadius: 6,
                background: verification.valid ? 'var(--mt-success-bg)' : 'var(--mt-danger-bg)',
                border: `1px solid ${
                  verification.valid ? 'var(--mt-success-border)' : 'var(--mt-danger-border)'
                }`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 10,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {verification.valid ? (
                  <ShieldCheck size={18} color="var(--mt-success-text)" />
                ) : (
                  <ShieldAlert size={18} color="var(--mt-danger-text)" />
                )}
                <div>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 800,
                      color: verification.valid
                        ? 'var(--mt-success-text)'
                        : 'var(--mt-danger-text)',
                    }}
                  >
                    {verification.valid
                      ? verification.truncated
                        ? `HASH CHAIN PARTIALLY VERIFIED THROUGH SEQ #${verification.verifiedToSeq ?? verification.windowEntryCount ?? 0} OF ${verification.totalEntries} (WINDOW TRUNCATED)`
                        : `HASH CHAIN VERIFIED (${verification.totalEntries} tamper-evident entries)`
                      : `CHAIN INTEGRITY FAILURE${
                          verification.brokenAtSeq ? ` AT SEQ #${verification.brokenAtSeq}` : ''
                        }`}
                  </div>
                  {verification.reason && (
                    <div style={{ fontSize: 11, color: 'var(--mt-danger-text)', marginTop: 2 }}>
                      {verification.reason}
                    </div>
                  )}
                </div>
              </div>
              <div
                style={{
                  fontSize: 10,
                  fontFamily: 'monospace',
                  color: 'var(--mt-text-secondary)',
                }}
              >
                Head: {verification.headHash.slice(0, 20)}...
              </div>
            </div>
          )}

          {isTruncated && verification && (
            <div
              role="status"
              style={{
                marginBottom: 14,
                padding: '10px 12px',
                borderRadius: 6,
                background: 'var(--mt-warning-bg)',
                border: '1px solid var(--mt-warning-border)',
                color: 'var(--mt-warning-text)',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              Showing {entries.length} of {verification.totalEntries} audit entries. Hash-chain
              verification above covers all {verification.totalEntries} entries.
            </div>
          )}

          {entries.length === 0 && !isLoading ? (
            <div
              style={{
                padding: 32,
                textAlign: 'center',
                color: 'var(--mt-text-secondary)',
                fontSize: 13,
              }}
            >
              No audit log entries recorded yet.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table
                style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}
              >
                <thead>
                  <tr
                    style={{
                      background: 'var(--mt-bg-page)',
                      color: 'var(--mt-text-secondary)',
                      borderBottom: '1px solid var(--mt-border)',
                    }}
                  >
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
                    <tr
                      key={entry.seq}
                      style={{
                        borderBottom: '1px solid var(--mt-border-subtle)',
                        verticalAlign: 'top',
                      }}
                    >
                      <td style={{ padding: '8px 10px', fontWeight: 700 }}>#{entry.seq}</td>
                      <td
                        style={{
                          padding: '8px 10px',
                          whiteSpace: 'nowrap',
                          color: 'var(--mt-text-secondary)',
                        }}
                      >
                        {entry.timestamp}
                      </td>
                      <td
                        style={{
                          padding: '8px 10px',
                          fontWeight: 700,
                          color: 'var(--mt-brand-text)',
                        }}
                      >
                        {entry.action}
                        {Object.keys(entry.details || {}).length > 0 && (
                          <div
                            style={{
                              fontSize: 10,
                              fontWeight: 400,
                              color: 'var(--mt-text-secondary)',
                              marginTop: 2,
                              maxWidth: 220,
                              wordBreak: 'break-word',
                            }}
                          >
                            {JSON.stringify(entry.details)}
                          </div>
                        )}
                      </td>
                      <td style={{ padding: '8px 10px', fontWeight: 600 }}>{entry.targetKey}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', fontSize: 10 }}>
                        {entry.actorAccountId}
                      </td>
                      <td style={{ padding: '8px 10px', fontSize: 10 }}>{entry.authMethod}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', fontSize: 10 }}>
                        <div title={entry.entryHash}>cur: {entry.entryHash.slice(0, 12)}...</div>
                        <div title={entry.prevHash} style={{ color: 'var(--mt-text-secondary)' }}>
                          prev: {entry.prevHash.slice(0, 12)}...
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {canLoadOlder && (
            <div style={{ marginTop: 14, display: 'flex', justifyContent: 'center' }}>
              <button
                type="button"
                onClick={loadOlderEntries}
                disabled={isLoading || isLoadingMore}
                className="mt-btn"
                style={{
                  padding: '7px 14px',
                  borderRadius: 4,
                  border: '1px solid var(--mt-brand-bg)',
                  background: 'var(--mt-brand-subtle-bg)',
                  color: 'var(--mt-brand-text)',
                }}
              >
                {isLoadingMore ? 'Loading Older Entries...' : 'Load Older Entries'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
