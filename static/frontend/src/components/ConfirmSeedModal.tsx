import React, { useCallback, useId, useRef } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { useDialogA11y } from '../hooks/useDialogA11y';

export interface ConfirmSeedModalProps {
  isOpen: boolean;
  currentMode?: 'DEMO' | 'LIVE';
  linkCount?: number;
  isSubmitting?: boolean;
  isBusy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmSeedModal: React.FC<ConfirmSeedModalProps> = ({
  isOpen,
  currentMode = 'LIVE',
  linkCount = 0,
  isSubmitting = false,
  isBusy = false,
  onConfirm,
  onCancel,
}) => {
  const titleId = useId();
  const descId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelBtnRef = useRef<HTMLButtonElement>(null);

  const busy = Boolean(isSubmitting || isBusy);

  const handleClose = useCallback(() => {
    if (!busy) {
      onCancel();
    }
  }, [busy, onCancel]);

  useDialogA11y({
    isOpen,
    onClose: handleClose,
    containerRef: dialogRef,
    initialFocusRef: cancelBtnRef,
  });

  if (!isOpen) return null;

  const isLive = currentMode === 'LIVE';

  return (
    <div
      className="mt-modal-backdrop no-print"
      style={{ zIndex: 2600 }}
      onClick={(e) => {
        if (e.target === e.currentTarget && !busy) {
          onCancel();
        }
      }}
    >
      <div
        ref={dialogRef}
        className="mt-modal-card"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        style={{
          maxWidth: 480,
          borderTop: '6px solid var(--mt-danger-bold)',
        }}
      >
        <div
          style={{
            padding: '20px 24px 12px',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div
              style={{
                background: 'var(--mt-danger-bg)',
                borderRadius: '50%',
                padding: 10,
                display: 'flex',
                flexShrink: 0,
              }}
            >
              <AlertTriangle size={24} color="var(--mt-danger-text)" />
            </div>
            <div>
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  color: 'var(--mt-danger-text)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.4px',
                }}
              >
                Destructive Dataset Overwrite Warning
              </div>
              <h2
                id={titleId}
                style={{
                  margin: '2px 0 0',
                  fontSize: 17,
                  fontWeight: 800,
                  color: 'var(--mt-text-primary)',
                }}
              >
                {isLive
                  ? 'Overwrite Initialized LIVE Data with DEMO Suite?'
                  : 'Reset Active DEMO Compliance Suite?'}
              </h2>
            </div>
          </div>
          <button
            type="button"
            onClick={handleClose}
            disabled={busy}
            aria-label="Close overwrite confirmation dialog"
            className="mt-icon-btn"
          >
            <X size={20} />
          </button>
        </div>

        <div id={descId} style={{ padding: '0 24px 20px' }}>
          <div
            style={{
              background: 'var(--mt-warning-bg)',
              border: '1px solid var(--mt-warning-border)',
              borderRadius: 6,
              padding: '12px 14px',
              fontSize: 12,
              lineHeight: '18px',
              color: 'var(--mt-text-secondary)',
            }}
          >
            {isLive ? (
              <>
                <strong style={{ color: 'var(--mt-danger-text)' }}>
                  Warning: Active mode is LIVE.
                </strong>{' '}
                Seeding the modeled DEMO suite will overwrite{' '}
                {linkCount > 0 ? (
                  <>
                    your initialized LIVE dataset (<strong>{linkCount}</strong> active trace{' '}
                    {linkCount === 1 ? 'link' : 'links'})
                  </>
                ) : (
                  'your active LIVE compliance state'
                )}{' '}
                in Forge KVS, including live test evidence references and 21 CFR Part 11 signature
                records, and switch the workspace to <strong>DEMO</strong> mode.
                <div style={{ marginTop: 8, color: 'var(--mt-text-muted)' }}>
                  Underlying Jira issues and Confluence pages are not deleted, but you will need to
                  re-run <em>Sync Live Atlassian</em> to restore live compliance tracking.
                </div>
              </>
            ) : (
              <>
                Seeding the DEMO suite will replace the current {linkCount} modeled trace{' '}
                {linkCount === 1 ? 'link' : 'links'} with the baseline demonstration dataset.
              </>
            )}
          </div>
        </div>

        <div
          style={{
            padding: '12px 24px',
            background: 'var(--mt-bg-surface-subtle)',
            borderTop: '1px solid var(--mt-border-subtle)',
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 8,
            flexWrap: 'wrap',
          }}
        >
          <button
            ref={cancelBtnRef}
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="mt-btn"
            style={{
              border: '1px solid var(--mt-border-input)',
              background: 'var(--mt-bg-surface)',
              color: 'var(--mt-text-primary)',
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={busy}
            className="mt-btn"
            style={{
              border: 'none',
              background: 'var(--mt-danger-bold)',
              color: 'var(--ds-text-inverse, #ffffff)',
            }}
          >
            {busy ? 'Seeding Demo Suite…' : 'Confirm Overwrite & Seed Demo'}
          </button>
        </div>
      </div>
    </div>
  );
};
