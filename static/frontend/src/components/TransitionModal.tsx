import React, { useId, useRef } from 'react';
import { X, ShieldAlert, ShieldCheck } from 'lucide-react';
import { ComplianceSummary, TransitionResult } from '../types';
import { useDialogA11y } from '../hooks/useDialogA11y';

export interface TransitionModalProps {
  isOpen: boolean;
  onClose: () => void;
  result: TransitionResult | null;
  summary: ComplianceSummary;
}

export const TransitionModal: React.FC<TransitionModalProps> = ({ isOpen, onClose, result, summary }) => {
  const titleId = useId();
  const descId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);

  const isActive = isOpen && Boolean(result);

  useDialogA11y({
    isOpen: isActive,
    onClose,
    containerRef: dialogRef,
  });

  if (!isOpen || !result) return null;

  const hasEvalError = Boolean(result.evalError);
  const evaluatedKey = (result.evaluatedIssueKey || '').trim().toUpperCase();
  const isEmptyGlobalSuite = !evaluatedKey && (summary.initialized === false || summary.totalHazards === 0);
  const isBlocked = !result.result || isEmptyGlobalSuite;
  const matchedLinks = evaluatedKey
    ? summary.traceLinks.filter(
        (l) =>
          (l.work?.key || '').toUpperCase() === evaluatedKey ||
          (l.hazard?.key || '').toUpperCase() === evaluatedKey
      )
    : [];
  const isLinkedIssue = matchedLinks.length > 0;
  const blockingReasons = summary.blockingReasons || [];

  return (
    <div
      className="mt-modal-backdrop no-print"
      style={{ zIndex: 2500 }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="mt-modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        style={{
          maxWidth: 540,
          borderTop: `6px solid ${
            hasEvalError
              ? 'var(--mt-warning-text)'
              : isBlocked
              ? 'var(--mt-danger-bold)'
              : 'var(--mt-success-bold)'
          }`,
        }}
      >
        <div
          style={{
            padding: '20px 24px',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {hasEvalError ? (
              <div
                style={{
                  background: 'var(--mt-warning-bg)',
                  borderRadius: '50%',
                  padding: 10,
                  display: 'flex',
                }}
              >
                <ShieldAlert size={28} color="var(--mt-warning-text)" />
              </div>
            ) : isBlocked ? (
              <div
                style={{
                  background: 'var(--mt-danger-bg)',
                  borderRadius: '50%',
                  padding: 10,
                  display: 'flex',
                }}
              >
                <ShieldAlert size={28} color="var(--mt-danger-text)" />
              </div>
            ) : (
              <div
                style={{
                  background: 'var(--mt-success-bg)',
                  borderRadius: '50%',
                  padding: 10,
                  display: 'flex',
                }}
              >
                <ShieldCheck size={28} color="var(--mt-success-text)" />
              </div>
            )}
            <div>
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  color: 'var(--mt-text-muted)',
                  textTransform: 'uppercase',
                }}
              >
                JIRA WORKFLOW VALIDATOR GATE — {evaluatedKey ? `ISSUE ${evaluatedKey}` : 'GLOBAL RELEASE GATE'}
              </div>
              <div
                id={titleId}
                style={{
                  fontSize: 17,
                  fontWeight: 800,
                  color: 'var(--mt-text-primary)',
                  marginTop: 2,
                }}
              >
                {hasEvalError
                  ? 'Gate Evaluation Failed'
                  : isBlocked
                  ? 'Transition to "Done" Blocked'
                  : 'Transition to "Done" Authorized'}
              </div>
              <div
                style={{
                  fontSize: 11,
                  color: 'var(--mt-text-muted)',
                  marginTop: 2,
                  fontStyle: 'italic',
                }}
              >
                Evaluated via shared workflowValidatorHandler policy; Jira workflow attachment requires site-admin.
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close transition gate dialog"
            className="mt-icon-btn"
          >
            <X size={20} />
          </button>
        </div>

        <div id={descId} style={{ padding: '0 24px 20px 24px', overflowY: 'auto' }}>
          {hasEvalError ? (
            <div
              role="alert"
              style={{
                background: 'var(--mt-warning-bg)',
                border: '1px solid var(--mt-warning-border)',
                borderRadius: 6,
                padding: '14px 16px',
              }}
            >
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 13,
                  color: 'var(--mt-warning-text)',
                  marginBottom: 6,
                }}
              >
                No Verdict Rendered:
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: 'var(--mt-text-secondary)',
                  whiteSpace: 'pre-line',
                  lineHeight: '18px',
                }}
              >
                {result.evalError}
                <br />
                The validator handler could not be reached, so no blocked/approved outcome is displayed. Retry once the backend is reachable.
              </div>
            </div>
          ) : isEmptyGlobalSuite ? (
            <div
              style={{
                background: 'var(--mt-danger-row-bg)',
                border: '1px solid var(--mt-danger-border)',
                borderRadius: 6,
                padding: '14px 16px',
              }}
            >
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 13,
                  color: 'var(--mt-danger-text)',
                  marginBottom: 6,
                }}
              >
                No Trace Links Configured — Sync Live Atlassian artifacts or seed a dataset before release
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: 'var(--mt-text-secondary)',
                  whiteSpace: 'pre-line',
                  lineHeight: '18px',
                }}
              >
                {result.errorMessage ||
                  'Global Release Gate fails closed when the compliance suite is uninitialized or contains 0 hazard trace links.'}
              </div>
              {blockingReasons.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--mt-danger-text)', marginBottom: 4 }}>
                    Blocking Reasons ({blockingReasons.length}):
                  </div>
                  <ul
                    style={{
                      margin: 0,
                      paddingLeft: 18,
                      fontSize: 12,
                      color: 'var(--mt-text-secondary)',
                      lineHeight: '18px',
                    }}
                  >
                    {blockingReasons.map((reason, idx) => (
                      <li key={idx}>{reason}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : isBlocked ? (
            <div
              style={{
                background: 'var(--mt-danger-row-bg)',
                border: '1px solid var(--mt-danger-border)',
                borderRadius: 6,
                padding: '14px 16px',
              }}
            >
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 13,
                  color: 'var(--mt-danger-text)',
                  marginBottom: 6,
                }}
              >
                MedTrace IEC 62304 Safety Gate Lockout:
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: 'var(--mt-text-secondary)',
                  whiteSpace: 'pre-line',
                  lineHeight: '18px',
                }}
              >
                {result.errorMessage ||
                  'Linked safety hazard lacks verified test coverage or has an invalidated 21 CFR Part 11 signature.'}
              </div>
              {blockingReasons.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--mt-danger-text)', marginBottom: 4 }}>
                    {evaluatedKey
                      ? `Active Suite Blocking Reasons (${blockingReasons.length}):`
                      : `Blocking Reasons (${blockingReasons.length}):`}
                  </div>
                  <ul
                    style={{
                      margin: 0,
                      paddingLeft: 18,
                      fontSize: 12,
                      color: 'var(--mt-text-secondary)',
                      lineHeight: '18px',
                    }}
                  >
                    {blockingReasons.map((reason, idx) => (
                      <li key={idx}>{reason}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : evaluatedKey && !isLinkedIssue ? (
            <div
              style={{
                background: 'var(--mt-success-bg)',
                border: '1px solid var(--mt-success-border)',
                borderRadius: 6,
                padding: '14px 16px',
              }}
            >
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 13,
                  color: 'var(--mt-success-text)',
                  marginBottom: 6,
                }}
              >
                Unlinked Issue Permitted:
              </div>
              <div style={{ fontSize: 12, color: 'var(--mt-text-secondary)', lineHeight: '18px' }}>
                ✓ Issue <b>{evaluatedKey}</b> is not bound to any ISO 14971 safety hazard in the active trace matrix.
                <br />
                ✓ Under the shared issue-gate policy, unlinked Jira issues are not blocked unless bound to a failing hazard.
                {summary.releaseBlocked && (
                  <>
                    <br />
                    <span style={{ color: 'var(--mt-warning-text)', fontWeight: 600 }}>
                      Note: Global release remains blocked by {blockingReasons.length || 'unresolved'} hazard{' '}
                      {blockingReasons.length === 1 ? 'gap' : 'gaps'} in the suite.
                    </span>
                    {blockingReasons.length > 0 && (
                      <ul style={{ margin: '6px 0 0', paddingLeft: 18, color: 'var(--mt-text-secondary)' }}>
                        {blockingReasons.map((reason, idx) => (
                          <li key={idx}>{reason}</li>
                        ))}
                      </ul>
                    )}
                  </>
                )}
              </div>
            </div>
          ) : evaluatedKey && isLinkedIssue ? (
            <div
              style={{
                background: 'var(--mt-success-bg)',
                border: '1px solid var(--mt-success-border)',
                borderRadius: 6,
                padding: '14px 16px',
              }}
            >
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 13,
                  color: 'var(--mt-success-text)',
                  marginBottom: 6,
                }}
              >
                Linked Hazard Verification Satisfied ({evaluatedKey}):
              </div>
              <div style={{ fontSize: 12, color: 'var(--mt-text-secondary)', lineHeight: '18px' }}>
                ✓ {matchedLinks.length} linked trace link(s) ({matchedLinks.map((l) => l.hazard.key).join(', ')}) verified with passing tests.
                <br />
                ✓ 21 CFR Part 11 electronic signatures match current Confluence SHA-256 digests.
                <br />
                ✓ Issue transition to <b>Done / Released</b> is authorized.
              </div>
            </div>
          ) : (
            <div
              style={{
                background: 'var(--mt-success-bg)',
                border: '1px solid var(--mt-success-border)',
                borderRadius: 6,
                padding: '14px 16px',
              }}
            >
              <div
                style={{
                  fontWeight: 700,
                  fontSize: 13,
                  color: 'var(--mt-success-text)',
                  marginBottom: 6,
                }}
              >
                All Global Release Gate Criteria Satisfied:
              </div>
              <div style={{ fontSize: 12, color: 'var(--mt-text-secondary)', lineHeight: '18px' }}>
                ✓ All {summary.totalHazards} hazard trace links verified with passing test evidence.
                <br />
                ✓ 21 CFR Part 11 electronic signatures validated against current SHA-256 digests.
                <br />
                ✓ Global release transition to <b>Done / Released</b> is authorized.
              </div>
            </div>
          )}
        </div>

        <div
          style={{
            padding: '12px 24px',
            background: 'var(--mt-bg-surface-subtle)',
            borderTop: '1px solid var(--mt-border-subtle)',
            display: 'flex',
            justifyContent: 'flex-end',
          }}
        >
          <button
            type="button"
            onClick={onClose}
            className="mt-btn"
            style={{
              padding: '8px 16px',
              borderRadius: 4,
              border: 'none',
              background: 'var(--mt-brand-bg)',
              color: 'var(--ds-text-inverse, #ffffff)',
            }}
          >
            Close Intercept Dialog
          </button>
        </div>
      </div>
    </div>
  );
};
