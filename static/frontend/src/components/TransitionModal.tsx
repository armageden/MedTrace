import React, { useEffect } from 'react';
import { X, ShieldAlert, ShieldCheck } from 'lucide-react';
import { ComplianceSummary, TransitionResult } from '../types';

interface TransitionModalProps {
  isOpen: boolean;
  onClose: () => void;
  result: TransitionResult | null;
  summary: ComplianceSummary;
}

export const TransitionModal: React.FC<TransitionModalProps> = ({ isOpen, onClose, result, summary }) => {
  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !result) return null;

  const hasEvalError = Boolean(result.evalError);
  const isBlocked = !result.result;
  const evaluatedKey = (result.evaluatedIssueKey || '').trim().toUpperCase();
  const matchedLinks = evaluatedKey
    ? summary.traceLinks.filter(
        (l) =>
          (l.work?.key || '').toUpperCase() === evaluatedKey ||
          (l.hazard?.key || '').toUpperCase() === evaluatedKey
      )
    : [];
  const isLinkedIssue = matchedLinks.length > 0;

  return (
    <div
      className="mt-modal-backdrop no-print"
      role="dialog"
      aria-modal="true"
      aria-labelledby="transition-modal-title"
      style={{ zIndex: 2500 }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="mt-modal-card"
        style={{
          maxWidth: 540,
          borderTop: `6px solid ${hasEvalError ? '#ff991f' : isBlocked ? '#de350b' : '#00875a'}`,
        }}
      >
        <div style={{ padding: '20px 24px', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {hasEvalError ? (
              <div style={{ background: '#fff0b3', borderRadius: '50%', padding: 10, display: 'flex' }}>
                <ShieldAlert size={28} color="#974f0c" />
              </div>
            ) : isBlocked ? (
              <div style={{ background: '#ffebe6', borderRadius: '50%', padding: 10, display: 'flex' }}>
                <ShieldAlert size={28} color="#bf2600" />
              </div>
            ) : (
              <div style={{ background: '#e3fcef', borderRadius: '50%', padding: 10, display: 'flex' }}>
                <ShieldCheck size={28} color="#006644" />
              </div>
            )}
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#505f79', textTransform: 'uppercase' }}>
                JIRA WORKFLOW VALIDATOR GATE — {evaluatedKey ? `ISSUE ${evaluatedKey}` : 'GLOBAL RELEASE GATE'}
              </div>
              <div id="transition-modal-title" style={{ fontSize: 17, fontWeight: 800, color: '#172b4d', marginTop: 2 }}>
                {hasEvalError
                  ? 'Gate Evaluation Failed'
                  : isBlocked
                  ? 'Transition to "Done" Blocked'
                  : 'Transition to "Done" Authorized'}
              </div>
              <div style={{ fontSize: 11, color: '#505f79', marginTop: 2, fontStyle: 'italic' }}>
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

        <div style={{ padding: '0 24px 20px 24px' }}>
          {hasEvalError ? (
            <div style={{ background: '#fffae6', border: '1px solid #ffe380', borderRadius: 6, padding: '14px 16px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#974f0c', marginBottom: 6 }}>No Verdict Rendered:</div>
              <div style={{ fontSize: 12, color: '#42526e', whiteSpace: 'pre-line', lineHeight: '18px' }}>
                {result.evalError}
                <br />
                The validator handler could not be reached, so no blocked/approved outcome is displayed. Retry once the backend is reachable.
              </div>
            </div>
          ) : isBlocked ? (
            <div style={{ background: '#fff5f5', border: '1px solid #ffbdad', borderRadius: 6, padding: '14px 16px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#bf2600', marginBottom: 6 }}>
                MedTrace IEC 62304 Safety Gate Lockout:
              </div>
              <div style={{ fontSize: 12, color: '#42526e', whiteSpace: 'pre-line', lineHeight: '18px' }}>
                {result.errorMessage || 'Linked safety hazard lacks verified test coverage or has an invalidated 21 CFR Part 11 signature.'}
              </div>
            </div>
          ) : evaluatedKey && !isLinkedIssue ? (
            <div style={{ background: '#e3fcef', border: '1px solid #abf5d1', borderRadius: 6, padding: '14px 16px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#006644', marginBottom: 6 }}>
                Unlinked Issue Permitted:
              </div>
              <div style={{ fontSize: 12, color: '#42526e', lineHeight: '18px' }}>
                ✓ Issue <b>{evaluatedKey}</b> is not bound to any ISO 14971 safety hazard in the active trace matrix.
                <br />
                ✓ Under the shared issue-gate policy, unlinked Jira issues are not blocked unless bound to a failing hazard.
                {summary.releaseBlocked && (
                  <>
                    <br />
                    <span style={{ color: '#974f0c', fontWeight: 600 }}>
                      Note: Global release remains blocked by other unresolved hazards in the suite.
                    </span>
                  </>
                )}
              </div>
            </div>
          ) : evaluatedKey && isLinkedIssue ? (
            <div style={{ background: '#e3fcef', border: '1px solid #abf5d1', borderRadius: 6, padding: '14px 16px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#006644', marginBottom: 6 }}>
                Linked Hazard Verification Satisfied ({evaluatedKey}):
              </div>
              <div style={{ fontSize: 12, color: '#42526e', lineHeight: '18px' }}>
                ✓ {matchedLinks.length} linked trace link(s) ({matchedLinks.map((l) => l.hazard.key).join(', ')}) verified with passing tests.
                <br />
                ✓ 21 CFR Part 11 electronic signatures match current Confluence SHA-256 digests.
                <br />
                ✓ Issue transition to <b>Done / Released</b> is authorized.
              </div>
            </div>
          ) : (
            <div style={{ background: '#e3fcef', border: '1px solid #abf5d1', borderRadius: 6, padding: '14px 16px' }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#006644', marginBottom: 6 }}>
                All Global Release Gate Criteria Satisfied:
              </div>
              <div style={{ fontSize: 12, color: '#42526e', lineHeight: '18px' }}>
                ✓ All {summary.totalHazards} hazard trace links verified with passing test evidence.
                <br />
                ✓ 21 CFR Part 11 electronic signatures validated against current SHA-256 digests.
                <br />
                ✓ Global release transition to <b>Done / Released</b> is authorized.
              </div>
            </div>
          )}
        </div>

        <div style={{ padding: '12px 24px', background: '#fafbfc', borderTop: '1px solid #ebecf0', display: 'flex', justifyContent: 'flex-end' }}>
          <button
            type="button"
            onClick={onClose}
            className="mt-btn"
            style={{
              padding: '8px 16px',
              borderRadius: 4,
              border: 'none',
              background: '#0052cc',
              color: '#ffffff',
            }}
          >
            Close Intercept Dialog
          </button>
        </div>
      </div>
    </div>
  );
};
