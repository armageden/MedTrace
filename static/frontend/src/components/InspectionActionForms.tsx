import React from 'react';
import { ClipboardCheck, Link2, PenTool, Zap } from 'lucide-react';
import { ForgePanelContext, PART11_ATTESTATION_PHRASE, TraceLink, VerificationTest } from '../types';

export interface BindIssueFormProps {
  hazardKey: string;
  bindIssueInput: string;
  bindPlaceholder: string;
  isBusy: boolean;
  labelStyle: React.CSSProperties;
  onChangeInput: (val: string) => void;
  onSubmit: () => void;
}

export const BindIssueForm: React.FC<BindIssueFormProps> = ({
  hazardKey,
  bindIssueInput,
  bindPlaceholder,
  isBusy,
  labelStyle,
  onChangeInput,
  onSubmit,
}) => (
  <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--mt-border-subtle)' }}>
    <label htmlFor="bind-issue-input" style={labelStyle}>
      Bind Jira Issue Key to {hazardKey}
    </label>
    <div className="mt-form-row" style={{ marginTop: 4 }}>
      <input
        id="bind-issue-input"
        type="text"
        className="mt-input"
        value={bindIssueInput}
        onChange={(e) => onChangeInput(e.target.value)}
        placeholder={bindPlaceholder}
      />
      <button
        type="button"
        disabled={isBusy || !bindIssueInput.trim()}
        onClick={onSubmit}
        className="mt-btn"
        style={{
          whiteSpace: 'nowrap',
          border: '1px solid var(--mt-brand-bg)',
          background: 'var(--mt-brand-subtle-bg)',
          color: 'var(--mt-brand-text)',
        }}
      >
        <Link2 size={13} /> Bind
      </button>
    </div>
  </div>
);

export interface RecordTestFormProps {
  testKey: string;
  panelContext?: ForgePanelContext;
  testStatusInput: VerificationTest['status'];
  testEvidenceUrl: string;
  testNotes: string;
  testValidationError: string | null;
  isBusy: boolean;
  onChangeStatus: (status: VerificationTest['status']) => void;
  onChangeEvidenceUrl: (url: string) => void;
  onChangeNotes: (notes: string) => void;
  onSubmit: () => void;
}

export const RecordTestForm: React.FC<RecordTestFormProps> = ({
  testKey,
  panelContext,
  testStatusInput,
  testEvidenceUrl,
  testNotes,
  testValidationError,
  isBusy,
  onChangeStatus,
  onChangeEvidenceUrl,
  onChangeNotes,
  onSubmit,
}) => (
  <div
    style={{
      marginTop: 10,
      paddingTop: 10,
      borderTop: '1px solid var(--mt-border-subtle)',
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
    }}
  >
    <div
      style={{
        fontSize: 11,
        fontWeight: 700,
        color: 'var(--mt-text-primary)',
        display: 'flex',
        alignItems: 'center',
        gap: 5,
      }}
    >
      <ClipboardCheck size={13} color="var(--mt-brand-text)" /> Record Verification Test Execution
    </div>
    <div className="mt-form-row">
      <select
        aria-label="Test execution status"
        className="mt-input"
        style={{ width: panelContext?.isCompactPanel ? '100%' : '42%' }}
        value={testStatusInput}
        onChange={(e) => onChangeStatus(e.target.value as VerificationTest['status'])}
      >
        <option value="PASSED">PASSED</option>
        <option value="FAILED">FAILED</option>
        <option value="IN_PROGRESS">IN_PROGRESS</option>
        <option value="UNTESTED">UNTESTED</option>
      </select>
      <input
        type="text"
        aria-label="Evidence URL"
        aria-invalid={Boolean(testValidationError)}
        className="mt-input"
        value={testEvidenceUrl}
        onChange={(e) => onChangeEvidenceUrl(e.target.value)}
        placeholder="https://... (leave blank to clear)"
      />
    </div>
    <input
      type="text"
      aria-label="Test execution notes"
      className="mt-input"
      value={testNotes}
      onChange={(e) => onChangeNotes(e.target.value)}
      placeholder="Execution summary / build SHA / HIL run ID"
    />
    {testValidationError && (
      <div
        role="alert"
        style={{
          padding: '6px 8px',
          borderRadius: 4,
          background: 'var(--mt-danger-bg)',
          border: '1px solid var(--mt-danger-border)',
          color: 'var(--mt-danger-text)',
          fontSize: 11,
          fontWeight: 600,
        }}
      >
        {testValidationError}
      </div>
    )}
    <button
      type="button"
      disabled={isBusy}
      onClick={onSubmit}
      className="mt-btn"
      style={{
        border: '1px solid var(--mt-success-bold)',
        background: 'var(--mt-success-bg)',
        color: 'var(--mt-success-text)',
      }}
    >
      <ClipboardCheck size={14} /> Record Test Result ({testKey})
    </button>
  </div>
);

export interface SignOffAttestationFormProps {
  specSha256Hash: string;
  signMeaning: string;
  attestationPhrase: string;
  trimmedPhrase: string;
  phraseMatches: boolean;
  attestationChecked: boolean;
  attestationConfirmed: boolean;
  canSubmitSignOff: boolean;
  labelStyle: React.CSSProperties;
  onChangeSignMeaning: (val: string) => void;
  onChangeAttestationPhrase: (val: string) => void;
  onChangeAttestationChecked: (checked: boolean) => void;
  onChangeAttestationConfirmed: (checked: boolean) => void;
  onSubmit: () => void;
}

export const SignOffAttestationForm: React.FC<SignOffAttestationFormProps> = ({
  specSha256Hash,
  signMeaning,
  attestationPhrase,
  trimmedPhrase,
  phraseMatches,
  attestationChecked,
  attestationConfirmed,
  canSubmitSignOff,
  labelStyle,
  onChangeSignMeaning,
  onChangeAttestationPhrase,
  onChangeAttestationChecked,
  onChangeAttestationConfirmed,
  onSubmit,
}) => (
  <div
    style={{
      marginTop: 10,
      paddingTop: 10,
      borderTop: '1px solid var(--mt-border-subtle)',
      display: 'flex',
      flexDirection: 'column',
      gap: 8,
    }}
  >
    <div
      style={{
        fontSize: 11,
        fontWeight: 700,
        color: 'var(--mt-text-primary)',
        display: 'flex',
        alignItems: 'center',
        gap: 5,
      }}
    >
      <PenTool size={13} color="var(--mt-brand-text)" /> Execute Electronic Attestation Sign-Off
    </div>
    <div
      style={{
        fontSize: 10,
        color: 'var(--mt-text-secondary)',
        background: 'var(--mt-bg-page)',
        padding: '6px 8px',
        borderRadius: 4,
      }}
    >
      Signer identity and role are derived server-side from your authenticated Atlassian session.
    </div>
    <div>
      <label htmlFor="signoff-meaning" style={labelStyle}>
        Attestation Meaning (min 5 chars)
      </label>
      <input
        id="signoff-meaning"
        type="text"
        className="mt-input"
        style={{ marginTop: 3 }}
        value={signMeaning}
        onChange={(e) => onChangeSignMeaning(e.target.value)}
        placeholder="e.g. Clinical safety approval of SRS revision"
      />
    </div>
    <div>
      <label htmlFor="signoff-attestation-phrase" style={labelStyle}>
        Required Attestation Phrase: <code>{PART11_ATTESTATION_PHRASE}</code>
      </label>
      <input
        id="signoff-attestation-phrase"
        type="text"
        className="mt-input"
        style={{ marginTop: 3 }}
        aria-invalid={trimmedPhrase.length > 0 && !phraseMatches}
        aria-describedby={trimmedPhrase.length > 0 && !phraseMatches ? 'signoff-phrase-error' : undefined}
        value={attestationPhrase}
        onChange={(e) => onChangeAttestationPhrase(e.target.value)}
        placeholder={PART11_ATTESTATION_PHRASE}
      />
      {trimmedPhrase.length > 0 && !phraseMatches && (
        <div
          id="signoff-phrase-error"
          role="alert"
          style={{ fontSize: 10, color: 'var(--mt-danger-text)', marginTop: 2 }}
        >
          Must exactly match: {PART11_ATTESTATION_PHRASE}
        </div>
      )}
    </div>
    <label
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 6,
        fontSize: 11,
        color: 'var(--mt-text-primary)',
        cursor: 'pointer',
      }}
    >
      <input
        type="checkbox"
        checked={attestationChecked}
        onChange={(e) => onChangeAttestationChecked(e.target.checked)}
        style={{ marginTop: 2 }}
      />
      <span>I confirm I am the signer and intend this electronic attestation.</span>
    </label>
    <label
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 6,
        fontSize: 11,
        color: 'var(--mt-text-primary)',
        cursor: 'pointer',
      }}
    >
      <input
        type="checkbox"
        checked={attestationConfirmed}
        onChange={(e) => onChangeAttestationConfirmed(e.target.checked)}
        style={{ marginTop: 2 }}
      />
      <span>
        I attest that this electronic attestation is my deliberate approval record and certifies
        SHA-256 hash <code>{specSha256Hash.slice(0, 10)}...</code>.
      </span>
    </label>
    <button
      type="button"
      disabled={!canSubmitSignOff}
      onClick={onSubmit}
      className="mt-btn"
      style={{
        border: 'none',
        background: 'var(--mt-brand-bg)',
        color: 'var(--ds-text-inverse, #ffffff)',
      }}
    >
      <PenTool size={14} aria-hidden="true" /> Sign Off Spec (Attestation)
    </button>
  </div>
);

export interface DemoSimulationFormProps {
  hazardKey: TraceLink['hazard']['key'];
  demoSimMeaning: string;
  demoSimConfirmed: boolean;
  isBusy: boolean;
  onChangeDemoSimMeaning: (val: string) => void;
  onChangeDemoSimConfirmed: (checked: boolean) => void;
  onSubmit: () => void;
}

export const DemoSimulationForm: React.FC<DemoSimulationFormProps> = ({
  hazardKey,
  demoSimMeaning,
  demoSimConfirmed,
  isBusy,
  onChangeDemoSimMeaning,
  onChangeDemoSimConfirmed,
  onSubmit,
}) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
    <div
      style={{
        fontSize: 10,
        fontWeight: 800,
        color: 'var(--mt-warning-text)',
        textTransform: 'uppercase',
      }}
    >
      DEMO MODE ONLY — Simulated Quick-Remediation
    </div>
    <input
      type="text"
      aria-label="Demo simulation meaning"
      className="mt-input"
      value={demoSimMeaning}
      onChange={(e) => onChangeDemoSimMeaning(e.target.value)}
      placeholder="Simulated remediation note (optional)"
    />
    <label
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 6,
        fontSize: 11,
        color: 'var(--mt-text-secondary)',
        cursor: 'pointer',
      }}
    >
      <input
        type="checkbox"
        checked={demoSimConfirmed}
        onChange={(e) => onChangeDemoSimConfirmed(e.target.checked)}
        style={{ marginTop: 2 }}
      />
      <span>
        Confirm simulated demo remediation (logs <code>DEMO_SIMULATION</code> to the Forge KVS audit
        chain; disabled in LIVE mode).
      </span>
    </label>
    <button
      type="button"
      onClick={onSubmit}
      disabled={isBusy || !demoSimConfirmed}
      className="mt-btn"
      style={{
        width: '100%',
        padding: '9px 14px',
        border: '1.5px solid var(--mt-warning-border)',
        background: 'var(--mt-warning-bg)',
        color: 'var(--mt-warning-text)',
      }}
    >
      <Zap size={15} />
      {isBusy
        ? 'Recording Simulated Demo Remediation...'
        : `Run Simulated Demo Remediation (${hazardKey})`}
    </button>
  </div>
);
