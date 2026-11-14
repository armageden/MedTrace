import React, { useEffect, useRef, useState } from 'react';
import { invokeResolver } from '../bridge';
import { useDialogA11y } from '../hooks/useDialogA11y';
import {
  BlastRadiusReport,
  ForgePanelContext,
  IssueGraphContextResult,
  PART11_ATTESTATION_PHRASE,
  TraceLink,
  VerificationTest,
} from '../types';
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  Clock,
  ClipboardCheck,
  FileText,
  GitPullRequest,
  Link2,
  Lock,
  PenTool,
  Share2,
  ShieldAlert,
  X,
  Zap,
} from 'lucide-react';

export interface InspectionDrawerProps {
  link: TraceLink | null;
  datasetMode?: 'DEMO' | 'LIVE';
  panelContext?: ForgePanelContext;
  blastRadius: BlastRadiusReport | null;
  onClose: () => void;
  onBindIssue: (
    hazardKey: string,
    issueKey: string,
    linkId?: string
  ) => Promise<boolean> | Promise<void> | void;
  onRecordTestResult: (params: {
    hazardKey: string;
    linkId?: string;
    testKey: string;
    status: VerificationTest['status'];
    evidenceUrl: string;
    notes: string;
  }) => Promise<boolean> | Promise<void> | void;
  onSignOffPart11: (params: {
    hazardKey: string;
    linkId?: string;
    specId?: string;
    meaning: string;
    attestationConfirmed: boolean;
    passwordConfirmed: boolean;
    attestationPhrase: string;
  }) => Promise<boolean> | Promise<void> | void;
  onRemediateDemo: (
    hazardKey: string,
    meaning: string
  ) => Promise<boolean> | Promise<void> | void;
  isMutating: boolean;
  isGlobalBusy?: boolean;
}

const DEFAULT_SIGN_MEANING = 'Approval of IEC 62304 safety specification and risk mitigation';
// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;

function validateEvidenceHttpsUrl(rawUrl: string): string | null {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return null;
  }
  if (CONTROL_CHAR_RE.test(trimmed)) {
    return 'Evidence URL must not contain control characters.';
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return 'Evidence URL must be a valid https:// URL.';
  }
  if (parsed.protocol !== 'https:') {
    return 'Evidence URL must start with https:// (http:// and javascript: URLs are not permitted).';
  }
  if (parsed.username !== '' || parsed.password !== '' || !parsed.hostname) {
    return 'Evidence URL must be a valid https:// URL without embedded credentials.';
  }
  return null;
}

export const InspectionDrawer: React.FC<InspectionDrawerProps> = ({
  link,
  datasetMode = 'LIVE',
  panelContext,
  blastRadius,
  onClose,
  onBindIssue,
  onRecordTestResult,
  onSignOffPart11,
  onRemediateDemo,
  isMutating,
  isGlobalBusy = false,
}) => {
  const drawerRef = useRef<HTMLElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const initializedLinkIdRef = useRef<string | null>(null);
  const bindDirtyRef = useRef(false);
  const latestLinkRef = useRef<TraceLink | null>(link);
  latestLinkRef.current = link;

  const [graphContext, setGraphContext] = useState<IssueGraphContextResult | null>(null);
  const [graphContextError, setGraphContextError] = useState<string | null>(null);
  const [isLoadingGraph, setIsLoadingGraph] = useState(false);

  // Bind Jira Issue form state
  const [bindIssueInput, setBindIssueInput] = useState('');

  // Record Test Result form state
  const [testStatusInput, setTestStatusInput] = useState<VerificationTest['status']>('PASSED');
  const [testEvidenceUrl, setTestEvidenceUrl] = useState('');
  const [testNotes, setTestNotes] = useState('');
  const [testValidationError, setTestValidationError] = useState<string | null>(null);

  // 21 CFR Part 11 §11.200 Sign-off form state (identity & role are derived server-side)
  const [signMeaning, setSignMeaning] = useState('');
  const [attestationPhrase, setAttestationPhrase] = useState('');
  const [attestationConfirmed, setAttestationConfirmed] = useState(false);
  const [passwordConfirmed, setPasswordConfirmed] = useState(false);

  // Demo simulation consent state (decoupled from Part 11 signMeaning)
  const [demoSimConfirmed, setDemoSimConfirmed] = useState(false);
  const [demoSimMeaning, setDemoSimMeaning] = useState('');

  const workKey = link?.work?.key?.trim() || '';
  const contextIssueKey = panelContext?.issueKey?.trim() || '';

  // Reset local form defaults strictly when selected link ID changes (survives 8s polling / focus refresh)
  useEffect(() => {
    const currentLink = latestLinkRef.current;
    if (!currentLink) {
      initializedLinkIdRef.current = null;
      bindDirtyRef.current = false;
      return;
    }
    if (initializedLinkIdRef.current === currentLink.id) {
      return;
    }
    initializedLinkIdRef.current = currentLink.id;
    bindDirtyRef.current = false;

    setBindIssueInput(currentLink.work.key || contextIssueKey || '');
    setTestStatusInput(currentLink.test.status);
    setTestEvidenceUrl(currentLink.test.evidenceUrl || '');
    setTestNotes(currentLink.test.notes || '');
    setTestValidationError(null);
    setSignMeaning(currentLink.signature.meaning || DEFAULT_SIGN_MEANING);
    setAttestationPhrase('');
    setAttestationConfirmed(false);
    setPasswordConfirmed(false);
    setDemoSimConfirmed(false);
    setDemoSimMeaning('');
  }, [link?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-fill unbound issue input from panelContext.issueKey only if user hasn't edited it
  useEffect(() => {
    const currentLink = latestLinkRef.current;
    if (!currentLink) {
      return;
    }
    if (!bindDirtyRef.current && !currentLink.work.key && contextIssueKey) {
      setBindIssueInput(contextIssueKey);
    }
  }, [contextIssueKey, link?.id]);

  // Fetch live AGG / Jira REST context dynamically for the selected link's Jira work key
  useEffect(() => {
    const currentLinkId = latestLinkRef.current?.id;
    if (!currentLinkId || !workKey) {
      setGraphContext(null);
      setGraphContextError(null);
      setIsLoadingGraph(false);
      return;
    }
    let cancelled = false;
    setIsLoadingGraph(true);
    setGraphContext(null);
    setGraphContextError(null);
    invokeResolver('queryGraphContext', { issueKey: workKey })
      .then((res) => {
        if (!cancelled) {
          setGraphContext(res ?? null);
          setGraphContextError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const message =
            err instanceof Error && err.message.trim()
              ? err.message
              : 'Unable to query Jira / AGG context.';
          setGraphContext(null);
          setGraphContextError(message);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIsLoadingGraph(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [link?.id, workKey]);

  // Centralized WCAG dialog Escape stack, focus trap, and focus restoration
  useDialogA11y({
    isOpen: Boolean(link),
    onClose,
    containerRef: drawerRef,
    initialFocusRef: closeButtonRef,
  });

  if (!link) return null;

  const isBusy = isMutating || isGlobalBusy;
  const isClassC = link.hazard.riskClass === 'CLASS_C';
  const isBroken = link.complianceState !== 'VERIFIED';
  const trimmedPhrase = attestationPhrase.trim();
  const phraseMatches = trimmedPhrase === PART11_ATTESTATION_PHRASE;
  const canSubmitSignOff =
    attestationConfirmed &&
    passwordConfirmed &&
    phraseMatches &&
    signMeaning.trim().length >= 5 &&
    !isBusy;

  const bindPlaceholder =
    datasetMode === 'LIVE'
      ? panelContext?.projectKey
        ? `e.g. ${panelContext.projectKey}-123`
        : 'e.g. PROJ-123'
      : 'e.g. MED-42';

  const savedEvidenceUrl = link.test.evidenceUrl?.trim() || '';
  const isSavedEvidenceSafeHttps =
    savedEvidenceUrl.length > 0 && validateEvidenceHttpsUrl(savedEvidenceUrl) === null;

  const handleBindClick = async () => {
    const trimmedIssue = bindIssueInput.trim();
    if (!trimmedIssue || isBusy) return;
    try {
      await onBindIssue(link.hazard.key, trimmedIssue, link.id);
    } catch {
      // Preserve form input if parent callback rejects
    }
  };

  const handleRecordTestClick = async () => {
    if (isBusy) return;
    const trimmedUrl = testEvidenceUrl.trim();
    const urlError = validateEvidenceHttpsUrl(trimmedUrl);
    if (urlError) {
      setTestValidationError(urlError);
      return;
    }
    setTestValidationError(null);
    try {
      await onRecordTestResult({
        hazardKey: link.hazard.key,
        linkId: link.id,
        testKey: link.test.testKey,
        status: testStatusInput,
        evidenceUrl: trimmedUrl,
        notes: testNotes.trim(),
      });
    } catch {
      // Preserve test inputs if parent callback rejects
    }
  };

  const handleSignOffClick = async () => {
    if (!canSubmitSignOff) return;
    try {
      const result = await onSignOffPart11({
        hazardKey: link.hazard.key,
        linkId: link.id,
        specId: link.spec.id,
        meaning: signMeaning.trim(),
        attestationConfirmed: true,
        passwordConfirmed: true,
        attestationPhrase: trimmedPhrase,
      });
      if (result !== false) {
        setAttestationPhrase('');
        setAttestationConfirmed(false);
        setPasswordConfirmed(false);
      }
    } catch {
      // Preserve attestation fields if parent callback rejects
    }
  };

  const handleRemediateDemoClick = async () => {
    if (isBusy || !demoSimConfirmed) return;
    try {
      const result = await onRemediateDemo(link.hazard.key, demoSimMeaning.trim());
      if (result !== false) {
        setDemoSimConfirmed(false);
        setDemoSimMeaning('');
      }
    } catch {
      // Preserve demo consent inputs if parent callback rejects
    }
  };

  return (
    <>
      <div className="mt-drawer-backdrop no-print" onClick={onClose} aria-hidden="true" />
      <aside
        ref={drawerRef}
        className="mt-drawer no-print"
        role="dialog"
        aria-modal="true"
        aria-labelledby="inspection-drawer-title"
      >
        {/* Header */}
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--mt-border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'var(--mt-bg-surface-subtle)',
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: 'var(--mt-text-muted)',
                textTransform: 'uppercase',
              }}
            >
              Regulatory Trace Inspection
            </div>
            <div
              id="inspection-drawer-title"
              style={{ fontSize: 16, fontWeight: 700, color: 'var(--mt-text-primary)' }}
            >
              {link.hazard.key} Lineage
            </div>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            aria-label="Close inspection drawer"
            className="mt-icon-btn"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          {/* Blast Radius Dossier Card */}
          {blastRadius && blastRadius.affectedHazardKeys.includes(link.hazard.key) && (
            <div
              style={{
                marginBottom: 16,
                padding: '14px 16px',
                borderRadius: 8,
                background: 'var(--mt-warning-bg)',
                border: '1.5px solid var(--mt-warning-border)',
                boxShadow: '0 2px 6px rgba(255, 171, 0, 0.15)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: 6,
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    color: 'var(--mt-warning-text)',
                    fontWeight: 800,
                    fontSize: 13,
                  }}
                >
                  <Zap size={16} /> Transitive Regulatory Blast Radius
                </div>
                <span
                  style={{
                    fontSize: 10,
                    fontFamily: 'monospace',
                    background: 'var(--mt-bg-surface)',
                    padding: '2px 6px',
                    borderRadius: 4,
                    border: '1px solid var(--mt-warning-border)',
                    color: 'var(--mt-text-secondary)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <Clock size={11} /> {blastRadius.executionTimeMs} ms
                </span>
              </div>

              <div style={{ fontSize: 11, color: 'var(--mt-text-primary)', marginBottom: 8 }}>
                Trigger: <b>{blastRadius.triggerArtifact.title}</b> ({blastRadius.triggerArtifact.deltaReason})
              </div>

              <div
                style={{
                  background: 'var(--mt-bg-surface)',
                  borderRadius: 6,
                  padding: '8px 10px',
                  border: '1px solid var(--mt-border-subtle)',
                  marginBottom: 10,
                }}
              >
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: 'var(--mt-text-muted)',
                    textTransform: 'uppercase',
                    marginBottom: 4,
                  }}
                >
                  Deterministic Graph Traversal (BFS):
                </div>
                {blastRadius.traversalPath.map((hop, idx) => (
                  <div key={idx} style={{ fontSize: 11, lineHeight: '16px', marginTop: 4, display: 'flex', gap: 6 }}>
                    <span style={{ fontWeight: 700, color: 'var(--mt-brand-text)', minWidth: 40 }}>
                      Hop {hop.hop}:
                    </span>
                    <span style={{ color: 'var(--mt-text-secondary)' }}>
                      <span style={{ fontWeight: 600, color: 'var(--mt-text-primary)' }}>{hop.edge}</span> →{' '}
                      {hop.effect}
                    </span>
                  </div>
                ))}
              </div>

              <div>
                <div
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: 'var(--mt-text-muted)',
                    textTransform: 'uppercase',
                    marginBottom: 4,
                  }}
                >
                  Mandatory Re-audit Actions:
                </div>
                {blastRadius.transitiveActionPlan.map((action, idx) => (
                  <div key={idx} style={{ fontSize: 11, color: 'var(--mt-text-primary)', lineHeight: '16px', marginTop: 3 }}>
                    • {action}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Violations Alert Banner */}
          {link.violations.length > 0 && (
            <div
              style={{
                marginBottom: 16,
                padding: '12px 14px',
                borderRadius: 6,
                background: 'var(--mt-danger-bg)',
                border: '1px solid var(--mt-danger-border)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  color: 'var(--mt-danger-text)',
                  fontWeight: 700,
                  fontSize: 13,
                  marginBottom: 4,
                }}
              >
                <AlertOctagon size={16} /> Regulatory Safety Gate Lockout
              </div>
              {link.violations.map((v, i) => (
                <div key={i} style={{ fontSize: 11, color: 'var(--mt-danger-text)', lineHeight: '16px', marginTop: 4 }}>
                  • {v}
                </div>
              ))}
            </div>
          )}

          {/* Stage 1: ISO 14971 Hazard */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <ShieldAlert
                size={15}
                color={isClassC ? 'var(--mt-danger-text)' : 'var(--mt-brand-text)'}
              />
              <span>1. ISO 14971 Risk Classification</span>
            </div>
            <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-text-primary)' }}>
              {link.hazard.title}
            </div>
            <div style={{ marginTop: 6, display: 'flex', gap: 8, fontSize: 11, flexWrap: 'wrap' }}>
              <span style={pillStyle('var(--mt-danger-bg)', 'var(--mt-danger-text)')}>
                {link.hazard.riskClass.replace('_', ' ')}
              </span>
              <span style={pillStyle('var(--mt-bg-page)', 'var(--mt-text-secondary)')}>
                Severity: {link.hazard.severity}
              </span>
              <span style={pillStyle('var(--mt-bg-page)', 'var(--mt-text-secondary)')}>
                Prob: {link.hazard.probability}
              </span>
            </div>
          </div>

          {/* Stage 2: Confluence SRS Spec */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <FileText size={15} color="var(--mt-brand-text)" />
              <span>2. Confluence Safety Spec (SRS)</span>
            </div>
            <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--mt-text-primary)' }}>
              {link.spec.title}
            </div>
            <div
              style={{
                fontSize: 11,
                color: 'var(--mt-text-secondary)',
                marginTop: 4,
                background: 'var(--mt-bg-page)',
                padding: '6px 8px',
                borderRadius: 4,
              }}
            >
              &ldquo;{link.spec.contentSnippet}&rdquo;
            </div>
            <div style={{ marginTop: 6, fontSize: 10, color: 'var(--mt-text-muted)' }}>
              <span>
                Revision: <b>v{link.spec.version}</b>
              </span>{' '}
              | <span>Last: {link.spec.lastUpdated}</span>
            </div>
            <div
              style={{
                marginTop: 4,
                fontSize: 10,
                fontFamily: 'monospace',
                color: link.spec.isSignatureInvalidated
                  ? 'var(--mt-danger-text)'
                  : 'var(--mt-text-muted)',
                wordBreak: 'break-all',
              }}
            >
              SHA-256: {link.spec.sha256Hash}
            </div>
          </div>

          {/* Stage 3: Jira Implementation + Bind Issue Control */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <GitPullRequest size={15} color="var(--mt-success-text)" />
              <span>3. Jira Work Item &amp; Issue Binding</span>
            </div>
            <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-brand-text)' }}>
              {link.work.key || 'Unbound'}: {link.work.title}
            </div>
            <div
              style={{
                marginTop: 6,
                fontSize: 11,
                color: 'var(--mt-text-secondary)',
                display: 'flex',
                gap: 12,
                flexWrap: 'wrap',
              }}
            >
              <span>
                Status: <b>{link.work.status}</b>
              </span>
              <span>
                PR: <b>{link.work.prNumber || 'None linked'}</b>
              </span>
              <span>
                Assignee: <b>{link.work.assignee || 'Unassigned'}</b>
              </span>
            </div>

            <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--mt-border-subtle)' }}>
              <label htmlFor="bind-issue-input" style={labelStyle}>
                Bind Jira Issue Key to {link.hazard.key}
              </label>
              <div className="mt-form-row" style={{ marginTop: 4 }}>
                <input
                  id="bind-issue-input"
                  type="text"
                  className="mt-input"
                  value={bindIssueInput}
                  onChange={(e) => {
                    bindDirtyRef.current = true;
                    setBindIssueInput(e.target.value);
                  }}
                  placeholder={bindPlaceholder}
                />
                <button
                  type="button"
                  disabled={isBusy || !bindIssueInput.trim()}
                  onClick={handleBindClick}
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
          </div>

          {/* Stage 4: IEC 62304 Verification Test + Record Result Form */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <Activity
                size={15}
                color={
                  link.test.status === 'PASSED'
                    ? 'var(--mt-success-text)'
                    : 'var(--mt-danger-text)'
                }
              />
              <span>4. IEC 62304 Verification Evidence</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-text-primary)' }}>
                {link.test.testKey}: {link.test.title}
              </span>
              <span
                style={pillStyle(
                  link.test.status === 'PASSED' ? 'var(--mt-success-bg)' : 'var(--mt-danger-bg)',
                  link.test.status === 'PASSED'
                    ? 'var(--mt-success-text)'
                    : 'var(--mt-danger-text)'
                )}
              >
                {link.test.status}
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--mt-text-muted)', marginTop: 4 }}>
              Type: {link.test.testType}
            </div>
            <div style={{ fontSize: 11, color: 'var(--mt-text-secondary)', marginTop: 2 }}>
              Execution: {link.test.executionDate || 'Not yet executed'}
            </div>
            {link.test.recordedBy && (
              <div style={{ fontSize: 10, color: 'var(--mt-text-muted)', marginTop: 2 }}>
                Recorded by: {link.test.recordedBy}
              </div>
            )}
            {savedEvidenceUrl && (
              <div style={{ fontSize: 10, color: 'var(--mt-text-secondary)', marginTop: 2, wordBreak: 'break-all' }}>
                Evidence:{' '}
                {isSavedEvidenceSafeHttps ? (
                  <a
                    href={savedEvidenceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: 'var(--mt-brand-text)' }}
                  >
                    {savedEvidenceUrl}
                  </a>
                ) : (
                  <span>{savedEvidenceUrl}</span>
                )}
              </div>
            )}
            {link.test.notes && (
              <div style={{ fontSize: 10, color: 'var(--mt-text-secondary)', marginTop: 2 }}>
                Notes: {link.test.notes}
              </div>
            )}

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
                  onChange={(e) => setTestStatusInput(e.target.value as VerificationTest['status'])}
                >
                  <option value="PASSED">PASSED</option>
                  <option value="FAILED">FAILED</option>
                  <option value="IN_PROGRESS">IN_PROGRESS</option>
                  <option value="UNTESTED">UNTESTED</option>
                </select>
                <input
                  type="text"
                  aria-label="Evidence URL"
                  className="mt-input"
                  value={testEvidenceUrl}
                  onChange={(e) => {
                    setTestEvidenceUrl(e.target.value);
                    if (testValidationError) {
                      setTestValidationError(null);
                    }
                  }}
                  placeholder="https://... (leave blank to clear)"
                />
              </div>
              <input
                type="text"
                aria-label="Test execution notes"
                className="mt-input"
                value={testNotes}
                onChange={(e) => setTestNotes(e.target.value)}
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
                onClick={handleRecordTestClick}
                className="mt-btn"
                style={{
                  border: '1px solid var(--mt-success-bold)',
                  background: 'var(--mt-success-bg)',
                  color: 'var(--mt-success-text)',
                }}
              >
                <ClipboardCheck size={14} /> Record Test Result ({link.test.testKey})
              </button>
            </div>
          </div>

          {/* Stage 5: 21 CFR Part 11 Electronic Signature + §11.200 Explicit Attestation Sign-Off */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <Lock
                size={15}
                color={
                  link.signature.isValid ? 'var(--mt-success-text)' : 'var(--mt-danger-text)'
                }
              />
              <span>5. FDA 21 CFR Part 11 Audit Trail &amp; Sign-Off</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 12, color: 'var(--mt-text-primary)' }}>
                {link.signature.signedBy || 'Unsigned'}
              </span>
              <span
                style={pillStyle(
                  link.signature.isValid ? 'var(--mt-success-bg)' : 'var(--mt-danger-bg)',
                  link.signature.isValid ? 'var(--mt-success-text)' : 'var(--mt-danger-text)'
                )}
              >
                {link.signature.isValid ? 'VALID SIGNATURE' : 'SIGNATURE REVOKED'}
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--mt-text-muted)', marginTop: 2 }}>
              Role: {link.signature.role} {link.signature.authMethod ? `• Auth: ${link.signature.authMethod}` : ''}
            </div>
            <div style={{ fontSize: 11, color: 'var(--mt-text-secondary)', marginTop: 2 }}>
              Meaning: &ldquo;{link.signature.meaning}&rdquo;
            </div>
            {link.signature.invalidationReason && (
              <div
                style={{
                  fontSize: 10,
                  color: 'var(--mt-danger-text)',
                  fontWeight: 600,
                  marginTop: 4,
                }}
              >
                {link.signature.invalidationReason}
              </div>
            )}

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
                <PenTool size={13} color="var(--mt-brand-text)" /> Execute 21 CFR Part 11 Sign-Off
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
                  Signature Meaning (§11.50, min 5 chars)
                </label>
                <input
                  id="signoff-meaning"
                  type="text"
                  className="mt-input"
                  style={{ marginTop: 3 }}
                  value={signMeaning}
                  onChange={(e) => setSignMeaning(e.target.value)}
                  placeholder="e.g. Clinical safety approval of SRS revision"
                />
              </div>
              <div>
                <label htmlFor="signoff-attestation-phrase" style={labelStyle}>
                  Required Attestation Phrase (§11.200): <code>{PART11_ATTESTATION_PHRASE}</code>
                </label>
                <input
                  id="signoff-attestation-phrase"
                  type="text"
                  className="mt-input"
                  style={{ marginTop: 3 }}
                  value={attestationPhrase}
                  onChange={(e) => setAttestationPhrase(e.target.value)}
                  placeholder={PART11_ATTESTATION_PHRASE}
                />
                {trimmedPhrase.length > 0 && !phraseMatches && (
                  <div style={{ fontSize: 10, color: 'var(--mt-danger-text)', marginTop: 2 }}>
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
                  checked={passwordConfirmed}
                  onChange={(e) => setPasswordConfirmed(e.target.checked)}
                  style={{ marginTop: 2 }}
                />
                <span>
                  I confirm my active Atlassian user session re-attestation for 21 CFR Part 11 §11.200.
                </span>
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
                  onChange={(e) => setAttestationConfirmed(e.target.checked)}
                  style={{ marginTop: 2 }}
                />
                <span>
                  I attest under 21 CFR Part 11 that this electronic signature is the legally binding
                  equivalent of my handwritten signature and certifies SHA-256 hash{' '}
                  <code>{link.spec.sha256Hash.slice(0, 10)}...</code>.
                </span>
              </label>
              <button
                type="button"
                disabled={!canSubmitSignOff}
                onClick={handleSignOffClick}
                className="mt-btn"
                style={{
                  border: 'none',
                  background: 'var(--mt-brand-bg)',
                  color: '#ffffff',
                }}
              >
                <PenTool size={14} /> Sign Off Spec (21 CFR Part 11)
              </button>
            </div>
          </div>

          {/* Atlassian Graph (AGG / Jira REST) Lineage Metadata */}
          <div
            style={{
              ...sectionStyle,
              background: 'var(--mt-bg-page)',
              border: '1px solid var(--mt-border)',
            }}
          >
            <div style={sectionHeader}>
              <Share2 size={15} color="var(--mt-brand-text)" />
              <span style={{ color: 'var(--mt-brand-text)' }}>
                Atlassian Graph Lineage Metadata (AGG / Jira REST)
              </span>
            </div>
            {link.graphMetadata ? (
              <>
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 4,
                    fontFamily: 'monospace',
                    fontSize: 10,
                  }}
                >
                  <div
                    style={{
                      background: 'var(--mt-bg-surface)',
                      padding: '5px 8px',
                      borderRadius: 4,
                      border: '1px solid var(--mt-border-subtle)',
                      wordBreak: 'break-all',
                    }}
                  >
                    <span style={{ color: 'var(--mt-text-muted)' }}>Jira ARI: </span>
                    <span style={{ color: 'var(--mt-text-primary)', fontWeight: 600 }}>
                      {link.graphMetadata.entityAri}
                    </span>
                  </div>
                  <div
                    style={{
                      background: 'var(--mt-bg-surface)',
                      padding: '5px 8px',
                      borderRadius: 4,
                      border: '1px solid var(--mt-border-subtle)',
                      wordBreak: 'break-all',
                    }}
                  >
                    <span style={{ color: 'var(--mt-text-muted)' }}>Hazard ARI: </span>
                    <span style={{ color: 'var(--mt-text-primary)', fontWeight: 600 }}>
                      {link.graphMetadata.hazardAri}
                    </span>
                  </div>
                  <div
                    style={{
                      background: 'var(--mt-bg-surface)',
                      padding: '5px 8px',
                      borderRadius: 4,
                      border: '1px solid var(--mt-border-subtle)',
                      wordBreak: 'break-all',
                    }}
                  >
                    <span style={{ color: 'var(--mt-text-muted)' }}>Spec ARI: </span>
                    <span style={{ color: 'var(--mt-text-primary)', fontWeight: 600 }}>
                      {link.graphMetadata.linkedSpecAri}
                    </span>
                  </div>
                  <div
                    style={{
                      background: 'var(--mt-bg-surface)',
                      padding: '5px 8px',
                      borderRadius: 4,
                      border: '1px solid var(--mt-border-subtle)',
                      wordBreak: 'break-all',
                    }}
                  >
                    <span style={{ color: 'var(--mt-text-muted)' }}>Edge Type: </span>
                    <span style={{ color: 'var(--mt-text-primary)', fontWeight: 600 }}>
                      {link.graphMetadata.edgeType || 'Unrecorded'}
                    </span>
                  </div>
                </div>
                <div
                  style={{
                    marginTop: 6,
                    fontSize: 10,
                    color: 'var(--mt-text-secondary)',
                    fontWeight: 600,
                  }}
                >
                  {link.graphMetadata.aggTraversalStatus}
                </div>
              </>
            ) : (
              <div style={{ fontSize: 11, color: 'var(--mt-text-muted)', lineHeight: '16px' }}>
                No static graph ARI metadata attached to this record.
              </div>
            )}

            <div
              style={{
                marginTop: 10,
                padding: '8px 10px',
                borderRadius: 6,
                background: 'var(--mt-brand-subtle-bg)',
                border: '1px solid var(--mt-border)',
              }}
            >
              <div
                style={{
                  fontSize: 10,
                  fontWeight: 700,
                  color: 'var(--mt-brand-text)',
                  textTransform: 'uppercase',
                  marginBottom: 4,
                }}
              >
                Live AGG / Jira REST Context ({link.work.key || 'Unbound'})
              </div>
              {isLoadingGraph ? (
                <div style={{ fontSize: 11, color: 'var(--mt-text-secondary)' }}>
                  Querying AGG / Jira REST for {link.work.key}...
                </div>
              ) : graphContextError ? (
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
                  Live Jira/AGG context query failed: {graphContextError}
                </div>
              ) : graphContext ? (
                <div
                  style={{
                    fontFamily: 'monospace',
                    fontSize: 10,
                    color: 'var(--mt-text-primary)',
                    lineHeight: '15px',
                  }}
                >
                  <div>
                    Source: <b>{graphContext.source}</b> | Issue: <b>{graphContext.issueKey}</b>
                    {graphContext.status?.name ? ` (${graphContext.status.name})` : ''}
                  </div>
                  {graphContext.summary && <div style={{ marginTop: 2 }}>Summary: {graphContext.summary}</div>}
                  <div style={{ marginTop: 2 }}>
                    Jira Links: {graphContext.issuelinks.length} | Confluence Links:{' '}
                    {graphContext.confluenceLinks.length}
                  </div>
                  {graphContext.confluenceLinks.map((c, idx) => (
                    <div key={idx} style={{ marginTop: 2, color: 'var(--mt-brand-text)' }}>
                      • {c.title} {c.pageId ? `(pageId=${c.pageId})` : ''}
                    </div>
                  ))}
                </div>
              ) : !workKey ? (
                <div style={{ fontSize: 10, color: 'var(--mt-text-secondary)' }}>
                  No Jira issue bound to this trace link yet.
                </div>
              ) : datasetMode === 'LIVE' ? (
                <div style={{ fontSize: 10, color: 'var(--mt-text-secondary)' }}>
                  No linked Jira/Confluence remote context returned for {workKey}.
                </div>
              ) : (
                <div style={{ fontSize: 10, color: 'var(--mt-text-secondary)' }}>
                  No live AGG/REST issue context returned for {workKey} (expected in offline/unlinked demo fixtures).
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer / Status or Explicit Demo Simulation */}
        <div
          style={{
            padding: '14px 20px',
            borderTop: '1px solid var(--mt-border-subtle)',
            background: 'var(--mt-bg-surface-subtle)',
          }}
        >
          {!isBroken ? (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
                color: 'var(--mt-success-text)',
                fontWeight: 700,
                fontSize: 13,
              }}
            >
              <CheckCircle2 size={16} /> Unbroken IEC 62304 Regulatory Compliance
            </div>
          ) : datasetMode === 'DEMO' ? (
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
                onChange={(e) => setDemoSimMeaning(e.target.value)}
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
                  onChange={(e) => setDemoSimConfirmed(e.target.checked)}
                  style={{ marginTop: 2 }}
                />
                <span>
                  Confirm simulated demo remediation (logs <code>DEMO_SIMULATION</code> to the Forge
                  KVS audit chain; disabled in LIVE mode).
                </span>
              </label>
              <button
                type="button"
                onClick={handleRemediateDemoClick}
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
                  : `Run Simulated Demo Remediation (${link.hazard.key})`}
              </button>
            </div>
          ) : (
            <div
              style={{
                fontSize: 11,
                color: 'var(--mt-text-secondary)',
                textAlign: 'center',
                fontWeight: 600,
              }}
            >
              LIVE mode active: record real test evidence and execute 21 CFR Part 11 sign-off above
              to clear this gate.
            </div>
          )}
        </div>
      </aside>
    </>
  );
};

const sectionStyle: React.CSSProperties = {
  marginBottom: 16,
  padding: '12px 14px',
  borderRadius: 6,
  border: '1px solid var(--mt-border-subtle)',
  background: 'var(--mt-bg-surface)',
};

const sectionHeader: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 6,
  fontSize: 11,
  fontWeight: 700,
  color: 'var(--mt-text-secondary)',
  textTransform: 'uppercase',
  marginBottom: 6,
};

const labelStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  color: 'var(--mt-text-secondary)',
};

const pillStyle = (bg: string, color: string): React.CSSProperties => ({
  fontSize: 10,
  fontWeight: 700,
  padding: '2px 6px',
  borderRadius: 4,
  background: bg,
  color,
});
