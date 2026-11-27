import React, { useEffect, useRef, useState } from 'react';
import { invokeResolver } from '../bridge';
import { useDialogA11y } from '../hooks/useDialogA11y';
import {
  getErrorMessage,
  getSafeHttpsUrl,
  hasPriorSignature,
  validateHttpsUrlError,
} from '../utils';
import { BlastRadiusCard } from './BlastRadiusCard';
import {
  BindIssueForm,
  DemoSimulationForm,
  RecordTestForm,
  SignOffAttestationForm,
} from './InspectionActionForms';
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
  FileText,
  GitPullRequest,
  Lock,
  Share2,
  ShieldAlert,
  X,
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
    attestationChecked: boolean;
    attestationPhrase: string;
  }) => Promise<boolean> | Promise<void> | void;
  onRemediateDemo: (
    hazardKey: string,
    meaning: string
  ) => Promise<boolean> | Promise<void> | void;
  onCreateReverificationTask?: (params: {
    hazardKey?: string;
    linkId?: string;
    issueKey?: string;
    reason?: string;
  }) => Promise<boolean> | Promise<void> | void;
  isMutating: boolean;
  isGlobalBusy?: boolean;
}

const DEFAULT_SIGN_MEANING = 'Approval of IEC 62304 safety specification and risk mitigation';

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
  onCreateReverificationTask,
  isMutating,
  isGlobalBusy = false,
}) => {
  const drawerRef = useRef<HTMLElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const initializedLinkIdRef = useRef<string | null>(null);
  const bindDirtyRef = useRef(false);
  const syncedSnapshotRef = useRef<{
    testStatus: VerificationTest['status'];
    evidenceUrl: string;
    notes: string;
    meaning: string;
  } | null>(null);
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

  // Electronic Attestation Sign-off form state (identity & role are derived server-side)
  const [signMeaning, setSignMeaning] = useState('');
  const [attestationPhrase, setAttestationPhrase] = useState('');
  const [attestationConfirmed, setAttestationConfirmed] = useState(false);
  const [attestationChecked, setAttestationChecked] = useState(false);

  // Demo simulation consent state (decoupled from Part 11 signMeaning)
  const [demoSimConfirmed, setDemoSimConfirmed] = useState(false);
  const [demoSimMeaning, setDemoSimMeaning] = useState('');

  const workKey = link?.work?.key?.trim() || '';
  const contextIssueKey = panelContext?.issueKey?.trim() || '';

  // Sync local form fields on link switch or when refreshed backend values change without overwriting dirty local edits
  useEffect(() => {
    const currentLink = latestLinkRef.current;
    if (!currentLink) {
      initializedLinkIdRef.current = null;
      bindDirtyRef.current = false;
      syncedSnapshotRef.current = null;
      return;
    }
    const nextEvidence = currentLink.test.evidenceUrl || '';
    const nextNotes = currentLink.test.notes || '';
    const nextMeaning = currentLink.signature.meaning || DEFAULT_SIGN_MEANING;
    const prevSnapshot = syncedSnapshotRef.current;

    if (initializedLinkIdRef.current !== currentLink.id) {
      initializedLinkIdRef.current = currentLink.id;
      bindDirtyRef.current = false;

      setBindIssueInput(currentLink.work.key || contextIssueKey || '');
      setTestStatusInput(currentLink.test.status);
      setTestEvidenceUrl(nextEvidence);
      setTestNotes(nextNotes);
      setTestValidationError(null);
      setSignMeaning(nextMeaning);
      setAttestationPhrase('');
      setAttestationConfirmed(false);
      setAttestationChecked(false);
      setDemoSimConfirmed(false);
      setDemoSimMeaning('');
    } else if (prevSnapshot) {
      if (testStatusInput === prevSnapshot.testStatus) setTestStatusInput(currentLink.test.status);
      if (testEvidenceUrl === prevSnapshot.evidenceUrl) setTestEvidenceUrl(nextEvidence);
      if (testNotes === prevSnapshot.notes) setTestNotes(nextNotes);
      if (signMeaning === prevSnapshot.meaning) setSignMeaning(nextMeaning);
    }

    syncedSnapshotRef.current = {
      testStatus: currentLink.test.status,
      evidenceUrl: nextEvidence,
      notes: nextNotes,
      meaning: nextMeaning,
    };
  }, [
    link?.id,
    link?.test.status,
    link?.test.evidenceUrl,
    link?.test.notes,
    link?.signature.meaning,
  ]); // eslint-disable-line react-hooks/exhaustive-deps

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

  // Fetch live Jira REST context dynamically for the selected link's Jira work key
  useEffect(() => {
    const currentLinkId = latestLinkRef.current?.id;
    const activeProjectKey = panelContext?.projectKey?.trim().toUpperCase();
    const isCrossProjectDemoFixture =
      datasetMode === 'DEMO' &&
      (Boolean(panelContext?.isConfluence) ||
        (Boolean(activeProjectKey) &&
          Boolean(workKey) &&
          !workKey.toUpperCase().startsWith(`${activeProjectKey}-`)));

    if (!currentLinkId || !workKey || isCrossProjectDemoFixture) {
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
          setGraphContext(null);
          setGraphContextError(getErrorMessage(err, 'Unable to query Jira REST context.'));
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
  }, [link?.id, workKey, datasetMode, panelContext?.projectKey, panelContext?.isConfluence]);

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
    attestationChecked &&
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
  const isSavedEvidenceSafeHttps = getSafeHttpsUrl(savedEvidenceUrl) !== null;

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
    const urlError = validateHttpsUrlError(trimmedUrl);
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
    const submittedLinkId = link.id;
    try {
      const result = await onSignOffPart11({
        hazardKey: link.hazard.key,
        linkId: submittedLinkId,
        specId: link.spec.id,
        meaning: signMeaning.trim(),
        attestationConfirmed: true,
        attestationChecked: true,
        attestationPhrase: trimmedPhrase,
      });
      if (result !== false && latestLinkRef.current?.id === submittedLinkId) {
        setAttestationPhrase('');
        setAttestationConfirmed(false);
        setAttestationChecked(false);
      }
    } catch {
      // Preserve attestation fields if parent callback rejects
    }
  };

  const handleRemediateDemoClick = async () => {
    if (isBusy || !demoSimConfirmed) return;
    const submittedLinkId = link.id;
    try {
      const result = await onRemediateDemo(link.hazard.key, demoSimMeaning.trim());
      if (result !== false && latestLinkRef.current?.id === submittedLinkId) {
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
            <BlastRadiusCard blastRadius={blastRadius} />
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
              {link.reverificationTaskKey && (
                <div
                  style={{
                    marginTop: 8,
                    fontSize: 11,
                    fontWeight: 700,
                    color: 'var(--mt-brand-text)',
                  }}
                >
                  Linked Re-Verification Jira Task: {link.reverificationTaskKey}
                </div>
              )}
              {datasetMode === 'LIVE' &&
                link.work.key &&
                !link.reverificationTaskKey &&
                onCreateReverificationTask && (
                  <button
                    type="button"
                    disabled={isBusy}
                    onClick={() => {
                      void onCreateReverificationTask({
                        hazardKey: link.hazard.key,
                        linkId: link.id,
                        issueKey: link.work.key,
                        reason: link.signature.invalidationReason || link.violations[0],
                      });
                    }}
                    className="mt-btn"
                    style={{
                      marginTop: 10,
                      border: '1px solid var(--mt-danger-border)',
                      background: 'var(--mt-bg-surface)',
                      color: 'var(--mt-danger-text)',
                      fontSize: 11,
                      padding: '5px 10px',
                    }}
                  >
                    <GitPullRequest size={13} /> Create Re-Verification Jira Task ({link.work.key})
                  </button>
                )}
            </div>
          )}

          {/* Stage 1: Hazard & IEC 62304 Software Safety Class */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <ShieldAlert
                size={15}
                color={isClassC ? 'var(--mt-danger-text)' : 'var(--mt-brand-text)'}
              />
              <span>1. Hazard &amp; IEC 62304 Software Safety Class</span>
            </div>
            <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--mt-text-primary)' }}>
              {link.hazard.title}
            </div>
            <div style={{ marginTop: 6, display: 'flex', gap: 8, fontSize: 11, flexWrap: 'wrap' }}>
              <span style={pillStyle('var(--mt-danger-bg)', 'var(--mt-danger-text)')}>
                IEC 62304 {link.hazard.riskClass.replace('_', ' ')}
              </span>
              {link.hazard.severity || link.hazard.probability ? (
                <>
                  {link.hazard.severity && (
                    <span style={pillStyle('var(--mt-bg-page)', 'var(--mt-text-secondary)')}>
                      ISO 14971 Severity: {link.hazard.severity}
                    </span>
                  )}
                  {link.hazard.probability && (
                    <span style={pillStyle('var(--mt-bg-page)', 'var(--mt-text-secondary)')}>
                      ISO 14971 Prob: {link.hazard.probability}
                    </span>
                  )}
                </>
              ) : (
                <span style={pillStyle('var(--mt-bg-page)', 'var(--mt-text-secondary)')}>
                  ISO 14971 Sev/Prob: Not synced from Jira
                </span>
              )}
              {datasetMode === 'LIVE' && link.hazard.source && (
                <span
                  style={pillStyle(
                    link.hazard.source === 'JIRA_ISSUE'
                      ? 'var(--mt-brand-subtle-bg)'
                      : 'var(--mt-warning-bg)',
                    link.hazard.source === 'JIRA_ISSUE'
                      ? 'var(--mt-brand-text)'
                      : 'var(--mt-warning-text)'
                  )}
                >
                  {link.hazard.source === 'JIRA_ISSUE' ? 'Native Jira Hazard' : 'App-Managed Hazard'}
                </span>
              )}
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

            <BindIssueForm
              hazardKey={link.hazard.key}
              bindIssueInput={bindIssueInput}
              bindPlaceholder={bindPlaceholder}
              isBusy={isBusy}
              labelStyle={labelStyle}
              onChangeInput={(val) => {
                bindDirtyRef.current = true;
                setBindIssueInput(val);
              }}
              onSubmit={handleBindClick}
            />
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
              {datasetMode === 'LIVE' && link.test.source
                ? ` • Source: ${link.test.source === 'JIRA_ISSUE' ? 'Native Jira Issue' : 'App-Managed Record'}`
                : ''}
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

            <RecordTestForm
              testKey={link.test.testKey}
              panelContext={panelContext}
              testStatusInput={testStatusInput}
              testEvidenceUrl={testEvidenceUrl}
              testNotes={testNotes}
              testValidationError={testValidationError}
              isBusy={isBusy}
              onChangeStatus={setTestStatusInput}
              onChangeEvidenceUrl={(val) => {
                setTestEvidenceUrl(val);
                if (testValidationError) {
                  setTestValidationError(null);
                }
              }}
              onChangeNotes={setTestNotes}
              onSubmit={handleRecordTestClick}
            />
          </div>

          {/* Stage 5: 21 CFR Part 11 Electronic Signature + Explicit Attestation Sign-Off */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <Lock
                size={15}
                color={
                  link.signature.isValid ? 'var(--mt-success-text)' : 'var(--mt-danger-text)'
                }
              />
              <span>5. Electronic Attestation &amp; Audit Trail</span>
            </div>
            {(() => {
              const hasPriorSig = hasPriorSignature(link.signature);
              const sigBg = link.signature.isValid
                ? 'var(--mt-success-bg)'
                : hasPriorSig
                  ? 'var(--mt-danger-bg)'
                  : 'var(--mt-warning-bg)';
              const sigColor = link.signature.isValid
                ? 'var(--mt-success-text)'
                : hasPriorSig
                  ? 'var(--mt-danger-text)'
                  : 'var(--mt-warning-text)';
              const sigBadgeText = link.signature.isValid
                ? 'VALID SIGNATURE'
                : hasPriorSig
                  ? 'SIGNATURE REVOKED'
                  : 'UNSIGNED';
              return (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: 12, color: 'var(--mt-text-primary)' }}>
                    {link.signature.signedBy || 'Unsigned'}
                  </span>
                  <span style={pillStyle(sigBg, sigColor)}>{sigBadgeText}</span>
                </div>
              );
            })()}
            {(link.signature.role || link.signature.authMethod) && (
              <div style={{ fontSize: 11, color: 'var(--mt-text-muted)', marginTop: 2 }}>
                {link.signature.role ? `Role: ${link.signature.role}` : ''}
                {link.signature.role && link.signature.authMethod ? ' • ' : ''}
                {link.signature.authMethod ? `Auth: ${link.signature.authMethod}` : ''}
              </div>
            )}
            {link.signature.meaning && (
              <div style={{ fontSize: 11, color: 'var(--mt-text-secondary)', marginTop: 2 }}>
                Meaning: &ldquo;{link.signature.meaning}&rdquo;
              </div>
            )}
            {link.signature.isValid &&
              link.signature.signedByAccountId &&
              link.test.recordedBy === link.signature.signedByAccountId && (
                <div
                  style={{
                    fontSize: 10,
                    color: 'var(--mt-warning-text)',
                    fontWeight: 600,
                    marginTop: 4,
                  }}
                >
                  Self-attested by test recorder — independent QA review required.
                </div>
              )}
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

            <SignOffAttestationForm
              specSha256Hash={link.spec.sha256Hash}
              signMeaning={signMeaning}
              attestationPhrase={attestationPhrase}
              trimmedPhrase={trimmedPhrase}
              phraseMatches={phraseMatches}
              attestationChecked={attestationChecked}
              attestationConfirmed={attestationConfirmed}
              canSubmitSignOff={canSubmitSignOff}
              labelStyle={labelStyle}
              onChangeSignMeaning={setSignMeaning}
              onChangeAttestationPhrase={setAttestationPhrase}
              onChangeAttestationChecked={setAttestationChecked}
              onChangeAttestationConfirmed={setAttestationConfirmed}
              onSubmit={handleSignOffClick}
            />
          </div>

          {/* Atlassian Lineage Metadata (Jira REST + Confluence Links) */}
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
                Atlassian Lineage Metadata (Jira REST + Confluence Links)
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
                Live Jira REST Context ({link.work.key || 'Unbound'})
              </div>
              {isLoadingGraph ? (
                <div style={{ fontSize: 11, color: 'var(--mt-text-secondary)' }}>
                  Querying Jira REST for {link.work.key}...
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
                  Live Jira REST context query failed: {graphContextError}
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
                  {graphContext.specOwners && graphContext.specOwners.length > 0 && (
                    <div style={{ marginTop: 2 }}>
                      Spec owners to re-review (Teamwork Graph):{' '}
                      {graphContext.specOwners.map((o) => o.name).join(', ')}
                    </div>
                  )}
                  {graphContext.teamworkGraphStatus === 'EMPTY' && (
                    <div style={{ marginTop: 2 }}>
                      Teamwork Graph returned no page owners (check that an admin granted the graph
                      scopes)
                    </div>
                  )}
                  {graphContext.teamworkGraphStatus === 'ERROR' && (
                    <div style={{ marginTop: 2, color: 'var(--mt-danger-text)' }}>
                      Teamwork Graph query failed
                    </div>
                  )}
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
                  No live Jira REST issue context returned for {workKey} (expected in offline/unlinked demo fixtures).
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
              <CheckCircle2 size={16} /> Verified trace (configured checks passed)
            </div>
          ) : datasetMode === 'DEMO' ? (
            <DemoSimulationForm
              hazardKey={link.hazard.key}
              demoSimMeaning={demoSimMeaning}
              demoSimConfirmed={demoSimConfirmed}
              isBusy={isBusy}
              onChangeDemoSimMeaning={setDemoSimMeaning}
              onChangeDemoSimConfirmed={setDemoSimConfirmed}
              onSubmit={handleRemediateDemoClick}
            />
          ) : (
            <div
              style={{
                fontSize: 11,
                color: 'var(--mt-text-secondary)',
                textAlign: 'center',
                fontWeight: 600,
              }}
            >
              LIVE mode active: record real test evidence and execute electronic attestation sign-off
              above to clear this gate.
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
