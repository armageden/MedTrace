import React, { useEffect, useState } from 'react';
import { invokeResolver } from '../bridge';
import {
  TraceLink,
  BlastRadiusReport,
  IssueGraphContextResult,
  ForgePanelContext,
  VerificationTest,
} from '../types';
import {
  X,
  ShieldAlert,
  FileText,
  GitPullRequest,
  Activity,
  Lock,
  AlertOctagon,
  CheckCircle2,
  Zap,
  Share2,
  Clock,
  Link2,
  ClipboardCheck,
  PenTool,
} from 'lucide-react';

interface InspectionDrawerProps {
  link: TraceLink | null;
  datasetMode: 'DEMO' | 'LIVE';
  panelContext: ForgePanelContext;
  blastRadius: BlastRadiusReport | null;
  onClose: () => void;
  onBindIssue: (hazardKey: string, issueKey: string) => Promise<void>;
  onRecordTestResult: (params: {
    hazardKey: string;
    testKey: string;
    status: VerificationTest['status'];
    evidenceUrl?: string;
    notes?: string;
  }) => Promise<void>;
  onSignOffPart11: (params: {
    hazardKey: string;
    meaning: string;
    role?: string;
    attestationConfirmed: boolean;
    attestationPhrase?: string;
  }) => Promise<void>;
  onRemediateDemo: (hazardKey: string, meaning: string) => Promise<void>;
  isMutating: boolean;
}

export const InspectionDrawer: React.FC<InspectionDrawerProps> = ({
  link,
  datasetMode,
  panelContext,
  blastRadius,
  onClose,
  onBindIssue,
  onRecordTestResult,
  onSignOffPart11,
  onRemediateDemo,
  isMutating,
}) => {
  const [graphContext, setGraphContext] = useState<IssueGraphContextResult | null>(null);
  const [isLoadingGraph, setIsLoadingGraph] = useState(false);

  // Bind Jira Issue form state
  const [bindIssueInput, setBindIssueInput] = useState('');

  // Record Test Result form state
  const [testStatusInput, setTestStatusInput] = useState<VerificationTest['status']>('PASSED');
  const [testEvidenceUrl, setTestEvidenceUrl] = useState('');
  const [testNotes, setTestNotes] = useState('');

  // 21 CFR Part 11 Sign-off form state
  const [signMeaning, setSignMeaning] = useState('');
  const [signRole, setSignRole] = useState('');
  const [attestationPhrase, setAttestationPhrase] = useState('');
  const [attestationConfirmed, setAttestationConfirmed] = useState(false);

  // Demo simulation consent state
  const [demoSimConfirmed, setDemoSimConfirmed] = useState(false);

  // Sync local form defaults when selected link changes
  useEffect(() => {
    if (!link) return;
    setBindIssueInput(panelContext.issueKey || link.work.key || '');
    setTestStatusInput(link.test.status);
    setTestEvidenceUrl(link.test.evidenceUrl || '');
    setTestNotes(link.test.notes || '');
    setSignMeaning(link.signature.meaning || 'Approval of IEC 62304 safety specification and risk mitigation');
    setSignRole(link.signature.role || 'Quality Assurance Director');
    setAttestationPhrase('');
    setAttestationConfirmed(false);
    setDemoSimConfirmed(false);
  }, [link, panelContext.issueKey]);

  // Fetch live AGG / Jira REST context dynamically for the selected link's Jira work key
  useEffect(() => {
    if (!link || !link.work.key) {
      setGraphContext(null);
      return;
    }
    let cancelled = false;
    setIsLoadingGraph(true);
    setGraphContext(null);
    invokeResolver<IssueGraphContextResult | null>('queryGraphContext', { issueKey: link.work.key })
      .then((res) => {
        if (!cancelled) setGraphContext(res || null);
      })
      .catch(() => {
        if (!cancelled) setGraphContext(null);
      })
      .finally(() => {
        if (!cancelled) setIsLoadingGraph(false);
      });

    return () => {
      cancelled = true;
    };
  }, [link?.work.key]);

  // Escape key close
  useEffect(() => {
    if (!link) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [link, onClose]);

  if (!link) return null;

  const isClassC = link.hazard.riskClass === 'CLASS_C';
  const isBroken = link.complianceState !== 'VERIFIED';
  const canSubmitSignOff = attestationConfirmed && signMeaning.trim().length >= 5 && !isMutating;

  return (
    <>
      <div className="mt-drawer-backdrop no-print" onClick={onClose} aria-hidden="true" />
      <aside
        className="mt-drawer no-print"
        role="dialog"
        aria-modal="true"
        aria-labelledby="inspection-drawer-title"
      >
        {/* Header */}
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid #ebecf0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: '#fafbfc',
          }}
        >
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#505f79', textTransform: 'uppercase' }}>
              Regulatory Trace Inspection
            </div>
            <div id="inspection-drawer-title" style={{ fontSize: 16, fontWeight: 700, color: '#172b4d' }}>
              {link.hazard.key} Lineage
            </div>
          </div>
          <button
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
                background: '#fffae6',
                border: '1.5px solid #ffe380',
                boxShadow: '0 2px 6px rgba(255, 171, 0, 0.15)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#974f0c', fontWeight: 800, fontSize: 13 }}>
                  <Zap size={16} color="#974f0c" /> Transitive Regulatory Blast Radius
                </div>
                <span
                  style={{
                    fontSize: 10,
                    fontFamily: 'monospace',
                    background: '#ffffff',
                    padding: '2px 6px',
                    borderRadius: 4,
                    border: '1px solid #ffe380',
                    color: '#42526e',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <Clock size={11} /> {blastRadius.executionTimeMs} ms
                </span>
              </div>

              <div style={{ fontSize: 11, color: '#172b4d', marginBottom: 8 }}>
                Trigger: <b>{blastRadius.triggerArtifact.title}</b> ({blastRadius.triggerArtifact.deltaReason})
              </div>

              <div style={{ background: '#ffffff', borderRadius: 6, padding: '8px 10px', border: '1px solid #f4f5f7', marginBottom: 10 }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#505f79', textTransform: 'uppercase', marginBottom: 4 }}>
                  Deterministic Graph Traversal (BFS):
                </div>
                {blastRadius.traversalPath.map((hop, idx) => (
                  <div key={idx} style={{ fontSize: 11, lineHeight: '16px', marginTop: 4, display: 'flex', gap: 6 }}>
                    <span style={{ fontWeight: 700, color: '#0052cc', minWidth: 40 }}>Hop {hop.hop}:</span>
                    <span style={{ color: '#42526e' }}>
                      <span style={{ fontWeight: 600, color: '#172b4d' }}>{hop.edge}</span> → {hop.effect}
                    </span>
                  </div>
                ))}
              </div>

              <div>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#505f79', textTransform: 'uppercase', marginBottom: 4 }}>
                  Mandatory Re-audit Actions:
                </div>
                {blastRadius.transitiveActionPlan.map((action, idx) => (
                  <div key={idx} style={{ fontSize: 11, color: '#172b4d', lineHeight: '16px', marginTop: 3 }}>
                    • {action}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Violations Alert Banner */}
          {link.violations.length > 0 && (
            <div style={{ marginBottom: 16, padding: '12px 14px', borderRadius: 6, background: '#ffebe6', border: '1px solid #ffbdad' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#bf2600', fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
                <AlertOctagon size={16} /> Regulatory Safety Gate Lockout
              </div>
              {link.violations.map((v, i) => (
                <div key={i} style={{ fontSize: 11, color: '#bf2600', lineHeight: '16px', marginTop: 4 }}>
                  • {v}
                </div>
              ))}
            </div>
          )}

          {/* Stage 1: ISO 14971 Hazard */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <ShieldAlert size={15} color={isClassC ? '#bf2600' : '#0052cc'} />
              <span>1. ISO 14971 Risk Classification</span>
            </div>
            <div style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>{link.hazard.title}</div>
            <div style={{ marginTop: 6, display: 'flex', gap: 8, fontSize: 11, flexWrap: 'wrap' }}>
              <span style={pillStyle('#ffebe6', '#bf2600')}>{link.hazard.riskClass.replace('_', ' ')}</span>
              <span style={pillStyle('#f4f5f7', '#42526e')}>Severity: {link.hazard.severity}</span>
              <span style={pillStyle('#f4f5f7', '#42526e')}>Prob: {link.hazard.probability}</span>
            </div>
          </div>

          {/* Stage 2: Confluence SRS Spec */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <FileText size={15} color="#0052cc" />
              <span>2. Confluence Safety Spec (SRS)</span>
            </div>
            <div style={{ fontWeight: 600, fontSize: 13, color: '#172b4d' }}>{link.spec.title}</div>
            <div style={{ fontSize: 11, color: '#42526e', marginTop: 4, background: '#f4f5f7', padding: '6px 8px', borderRadius: 4 }}>
              &ldquo;{link.spec.contentSnippet}&rdquo;
            </div>
            <div style={{ marginTop: 6, fontSize: 10, color: '#505f79' }}>
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
                color: link.spec.isSignatureInvalidated ? '#bf2600' : '#505f79',
                wordBreak: 'break-all',
              }}
            >
              SHA-256: {link.spec.sha256Hash}
            </div>
          </div>

          {/* Stage 3: Jira Implementation + Bind Issue Control */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <GitPullRequest size={15} color="#006644" />
              <span>3. Jira Work Item &amp; Issue Binding</span>
            </div>
            <div style={{ fontWeight: 700, fontSize: 13, color: '#0052cc' }}>
              {link.work.key || 'Unbound'}: {link.work.title}
            </div>
            <div style={{ marginTop: 6, fontSize: 11, color: '#42526e', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
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

            <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #f4f5f7' }}>
              <label htmlFor="bind-issue-input" style={labelStyle}>
                Bind Jira Issue Key to {link.hazard.key}
              </label>
              <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                <input
                  id="bind-issue-input"
                  type="text"
                  className="mt-input"
                  value={bindIssueInput}
                  onChange={(e) => setBindIssueInput(e.target.value)}
                  placeholder="e.g. MED-42"
                />
                <button
                  type="button"
                  disabled={isMutating || !bindIssueInput.trim()}
                  onClick={() => onBindIssue(link.hazard.key, bindIssueInput.trim())}
                  className="mt-btn"
                  style={{
                    whiteSpace: 'nowrap',
                    border: '1px solid #0052cc',
                    background: '#deebff',
                    color: '#0052cc',
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
              <Activity size={15} color={link.test.status === 'PASSED' ? '#006644' : '#bf2600'} />
              <span>4. IEC 62304 Verification Evidence</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 13, color: '#172b4d' }}>
                {link.test.testKey}: {link.test.title}
              </span>
              <span style={pillStyle(link.test.status === 'PASSED' ? '#e3fcef' : '#ffebe6', link.test.status === 'PASSED' ? '#006644' : '#bf2600')}>
                {link.test.status}
              </span>
            </div>
            <div style={{ fontSize: 11, color: '#505f79', marginTop: 4 }}>Type: {link.test.testType}</div>
            <div style={{ fontSize: 11, color: '#42526e', marginTop: 2 }}>
              Execution: {link.test.executionDate || 'Not yet executed'}
            </div>
            {link.test.recordedBy && (
              <div style={{ fontSize: 10, color: '#505f79', marginTop: 2 }}>Recorded by: {link.test.recordedBy}</div>
            )}
            {link.test.notes && (
              <div style={{ fontSize: 10, color: '#42526e', marginTop: 2 }}>Notes: {link.test.notes}</div>
            )}

            <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #f4f5f7', display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#172b4d', display: 'flex', alignItems: 'center', gap: 5 }}>
                <ClipboardCheck size={13} color="#0052cc" /> Record Verification Test Execution
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <select
                  aria-label="Test execution status"
                  className="mt-input"
                  style={{ width: '42%' }}
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
                  onChange={(e) => setTestEvidenceUrl(e.target.value)}
                  placeholder="Evidence URL (optional)"
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
              <button
                type="button"
                disabled={isMutating}
                onClick={() =>
                  onRecordTestResult({
                    hazardKey: link.hazard.key,
                    testKey: link.test.testKey,
                    status: testStatusInput,
                    evidenceUrl: testEvidenceUrl.trim() || undefined,
                    notes: testNotes.trim() || undefined,
                  })
                }
                className="mt-btn"
                style={{
                  border: '1px solid #00875a',
                  background: '#e3fcef',
                  color: '#006644',
                }}
              >
                <ClipboardCheck size={14} /> Record Test Result ({link.test.testKey})
              </button>
            </div>
          </div>

          {/* Stage 5: 21 CFR Part 11 Electronic Signature + Explicit Attestation Sign-Off */}
          <div style={sectionStyle}>
            <div style={sectionHeader}>
              <Lock size={15} color={link.signature.isValid ? '#006644' : '#bf2600'} />
              <span>5. FDA 21 CFR Part 11 Audit Trail &amp; Sign-Off</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 12, color: '#172b4d' }}>{link.signature.signedBy || 'Unsigned'}</span>
              <span style={pillStyle(link.signature.isValid ? '#e3fcef' : '#ffebe6', link.signature.isValid ? '#006644' : '#bf2600')}>
                {link.signature.isValid ? 'VALID SIGNATURE' : 'SIGNATURE REVOKED'}
              </span>
            </div>
            <div style={{ fontSize: 11, color: '#505f79', marginTop: 2 }}>
              Role: {link.signature.role} {link.signature.authMethod ? `• Auth: ${link.signature.authMethod}` : ''}
            </div>
            <div style={{ fontSize: 11, color: '#42526e', marginTop: 2 }}>Meaning: &ldquo;{link.signature.meaning}&rdquo;</div>
            {link.signature.invalidationReason && (
              <div style={{ fontSize: 10, color: '#bf2600', fontWeight: 600, marginTop: 4 }}>
                {link.signature.invalidationReason}
              </div>
            )}

            <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #f4f5f7', display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: '#172b4d', display: 'flex', alignItems: 'center', gap: 5 }}>
                <PenTool size={13} color="#0052cc" /> Execute 21 CFR Part 11 Sign-Off
              </div>
              <label htmlFor="signoff-meaning" style={labelStyle}>
                Signature Meaning (§11.50, min 5 chars)
              </label>
              <input
                id="signoff-meaning"
                type="text"
                className="mt-input"
                value={signMeaning}
                onChange={(e) => setSignMeaning(e.target.value)}
                placeholder="e.g. Clinical safety approval of SRS v3"
              />
              <div style={{ display: 'flex', gap: 6 }}>
                <input
                  type="text"
                  aria-label="Signer role"
                  className="mt-input"
                  value={signRole}
                  onChange={(e) => setSignRole(e.target.value)}
                  placeholder="Signer Role"
                />
                <input
                  type="text"
                  aria-label="Optional attestation phrase"
                  className="mt-input"
                  value={attestationPhrase}
                  onChange={(e) => setAttestationPhrase(e.target.value)}
                  placeholder="Attestation note (optional)"
                />
              </div>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 11, color: '#172b4d', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={attestationConfirmed}
                  onChange={(e) => setAttestationConfirmed(e.target.checked)}
                  style={{ marginTop: 2 }}
                />
                <span>
                  I attest under 21 CFR Part 11 that this electronic signature is the legally binding equivalent of my handwritten signature and certifies SHA-256 hash <code>{link.spec.sha256Hash.slice(0, 10)}...</code>.
                </span>
              </label>
              <button
                type="button"
                disabled={!canSubmitSignOff}
                onClick={() =>
                  onSignOffPart11({
                    hazardKey: link.hazard.key,
                    meaning: signMeaning.trim(),
                    role: signRole.trim() || undefined,
                    attestationConfirmed: true,
                    attestationPhrase: attestationPhrase.trim() || undefined,
                  })
                }
                className="mt-btn"
                style={{
                  border: 'none',
                  background: '#0052cc',
                  color: '#ffffff',
                }}
              >
                <PenTool size={14} /> Sign Off Spec (21 CFR Part 11)
              </button>
            </div>
          </div>

          {/* Dynamic Teamwork Graph (TWG) Lineage Metadata */}
          <div style={{ ...sectionStyle, background: '#f4f5f7', border: '1px solid #dfe1e6' }}>
            <div style={sectionHeader}>
              <Share2 size={15} color="#0052cc" />
              <span style={{ color: '#0052cc' }}>Atlassian Teamwork Graph (TWG) Node</span>
            </div>
            {link.graphMetadata ? (
              <>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontFamily: 'monospace', fontSize: 10 }}>
                  <div style={{ background: '#ffffff', padding: '5px 8px', borderRadius: 4, border: '1px solid #ebecf0', wordBreak: 'break-all' }}>
                    <span style={{ color: '#505f79' }}>Jira ARI: </span>
                    <span style={{ color: '#172b4d', fontWeight: 600 }}>{link.graphMetadata.entityAri}</span>
                  </div>
                  <div style={{ background: '#ffffff', padding: '5px 8px', borderRadius: 4, border: '1px solid #ebecf0', wordBreak: 'break-all' }}>
                    <span style={{ color: '#505f79' }}>Hazard ARI: </span>
                    <span style={{ color: '#172b4d', fontWeight: 600 }}>{link.graphMetadata.hazardAri}</span>
                  </div>
                  <div style={{ background: '#ffffff', padding: '5px 8px', borderRadius: 4, border: '1px solid #ebecf0', wordBreak: 'break-all' }}>
                    <span style={{ color: '#505f79' }}>Spec ARI: </span>
                    <span style={{ color: '#172b4d', fontWeight: 600 }}>{link.graphMetadata.linkedSpecAri}</span>
                  </div>
                </div>
                <div style={{ marginTop: 6, fontSize: 10, color: '#42526e', fontWeight: 600 }}>
                  {link.graphMetadata.aggTraversalStatus}
                </div>
              </>
            ) : (
              <div style={{ fontSize: 11, color: '#505f79', lineHeight: '16px' }}>
                No static graph ARI metadata attached to this record.
              </div>
            )}

            <div style={{ marginTop: 10, padding: '8px 10px', borderRadius: 6, background: '#deebff', border: '1px solid #b3d4ff' }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#0052cc', textTransform: 'uppercase', marginBottom: 4 }}>
                Live Teamwork Graph Context ({link.work.key || 'Unbound'})
              </div>
              {isLoadingGraph ? (
                <div style={{ fontSize: 11, color: '#42526e' }}>Querying AGG / Jira REST for {link.work.key}...</div>
              ) : graphContext ? (
                <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#172b4d', lineHeight: '15px' }}>
                  <div>
                    Source: <b>{graphContext.source}</b> | Issue: <b>{graphContext.issueKey}</b>
                    {graphContext.status?.name ? ` (${graphContext.status.name})` : ''}
                  </div>
                  {graphContext.summary && <div style={{ marginTop: 2 }}>Summary: {graphContext.summary}</div>}
                  <div style={{ marginTop: 2 }}>
                    Jira Links: {graphContext.issuelinks.length} | Confluence Links: {graphContext.confluenceLinks.length}
                  </div>
                  {graphContext.confluenceLinks.map((c, idx) => (
                    <div key={idx} style={{ marginTop: 2, color: '#0052cc' }}>
                      • {c.title} {c.pageId ? `(pageId=${c.pageId})` : ''}
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: 10, color: '#42526e' }}>
                  No live AGG/REST issue context returned for {link.work.key || 'this item'} (expected in offline/unlinked demo fixtures).
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer / Status or Explicit Demo Simulation */}
        <div style={{ padding: '14px 20px', borderTop: '1px solid #ebecf0', background: '#fafbfc' }}>
          {!isBroken ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, color: '#006644', fontWeight: 700, fontSize: 13 }}>
              <CheckCircle2 size={16} /> Unbroken IEC 62304 Regulatory Compliance
            </div>
          ) : datasetMode === 'DEMO' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ fontSize: 10, fontWeight: 800, color: '#974f0c', textTransform: 'uppercase' }}>
                DEMO MODE ONLY — Simulated Quick-Remediation
              </div>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: 6, fontSize: 11, color: '#42526e', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={demoSimConfirmed}
                  onChange={(e) => setDemoSimConfirmed(e.target.checked)}
                  style={{ marginTop: 2 }}
                />
                <span>
                  Confirm simulated demo remediation (logs <code>DEMO_SIMULATION</code> to the immutable audit chain; disabled in LIVE mode).
                </span>
              </label>
              <button
                type="button"
                onClick={() => onRemediateDemo(link.hazard.key, signMeaning.trim())}
                disabled={isMutating || !demoSimConfirmed}
                className="mt-btn"
                style={{
                  width: '100%',
                  padding: '9px 14px',
                  border: '1.5px solid #ff991f',
                  background: '#fff0b3',
                  color: '#974f0c',
                }}
              >
                <Zap size={15} />
                {isMutating ? 'Recording Simulated Demo Remediation...' : `Run Simulated Demo Remediation (${link.hazard.key})`}
              </button>
            </div>
          ) : (
            <div style={{ fontSize: 11, color: '#42526e', textAlign: 'center', fontWeight: 600 }}>
              LIVE mode active: record real test evidence and execute 21 CFR Part 11 sign-off above to clear this gate.
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
  border: '1px solid #ebecf0',
  background: '#ffffff',
};

const sectionHeader: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 6,
  fontSize: 11,
  fontWeight: 700,
  color: '#42526e',
  textTransform: 'uppercase',
  marginBottom: 6,
};

const labelStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 600,
  color: '#42526e',
};

const pillStyle = (bg: string, color: string): React.CSSProperties => ({
  fontSize: 10,
  fontWeight: 700,
  padding: '2px 6px',
  borderRadius: 4,
  background: bg,
  color,
});
