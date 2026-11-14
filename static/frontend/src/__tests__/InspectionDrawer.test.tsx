import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { InspectionDrawer } from '../components/InspectionDrawer';
import * as bridgeModule from '../bridge';
import {
  ForgePanelContext,
  PART11_ATTESTATION_PHRASE,
  TraceLink,
} from '../types';

vi.mock('../bridge', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../bridge')>();
  return {
    ...actual,
    invokeResolver: vi.fn(),
  };
});

function makeLink(overrides?: Partial<TraceLink>): TraceLink {
  return {
    id: 'link-1',
    hazard: {
      id: 'haz-1',
      key: 'HAZ-201',
      title: 'Over-infusion protection',
      riskClass: 'CLASS_C',
      severity: 'CATASTROPHIC',
      probability: 'REMOTE',
      mitigationRequirementId: 'SRS-201',
      status: 'ACTION_REQUIRED',
    },
    spec: {
      id: 'spec-201',
      pageId: '5511',
      title: 'SRS-201: Basal Flow Limiter',
      version: 4,
      sha256Hash: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      lastSignedHash: '',
      isSignatureInvalidated: true,
      contentSnippet: 'Max infusion rate shall not exceed 10 mL/h.',
      lastUpdated: '2026-01-05T00:00:00.000Z',
    },
    work: {
      id: 'work-1',
      key: 'PUMP-19',
      title: 'Implement basal rate cap',
      status: 'Done',
      assignee: 'Jane Doe',
    },
    test: {
      id: 'test-1',
      testKey: 'TEST-201',
      title: 'Basal cap HIL suite',
      testType: 'Automated HIL (Hardware-in-Loop)',
      status: 'FAILED',
      evidenceUrl: 'https://ci.example.com/run/99',
      notes: 'Previous failing run',
    },
    signature: {
      id: 'sig-1',
      signedBy: '',
      signedAt: '',
      role: 'QA Engineer',
      meaning: '',
      artifactSha256: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      isValid: false,
      invalidationReason: 'Spec version v4 changed after v3 sign-off',
    },
    complianceState: 'SIGNATURE_DRIFT',
    violations: ['Part 11 signature invalidated'],
    graphMetadata: {
      entityAri: 'ari:cloud:jira:c1:issue/19',
      hazardAri: 'ari:cloud:jira:c1:issue/1',
      linkedSpecAri: 'ari:cloud:confluence:c1:page/5511',
      edgeType: 'REST:jira-remotelink',
      aggTraversalStatus: 'Verified via REST',
    },
    ...overrides,
  };
}

const LIVE_PANEL_CONTEXT: ForgePanelContext = {
  extensionType: 'jira:projectPage',
  isCompactPanel: false,
  isConfluence: false,
  projectKey: 'PUMP',
};

describe('FE-05: InspectionDrawer form persistence, error surfacing, and §11.200 enforcement', () => {
  const mockedInvokeResolver = vi.mocked(bridgeModule.invokeResolver);

  beforeEach(() => {
    vi.clearAllMocks();
    mockedInvokeResolver.mockResolvedValue(null);
  });

  it('preserves uncommitted form edits across poll re-renders for same link.id and resets when switching link.id', async () => {
    const link1 = makeLink({ id: 'link-1' });
    const link2 = makeLink({
      id: 'link-2',
      hazard: { ...link1.hazard, key: 'HAZ-202', title: 'Second hazard' },
      test: { ...link1.test, testKey: 'TEST-202', evidenceUrl: '', notes: '' },
      work: { ...link1.work, key: 'PUMP-20' },
    });

    const noopAsync = async () => true;
    const { rerender } = render(
      <InspectionDrawer
        link={link1}
        datasetMode="DEMO"
        panelContext={LIVE_PANEL_CONTEXT}
        blastRadius={null}
        onClose={() => {}}
        onBindIssue={noopAsync}
        onRecordTestResult={noopAsync}
        onSignOffPart11={noopAsync}
        onRemediateDemo={noopAsync}
        isMutating={false}
      />
    );

    await waitFor(() => {
      expect(
        screen.getByText(/No live AGG\/REST issue context returned for PUMP-19/i)
      ).toBeInTheDocument();
    });

    const user = userEvent.setup();
    const bindInput = screen.getByLabelText(/Bind Jira Issue Key/i);
    const evidenceInput = screen.getByLabelText('Evidence URL');
    const notesInput = screen.getByLabelText('Test execution notes');
    const meaningInput = screen.getByLabelText(/Signature Meaning/i);
    const phraseInput = screen.getByLabelText(/Required Attestation Phrase/i);
    const demoMeaningInput = screen.getByLabelText('Demo simulation meaning');

    await user.clear(bindInput);
    await user.type(bindInput, 'PUMP-77');
    await user.clear(evidenceInput);
    await user.type(evidenceInput, 'https://ci.example.com/run/100');
    await user.clear(notesInput);
    await user.type(notesInput, 'Draft uncommitted note');
    await user.clear(meaningInput);
    await user.type(meaningInput, 'Draft meaning text');
    await user.type(phraseInput, PART11_ATTESTATION_PHRASE);
    await user.type(demoMeaningInput, 'Draft demo note');

    // Simulate 8s poll creating a brand new TraceLink object ref with the SAME link.id
    const clonedLink1: TraceLink = {
      ...link1,
      hazard: { ...link1.hazard },
      spec: { ...link1.spec },
      work: { ...link1.work },
      test: { ...link1.test, notes: 'Polled server note' },
      signature: { ...link1.signature },
    };

    rerender(
      <InspectionDrawer
        link={clonedLink1}
        datasetMode="DEMO"
        panelContext={LIVE_PANEL_CONTEXT}
        blastRadius={null}
        onClose={() => {}}
        onBindIssue={noopAsync}
        onRecordTestResult={noopAsync}
        onSignOffPart11={noopAsync}
        onRemediateDemo={noopAsync}
        isMutating={false}
      />
    );

    expect(screen.getByLabelText(/Bind Jira Issue Key/i)).toHaveValue('PUMP-77');
    expect(screen.getByLabelText('Evidence URL')).toHaveValue('https://ci.example.com/run/100');
    expect(screen.getByLabelText('Test execution notes')).toHaveValue('Draft uncommitted note');
    expect(screen.getByLabelText(/Signature Meaning/i)).toHaveValue('Draft meaning text');
    expect(screen.getByLabelText(/Required Attestation Phrase/i)).toHaveValue(
      PART11_ATTESTATION_PHRASE
    );
    expect(screen.getByLabelText('Demo simulation meaning')).toHaveValue('Draft demo note');

    // Switch to a different link.id -> must reset form fields
    rerender(
      <InspectionDrawer
        link={link2}
        datasetMode="DEMO"
        panelContext={LIVE_PANEL_CONTEXT}
        blastRadius={null}
        onClose={() => {}}
        onBindIssue={noopAsync}
        onRecordTestResult={noopAsync}
        onSignOffPart11={noopAsync}
        onRemediateDemo={noopAsync}
        isMutating={false}
      />
    );

    expect(screen.getByLabelText(/Bind Jira Issue Key/i)).toHaveValue('PUMP-20');
    expect(screen.getByLabelText('Evidence URL')).toHaveValue('');
    expect(screen.getByLabelText('Test execution notes')).toHaveValue('');
    expect(screen.getByLabelText(/Required Attestation Phrase/i)).toHaveValue('');
    expect(screen.getByLabelText('Demo simulation meaning')).toHaveValue('');

    await waitFor(() => {
      expect(
        screen.getByText(/No live AGG\/REST issue context returned for PUMP-20/i)
      ).toBeInTheDocument();
    });
  });

  it('surfaces queryGraphContext rejections as role="alert" and renders edgeType metadata', async () => {
    mockedInvokeResolver.mockRejectedValueOnce(new Error('AGG network timeout'));
    const link = makeLink();

    render(
      <InspectionDrawer
        link={link}
        datasetMode="LIVE"
        panelContext={LIVE_PANEL_CONTEXT}
        blastRadius={null}
        onClose={() => {}}
        onBindIssue={async () => true}
        onRecordTestResult={async () => true}
        onSignOffPart11={async () => true}
        onRemediateDemo={async () => true}
        isMutating={false}
      />
    );

    expect(screen.getByText('REST:jira-remotelink')).toBeInTheDocument();
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Live Jira/AGG context query failed: AGG network timeout');
    expect(screen.queryByText(/offline\/unlinked demo fixtures/i)).not.toBeInTheDocument();
  });

  it('validates https:// evidenceUrl and sends explicit empty strings when clearing evidenceUrl and notes', async () => {
    const link = makeLink();
    const onRecordTestResult = vi.fn().mockResolvedValue(true);

    render(
      <InspectionDrawer
        link={link}
        datasetMode="LIVE"
        panelContext={LIVE_PANEL_CONTEXT}
        blastRadius={null}
        onClose={() => {}}
        onBindIssue={async () => true}
        onRecordTestResult={onRecordTestResult}
        onSignOffPart11={async () => true}
        onRemediateDemo={async () => true}
        isMutating={false}
      />
    );

    const user = userEvent.setup();
    const evidenceInput = screen.getByLabelText('Evidence URL');
    const notesInput = screen.getByLabelText('Test execution notes');
    const recordBtn = screen.getByRole('button', { name: /Record Test Result/i });

    await user.clear(evidenceInput);
    await user.type(evidenceInput, 'http://insecure.example.com/report');
    await user.click(recordBtn);

    const urlAlert = screen.getByRole('alert');
    expect(urlAlert).toHaveTextContent(/Evidence URL must start with https:\/\//i);
    expect(onRecordTestResult).not.toHaveBeenCalled();

    await user.clear(evidenceInput);
    await user.clear(notesInput);
    await user.click(recordBtn);

    await waitFor(() => {
      expect(onRecordTestResult).toHaveBeenCalledWith({
        hazardKey: 'HAZ-201',
        linkId: 'link-1',
        testKey: 'TEST-201',
        status: 'FAILED',
        evidenceUrl: '',
        notes: '',
      });
    });
  });

  it('enforces Part 11 §11.200 attestation fields, clears only on true, retains on false, and omits signedBy/role', async () => {
    const link = makeLink();
    const onSignOffPart11 = vi
      .fn()
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true);

    render(
      <InspectionDrawer
        link={link}
        datasetMode="LIVE"
        panelContext={LIVE_PANEL_CONTEXT}
        blastRadius={null}
        onClose={() => {}}
        onBindIssue={async () => true}
        onRecordTestResult={async () => true}
        onSignOffPart11={onSignOffPart11}
        onRemediateDemo={async () => true}
        isMutating={false}
      />
    );

    expect(
      screen.getByText(/Signer identity and role are derived server-side/i)
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/signedBy/i)).not.toBeInTheDocument();

    const user = userEvent.setup();
    const signBtn = screen.getByRole('button', { name: /Sign Off Spec/i });
    const meaningInput = screen.getByLabelText(/Signature Meaning/i);
    const phraseInput = screen.getByLabelText(/Required Attestation Phrase/i);
    const pwdBox = screen.getByLabelText(/I confirm my active Atlassian user session re-attestation/i);
    const attBox = screen.getByLabelText(/I attest under 21 CFR Part 11/i);

    expect(signBtn).toBeDisabled();

    await user.type(phraseInput, 'WRONG PHRASE');
    expect(screen.getByText(new RegExp(`Must exactly match: ${PART11_ATTESTATION_PHRASE}`))).toBeInTheDocument();
    await user.click(pwdBox);
    await user.click(attBox);
    expect(signBtn).toBeDisabled();

    await user.clear(phraseInput);
    await user.type(phraseInput, PART11_ATTESTATION_PHRASE);
    await user.clear(meaningInput);
    await user.type(meaningInput, 'abc');
    expect(signBtn).toBeDisabled();

    await user.clear(meaningInput);
    await user.type(meaningInput, 'Clinical safety approval v4');
    expect(signBtn).toBeEnabled();

    // First attempt returns false -> MUST retain attestation inputs
    await user.click(signBtn);
    await waitFor(() => expect(onSignOffPart11).toHaveBeenCalledTimes(1));
    expect(phraseInput).toHaveValue(PART11_ATTESTATION_PHRASE);
    expect(pwdBox).toBeChecked();
    expect(attBox).toBeChecked();

    const submittedPayload = onSignOffPart11.mock.calls[0][0];
    expect(submittedPayload).toEqual({
      hazardKey: 'HAZ-201',
      linkId: 'link-1',
      specId: 'spec-201',
      meaning: 'Clinical safety approval v4',
      attestationConfirmed: true,
      passwordConfirmed: true,
      attestationPhrase: PART11_ATTESTATION_PHRASE,
    });
    expect('signedBy' in submittedPayload).toBe(false);
    expect('role' in submittedPayload).toBe(false);

    // Second attempt returns true -> clears attestation phrase & checkboxes
    await user.click(signBtn);
    await waitFor(() => {
      expect(phraseInput).toHaveValue('');
      expect(pwdBox).not.toBeChecked();
      expect(attBox).not.toBeChecked();
    });
  });

  it('hides Demo Simulation & MED-42 copy in LIVE mode and decouples demoSimMeaning in DEMO mode', async () => {
    const link = makeLink();
    const onRemediateDemo = vi.fn().mockResolvedValue(true);

    const { rerender } = render(
      <InspectionDrawer
        link={link}
        datasetMode="LIVE"
        panelContext={LIVE_PANEL_CONTEXT}
        blastRadius={null}
        onClose={() => {}}
        onBindIssue={async () => true}
        onRecordTestResult={async () => true}
        onSignOffPart11={async () => true}
        onRemediateDemo={onRemediateDemo}
        isMutating={false}
      />
    );

    expect(screen.getByLabelText(/Bind Jira Issue Key/i)).toHaveAttribute(
      'placeholder',
      'e.g. PUMP-123'
    );
    expect(screen.queryByPlaceholderText('e.g. MED-42')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Run Simulated Demo Remediation/i })).not.toBeInTheDocument();

    await waitFor(() => {
      expect(
        screen.getByText(/No linked Jira\/Confluence remote context returned for PUMP-19\./i)
      ).toBeInTheDocument();
    });

    rerender(
      <InspectionDrawer
        link={link}
        datasetMode="DEMO"
        panelContext={LIVE_PANEL_CONTEXT}
        blastRadius={null}
        onClose={() => {}}
        onBindIssue={async () => true}
        onRecordTestResult={async () => true}
        onSignOffPart11={async () => true}
        onRemediateDemo={onRemediateDemo}
        isMutating={false}
      />
    );

    const user = userEvent.setup();
    const signMeaning = screen.getByLabelText(/Signature Meaning/i);
    await user.clear(signMeaning);
    await user.type(signMeaning, 'Official Part 11 Meaning');

    const demoMeaning = screen.getByLabelText('Demo simulation meaning');
    await user.type(demoMeaning, 'Demo dry run note');
    await user.click(screen.getByLabelText(/Confirm simulated demo remediation/i));
    await user.click(screen.getByRole('button', { name: /Run Simulated Demo Remediation/i }));

    await waitFor(() => {
      expect(onRemediateDemo).toHaveBeenCalledWith('HAZ-201', 'Demo dry run note');
      expect(demoMeaning).toHaveValue('');
      expect(signMeaning).toHaveValue('Official Part 11 Meaning');
    });
  });
});
