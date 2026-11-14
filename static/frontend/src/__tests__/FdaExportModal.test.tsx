import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { FdaExportModal, escapeCsvCell } from '../components/FdaExportModal';
import * as bridgeModule from '../bridge';
import { AuditChainVerification, AuditLogEntry, ComplianceSummary, TraceLink } from '../types';

vi.mock('../bridge', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../bridge')>();
  return {
    ...actual,
    invokeResolver: vi.fn(),
  };
});

function makeLink(id: string, sigId: string, overrides?: Partial<TraceLink>): TraceLink {
  return {
    id,
    hazard: {
      id: `haz-${id}`,
      key: `HAZ-${id}`,
      title: `Hazard ${id}`,
      riskClass: 'CLASS_C',
      severity: 'CATASTROPHIC',
      probability: 'REMOTE',
      mitigationRequirementId: 'SRS-104',
      status: 'ACTION_REQUIRED',
    },
    spec: {
      id: `spec-${id}`,
      pageId: `page-${id}`,
      title: 'SRS-104: Pump Occlusion Alarm Limits',
      version: 2,
      sha256Hash: 'abc123def456',
      lastSignedHash: 'abc123def456',
      isSignatureInvalidated: false,
      contentSnippet: 'Alarm within 500ms.',
      lastUpdated: '2026-01-01T00:00:00.000Z',
    },
    work: {
      id: `work-${id}`,
      key: 'MED-42',
      title: 'Implement alarm driver',
      status: 'Done',
      assignee: 'Alice Engineer',
      commitSha: 'deadbeef1234',
    },
    test: {
      id: `test-${id}`,
      testKey: 'TEST-88',
      title: 'Occlusion HIL test',
      testType: 'Automated HIL (Hardware-in-Loop)',
      status: 'PASSED',
      evidenceUrl: 'https://ci.example.com/builds/88',
    },
    signature: {
      id: sigId,
      signedBy: 'Alice QA',
      signedAt: '2026-01-02T00:00:00.000Z',
      role: 'QA Lead',
      meaning: 'Approved for clinical trial',
      artifactSha256: 'abc123def456',
      isValid: true,
    },
    complianceState: 'VERIFIED',
    violations: [],
    ...overrides,
  };
}

function makeSummary(overrides?: Partial<ComplianceSummary>): ComplianceSummary {
  return {
    projectName: 'InfusionPump X1',
    datasetMode: 'DEMO',
    initialized: true,
    standards: ['IEC 62304:2006+A1:2015', 'ISO 14971:2019', 'FDA 21 CFR Part 11'],
    totalHazards: 2,
    classCCount: 2,
    classBCount: 0,
    classACount: 0,
    verifiedPercentage: 50,
    releaseBlocked: true,
    blockingReasons: ['HAZ-2 lacks passing verification evidence'],
    signatureDriftCount: 0,
    traceLinks: [
      makeLink('1', 'sig-shared'),
      makeLink('2', 'sig-shared', {
        hazard: {
          id: 'haz-2',
          key: 'HAZ-2',
          title: '=SUM(A1:A2) Hazard',
          riskClass: 'CLASS_C',
          severity: 'CRITICAL',
          probability: 'OCCASIONAL',
          mitigationRequirementId: 'SRS-105',
          status: 'ACTION_REQUIRED',
        },
        test: {
          id: 'test-2',
          testKey: 'TEST-89',
          title: 'Untested',
          testType: 'Unit Test',
          status: 'UNTESTED',
          evidenceUrl: 'javascript:alert(1)',
        },
        complianceState: 'INCOMPLETE',
        violations: ['Test is UNTESTED'],
      }),
    ],
    lastAuditTimestamp: '2026-01-03T12:00:00.000Z',
    auditEntryCount: 2,
    auditHeadHash: 'headhash9999999999',
    ...overrides,
  };
}

describe('FE-06: FdaExportModal CSV injection neutralization, audit evidence, and watermarks', () => {
  const mockedInvokeResolver = vi.mocked(bridgeModule.invokeResolver);

  beforeEach(() => {
    vi.clearAllMocks();
    const verification: AuditChainVerification = {
      valid: true,
      totalEntries: 2,
      headHash: 'headhash9999999999aabbcc',
    };
    const entries: AuditLogEntry[] = [
      {
        seq: 1,
        timestamp: '2026-01-01T00:00:00.000Z',
        actorAccountId: 'acc-1',
        action: 'SEED_DEMO',
        targetKey: 'SUITE',
        details: {},
        prevHash: 'GENESIS',
        entryHash: 'hash111111111111',
        authMethod: 'FORGE_USER_SESSION',
      },
      {
        seq: 2,
        timestamp: '2026-01-02T00:00:00.000Z',
        actorAccountId: 'acc-2',
        action: 'PART11_SIGNOFF',
        targetKey: 'HAZ-1',
        details: { specId: 'spec-1' },
        prevHash: 'hash111111111111',
        entryHash: 'headhash9999999999aabbcc',
        authMethod: 'PART11_ATTESTATION',
      },
    ];
    mockedInvokeResolver.mockImplementation(async (key) => {
      if (key === 'verifyAuditChain') return verification;
      if (key === 'getAuditLog') return entries;
      throw new Error(`Unexpected resolver ${key}`);
    });
  });

  it('neutralizes CWE-1236 formula triggers while applying RFC 4180 quoting', () => {
    expect(escapeCsvCell('=SUM(A1:A2)')).toBe("'=SUM(A1:A2)");
    expect(escapeCsvCell('+1+1')).toBe("'+1+1");
    expect(escapeCsvCell('-2-2')).toBe("'-2-2");
    expect(escapeCsvCell('@A')).toBe("'@A");
    expect(escapeCsvCell('@SUM(1,1)')).toBe('"\'@SUM(1,1)"');
    expect(escapeCsvCell('\t=1')).toBe("'\t=1");
    expect(escapeCsvCell('\r=1')).toBe(`"'\r=1"`);
    expect(escapeCsvCell(' =1')).toBe("' =1");
    expect(escapeCsvCell('  @cmd')).toBe("'  @cmd");
    expect(escapeCsvCell('hello, "world"')).toBe('"hello, ""world"""');
    expect(escapeCsvCell('line1\nline2')).toBe('"line1\nline2"');
    expect(escapeCsvCell('plain')).toBe('plain');
    expect(escapeCsvCell(undefined)).toBe('');
    expect(escapeCsvCell(null)).toBe('');
    expect(escapeCsvCell(42)).toBe('42');
    expect(escapeCsvCell(true)).toBe('true');
  });

  it('renders DEMO watermark, RELEASE BLOCKED alert, full spec title, safe evidence links, and zero duplicate key warnings', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const summary = makeSummary();

    try {
      render(<FdaExportModal summary={summary} onClose={() => {}} />);

      expect(
        screen.getByText('DEMO DATASET — NON-CLINICAL / NOT FOR REGULATORY SUBMISSION')
      ).toBeInTheDocument();

      const blockedAlert = screen.getByRole('alert');
      expect(blockedAlert).toHaveTextContent(/RELEASE BLOCKED/i);
      expect(blockedAlert).toHaveTextContent('HAZ-2 lacks passing verification evidence');

      // Full spec title containing colon is NOT truncated
      expect(
        screen.getAllByText('SRS-104: Pump Occlusion Alarm Limits (v2)').length
      ).toBeGreaterThanOrEqual(2);

      // Safe HTTPS URL renders as <a>, non-HTTPS javascript: URL is plain text
      const safeLink = screen.getByRole('link', { name: 'https://ci.example.com/builds/88' });
      expect(safeLink).toHaveAttribute('rel', 'noopener noreferrer');
      expect(screen.queryByRole('link', { name: /javascript:/i })).not.toBeInTheDocument();
      expect(screen.getByText(/javascript:alert\(1\) \(non-HTTPS link disabled\)/i)).toBeInTheDocument();

      await waitFor(() => {
        expect(mockedInvokeResolver).toHaveBeenCalledWith('verifyAuditChain');
        expect(mockedInvokeResolver).toHaveBeenCalledWith('getAuditLog', { limit: 200 });
        expect(screen.getByText(/HASH CHAIN VERIFIED \(2 entries\)/i)).toBeInTheDocument();
      });

      const keyErrors = consoleErrorSpy.mock.calls.filter((call) =>
        call.some((arg) => typeof arg === 'string' && arg.includes('same key'))
      );
      expect(keyErrors).toHaveLength(0);
    } finally {
      consoleErrorSpy.mockRestore();
    }
  });

  it('exports JSON and CSV packages with datasetMode prefix, audit verification, entries, commitSha, evidenceUrl, and neutralized formulas', async () => {
    const downloadedFiles: Array<{ filename: string; content: string }> = [];
    const OriginalBlob = globalThis.Blob;

    class CapturingBlob extends OriginalBlob {
      public readonly capturedText: string;
      constructor(parts?: BlobPart[], options?: BlobPropertyBag) {
        super(parts, options);
        this.capturedText = (parts || []).map((p) => String(p)).join('');
      }
    }

    const blobMap = new Map<string, CapturingBlob>();
    const createUrlSpy = vi
      .spyOn(URL, 'createObjectURL')
      .mockImplementation((blob: Blob | MediaSource) => {
        const fakeUrl = `blob:test-${blobMap.size + 1}`;
        blobMap.set(fakeUrl, blob as CapturingBlob);
        return fakeUrl;
      });
    const revokeUrlSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    const anchorClickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(function (this: HTMLAnchorElement) {
        const blob = blobMap.get(this.href);
        downloadedFiles.push({
          filename: this.download,
          content: blob ? blob.capturedText : '',
        });
      });

    vi.stubGlobal('Blob', CapturingBlob);

    try {
      const summary = makeSummary({ datasetMode: 'DEMO' });
      render(<FdaExportModal summary={summary} onClose={() => {}} />);

      await waitFor(() => {
        expect(screen.getByText(/HASH CHAIN VERIFIED/i)).toBeInTheDocument();
      });

      const user = userEvent.setup();
      await user.click(screen.getByRole('button', { name: /Download JSON/i }));
      await user.click(screen.getByRole('button', { name: /Download CSV/i }));

      expect(downloadedFiles).toHaveLength(2);
      const [jsonFile, csvFile] = downloadedFiles;

      expect(jsonFile.filename).toMatch(/^demo-medtrace-fda-dossier-.*\.json$/);
      const parsedJson = JSON.parse(jsonFile.content) as {
        exportMetadata: { datasetMode: string; releaseBlocked: boolean; blockingReasons: string[] };
        verifyAuditChain: AuditChainVerification;
        auditLogEntries: AuditLogEntry[];
      };
      expect(parsedJson.exportMetadata.datasetMode).toBe('DEMO');
      expect(parsedJson.exportMetadata.releaseBlocked).toBe(true);
      expect(parsedJson.exportMetadata.blockingReasons).toContain(
        'HAZ-2 lacks passing verification evidence'
      );
      expect(parsedJson.verifyAuditChain.valid).toBe(true);
      expect(parsedJson.auditLogEntries).toHaveLength(2);

      expect(csvFile.filename).toMatch(/^demo-medtrace-trace-matrix-.*\.csv$/);
      expect(csvFile.content).toContain('SRS-104: Pump Occlusion Alarm Limits');
      expect(csvFile.content).toContain('deadbeef1234');
      expect(csvFile.content).toContain('https://ci.example.com/builds/88');
      expect(csvFile.content).toContain('headhash9999999999aabbcc');
      expect(csvFile.content).toContain("'=SUM(A1:A2) Hazard");
    } finally {
      vi.unstubAllGlobals();
      createUrlSpy.mockRestore();
      revokeUrlSpy.mockRestore();
      anchorClickSpy.mockRestore();
    }
  });
});
