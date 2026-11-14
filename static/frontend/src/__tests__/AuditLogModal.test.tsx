import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AuditLogModal } from '../components/AuditLogModal';
import * as bridgeModule from '../bridge';
import { AuditLogEntry } from '../types';

vi.mock('../bridge', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../bridge')>();
  return {
    ...actual,
    invokeResolver: vi.fn(),
  };
});

function makeAuditEntries(startSeq: number, endSeq: number): AuditLogEntry[] {
  const list: AuditLogEntry[] = [];
  for (let seq = startSeq; seq <= endSeq; seq++) {
    list.push({
      seq,
      timestamp: `2026-01-01T00:00:${String(seq).padStart(2, '0')}Z`,
      actorAccountId: `acc-${seq}`,
      action: 'RECORD_TEST_RESULT',
      targetKey: `HAZ-${seq}`,
      details: {},
      prevHash: `prev-${seq - 1}`,
      entryHash: `hash-${seq}-abcdef123456`,
      authMethod: 'FORGE_USER_SESSION',
    });
  }
  return list;
}

describe('FE-07: AuditLogModal truncation notice, beforeSeq pagination, and failure alerts', () => {
  const mockedInvokeResolver = vi.mocked(bridgeModule.invokeResolver);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('displays truncation warning, paginates older entries via beforeSeq, and deduplicates overlapping seqs', async () => {
    const page1Asc = makeAuditEntries(51, 150);
    // Include overlap seq 51 intentionally to verify deduplication
    const page2Asc = makeAuditEntries(1, 51);

    mockedInvokeResolver.mockImplementation(async (key, payload) => {
      if (key === 'verifyAuditChain') {
        return {
          valid: true,
          totalEntries: 150,
          headHash: 'hash-150-abcdef123456',
        };
      }
      if (key === 'getAuditLog') {
        const p = payload as { limit?: number; beforeSeq?: number } | undefined;
        if (p?.beforeSeq === 51) {
          return page2Asc;
        }
        return page1Asc;
      }
      throw new Error(`Unexpected resolver ${key}`);
    });

    render(<AuditLogModal isOpen={true} onClose={() => {}} />);

    expect(
      screen.getByText('SHA-256 Hash-Chained Audit Ledger (Forge KVS)')
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(
        screen.getByText(
          'Showing 100 of 150 audit entries. Hash-chain verification above covers all 150 entries.'
        )
      ).toBeInTheDocument();
    });

    expect(screen.getByText('#150')).toBeInTheDocument();
    expect(screen.getByText('#51')).toBeInTheDocument();
    expect(screen.queryByText('#50')).not.toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Load Older Entries' }));

    await waitFor(() => {
      expect(mockedInvokeResolver).toHaveBeenCalledWith('getAuditLog', {
        limit: 100,
        beforeSeq: 51,
      });
      expect(screen.getByText('#50')).toBeInTheDocument();
      expect(screen.getByText('#1')).toBeInTheDocument();
    });

    // Overlap seq #51 must only appear once
    expect(screen.getAllByText('#51')).toHaveLength(1);
    expect(screen.queryByRole('button', { name: 'Load Older Entries' })).not.toBeInTheDocument();
  });

  it('displays broken chain seq and role="alert" on resolver failure', async () => {
    mockedInvokeResolver
      .mockResolvedValueOnce(makeAuditEntries(1, 3))
      .mockResolvedValueOnce({
        valid: false,
        totalEntries: 3,
        headHash: 'badhead',
        brokenAtSeq: 2,
        reason: 'Entry hash mismatch at seq #2',
      });

    const { rerender } = render(<AuditLogModal isOpen={true} onClose={() => {}} />);

    await waitFor(() => {
      expect(screen.getByText('CHAIN INTEGRITY FAILURE AT SEQ #2')).toBeInTheDocument();
      expect(screen.getByText('Entry hash mismatch at seq #2')).toBeInTheDocument();
    });

    mockedInvokeResolver.mockRejectedValueOnce(new Error('KVS timeout'));
    rerender(<AuditLogModal isOpen={false} onClose={() => {}} />);
    rerender(<AuditLogModal isOpen={true} onClose={() => {}} />);

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('KVS timeout');
  });

  it('continues paginated verifyAuditChain across truncated windows until completion', async () => {
    mockedInvokeResolver.mockImplementation(async (fnKey, payload) => {
      if (fnKey === 'getAuditLog') {
        return makeAuditEntries(201, 250);
      }
      if (fnKey === 'verifyAuditChain') {
        const fromSeq = (payload as { fromSeq?: number } | undefined)?.fromSeq ?? 1;
        if (fromSeq === 1) {
          return {
            valid: true,
            totalEntries: 250,
            headHash: 'head-seq-200-abc123',
            verifiedFromSeq: 1,
            verifiedToSeq: 200,
            windowEntryCount: 200,
            truncated: true,
            nextFromSeq: 201,
          };
        }
        return {
          valid: true,
          totalEntries: 250,
          headHash: 'head-seq-250-final999',
          verifiedFromSeq: 201,
          verifiedToSeq: 250,
          windowEntryCount: 50,
          truncated: false,
        };
      }
      return null;
    });

    render(<AuditLogModal isOpen={true} onClose={() => {}} />);

    await waitFor(() => {
      expect(
        screen.getByText('HASH CHAIN VERIFIED (250 tamper-evident entries)')
      ).toBeInTheDocument();
      expect(screen.getByText(/Head: head-seq-250-final9/)).toBeInTheDocument();
    });

    expect(mockedInvokeResolver).toHaveBeenCalledWith('verifyAuditChain');
    expect(mockedInvokeResolver).toHaveBeenCalledWith('verifyAuditChain', {
      fromSeq: 201,
      maxEntries: 200,
      expectedPrevHash: 'head-seq-200-abc123',
    });
  });
});
