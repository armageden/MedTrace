import { invokeResolver } from './bridge';
import type { AuditChainVerification } from './types';

const AUDIT_VERIFY_PAGE_SIZE = 200;
const MAX_AUDIT_VERIFY_PAGES = 50;

/**
 * Verifies the tamper-evident audit hash chain across bounded backend windows.
 * Starts with an unparameterized `verifyAuditChain` call (preserving backward compatibility)
 * and continues stepping sequentially through `nextFromSeq` + `expectedPrevHash` anchors
 * whenever the backend returns `truncated: true`.
 */
export async function verifyAuditChainBounded(
  shouldCancel?: () => boolean
): Promise<AuditChainVerification | null> {
  const first = await invokeResolver('verifyAuditChain');
  if (!first || shouldCancel?.()) {
    return first ?? null;
  }

  let current: AuditChainVerification = { ...first };
  const initialFromSeq = first.verifiedFromSeq ?? 1;
  let totalWindowCount =
    first.windowEntryCount ?? (first.verifiedToSeq ? first.verifiedToSeq - initialFromSeq + 1 : 0);
  let pages = 1;

  while (
    current.valid &&
    current.truncated === true &&
    typeof current.nextFromSeq === 'number' &&
    pages < MAX_AUDIT_VERIFY_PAGES
  ) {
    if (shouldCancel?.()) {
      return current;
    }

    const expectedNextSeq = current.nextFromSeq;
    const next = await invokeResolver('verifyAuditChain', {
      fromSeq: expectedNextSeq,
      maxEntries: AUDIT_VERIFY_PAGE_SIZE,
      expectedPrevHash: current.headHash,
    });

    if (!next) {
      break;
    }

    pages += 1;
    const nextCount =
      next.windowEntryCount ??
      (next.verifiedToSeq && next.verifiedToSeq >= expectedNextSeq
        ? next.verifiedToSeq - expectedNextSeq + 1
        : 0);
    totalWindowCount += Math.max(0, nextCount);

    current = {
      ...next,
      verifiedFromSeq: initialFromSeq,
      windowEntryCount: totalWindowCount,
    };

    if (!next.valid || !next.truncated) {
      break;
    }
    if (typeof next.nextFromSeq === 'number' && next.nextFromSeq <= expectedNextSeq) {
      // Defensive termination if a server or mock fails to advance the cursor.
      break;
    }
  }

  return current;
}
