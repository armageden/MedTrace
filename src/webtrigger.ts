import crypto from 'crypto';
import { ComplianceEngine } from './compliance-engine';
import { SeederService } from './seeder';
import { LiveIngestionService } from './ingestion';
import { McpToolService } from './mcp-server';
import { isMatchedInSuite, probeUnsyncedSafetyIssue, workflowValidatorHandler } from './workflow-validator';
import { isForgeRuntime } from './runtime';
import {
  MAX_TIMESTAMP_AGE_MS,
  MAX_FUTURE_SKEW_MS,
  NONCE_TTL_MS,
  NonceStore,
  getNonceStore,
  setNonceStore,
  createInMemoryNonceStore,
  NonceClaimResult,
} from './nonce-store';

export interface WebtriggerRequest {
  method?: string;
  body?: unknown;
  path?: string;
  headers?: Record<string, string | string[] | undefined>;
  queryParameters?: Record<string, string | string[] | undefined>;
  query?: Record<string, string | undefined>;
}

export interface WebtriggerResponse {
  statusCode: number;
  headers: { [key: string]: string[] };
  body: string;
}

export class WebtriggerHttpError extends Error {
  public readonly statusCode: number;
  public readonly publicMessage: string;

  constructor(statusCode: number, publicMessage: string) {
    super(publicMessage);
    this.name = 'WebtriggerHttpError';
    this.statusCode = statusCode;
    this.publicMessage = publicMessage;
  }
}

const ALLOWED_WEBTRIGGER_POST_ACTIONS: ReadonlySet<string> = new Set([
  'status',
  'get-hazard-lineage',
  'seed',
  'remediate',
  'verify',
  'verify-release-gate',
  'validate',
  'simulate_transition',
]);

const MAX_WEBTRIGGER_PR_DIFF_CHARS = 100_000;

function stripTraceLinksResponse(
  suite: Awaited<ReturnType<typeof SeederService.getActiveComplianceSuite>>
): WebtriggerResponse {
  const { traceLinks: _traceLinks, ...statusSummary } = suite;
  return jsonResponse(200, statusSummary);
}

/**
 * Verifies an HMAC-SHA256 request signature over `timestamp.nonce.payload` using timing-safe comparison.
 * Fails closed (`false`) when `secret` is missing/empty or any header/input is malformed.
 */
export function verifyHmacSignature(
  payload: string,
  timestamp: string,
  signatureHeader: string,
  secret: string,
  nonce: string = ''
): boolean {
  if (typeof secret !== 'string' || secret.trim() === '') return false;
  if (typeof payload !== 'string') return false;
  if (typeof timestamp !== 'string' || !/^\d+$/.test(timestamp.trim())) return false;
  if (typeof signatureHeader !== 'string' || !/^sha256=[a-f0-9]{64}$/i.test(signatureHeader.trim())) {
    return false;
  }

  const cleanTimestamp = timestamp.trim();
  const cleanNonce = typeof nonce === 'string' ? nonce : '';
  const signingInput = cleanNonce
    ? `${cleanTimestamp}.${cleanNonce}.${payload}`
    : `${cleanTimestamp}.${payload}`;
  const providedHex = signatureHeader.trim().slice('sha256='.length).toLowerCase();
  const expectedHex = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest('hex');

  const sigBuf = Buffer.from(providedHex, 'hex');
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (sigBuf.length !== expectedBuf.length || sigBuf.length !== 32) {
    return false;
  }
  return crypto.timingSafeEqual(sigBuf, expectedBuf);
}

/**
 * Atomically claims a request nonce through the active `NonceStore`, distinguishing replays from storage failures.
 */
export async function claimNonceDetailed(
  nonce: string,
  store: NonceStore = getNonceStore(),
  ttlMs: number = NONCE_TTL_MS
): Promise<NonceClaimResult> {
  const cleanNonce = typeof nonce === 'string' ? nonce.trim() : '';
  if (!cleanNonce) return 'REPLAY';

  // Keep the single `nonce:` prefix; NonceStore hashes the key once via `toKvsNonceKey`.
  const storageKey = `nonce:${cleanNonce}`;
  const now = Date.now();

  if (typeof store.claimDetailed === 'function') {
    return store.claimDetailed(storageKey, { consumedAt: now }, ttlMs);
  }
  if (typeof store.claim === 'function') {
    try {
      const claimed = await store.claim(storageKey, { consumedAt: now }, ttlMs);
      return claimed ? 'CLAIMED' : 'REPLAY';
    } catch (err: unknown) {
      console.error('[MedTrace NonceStore] claim failed:', err instanceof Error ? err.message : 'Unknown error');
      return 'STORAGE_ERROR';
    }
  }

  try {
    const existing = await store.get(storageKey);
    if (existing && now - existing.consumedAt < ttlMs) {
      return 'REPLAY';
    }
    await store.set(storageKey, { consumedAt: now });
    return 'CLAIMED';
  } catch (err: unknown) {
    console.error('[MedTrace NonceStore] storage fallback failed:', err instanceof Error ? err.message : 'Unknown error');
    return 'STORAGE_ERROR';
  }
}

/**
 * Atomically claims a request nonce and returns `true` when accepted or `false` on replay/rejection.
 */
export async function claimNonce(
  nonce: string,
  store: NonceStore = getNonceStore(),
  ttlMs: number = NONCE_TTL_MS
): Promise<boolean> {
  return (await claimNonceDetailed(nonce, store, ttlMs)) === 'CLAIMED';
}

export { getNonceStore, setNonceStore, createInMemoryNonceStore };

function getHeader(
  headers: Record<string, string | string[] | undefined> | undefined,
  name: string
): string | undefined {
  if (!headers) return undefined;
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      if (Array.isArray(v)) {
        return typeof v[0] === 'string' ? v[0] : undefined;
      }
      return typeof v === 'string' ? v : undefined;
    }
  }
  return undefined;
}

function jsonResponse(
  statusCode: number,
  payload: unknown,
  extraHeaders?: Record<string, string[]>
): WebtriggerResponse {
  return {
    statusCode,
    headers: {
      'Content-Type': ['application/json'],
      ...(extraHeaders || {}),
    },
    body: JSON.stringify(payload),
  };
}

/**
 * Forge webtrigger entrypoint for authenticated MCP/CI-CD requests.
 * Enforces fail-closed HMAC verification, asymmetric timestamp bounds `[-300s, +30s]`, single-use nonces,
 * strict HTTP method/body/action validation, LIVE-mode mutation guards, and sanitized error responses.
 */
export async function mcpWebtriggerHandler(request: WebtriggerRequest): Promise<WebtriggerResponse> {
  const configuredSecret = process.env.MEDTRACE_MCP_SECRET;
  if (typeof configuredSecret !== 'string' || configuredSecret.trim() === '') {
    return jsonResponse(500, {
      error: 'Server misconfiguration: MEDTRACE_MCP_SECRET must be configured in Forge environment (fail-closed).',
    });
  }

  const method =
    request.method === undefined
      ? request.body !== undefined
        ? 'POST'
        : 'GET'
      : String(request.method).trim().toUpperCase();

  if (method !== 'GET' && method !== 'POST') {
    return jsonResponse(
      405,
      { error: `Method Not Allowed: ${method || '(empty)'}. Supported methods: GET, POST.` },
      { Allow: ['GET, POST'] }
    );
  }

  const rawTimestampHeader = getHeader(request.headers, 'x-medtrace-timestamp');
  const timestampHeader = typeof rawTimestampHeader === 'string' ? rawTimestampHeader.trim() : '';
  if (!timestampHeader) {
    return jsonResponse(401, {
      error: 'Unauthorized: Missing x-medtrace-timestamp header.',
    });
  }
  if (!/^\d+$/.test(timestampHeader)) {
    return jsonResponse(401, {
      error: 'Unauthorized: Invalid x-medtrace-timestamp format (epoch milliseconds required).',
    });
  }

  const rawNonce =
    getHeader(request.headers, 'x-medtrace-nonce') ??
    getHeader(request.headers, 'x-medtrace-event-id');
  const nonceHeader = typeof rawNonce === 'string' ? rawNonce.trim() : '';
  // Disallow `.` and whitespace/control characters so `${timestamp}.${nonce}.${body}` has unambiguous boundaries.
  if (!nonceHeader || nonceHeader.length > 256 || /[.\s\u0000-\u001f\u007f]/.test(nonceHeader)) {
    return jsonResponse(401, {
      error: 'Unauthorized: Missing or invalid x-medtrace-nonce header (1-256 characters, no dots or whitespace).',
    });
  }

  const signatureHeader = getHeader(request.headers, 'x-medtrace-signature')?.trim();
  if (!signatureHeader || !/^sha256=[a-f0-9]{64}$/i.test(signatureHeader)) {
    return jsonResponse(401, {
      error: 'Unauthorized: Missing or invalid x-medtrace-signature header.',
    });
  }

  const reqTime = Number(timestampHeader);
  const now = Date.now();
  if (!Number.isSafeInteger(reqTime)) {
    return jsonResponse(401, { error: 'Unauthorized: Invalid x-medtrace-timestamp value.' });
  }
  if (now - reqTime > MAX_TIMESTAMP_AGE_MS || reqTime - now > MAX_FUTURE_SKEW_MS) {
    return jsonResponse(401, {
      error: 'Unauthorized: Request timestamp outside allowed replay window.',
    });
  }

  let rawBody: string;
  if (typeof request.body === 'string') {
    rawBody = request.body;
  } else if (request.body === undefined || request.body === null) {
    rawBody = '';
  } else if (!isForgeRuntime() && typeof request.body === 'object') {
    rawBody = JSON.stringify(request.body);
  } else {
    return jsonResponse(401, { error: 'Unauthorized: Malformed request body.' });
  }

  if (!verifyHmacSignature(rawBody, timestampHeader, signatureHeader, configuredSecret, nonceHeader)) {
    return jsonResponse(401, { error: 'Unauthorized: Invalid HMAC-SHA256 request signature.' });
  }

  const claimOutcome = await claimNonceDetailed(nonceHeader, getNonceStore(), NONCE_TTL_MS);
  if (claimOutcome === 'REPLAY') {
    return jsonResponse(409, {
      error: 'Conflict: Replay attack detected — nonce has already been consumed within TTL window.',
    });
  }
  if (claimOutcome === 'STORAGE_ERROR') {
    return jsonResponse(500, {
      error: 'Internal Server Error: Replay protection store unavailable.',
    });
  }

  try {
    if (method === 'GET') {
      if (rawBody !== '') {
        throw new WebtriggerHttpError(400, 'Bad Request: GET requests must not include a request body.');
      }

      const rawQueryAction =
        (Array.isArray(request.queryParameters?.action)
          ? request.queryParameters?.action[0]
          : request.queryParameters?.action) ?? request.query?.action;
      const cleanQueryAction =
        typeof rawQueryAction === 'string' && rawQueryAction.trim().length > 0
          ? rawQueryAction.trim()
          : undefined;
      if (cleanQueryAction && cleanQueryAction !== 'status') {
        throw new WebtriggerHttpError(
          400,
          `Bad Request: Unsupported GET query action "${cleanQueryAction}". Use POST for data queries.`
        );
      }

      const suite = await SeederService.getActiveComplianceSuite();
      return stripTraceLinksResponse(suite);
    }

    if (rawBody.trim() === '') {
      throw new WebtriggerHttpError(400, 'Bad Request: POST requests must include a JSON object body.');
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      throw new WebtriggerHttpError(400, 'Bad Request: Malformed JSON payload.');
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new WebtriggerHttpError(400, 'Bad Request: JSON payload must be a plain object.');
    }

    const body = parsed as Record<string, unknown>;
    const action = typeof body.action === 'string' ? body.action.trim() : '';
    if (!action || !ALLOWED_WEBTRIGGER_POST_ACTIONS.has(action)) {
      throw new WebtriggerHttpError(
        400,
        `Bad Request: Unknown or missing webtrigger action "${action || '(empty)'}".`
      );
    }

    switch (action) {
      case 'status': {
        const suite = await SeederService.getActiveComplianceSuite();
        return stripTraceLinksResponse(suite);
      }

      case 'get-hazard-lineage': {
        const hazardKey = typeof body.hazardKey === 'string' ? body.hazardKey.trim() : '';
        const issueKey = typeof body.issueKey === 'string' ? body.issueKey.trim() : '';
        if (!hazardKey && !issueKey) {
          let suite = await SeederService.getActiveComplianceSuite();
          if (isForgeRuntime() && suite.datasetMode === 'LIVE' && suite.initialized !== false) {
            suite = await LiveIngestionService.reconcileConfluenceSpecs(suite, {
              allowAppFallback: true,
            });
          }
          return stripTraceLinksResponse(suite);
        }
        const result = await McpToolService.getHazardLineage(
          {
            hazardKey: hazardKey || undefined,
            issueKey: issueKey || undefined,
          },
          { includeAvailableKeys: false }
        );
        return jsonResponse(200, result);
      }

      case 'seed': {
        const active = await SeederService.getActiveComplianceSuite();
        if (active.datasetMode === 'LIVE') {
          throw new WebtriggerHttpError(
            403,
            'Forbidden: Cannot overwrite a LIVE compliance suite with demo data via webtrigger.'
          );
        }
        const summary = await SeederService.seedEnterpriseDemoSuite(
          'service:mcp-webtrigger',
          'HMAC_WEBTRIGGER'
        );
        return jsonResponse(200, { success: true, summary });
      }

      case 'remediate': {
        const active = await SeederService.getActiveComplianceSuite();
        if (active.datasetMode === 'LIVE') {
          throw new WebtriggerHttpError(
            403,
            'Forbidden: Cannot auto-remediate gaps on a LIVE compliance suite via webtrigger.'
          );
        }
        const hazardKey = typeof body.hazardKey === 'string' ? body.hazardKey.trim() : '';
        if (!hazardKey) {
          throw new WebtriggerHttpError(400, 'Bad Request: hazardKey is required for remediate action.');
        }
        const exists = active.traceLinks.some(
          (link) => link.hazard.key.toLowerCase() === hazardKey.toLowerCase()
        );
        if (!exists) {
          throw new WebtriggerHttpError(
            404,
            `Not Found: Hazard ${hazardKey} not found in active compliance suite; nothing was remediated.`
          );
        }
        const summary = await SeederService.remediateClassCGap(hazardKey, 'service:mcp-webtrigger', {
          simulate: body.simulate === true,
          attestationConfirmed: body.attestationConfirmed === true,
          meaning: typeof body.meaning === 'string' ? body.meaning.trim() : undefined,
          authMethod: 'HMAC_WEBTRIGGER',
        });
        return jsonResponse(200, { success: true, summary });
      }

      case 'verify': {
        const rawPrDiff = typeof body.prDiff === 'string' ? body.prDiff : '';
        const result = await McpToolService.verifyIecCompliance({
          prDiff:
            rawPrDiff.length > MAX_WEBTRIGGER_PR_DIFF_CHARS
              ? rawPrDiff.slice(0, MAX_WEBTRIGGER_PR_DIFF_CHARS)
              : rawPrDiff,
          componentName:
            typeof body.componentName === 'string'
              ? body.componentName.slice(0, 1000)
              : undefined,
          issueKey:
            typeof body.issueKey === 'string' && body.issueKey.trim() !== ''
              ? body.issueKey.trim().slice(0, 64)
              : undefined,
        });
        return jsonResponse(200, result);
      }

      case 'verify-release-gate': {
        const issueKey =
          typeof body.issueKey === 'string' && body.issueKey.trim() !== ''
            ? body.issueKey.trim()
            : undefined;
        const requireLiveMode = body.requireLiveMode === true;
        let suite = await SeederService.getActiveComplianceSuite(
          issueKey ? { issueKeyFilter: issueKey } : undefined
        );

        if (isForgeRuntime() && suite.datasetMode === 'LIVE' && suite.initialized !== false) {
          const cleanUpperKey = issueKey ? issueKey.toUpperCase() : '';
          const targetPageIds = cleanUpperKey
            ? suite.traceLinks
                .filter(
                  (l) =>
                    (l.work?.key || '').toUpperCase() === cleanUpperKey ||
                    (l.hazard?.key || '').toUpperCase() === cleanUpperKey ||
                    (l.test?.testKey || '').toUpperCase() === cleanUpperKey
                )
                .map((l) => l.spec?.pageId)
                .filter((p): p is string => typeof p === 'string' && p.trim().length > 0)
            : undefined;
          if (!cleanUpperKey || (targetPageIds && targetPageIds.length > 0)) {
            suite = await LiveIngestionService.reconcileConfluenceSpecs(suite, {
              ...(cleanUpperKey ? { issueKeyFilter: issueKey, targetPageIds } : {}),
              allowAppFallback: true,
              failClosedOnBudget: true,
            });
          }
        }

        if (
          requireLiveMode &&
          (suite.datasetMode !== 'LIVE' || suite.initialized === false || suite.totalHazards === 0)
        ) {
          return jsonResponse(403, {
            result: false,
            releaseBlocked: true,
            datasetMode: suite.datasetMode,
            initialized: suite.initialized ?? false,
            errorMessage:
              'Safety Gate Blocked: Release gate requires an initialized LIVE compliance suite (DEMO or uninitialized suites cannot authorize clinical release).',
          });
        }

        const isInitialized =
          suite.initialized !== false &&
          Array.isArray(suite.traceLinks) &&
          !(suite.traceLinks.length === 0 && (!issueKey || (suite.totalHazards ?? 0) === 0));
        const matchedInSuite = issueKey ? isMatchedInSuite(issueKey, suite) : false;
        const safetyProbe =
          issueKey && isInitialized && !matchedInSuite
            ? await probeUnsyncedSafetyIssue(issueKey, undefined, { failClosedOnMissingIssue: true })
            : undefined;
        const transitionToDone = body.transitionToDone === true;

        const gate = ComplianceEngine.evaluateIssueReleaseGate(
          issueKey,
          suite,
          safetyProbe || transitionToDone
            ? {
                ...(safetyProbe ?? {}),
                ...(transitionToDone ? { transitionToDone: true } : {}),
              }
            : undefined
        );
        return jsonResponse(gate.result ? 200 : 403, {
          ...gate,
          evaluatedIssueKey: issueKey,
        });
      }

      case 'validate':
      case 'simulate_transition': {
        const issueKey =
          typeof body.issueKey === 'string' && body.issueKey.trim() !== ''
            ? body.issueKey.trim()
            : undefined;
        const transitionName =
          typeof body.transitionName === 'string' && body.transitionName.trim() !== ''
            ? body.transitionName.trim()
            : 'Done';

        const outcome = await workflowValidatorHandler(
          issueKey
            ? { issue: { key: issueKey }, transition: { name: transitionName } }
            : { transition: { name: transitionName } }
        );
        return jsonResponse(200, {
          ...outcome,
          evaluatedIssueKey: issueKey,
        });
      }
    }
    throw new WebtriggerHttpError(400, `Bad Request: Unsupported action "${action}".`);
  } catch (err: unknown) {
    if (err instanceof WebtriggerHttpError) {
      return jsonResponse(err.statusCode, { error: err.publicMessage });
    }
    const errorId = crypto.randomUUID();
    console.error(
      `[MedTrace MCP Webtrigger] Error (${errorId}):`,
      err instanceof Error ? err.message : 'Unknown error'
    );
    return jsonResponse(500, {
      error: 'Internal Server Error: Request could not be processed.',
      errorId,
    });
  }
}
