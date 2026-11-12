import api, { route } from '@forge/api';
import Resolver from '@forge/resolver';
import crypto from 'node:crypto';
import { AuditLogService } from './audit-log';
import { ComplianceEngine } from './compliance-engine';
import { LiveIngestionService } from './ingestion';
import { rovoActionHandler, McpToolService } from './mcp-server';
import {
  NonceStore,
  getNonceStore,
  setNonceStore,
  createInMemoryNonceStore,
  NonceClaimResult,
} from './nonce-store';
import { isForgeRuntime } from './runtime';
import { SeederService } from './seeder';
import { TeamworkGraphService } from './teamwork-graph';
import { workflowValidatorHandler } from './workflow-validator';

const resolver = new Resolver();

/**
 * Enforces authenticated user identity and Jira/Confluence edit/admin permissions
 * on mutating Forge UI resolvers.
 */
async function assertAuthorizedOperator(req: any): Promise<string> {
  const accountId: string | undefined = req?.context?.accountId;
  if (!accountId || typeof accountId !== 'string' || accountId.trim() === '') {
    throw new Error('Unauthorized: Authenticated Atlassian accountId is required.');
  }

  if (!isForgeRuntime()) {
    return accountId;
  }

  const extType: string = req?.context?.extension?.type || '';
  if (extType.startsWith('confluence')) {
    const confResp = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces?limit=1`);
    if (confResp.status !== 200) {
      throw new Error(`Forbidden: Confluence user session lacks access (HTTP ${confResp.status}).`);
    }
    return accountId;
  }

  const projectKey: string | undefined = req?.context?.extension?.project?.key;
  const permRoute = projectKey
    ? route`/rest/api/3/mypermissions?permissions=ADMINISTER_PROJECTS,EDIT_ISSUES&projectKey=${projectKey}`
    : route`/rest/api/3/mypermissions?permissions=ADMINISTER_PROJECTS,EDIT_ISSUES`;

  const permResp = await api.asUser().requestJira(permRoute);
  if (permResp.status !== 200) {
    throw new Error(`Forbidden: Unable to verify Jira permissions (HTTP ${permResp.status}).`);
  }
  const permData = await permResp.json();
  const canEdit = Boolean(permData?.permissions?.EDIT_ISSUES?.havePermission);
  const canAdmin = Boolean(permData?.permissions?.ADMINISTER_PROJECTS?.havePermission);
  if (!canEdit && !canAdmin) {
    throw new Error('Forbidden: Requires Jira EDIT_ISSUES or ADMINISTER_PROJECTS permission.');
  }

  return accountId;
}

// 1. Fetch current compliance state
resolver.define('getComplianceSuite', async () => {
  return await SeederService.getActiveComplianceSuite();
});

// 2. Demo Dataset Seeder (RBAC-protected)
resolver.define('seedDemoSuite', async (req) => {
  const accountId = await assertAuthorizedOperator(req);
  return await SeederService.seedEnterpriseDemoSuite(accountId, 'FORGE_USER_SESSION');
});

// 2b. Live Jira + Confluence Ingestion Sync (RBAC-protected)
resolver.define('syncLiveSuite', async (req) => {
  const accountId = await assertAuthorizedOperator(req);
  return await LiveIngestionService.syncFromAtlassian(
    {
      projectKey: req?.payload?.projectKey || req?.context?.extension?.project?.key,
      spaceId: req?.payload?.spaceId,
      jql: req?.payload?.jql,
    },
    accountId
  );
});

// 3. Explicit Demo Remediation (disallowed in LIVE mode; requires simulate + attestationConfirmed)
resolver.define('remediateGap', async (req) => {
  const accountId = await assertAuthorizedOperator(req);
  const hazardKey = req.payload?.hazardKey || 'HAZ-101';
  return await SeederService.remediateClassCGap(hazardKey, accountId, {
    simulate: Boolean(req.payload?.simulate),
    attestationConfirmed: Boolean(req.payload?.attestationConfirmed),
    meaning: typeof req.payload?.meaning === 'string' ? req.payload.meaning : undefined,
    authMethod: 'PART11_ATTESTATION',
  });
});

// 3b. Record explicit verification test execution result (RBAC-protected)
resolver.define('recordTestResult', async (req) => {
  const accountId = await assertAuthorizedOperator(req);
  return await SeederService.recordTestResult({
    hazardKey: req.payload?.hazardKey,
    testKey: req.payload?.testKey,
    status: req.payload?.status,
    evidenceUrl: req.payload?.evidenceUrl,
    executionDate: req.payload?.executionDate,
    notes: req.payload?.notes,
    actorAccountId: accountId,
    authMethod: 'FORGE_USER_SESSION',
  });
});

// 3c. Explicit 21 CFR Part 11 Electronic Signature Sign-Off (RBAC-protected)
resolver.define('signOffPart11', async (req) => {
  const accountId = await assertAuthorizedOperator(req);
  const hazardKey = req.payload?.hazardKey;
  if (!hazardKey) {
    throw new Error('hazardKey is required for 21 CFR Part 11 sign-off.');
  }
  return await SeederService.signOffPart11({
    hazardKey,
    attestation: {
      meaning: req.payload?.meaning || '',
      attestationConfirmed: Boolean(req.payload?.attestationConfirmed),
      passwordConfirmed: Boolean(req.payload?.passwordConfirmed),
      attestationPhrase: req.payload?.attestationPhrase,
      signedBy: req.payload?.signedBy,
      role: req.payload?.role,
    },
    actorAccountId: accountId,
    authMethod: 'PART11_ATTESTATION',
  });
});

// 4. Teamwork Graph & Jira/Confluence Context Query
resolver.define('queryGraphContext', async (req) => {
  const issueKey = req.payload?.issueKey || req.context?.extension?.issue?.key || 'MED-42';
  return await TeamworkGraphService.queryIssueGraphContext(issueKey);
});

// 4b. Bind a Jira issue to a hazard trace link (RBAC-protected)
resolver.define('bindIssueToHazard', async (req) => {
  const accountId = await assertAuthorizedOperator(req);
  const hazardKey = req.payload?.hazardKey;
  const issueKey = req.payload?.issueKey || req.context?.extension?.issue?.key;
  if (!hazardKey) return { success: false, error: 'hazardKey required' };
  if (!issueKey) return { success: false, error: 'no issue context' };
  try {
    const summary = await SeederService.bindIssueToHazard(hazardKey, issueKey, accountId, 'FORGE_USER_SESSION');
    return { success: true, summary };
  } catch (err: any) {
    return { success: false, error: err?.message || 'bind failed' };
  }
});

// 5. Simulate Jira Release Transition (Human-Initiated Transition Gate)
resolver.define('simulateTransition', async (req) => {
  const issueKey = req?.payload?.issueKey || req?.context?.extension?.issue?.key || 'MED-42';
  return await workflowValidatorHandler({ issue: { key: issueKey }, transition: { name: 'Done' } });
});

// 6. Deterministic Regulatory Blast Radius & Transitive Impact Analyzer
resolver.define('analyzeBlastRadius', async (req) => {
  const triggerKey = req?.payload?.triggerKey || 'srs-104';
  const suite = await SeederService.getActiveComplianceSuite();
  return ComplianceEngine.computeBlastRadius(triggerKey, suite);
});

// 7. Hash-chained Immutable Audit Log Retrieval & Verification
resolver.define('getAuditLog', async (req) => {
  const limit = typeof req?.payload?.limit === 'number' ? req.payload.limit : 50;
  return await AuditLogService.getAuditLog(limit);
});

resolver.define('verifyAuditChain', async () => {
  return await AuditLogService.verifyAuditChain();
});

const getMcpSecret = (): string => process.env.MEDTRACE_MCP_SECRET || '';

/**
 * Claims a unique event nonce using the injected NonceStore.
 */
export async function claimNonce(
  nonce: string,
  store: NonceStore = getNonceStore(),
  ttlMs: number = 300_000
): Promise<boolean> {
  const outcome = await claimNonceDetailed(nonce, store, ttlMs);
  if (outcome === 'STORAGE_ERROR') {
    throw new Error('Nonce storage backend failure.');
  }
  return outcome === 'CLAIMED';
}

export async function claimNonceDetailed(
  nonce: string,
  store: NonceStore = getNonceStore(),
  ttlMs: number = 300_000
): Promise<NonceClaimResult> {
  const nonceKey = `nonce:${nonce.length > 64 ? crypto.createHash('sha256').update(nonce).digest('hex') : nonce}`;
  const now = Date.now();

  if (store.claimDetailed) {
    return await store.claimDetailed(nonceKey, { consumedAt: now }, ttlMs);
  }
  const ok = await store.claim(nonceKey, { consumedAt: now }, ttlMs);
  return ok ? 'CLAIMED' : 'REPLAY';
}

export { NonceStore, getNonceStore, setNonceStore, createInMemoryNonceStore };

/**
 * Validates HMAC-SHA256 signature binding timestamp, payload, and optional nonce against replay/tampering.
 */
export function verifyHmacSignature(
  rawBody: string,
  timestamp: string,
  signatureHeader: string,
  secret: string,
  nonce?: string
): boolean {
  try {
    const cleanSig = signatureHeader.replace(/^sha256=/, '').trim();
    const sigBuffer = Buffer.from(cleanSig, 'hex');
    const message = nonce ? `${timestamp}.${nonce}.${rawBody || ''}` : `${timestamp}.${rawBody || ''}`;
    const expectedSig = crypto.createHmac('sha256', secret).update(message).digest('hex');
    const expectedBuffer = Buffer.from(expectedSig, 'hex');

    if (sigBuffer.length !== expectedBuffer.length) {
      return false;
    }
    return crypto.timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    return false;
  }
}

function extractHeader(headers: any, name: string): string | undefined {
  if (!headers) return undefined;
  const val = headers[name] !== undefined ? headers[name] : headers[name.toLowerCase()];
  if (Array.isArray(val)) return val[0];
  if (typeof val === 'string') return val;
  return undefined;
}

const JSON_HEADERS = { 'Content-Type': ['application/json'] };

/**
 * Webtrigger for real-time 2-way sync with local MCP Server and CI/CD pipelines.
 * Enforces fail-closed HMAC-SHA256 verification, 300s timestamp window, and atomic KVS nonce replay defense.
 */
export async function mcpWebtriggerHandler(request: any): Promise<any> {
  console.log('[MedTrace MCP Webtrigger] Handling external MCP sync request:', request?.method);

  try {
    const secret = getMcpSecret();
    if (!secret) {
      console.error('[MedTrace MCP Webtrigger] Fail-closed: MEDTRACE_MCP_SECRET is not configured.');
      return {
        body: JSON.stringify({
          error: 'Server misconfiguration: MEDTRACE_MCP_SECRET must be configured in Forge environment (fail-closed).',
        }),
        headers: JSON_HEADERS,
        statusCode: 500,
      };
    }

    const timestampHeader = extractHeader(request?.headers, 'x-medtrace-timestamp');
    const signatureHeader = extractHeader(request?.headers, 'x-medtrace-signature');
    const nonceHeader =
      extractHeader(request?.headers, 'x-medtrace-nonce') ||
      extractHeader(request?.headers, 'x-medtrace-event-id');

    if (!timestampHeader) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Missing x-medtrace-timestamp header.' }),
        headers: JSON_HEADERS,
        statusCode: 401,
      };
    }

    if (!/^\d+$/.test(timestampHeader.trim())) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Invalid x-medtrace-timestamp format.' }),
        headers: JSON_HEADERS,
        statusCode: 401,
      };
    }

    const reqTime = Number(timestampHeader.trim());
    if (!Number.isFinite(reqTime) || Math.abs(Date.now() - reqTime) > 300_000) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Request timestamp expired (>300s replay window).' }),
        headers: JSON_HEADERS,
        statusCode: 401,
      };
    }

    if (!signatureHeader) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Missing x-medtrace-signature header.' }),
        headers: JSON_HEADERS,
        statusCode: 401,
      };
    }

    if (!nonceHeader) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Missing x-medtrace-nonce header.' }),
        headers: JSON_HEADERS,
        statusCode: 401,
      };
    }

    const rawBody =
      typeof request.body === 'string'
        ? request.body
        : request.body
          ? JSON.stringify(request.body)
          : '';
    const isValidSig = verifyHmacSignature(rawBody, timestampHeader, signatureHeader, secret, nonceHeader);
    if (!isValidSig) {
      return {
        body: JSON.stringify({
          error: 'Unauthorized: Cryptographic HMAC-SHA256 signature mismatch (tamper/replay protection).',
        }),
        headers: JSON_HEADERS,
        statusCode: 401,
      };
    }

    const nonceOutcome = await claimNonceDetailed(nonceHeader);
    if (nonceOutcome === 'REPLAY') {
      return {
        body: JSON.stringify({
          error: 'Unauthorized: Replay attack detected (nonce/eventId already consumed within validity window).',
        }),
        headers: JSON_HEADERS,
        statusCode: 409,
      };
    }
    if (nonceOutcome === 'STORAGE_ERROR') {
      return {
        body: JSON.stringify({
          error: 'Internal Server Error: Replay protection store unavailable.',
        }),
        headers: JSON_HEADERS,
        statusCode: 500,
      };
    }

    let body: any = {};
    if (String(request?.method || '').toUpperCase() === 'POST') {
      if (typeof request.body === 'string' && request.body.trim() !== '') {
        try {
          body = JSON.parse(request.body);
        } catch {
          return {
            body: JSON.stringify({ error: 'Bad Request: Malformed JSON payload.' }),
            headers: JSON_HEADERS,
            statusCode: 400,
          };
        }
      } else if (request.body && typeof request.body === 'object') {
        body = request.body;
      }
    }

    if (body.action === 'seed') {
      const seeded = await SeederService.seedEnterpriseDemoSuite('service:mcp-webtrigger', 'HMAC_WEBTRIGGER');
      return {
        body: JSON.stringify({ success: true, summary: seeded.summary }),
        headers: JSON_HEADERS,
        statusCode: 200,
      };
    }

    if (body.action === 'remediate') {
      const hazardKey = body.hazardKey || 'HAZ-101';
      // Never accept caller-supplied Jira accountId spoofing over webtrigger; attribute to authenticated service principal.
      const serviceActor = 'service:mcp-webtrigger';
      const updated = await SeederService.remediateClassCGap(hazardKey, serviceActor, {
        simulate: Boolean(body.simulate),
        attestationConfirmed: Boolean(body.attestationConfirmed),
        meaning: typeof body.meaning === 'string' ? body.meaning : undefined,
        authMethod: 'HMAC_WEBTRIGGER',
      });
      return {
        body: JSON.stringify({ success: true, summary: updated }),
        headers: JSON_HEADERS,
        statusCode: 200,
      };
    }

    if (body.action === 'verify') {
      const result = await McpToolService.verifyIecCompliance({
        prDiff: body.prDiff,
        componentName: body.componentName,
        issueKey: body.issueKey,
      });
      return {
        body: JSON.stringify(result),
        headers: JSON_HEADERS,
        statusCode: 200,
      };
    }

    if (body.action === 'verify-release-gate') {
      const issueKey =
        typeof body.issueKey === 'string' && body.issueKey.trim() !== '' ? body.issueKey.trim() : undefined;
      const suite = await SeederService.getActiveComplianceSuite();
      const outcome = ComplianceEngine.evaluateIssueReleaseGate(issueKey, suite);
      return {
        body: JSON.stringify(outcome),
        headers: JSON_HEADERS,
        statusCode: outcome.result ? 200 : 403,
      };
    }

    if (body.action === 'validate' || body.action === 'simulate_transition') {
      const issueKey = body.issueKey || 'MED-42';
      const result = await workflowValidatorHandler({ issue: { key: issueKey }, transition: { name: 'Done' } });
      return {
        body: JSON.stringify(result),
        headers: JSON_HEADERS,
        statusCode: 200,
      };
    }

    const suite = await SeederService.getActiveComplianceSuite();
    return {
      body: JSON.stringify(suite),
      headers: JSON_HEADERS,
      statusCode: 200,
    };
  } catch (err: any) {
    return {
      body: JSON.stringify({ error: err?.message || 'Failed to process MCP request' }),
      headers: JSON_HEADERS,
      statusCode: 500,
    };
  }
}

/**
 * Forge product event trigger (`avi:confluence:updated:page`).
 * Detects Confluence SRS modifications and invalidates drifted Part 11 signatures in KVS.
 */
export async function confluencePageUpdatedTrigger(event: any): Promise<any> {
  console.log('[MedTrace ConfluenceTrigger] Page updated event:', event?.content?.id || event?.page?.id || 'unknown');
  return await LiveIngestionService.handleConfluencePageUpdated(event);
}

// Export handlers matching manifest.yml functions
export const resolverHandler = resolver.getDefinitions();
export { workflowValidatorHandler, rovoActionHandler };
