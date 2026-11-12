import Resolver from '@forge/resolver';
import crypto from 'node:crypto';
import { SeederService } from './seeder';
import { TeamworkGraphService } from './teamwork-graph';
import { workflowValidatorHandler } from './workflow-validator';
import { rovoActionHandler, McpToolService } from './mcp-server';
import { ComplianceEngine } from './compliance-engine';

const resolver = new Resolver();

// 1. Fetch current compliance state
resolver.define('getComplianceSuite', async () => {
  return await SeederService.getActiveComplianceSuite();
});

// 2. 1-Click Bulletproof Enterprise Seeder
resolver.define('seedDemoSuite', async () => {
  return await SeederService.seedEnterpriseDemoSuite();
});

// 3. Remediate Class C Gap (Hero demo fix simulation)
resolver.define('remediateGap', async (req) => {
  const hazardKey = req.payload?.hazardKey || 'HAZ-101';
  const accountId = req.context?.accountId;
  return await SeederService.remediateClassCGap(hazardKey, accountId);
});

// 4. Teamwork Graph GraphQL Context Query
resolver.define('queryGraphContext', async (req) => {
  const issueKey = req.payload?.issueKey || 'MED-42';
  return await TeamworkGraphService.queryIssueGraphContext(issueKey);
});

// 4b. Bind a Jira issue to a hazard trace link (makes the safety gate real)
resolver.define('bindIssueToHazard', async (req) => {
  const hazardKey = req.payload?.hazardKey;
  const issueKey = req.context?.extension?.issue?.key || req.payload?.issueKey;
  if (!hazardKey) return { success: false, error: 'hazardKey required' };
  if (!issueKey) return { success: false, error: 'no issue context' };
  try {
    const summary = await SeederService.bindIssueToHazard(hazardKey, issueKey);
    return { success: true, summary };
  } catch (err: any) {
    return { success: false, error: err?.message || 'bind failed' };
  }
});

// 5. Simulate Jira Release Transition (Human-Initiated Transition Gate)
resolver.define('simulateTransition', async (req) => {
  const issueKey = req?.payload?.issueKey || 'MED-42';
  return await workflowValidatorHandler({ issue: { key: issueKey }, transition: { name: 'Done' } });
});

// 6. Deterministic Regulatory Blast Radius & Transitive Impact Analyzer
resolver.define('analyzeBlastRadius', async (req) => {
  const triggerKey = req?.payload?.triggerKey || 'srs-104';
  const suite = await SeederService.getActiveComplianceSuite();
  return ComplianceEngine.computeBlastRadius(triggerKey, suite);
});

import { NonceStore, getNonceStore, setNonceStore, createInMemoryNonceStore } from './nonce-store';

const getMcpSecret = (): string => process.env.MEDTRACE_MCP_SECRET || '';

/**
 * Claims a unique event nonce using the injected NonceStore (default: Forge KVS in production).
 * Ephemeral serverless invocations persist state in Forge storage:app to reject replay attacks across instances.
 * Implements lazy pruning on access: expired records are pruned via store.delete() upon lookup.
 */
export async function claimNonce(
  nonce: string,
  store: NonceStore = getNonceStore(),
  ttlMs: number = 300_000
): Promise<boolean> {
  const nonceKey = `nonce:${nonce.length > 64 ? crypto.createHash('sha256').update(nonce).digest('hex') : nonce}`;
  const now = Date.now();

  return await store.claim(nonceKey, { consumedAt: now }, ttlMs);
}

export { NonceStore, getNonceStore, setNonceStore, createInMemoryNonceStore };

/**
 * Validates HMAC-SHA256 signature binding timestamp, payload, and optional nonce against replay/tampering
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

/**
 * Webtrigger for real-time 2-way sync with local MCP Server (Cursor / Claude Desktop)
 * Enforces cryptographic HMAC-SHA256 signature verification, 5-minute replay window,
 * and unique event nonce idempotency to prevent replay attacks inside the window.
 */
export async function mcpWebtriggerHandler(request: any): Promise<any> {
  console.log('[MedTrace MCP Webtrigger] Handling external MCP sync request:', request?.method);

  try {
    const secret = getMcpSecret();
    if (!secret) {
      console.error('[MedTrace MCP Webtrigger] Fail-closed: MEDTRACE_MCP_SECRET is not configured.');
      return {
        body: JSON.stringify({ error: 'Server misconfiguration: MEDTRACE_MCP_SECRET must be configured in Forge environment (fail-closed).' }),
        headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
        statusCode: 500,
      };
    }

    // HMAC-SHA256 required on every request (GET and POST). The shared secret itself is
    // never transmitted: only its signature over (timestamp.nonce.body) is.
    const timestampHeader = extractHeader(request?.headers, 'x-medtrace-timestamp');
    const signatureHeader = extractHeader(request?.headers, 'x-medtrace-signature');
    const nonceHeader =
      extractHeader(request?.headers, 'x-medtrace-nonce') ||
      extractHeader(request?.headers, 'x-medtrace-event-id');

    if (!timestampHeader) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Missing x-medtrace-timestamp header.' }),
        headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
        statusCode: 401,
      };
    }

    const reqTime = parseInt(timestampHeader, 10);
    if (isNaN(reqTime) || Math.abs(Date.now() - reqTime) > 300_000) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Request timestamp expired (>300s replay window).' }),
        headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
        statusCode: 401,
      };
    }

    if (!signatureHeader) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Missing x-medtrace-signature header.' }),
        headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
        statusCode: 401,
      };
    }

    if (!nonceHeader) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Missing x-medtrace-nonce header.' }),
        headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
        statusCode: 401,
      };
    }

    const rawBody = typeof request.body === 'string' ? request.body : (request.body ? JSON.stringify(request.body) : '');
    const isValidSig = verifyHmacSignature(rawBody, timestampHeader, signatureHeader, secret, nonceHeader);
    if (!isValidSig) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Cryptographic HMAC-SHA256 signature mismatch (tamper/replay protection).' }),
        headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
        statusCode: 401,
      };
    }

    const isClaimed = await claimNonce(nonceHeader);
    if (!isClaimed) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Replay attack detected (nonce/eventId already consumed within validity window).' }),
        headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
        statusCode: 409,
      };
    }

    // Body parsing (for POST actions). GET requests fall through with an empty body.
    let body: any = {};
    if (request?.method === 'POST') {
      try {
        body = JSON.parse(request.body || '{}');
      } catch {}
    }

      if (body.action === 'seed') {
        const seeded = await SeederService.seedEnterpriseDemoSuite();
        return {
          body: JSON.stringify({ success: true, summary: seeded.summary }),
          headers: {
            'Content-Type': ['application/json'],
            'Access-Control-Allow-Origin': ['*'],
          },
          statusCode: 200,
        };
      }

      if (body.action === 'remediate') {
        const hazardKey = body.hazardKey || 'HAZ-101';
        const accountId = request?.context?.accountId || body.accountId;
        const updated = await SeederService.remediateClassCGap(hazardKey, accountId);
        return {
          body: JSON.stringify({ success: true, summary: updated }),
          headers: {
            'Content-Type': ['application/json'],
            'Access-Control-Allow-Origin': ['*'],
          },
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
          headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
          statusCode: 200,
        };
      }

      if (body.action === 'verify-release-gate') {
        const issueKey = typeof body.issueKey === 'string' && body.issueKey.trim() !== '' ? body.issueKey.trim() : undefined;
        if (issueKey) {
          const suite = await SeederService.getActiveComplianceSuite();
          const matchedLink = suite.traceLinks.find(
            (l: any) => (l.work?.key || '').toUpperCase() === issueKey.toUpperCase() || (l.hazard?.key || '').toUpperCase() === issueKey.toUpperCase()
          );
          if (!matchedLink) {
            // Unlinked issue: not a safety hazard. Approve unless the whole suite is globally blocked.
            const result = !suite.releaseBlocked;
            return {
              body: JSON.stringify({ result, errorMessage: result ? `Issue ${issueKey} is not linked to any safety hazard; release gate approved.` : suite.blockingReasons[0] }),
              headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
              statusCode: result ? 200 : 403,
            };
          }
        }
        const outcome = await workflowValidatorHandler(issueKey ? { issue: { key: issueKey } } : {});
        return {
          body: JSON.stringify(outcome),
          headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
          statusCode: outcome.result ? 200 : 403,
        };
      }

      if (body.action === 'validate' || body.action === 'simulate_transition') {
        const issueKey = body.issueKey || 'MED-42';
        const result = await workflowValidatorHandler({ issue: { key: issueKey }, transition: { name: 'Done' } });
        return {
          body: JSON.stringify(result),
          headers: {
            'Content-Type': ['application/json'],
            'Access-Control-Allow-Origin': ['*'],
          },
          statusCode: 200,
        };
      }

    // Default GET: return live compliance suite
    const suite = await SeederService.getActiveComplianceSuite();
    return {
      body: JSON.stringify(suite),
      headers: {
        'Content-Type': ['application/json'],
        'Access-Control-Allow-Origin': ['*'],
      },
      statusCode: 200,
    };
  } catch (err: any) {
    return {
      body: JSON.stringify({ error: err?.message || 'Failed to fetch MCP state' }),
      headers: {
        'Content-Type': ['application/json'],
        'Access-Control-Allow-Origin': ['*'],
      },
      statusCode: 500,
    };
  }
}

// Export handlers matching manifest.yml functions
export const resolverHandler = resolver.getDefinitions();
export { workflowValidatorHandler, rovoActionHandler };
