import Resolver from '@forge/resolver';
import { kvs } from '@forge/kvs';
import crypto from 'node:crypto';
import { SeederService } from './seeder';
import { TeamworkGraphService } from './teamwork-graph';
import { workflowValidatorHandler } from './workflow-validator';
import { rovoActionHandler } from './mcp-server';
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
  return await SeederService.remediateClassCGap(hazardKey);
});

// 4. Teamwork Graph GraphQL Context Query
resolver.define('queryGraphContext', async (req) => {
  const issueKey = req.payload?.issueKey || 'HAZ-101';
  return await TeamworkGraphService.queryIssueGraphContext(issueKey);
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

const MCP_SECRET = process.env.MEDTRACE_MCP_SECRET || 'medtrace-sec-2026';

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

  const existing = await store.get(nonceKey);
  if (existing && (now - existing.consumedAt < ttlMs)) {
    return false; // Replay attack detected within window
  }

  // Lazy pruning: delete expired key before updating
  if (existing) {
    await store.delete(nonceKey);
  }

  await store.set(nonceKey, { consumedAt: now });
  return true;
}

// Retained for backward-compatibility with existing exports
export const consumedNonces = {
  has: (nonce: string) => false,
  add: (nonce: string) => {},
};

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
    // Header-only secret check: secrets in query parameters leak into web logs, proxies, and browser history
    const authHeader = extractHeader(request?.headers, 'x-medtrace-key');

    // 1. Shared secret check (enforced on all requests to protect clinical records)
    if (authHeader !== MCP_SECRET) {
      return {
        body: JSON.stringify({ error: 'Unauthorized: Missing or invalid x-medtrace-key header.' }),
        headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
        statusCode: 401,
      };
    }

    // 2. If request contains state mutation payload (POST), require timestamp, nonce & HMAC signature
    if (request?.method === 'POST') {
      const timestampHeader = extractHeader(request?.headers, 'x-medtrace-timestamp');
      const signatureHeader = extractHeader(request?.headers, 'x-medtrace-signature');
      const nonceHeader =
        extractHeader(request?.headers, 'x-medtrace-nonce') ||
        extractHeader(request?.headers, 'x-medtrace-event-id');

      // Replay attack prevention: enforce 5-minute request validity window
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

      // Cryptographic HMAC-SHA256 binding signature over (timestamp + [nonce] + rawBody)
      if (!signatureHeader) {
        return {
          body: JSON.stringify({ error: 'Unauthorized: Missing x-medtrace-signature header.' }),
          headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
          statusCode: 401,
        };
      }

      const rawBody = typeof request.body === 'string' ? request.body : JSON.stringify(request.body || {});
      const isValidSig =
        verifyHmacSignature(rawBody, timestampHeader, signatureHeader, MCP_SECRET, nonceHeader) ||
        verifyHmacSignature(rawBody, timestampHeader, signatureHeader, MCP_SECRET);

      if (!isValidSig) {
        return {
          body: JSON.stringify({ error: 'Unauthorized: Cryptographic HMAC-SHA256 signature mismatch (tamper/replay protection).' }),
          headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
          statusCode: 401,
        };
      }

      // Idempotency & In-Window Replay Defense: reject duplicate nonce/eventId via Forge storage:app
      if (nonceHeader) {
        const isClaimed = await claimNonce(nonceHeader);
        if (!isClaimed) {
          return {
            body: JSON.stringify({ error: 'Unauthorized: Replay attack detected (nonce/eventId already consumed within validity window).' }),
            headers: { 'Content-Type': ['application/json'], 'Access-Control-Allow-Origin': ['*'] },
            statusCode: 409,
          };
        }
      }
      let body: any = {};
      try {
        body = JSON.parse(request.body || '{}');
      } catch {}

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
        const updated = await SeederService.remediateClassCGap(hazardKey);
        return {
          body: JSON.stringify({ success: true, summary: updated }),
          headers: {
            'Content-Type': ['application/json'],
            'Access-Control-Allow-Origin': ['*'],
          },
          statusCode: 200,
        };
      }
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
