#!/usr/bin/env node

/**
 * MedTrace Model Context Protocol (MCP) Server
 * Live 2-Way Sync with Atlassian Cloud (Forge Production Backend)
 * Exposes IEC 62304 & ISO 14971 Compliance Tools to Cursor, Claude Desktop, and AI coding agents.
 */

import readline from 'readline';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Load local .env from cwd or repo root relative to this module
try {
  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  const candidateEnvPaths = [
    path.resolve(process.cwd(), '.env'),
    path.resolve(moduleDir, '..', '.env'),
  ];
  for (const envPath of candidateEnvPaths) {
    if (fs.existsSync(envPath)) {
      const lines = fs.readFileSync(envPath, 'utf8').split('\n');
      for (const line of lines) {
        const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
        if (match && !process.env[match[1]]) {
          process.env[match[1]] = (match[2] || '').trim().replace(/^['"]|['"]$/g, '');
        }
      }
      break;
    }
  }
} catch {}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const SERVER_NAME = 'medtrace-mcp-server';
const SERVER_VERSION = '1.1.0';
const MCP_SECRET = process.env.MEDTRACE_MCP_SECRET;

if (!MCP_SECRET) {
  console.error('[MedTrace MCP Server] Fatal Security Error: MEDTRACE_MCP_SECRET is not configured.');
  console.error('[MedTrace MCP Server] Fail-closed: Refusing to start with insecure default secret.');
  console.error('[MedTrace MCP Server] Please export MEDTRACE_MCP_SECRET="<secret>" before starting this server.');
  process.exit(1);
}

const FORGE_WEBTRIGGER_URL = process.env.MEDTRACE_WEBTRIGGER_URL;
if (!FORGE_WEBTRIGGER_URL) {
  console.error('[MedTrace MCP Server] Warning: MEDTRACE_WEBTRIGGER_URL is not configured.');
  console.error('[MedTrace MCP Server] Export MEDTRACE_WEBTRIGGER_URL="<url>" to connect to your live Forge webtrigger.');
}

async function signedCloudRequest(method, payloadObj) {
  if (!FORGE_WEBTRIGGER_URL) {
    return {
      ok: false,
      status: 0,
      error: 'MEDTRACE_WEBTRIGGER_URL is not configured.',
    };
  }

  try {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();
    const payload = method === 'POST' ? JSON.stringify(payloadObj || {}) : '';
    const signature = crypto
      .createHmac('sha256', MCP_SECRET)
      .update(`${timestamp}.${nonce}.${payload}`)
      .digest('hex');

    const headers = {
      Accept: 'application/json',
      'x-medtrace-timestamp': timestamp,
      'x-medtrace-nonce': nonce,
      'x-medtrace-signature': `sha256=${signature}`,
    };
    if (method === 'POST') {
      headers['Content-Type'] = 'application/json';
    }

    const resp = await fetch(FORGE_WEBTRIGGER_URL, {
      method,
      headers,
      ...(method === 'POST' ? { body: payload } : {}),
      signal: AbortSignal.timeout(4000),
    });

    const rawText = await resp.text();
    let parsed = null;
    try {
      parsed = rawText ? JSON.parse(rawText) : null;
    } catch {
      parsed = { raw: rawText };
    }

    if (!resp.ok) {
      return {
        ok: false,
        status: resp.status,
        error: parsed?.error || `HTTP ${resp.status} ${resp.statusText || ''}`.trim(),
        data: parsed,
      };
    }

    return { ok: true, status: resp.status, data: parsed };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      error: err?.message || 'Network/timeout error communicating with Forge webtrigger.',
    };
  }
}

const TOOLS = [
  {
    name: 'medtrace_get_hazard_lineage',
    description:
      'Retrieves complete ISO 14971 hazard safety lineage, linked Confluence SRS specifications, and verification test status live from Atlassian Cloud.',
    inputSchema: {
      type: 'object',
      properties: {
        hazardKey: {
          type: 'string',
          description: 'Optional hazard, Jira issue, spec, or test key (e.g. HAZ-101, MED-42, TEST-88). Omit to retrieve full project lineage.',
        },
        issueKey: {
          type: 'string',
          description: 'Optional alias for hazardKey (e.g. MED-42).',
        },
      },
    },
  },
  {
    name: 'medtrace_verify_iec_compliance',
    description:
      'Audits the active sprint or PR diff against IEC 62304 and FDA 21 CFR Part 11 requirements via the live Forge BFS compliance engine.',
    inputSchema: {
      type: 'object',
      properties: {
        prDiff: {
          type: 'string',
          description: 'Git PR diff or modified code snippet to analyze against safety hazards.',
        },
        componentName: {
          type: 'string',
          description: 'Optional component or subsystem name.',
        },
        issueKey: {
          type: 'string',
          description: 'Optional Jira issue key referenced by the change under audit (e.g. MED-42).',
        },
      },
    },
  },
  {
    name: 'medtrace_remediate_safety_gap',
    description:
      'Runs an explicit demo-mode remediation simulation on Atlassian Cloud (disabled in LIVE mode; requires simulate: true and attestationConfirmed: true).',
    inputSchema: {
      type: 'object',
      properties: {
        hazardKey: {
          type: 'string',
          description: 'Required hazard key to remediate (e.g. HAZ-101).',
        },
        simulate: {
          type: 'boolean',
          description: 'Must be true to confirm demo simulation mode.',
        },
        attestationConfirmed: {
          type: 'boolean',
          description: 'Must be true to confirm 21 CFR Part 11 attestation meaning.',
        },
        meaning: {
          type: 'string',
          description: 'Signature meaning statement (e.g. Clinical Safety Re-Certification).',
        },
      },
      required: ['hazardKey', 'simulate', 'attestationConfirmed'],
    },
  },
];

function unavailableResult(id, cloudResp) {
  return {
    jsonrpc: '2.0',
    id,
    result: {
      isError: true,
      content: [
        {
          type: 'text',
          text: JSON.stringify(
            {
              source: 'UNAVAILABLE',
              httpStatus: cloudResp.status,
              error: cloudResp.error,
              hint: 'Verify MEDTRACE_WEBTRIGGER_URL and MEDTRACE_MCP_SECRET, then retry.',
            },
            null,
            2
          ),
        },
      ],
    },
  };
}

async function handleMessage(message) {
  const { id, method, params } = message || {};

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: SERVER_NAME,
          version: SERVER_VERSION,
        },
      },
    };
  }

  if (method === 'notifications/initialized') {
    return null;
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: TOOLS,
      },
    };
  }

  if (method === 'tools/call') {
    const { name, arguments: args = {} } = params || {};

    if (name === 'medtrace_get_hazard_lineage') {
      const cloudResp = await signedCloudRequest('GET');
      if (!cloudResp.ok || !cloudResp.data?.traceLinks) {
        return unavailableResult(id, cloudResp);
      }

      const liveSuite = cloudResp.data;
      const lookupKey = String(args?.hazardKey || args?.issueKey || '').trim();

      if (lookupKey) {
        const lower = lookupKey.toLowerCase();
        const match = liveSuite.traceLinks.find(
          (l) =>
            l.hazard?.key?.toLowerCase() === lower ||
            l.work?.key?.toLowerCase() === lower ||
            l.test?.testKey?.toLowerCase() === lower ||
            l.spec?.id?.toLowerCase() === lower ||
            (l.spec?.pageId && String(l.spec.pageId).toLowerCase() === lower)
        );
        if (!match) {
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      source: 'Atlassian Cloud (Forge Production KVS)',
                      found: false,
                      queriedKey: lookupKey,
                      message: `No trace link found for key "${lookupKey}".`,
                    },
                    null,
                    2
                  ),
                },
              ],
            },
          };
        }

        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    source: 'Atlassian Cloud (Forge Production KVS)',
                    found: true,
                    hazard: match.hazard,
                    spec: match.spec,
                    work: match.work,
                    test: match.test,
                    signature: match.signature,
                    complianceState: match.complianceState,
                    violations: match.violations,
                  },
                  null,
                  2
                ),
              },
            ],
          },
        };
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  source: 'Atlassian Cloud (Forge Production KVS)',
                  projectName: liveSuite.projectName,
                  datasetMode: liveSuite.datasetMode,
                  totalHazards: liveSuite.totalHazards,
                  verifiedPercentage: `${liveSuite.verifiedPercentage}%`,
                  releaseBlocked: liveSuite.releaseBlocked,
                  traceLinks: liveSuite.traceLinks,
                },
                null,
                2
              ),
            },
          ],
        },
      };
    }

    if (name === 'medtrace_verify_iec_compliance') {
      const cloudResp = await signedCloudRequest('POST', {
        action: 'verify',
        prDiff: args?.prDiff,
        componentName: args?.componentName,
        issueKey: args?.issueKey,
      });

      if (!cloudResp.ok) {
        return unavailableResult(id, cloudResp);
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(cloudResp.data, null, 2) }],
        },
      };
    }

    if (name === 'medtrace_remediate_safety_gap') {
      const hazardKey = typeof args?.hazardKey === 'string' ? args.hazardKey.trim() : '';
      if (!hazardKey) {
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: -32602,
            message: 'Invalid params: hazardKey is required.',
          },
        };
      }

      const cloudResp = await signedCloudRequest('POST', {
        action: 'remediate',
        hazardKey,
        simulate: Boolean(args?.simulate),
        attestationConfirmed: Boolean(args?.attestationConfirmed),
        meaning: typeof args?.meaning === 'string' ? args.meaning : undefined,
      });

      if (!cloudResp.ok) {
        return unavailableResult(id, cloudResp);
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  source: 'Atlassian Cloud (Forge Production KVS)',
                  remediated: true,
                  hazardKey,
                  summary: cloudResp.data?.summary,
                },
                null,
                2
              ),
            },
          ],
        },
      };
    }

    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: -32601,
        message: `Unknown tool: ${name}`,
      },
    };
  }

  if (id === undefined) return null;
  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: -32601,
      message: `Unsupported method: ${method}`,
    },
  };
}

rl.on('line', async (line) => {
  if (!line.trim()) return;
  let messageId = null;
  try {
    const message = JSON.parse(line);
    messageId = message?.id ?? null;
    const response = await handleMessage(message);
    if (response) {
      process.stdout.write(JSON.stringify(response) + '\n');
    }
  } catch (err) {
    console.error('Error handling MCP JSON-RPC message:', err);
    if (messageId != null) {
      const isParseError = err instanceof SyntaxError;
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: messageId,
          error: {
            code: isParseError ? -32700 : -32603,
            message: isParseError ? 'Parse error' : `Internal error: ${err?.message || 'unexpected failure'}`,
          },
        }) + '\n'
      );
    }
  }
});
