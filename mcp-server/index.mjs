#!/usr/bin/env node

/**
 * MedTrace Model Context Protocol (MCP) Server
 * Live 2-Way Sync with Atlassian Cloud (Forge Production Backend)
 * Exposes IEC 62304 & ISO 14971 Compliance Tools to Cursor, Claude Desktop, and AI coding agents.
 */

import readline from 'node:readline';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const SERVER_NAME = 'medtrace-mcp-server';
export const SERVER_VERSION = '1.1.0';
export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
export const MIN_REQUEST_TIMEOUT_MS = 1_000;
export const MAX_REQUEST_TIMEOUT_MS = 60_000;

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Parses `.env` content supporting full-line `#` comments, optional `export ` prefix,
 * quoted values containing `#` (with `\"` / `\'` / `\\` unescaping and trailing `#` comments),
 * and unquoted values with trailing ` # comment`. Never overrides pre-existing keys in `env`.
 */
export function parseEnvContent(content, env = {}) {
  if (typeof content !== 'string') return env;

  const preExistingKeys = new Set(
    Object.keys(env).filter((key) => env[key] !== undefined)
  );

  for (const rawLine of content.split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    line = line.replace(/^export\s+/, '');
    const match = line.match(/^([\w.-]+)\s*=\s*(.*)$/);
    if (!match) continue;

    const key = match[1];
    const rawRest = match[2].trimStart();
    let parsedValue = '';

    if (rawRest.startsWith('"') || rawRest.startsWith("'")) {
      const quote = rawRest[0];
      let out = '';
      let closed = false;
      for (let i = 1; i < rawRest.length; i += 1) {
        const ch = rawRest[i];
        if (ch === '\\' && i + 1 < rawRest.length) {
          const next = rawRest[i + 1];
          if (next === quote || next === '\\') {
            out += next;
            i += 1;
            continue;
          }
        }
        if (ch === quote) {
          closed = true;
          break;
        }
        out += ch;
      }
      parsedValue = closed ? out : out.replace(/\s+#.*$/, '').trim();
    } else if (rawRest.startsWith('#') || rawRest === '') {
      parsedValue = '';
    } else {
      parsedValue = rawRest.replace(/\s+#.*$/, '').trim();
    }

    if (!preExistingKeys.has(key)) {
      env[key] = parsedValue;
    }
  }

  return env;
}

/**
 * Loads `.env` from `cwd` first, then the repository root relative to this module.
 */
export function loadLocalEnv(targetEnv = process.env, cwd = process.cwd()) {
  try {
    const moduleDir = path.dirname(fileURLToPath(import.meta.url));
    const candidateEnvPaths = [
      path.resolve(cwd, '.env'),
      path.resolve(moduleDir, '..', '.env'),
    ];
    for (const envPath of candidateEnvPaths) {
      if (fs.existsSync(envPath)) {
        const content = fs.readFileSync(envPath, 'utf8');
        parseEnvContent(content, targetEnv);
        return envPath;
      }
    }
  } catch {}
  return null;
}

/**
 * Validates `MEDTRACE_WEBTRIGGER_URL`, enforcing `https://` without embedded credentials
 * unless `allowInsecureLocalhost === true` for explicit local loopback development/testing.
 */
export function validateWebtriggerUrl(
  rawUrl,
  allowInsecureLocalhost = process.env.MEDTRACE_ALLOW_INSECURE_LOCALHOST === 'true'
) {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    return { ok: false, error: 'MEDTRACE_WEBTRIGGER_URL is not configured.' };
  }

  const trimmed = rawUrl.trim();
  if (CONTROL_CHAR_RE.test(trimmed)) {
    return { ok: false, error: 'MEDTRACE_WEBTRIGGER_URL contains invalid control characters.' };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { ok: false, error: 'MEDTRACE_WEBTRIGGER_URL is not a valid URL.' };
  }

  if (parsed.username !== '' || parsed.password !== '') {
    return { ok: false, error: 'MEDTRACE_WEBTRIGGER_URL must not contain embedded credentials.' };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return { ok: false, error: 'MEDTRACE_WEBTRIGGER_URL is missing a hostname.' };
  }

  if (parsed.protocol === 'https:') {
    return { ok: true, url: parsed.toString() };
  }

  const isLoopback = LOOPBACK_HOSTS.has(hostname);
  if (parsed.protocol === 'http:' && isLoopback) {
    if (allowInsecureLocalhost === true) {
      return { ok: true, url: parsed.toString() };
    }
    return {
      ok: false,
      error:
        'Insecure http:// loopback MEDTRACE_WEBTRIGGER_URL rejected; set MEDTRACE_ALLOW_INSECURE_LOCALHOST=true for local development/testing only.',
    };
  }

  return {
    ok: false,
    error: `Unsafe MEDTRACE_WEBTRIGGER_URL (${parsed.protocol}//${hostname}): https:// is required.`,
  };
}

/**
 * Resolves `MEDTRACE_REQUEST_TIMEOUT_MS` (default 15000ms, clamped to 1000..60000ms).
 */
export function resolveRequestTimeoutMs(raw = process.env.MEDTRACE_REQUEST_TIMEOUT_MS) {
  if (typeof raw !== 'string' && typeof raw !== 'number') {
    return DEFAULT_REQUEST_TIMEOUT_MS;
  }
  const str = String(raw).trim();
  if (!str) return DEFAULT_REQUEST_TIMEOUT_MS;
  const parsed = Number(str);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_REQUEST_TIMEOUT_MS;
  }
  return Math.min(MAX_REQUEST_TIMEOUT_MS, Math.max(MIN_REQUEST_TIMEOUT_MS, Math.floor(parsed)));
}

/**
 * Formats truthful source labels aligned with the active Forge KVS dataset mode.
 */
export function formatSourceLabel(datasetMode) {
  if (datasetMode === 'LIVE') return 'Atlassian Cloud (Forge KVS - LIVE)';
  if (datasetMode === 'DEMO') return 'Atlassian Forge KVS (DEMO Dataset)';
  return 'Atlassian Forge KVS (UNSPECIFIED)';
}

function collectCanonicalLinkKeys(link) {
  return [
    link?.hazard?.key,
    link?.hazard?.id,
    link?.work?.key,
    link?.work?.id,
    link?.test?.testKey,
    link?.test?.id,
    link?.spec?.id,
    link?.spec?.pageId,
    link?.signature?.id,
  ]
    .filter((val) => typeof val === 'string' && val.trim() !== '')
    .map((val) => val.trim().toLowerCase());
}

/**
 * Sends an HMAC-SHA256 signed, nonce-protected request to the configured Forge webtrigger.
 */
export async function signedCloudRequest(method, payloadObj, configOverride = undefined) {
  const rawSecret =
    configOverride && typeof configOverride.secret === 'string'
      ? configOverride.secret
      : process.env.MEDTRACE_MCP_SECRET;
  if (typeof rawSecret !== 'string' || rawSecret.trim() === '') {
    return {
      ok: false,
      status: 0,
      errorType: 'CONFIG_ERROR',
      error: 'MEDTRACE_MCP_SECRET is not configured.',
    };
  }

  const rawUrl =
    configOverride && typeof configOverride.webtriggerUrl === 'string'
      ? configOverride.webtriggerUrl
      : process.env.MEDTRACE_WEBTRIGGER_URL;
  const allowInsecureLocalhost =
    configOverride && typeof configOverride.allowInsecureLocalhost === 'boolean'
      ? configOverride.allowInsecureLocalhost
      : process.env.MEDTRACE_ALLOW_INSECURE_LOCALHOST === 'true';

  const urlCheck = validateWebtriggerUrl(rawUrl, allowInsecureLocalhost);
  if (!urlCheck.ok) {
    return {
      ok: false,
      status: 0,
      errorType: 'CONFIG_ERROR',
      error: urlCheck.error,
    };
  }

  const timeoutMs = resolveRequestTimeoutMs(
    configOverride && configOverride.timeoutMs !== undefined
      ? configOverride.timeoutMs
      : process.env.MEDTRACE_REQUEST_TIMEOUT_MS
  );

  try {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomUUID();
    const payload = method === 'POST' ? JSON.stringify(payloadObj || {}) : '';
    const signature = crypto
      .createHmac('sha256', rawSecret)
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

    const resp = await fetch(urlCheck.url, {
      method,
      headers,
      ...(method === 'POST' ? { body: payload } : {}),
      signal: AbortSignal.timeout(timeoutMs),
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
    if (err?.name === 'TimeoutError' || err?.name === 'AbortError' || err?.code === 'ABORT_ERR') {
      return {
        ok: false,
        status: 0,
        errorType: 'TIMEOUT',
        error: `Forge webtrigger request timed out after ${timeoutMs}ms (possible Forge cold start).`,
      };
    }
    return {
      ok: false,
      status: 0,
      errorType: 'NETWORK_ERROR',
      error: err?.message || 'Network error communicating with Forge webtrigger.',
    };
  }
}

export const TOOLS = [
  {
    name: 'medtrace_get_hazard_lineage',
    description:
      'Retrieves complete ISO 14971 hazard safety lineage, linked Confluence SRS specifications, and verification test status live from Atlassian Cloud.',
    inputSchema: {
      type: 'object',
      properties: {
        hazardKey: {
          type: 'string',
          description:
            'Optional hazard, Jira issue, spec, test, or signature key (e.g. HAZ-101, MED-42, TEST-88). Omit to retrieve full project lineage.',
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

/**
 * Classifies Forge webtrigger network, auth/replay, policy/validation, and upstream 5xx failures
 * into truthful MCP tool error responses (`isError: true`).
 */
export function cloudErrorResult(id, cloudResp) {
  const status = Number(cloudResp?.status ?? 0);
  let payload;

  if (status === 0) {
    payload = {
      source: 'UNAVAILABLE',
      errorType: cloudResp?.errorType || 'NETWORK_ERROR',
      httpStatus: 0,
      error: cloudResp?.error || 'Unable to reach Forge webtrigger.',
      hint: 'Verify MEDTRACE_WEBTRIGGER_URL connectivity and retry.',
    };
  } else if (status === 401 || status === 409) {
    payload = {
      source: 'ATLASSIAN_CLOUD_REJECTED',
      errorType: status === 401 ? 'AUTH_FAILED' : 'REPLAY_DETECTED',
      httpStatus: status,
      error: cloudResp?.error || `HTTP ${status}`,
      hint:
        status === 401
          ? 'Verify MEDTRACE_MCP_SECRET matches Forge environment and clock skew.'
          : 'Duplicate nonce rejected; retry request.',
    };
  } else if (status >= 400 && status < 500) {
    payload = {
      source: 'POLICY_OR_VALIDATION_ERROR',
      errorType: 'BACKEND_REJECTED',
      httpStatus: status,
      error: cloudResp?.error || `HTTP ${status}`,
      details: cloudResp?.data,
    };
  } else {
    payload = {
      source: 'BACKEND_ERROR',
      errorType: 'UPSTREAM_ERROR',
      httpStatus: status,
      error: cloudResp?.error || `HTTP ${status}`,
      hint: 'Forge backend returned an internal error; inspect Forge logs.',
    };
  }

  return {
    jsonrpc: '2.0',
    id,
    result: {
      isError: true,
      content: [
        {
          type: 'text',
          text: JSON.stringify(payload, null, 2),
        },
      ],
    },
  };
}

function jsonRpcError(id, code, message) {
  return {
    jsonrpc: '2.0',
    id,
    error: { code, message },
  };
}

/**
 * Processes a parsed JSON-RPC 2.0 request or notification object.
 */
export async function handleMessage(message) {
  if (Array.isArray(message)) {
    return jsonRpcError(null, -32600, 'Invalid Request: batch requests are not supported.');
  }

  if (!isPlainObject(message)) {
    return jsonRpcError(null, -32600, 'Invalid Request: message must be a JSON object.');
  }

  const hasId = Object.prototype.hasOwnProperty.call(message, 'id') && message.id !== undefined;
  const rawId = message.id;
  const isValidId =
    !hasId ||
    rawId === null ||
    typeof rawId === 'string' ||
    (typeof rawId === 'number' && Number.isFinite(rawId));

  if (!isValidId) {
    return jsonRpcError(null, -32600, 'Invalid Request: id must be a string, finite number, or null.');
  }

  const safeId = hasId ? rawId : null;

  if (message.jsonrpc !== '2.0') {
    return jsonRpcError(safeId, -32600, 'Invalid Request: jsonrpc must be "2.0".');
  }

  if (typeof message.method !== 'string' || message.method.trim() === '') {
    return jsonRpcError(safeId, -32600, 'Invalid Request: method must be a non-empty string.');
  }

  // Notifications carry no `id` (or `id === undefined`) and must produce zero stdout output.
  if (!hasId) {
    return null;
  }

  const id = rawId;
  const method = message.method.trim();
  const params = message.params;

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

  if (method === 'ping') {
    return {
      jsonrpc: '2.0',
      id,
      result: {},
    };
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
    if (!isPlainObject(params) || typeof params.name !== 'string' || params.name.trim() === '') {
      return jsonRpcError(id, -32602, 'Invalid params: tool name is required.');
    }

    if (params.arguments !== undefined && !isPlainObject(params.arguments)) {
      return jsonRpcError(id, -32602, 'Invalid params: arguments must be a JSON object.');
    }

    const name = params.name.trim();
    const args = params.arguments ?? {};

    if (name === 'medtrace_get_hazard_lineage') {
      const cloudResp = await signedCloudRequest('GET');
      if (!cloudResp.ok) {
        return cloudErrorResult(id, cloudResp);
      }
      if (!Array.isArray(cloudResp.data?.traceLinks)) {
        return cloudErrorResult(id, {
          ok: false,
          status: 502,
          error: 'Malformed compliance suite response from Forge webtrigger: missing traceLinks array.',
          data: cloudResp.data,
        });
      }

      const liveSuite = cloudResp.data;
      const initialized = liveSuite.initialized ?? liveSuite.traceLinks.length > 0;
      const source = formatSourceLabel(liveSuite.datasetMode);
      const rawHazardKey = typeof args.hazardKey === 'string' ? args.hazardKey : '';
      const rawIssueKey = typeof args.issueKey === 'string' ? args.issueKey : '';
      const lookupKey = (rawHazardKey || rawIssueKey).trim();

      if (lookupKey) {
        const lower = lookupKey.toLowerCase();
        const matches = liveSuite.traceLinks.filter((l) =>
          collectCanonicalLinkKeys(l).includes(lower)
        );

        if (matches.length === 0) {
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      source,
                      datasetMode: liveSuite.datasetMode,
                      initialized,
                      found: false,
                      queriedKey: lookupKey,
                      message: `No trace link found for key "${lookupKey}" in project "${liveSuite.projectName || 'MedTrace'}".`,
                      availableKeys: liveSuite.traceLinks.map((l) => ({
                        hazardKey: l.hazard?.key,
                        workKey: l.work?.key,
                        specId: l.spec?.id,
                        testKey: l.test?.testKey,
                      })),
                    },
                    null,
                    2
                  ),
                },
              ],
            },
          };
        }

        const match = matches[0];
        return {
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    source,
                    datasetMode: liveSuite.datasetMode,
                    initialized,
                    found: true,
                    traceLink: match,
                    ...(matches.length > 1 ? { matchedLinks: matches } : {}),
                    regulatoryStatus: match.complianceState,
                    riskClass: match.hazard?.riskClass,
                    safetyRequirement: match.spec?.title,
                    testStatus: match.test?.status,
                    part11Valid: match.signature?.isValid,
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
                  source,
                  projectName: liveSuite.projectName,
                  datasetMode: liveSuite.datasetMode,
                  initialized,
                  totalHazards: liveSuite.totalHazards,
                  verifiedPercentage: `${liveSuite.verifiedPercentage ?? 0}%`,
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
        prDiff: typeof args.prDiff === 'string' ? args.prDiff : undefined,
        componentName: typeof args.componentName === 'string' ? args.componentName : undefined,
        issueKey: typeof args.issueKey === 'string' ? args.issueKey : undefined,
      });

      if (!cloudResp.ok) {
        return cloudErrorResult(id, cloudResp);
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
      const hazardKey = typeof args.hazardKey === 'string' ? args.hazardKey.trim() : '';
      if (!hazardKey) {
        return jsonRpcError(id, -32602, 'Invalid params: hazardKey is required.');
      }
      if (args.simulate !== true) {
        return jsonRpcError(
          id,
          -32602,
          'Invalid params: simulate must be boolean true to confirm demo simulation mode.'
        );
      }
      if (args.attestationConfirmed !== true) {
        return jsonRpcError(
          id,
          -32602,
          'Invalid params: attestationConfirmed must be boolean true.'
        );
      }
      if (args.meaning !== undefined && typeof args.meaning !== 'string') {
        return jsonRpcError(
          id,
          -32602,
          'Invalid params: meaning must be a string when provided.'
        );
      }

      const cloudResp = await signedCloudRequest('POST', {
        action: 'remediate',
        hazardKey,
        simulate: true,
        attestationConfirmed: true,
        meaning:
          typeof args.meaning === 'string' && args.meaning.trim() !== ''
            ? args.meaning.trim()
            : undefined,
      });

      if (!cloudResp.ok) {
        return cloudErrorResult(id, cloudResp);
      }

      const summary = cloudResp.data?.summary;
      const datasetMode = summary?.datasetMode ?? 'DEMO';

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  source: formatSourceLabel(datasetMode),
                  datasetMode,
                  remediated: true,
                  hazardKey,
                  summary,
                },
                null,
                2
              ),
            },
          ],
        },
      };
    }

    return jsonRpcError(id, -32601, `Unknown tool: ${name}`);
  }

  return jsonRpcError(id, -32601, `Unsupported method: ${method}`);
}

/**
 * Creates a serialized FIFO NDJSON line processor so concurrent stdin lines never flush out of order
 * and parse errors emit JSON-RPC `-32700` with `id: null` before inspecting message fields.
 */
export function createLineProcessor(options = {}) {
  const write = options.write || ((text) => process.stdout.write(text));
  const onError = options.onError || ((...args) => console.error(...args));
  const handler = options.handler || handleMessage;
  let lineQueue = Promise.resolve();

  function processLine(line) {
    lineQueue = lineQueue
      .then(async () => {
        if (typeof line !== 'string' || !line.trim()) return;

        let message;
        try {
          message = JSON.parse(line);
        } catch {
          write(JSON.stringify(jsonRpcError(null, -32700, 'Parse error')) + '\n');
          return;
        }

        try {
          const response = await handler(message);
          if (response !== null && response !== undefined) {
            write(JSON.stringify(response) + '\n');
          }
        } catch (err) {
          onError('Error handling MCP JSON-RPC message:', err);
          if (
            isPlainObject(message) &&
            (!Object.prototype.hasOwnProperty.call(message, 'id') || message.id === undefined)
          ) {
            return;
          }
          const safeId =
            isPlainObject(message) &&
            (message.id === null ||
              typeof message.id === 'string' ||
              (typeof message.id === 'number' && Number.isFinite(message.id)))
              ? message.id
              : null;
          write(
            JSON.stringify(
              jsonRpcError(safeId, -32603, `Internal error: ${err?.message || 'unexpected failure'}`)
            ) + '\n'
          );
        }
      })
      .catch((err) => {
        try {
          onError('Unexpected MCP line queue error:', err);
        } catch {}
      });

    return lineQueue;
  }

  processLine.waitForIdle = () => lineQueue;
  return processLine;
}

const isMainModule =
  process.env.MEDTRACE_MCP_NO_AUTOSTART !== '1' &&
  process.env.MEDTRACE_MCP_NO_AUTOSTART !== 'true' &&
  typeof process.argv[1] === 'string' &&
  process.argv[1].length > 0 &&
  (() => {
    try {
      const moduleRealUrl = (() => {
        try {
          return pathToFileURL(fs.realpathSync(fileURLToPath(import.meta.url))).href;
        } catch {
          return import.meta.url;
        }
      })();
      const resolvedArgv = pathToFileURL(path.resolve(process.argv[1])).href;
      const realArgv = fs.existsSync(process.argv[1])
        ? pathToFileURL(fs.realpathSync(process.argv[1])).href
        : resolvedArgv;
      return (
        import.meta.url === resolvedArgv ||
        import.meta.url === realArgv ||
        moduleRealUrl === realArgv
      );
    } catch {
      return false;
    }
  })();

if (isMainModule) {
  loadLocalEnv();

  const mcpSecret = process.env.MEDTRACE_MCP_SECRET;
  if (typeof mcpSecret !== 'string' || mcpSecret.trim() === '') {
    console.error('[MedTrace MCP Server] Fatal Security Error: MEDTRACE_MCP_SECRET is not configured.');
    console.error('[MedTrace MCP Server] Fail-closed: Refusing to start with missing shared secret.');
    console.error('[MedTrace MCP Server] Configure MEDTRACE_MCP_SECRET in your environment or .env before starting.');
    process.exit(1);
  }

  const urlValidation = validateWebtriggerUrl(
    process.env.MEDTRACE_WEBTRIGGER_URL,
    process.env.MEDTRACE_ALLOW_INSECURE_LOCALHOST === 'true'
  );
  if (!urlValidation.ok) {
    console.error(`[MedTrace MCP Server] Fatal Configuration Error: ${urlValidation.error}`);
    console.error('[MedTrace MCP Server] Fail-closed: Export a valid https:// MEDTRACE_WEBTRIGGER_URL before starting.');
    process.exit(1);
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  const processLine = createLineProcessor();
  rl.on('line', (line) => {
    void processLine(line);
  });
}
