import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

process.env.MEDTRACE_MCP_NO_AUTOSTART = '1';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const mcpEntry = path.resolve(__dirname, '..', 'mcp-server', 'index.mjs');

const mcpModule = await import('../mcp-server/index.mjs');

function makeSampleSuite(datasetMode = 'DEMO', overrides = {}) {
  return {
    projectName: datasetMode === 'LIVE' ? 'MedTrace Clinical Live' : 'Smart Infusion Pump Firmware v2.1',
    datasetMode,
    initialized: true,
    standards: ['IEC 62304:2006+A1:2015', 'ISO 14971:2019', 'FDA 21 CFR Part 11'],
    totalHazards: 2,
    classCCount: 1,
    classBCount: 1,
    classACount: 0,
    verifiedPercentage: 50,
    releaseBlocked: true,
    blockingReasons: ['IEC 62304 Critical Gap: HAZ-101 requires verified test coverage.'],
    signatureDriftCount: 0,
    lastAuditTimestamp: '2026-11-13T00:00:00.000Z',
    traceLinks: [
      {
        id: 'trace-HAZ-101-srs-104-MED-42',
        hazard: {
          id: 'haz-id-101',
          key: 'HAZ-101',
          title: 'Over-Infusion Hazard',
          riskClass: 'CLASS_C',
          severity: 'CATASTROPHIC',
          probability: 'OCCASIONAL',
          mitigationRequirementId: 'srs-104',
          status: 'ACTION_REQUIRED',
        },
        spec: {
          id: 'srs-104',
          pageId: '98304',
          title: 'SRS-104: Hardware Bolus Clamp',
          version: 3,
          sha256Hash: 'a'.repeat(64),
          lastSignedHash: 'a'.repeat(64),
          isSignatureInvalidated: false,
          contentSnippet: 'Hardware clamp clause',
          lastUpdated: '2026-11-12T00:00:00.000Z',
        },
        work: {
          id: 'work-id-42',
          key: 'MED-42',
          title: 'Implement Hardware Clamp',
          status: 'In Progress',
          assignee: 'Dr. Sarah Lin',
        },
        test: {
          id: 'test-id-88',
          testKey: 'TEST-88',
          title: 'Motor Stress Test',
          testType: 'Automated HIL (Hardware-in-Loop)',
          status: 'UNTESTED',
        },
        signature: {
          id: 'sig-id-001',
          signedBy: 'Dr. Sarah Lin',
          signedAt: '2026-11-12T00:00:00.000Z',
          role: 'Lead Clinical Safety Engineer',
          meaning: 'Safety mitigation review',
          artifactSha256: 'a'.repeat(64),
          isValid: true,
        },
        complianceState: 'SAFETY_VIOLATION',
        violations: ['IEC 62304 Critical Gap: HAZ-101 requires verified test coverage.'],
      },
      {
        id: 'trace-HAZ-102-srs-105-MED-43',
        hazard: {
          id: 'haz-id-102',
          key: 'HAZ-102',
          title: 'Air-In-Line Detection Failure',
          riskClass: 'CLASS_B',
          severity: 'SERIOUS',
          probability: 'REMOTE',
          mitigationRequirementId: 'srs-105',
          status: 'MITIGATED',
        },
        spec: {
          id: 'srs-105',
          pageId: '98305',
          title: 'SRS-105: Ultrasonic Sensor Check',
          version: 2,
          sha256Hash: 'b'.repeat(64),
          lastSignedHash: 'b'.repeat(64),
          isSignatureInvalidated: false,
          contentSnippet: 'Ultrasonic sensor clause',
          lastUpdated: '2026-11-12T00:00:00.000Z',
        },
        work: {
          id: 'work-id-43',
          key: 'MED-43',
          title: 'Air Bubble Detector Driver',
          status: 'Done',
          assignee: 'Alice QA',
        },
        test: {
          id: 'test-id-89',
          testKey: 'TEST-89',
          title: 'Sensor Calibration Test',
          testType: 'Integration Test',
          status: 'PASSED',
        },
        signature: {
          id: 'sig-id-002',
          signedBy: 'Alice QA',
          signedAt: '2026-11-12T00:00:00.000Z',
          role: 'QA Lead',
          meaning: 'Release sign-off',
          artifactSha256: 'b'.repeat(64),
          isValid: true,
        },
        complianceState: 'VERIFIED',
        violations: [],
      },
    ],
    ...overrides,
  };
}

/**
 * Local Forge webtrigger simulator strictly enforcing HMAC-SHA256 via crypto.timingSafeEqual,
 * timestamp bounds [-300s, +30s], and single-use nonces (409 on replay).
 */
async function startAuthenticatedWebtriggerServer(secret) {
  const seenNonces = new Set();
  const requests = [];
  const sockets = new Set();

  const state = {
    suite: makeSampleSuite('DEMO'),
    overrideStatus: null,
    overrideBody: null,
    delayMs: 0,
    hangForever: false,
    onRequest: null,
  };

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', async () => {
      const rawBody = Buffer.concat(chunks).toString('utf8');
      const timestamp = String(req.headers['x-medtrace-timestamp'] ?? '').trim();
      const nonce = String(req.headers['x-medtrace-nonce'] ?? '').trim();
      const signature = String(req.headers['x-medtrace-signature'] ?? '').trim();

      const now = Date.now();
      const tsNum = Number(timestamp);
      const validTs =
        /^\d+$/.test(timestamp) &&
        Number.isSafeInteger(tsNum) &&
        now - tsNum <= 300_000 &&
        tsNum - now <= 30_000;

      const validNonce = nonce.length >= 1 && nonce.length <= 256;
      const validSigFormat = /^sha256=[a-f0-9]{64}$/i.test(signature);

      let sigMatches = false;
      if (validTs && validNonce && validSigFormat) {
        const expectedHex = crypto
          .createHmac('sha256', secret)
          .update(`${timestamp}.${nonce}.${rawBody}`)
          .digest('hex');
        const providedBuf = Buffer.from(signature.slice('sha256='.length).toLowerCase(), 'hex');
        const expectedBuf = Buffer.from(expectedHex, 'hex');
        sigMatches =
          providedBuf.length === expectedBuf.length &&
          providedBuf.length === 32 &&
          crypto.timingSafeEqual(providedBuf, expectedBuf);
      }

      if (!validTs || !validNonce || !sigMatches) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized: Invalid HMAC signature, timestamp, or nonce.' }));
        return;
      }

      if (seenNonces.has(nonce)) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Conflict: Replay attack detected.' }));
        return;
      }
      seenNonces.add(nonce);

      let parsedBody = null;
      if (rawBody) {
        try {
          parsedBody = JSON.parse(rawBody);
        } catch {
          parsedBody = null;
        }
      }

      const record = {
        method: req.method,
        headers: req.headers,
        rawBody,
        body: parsedBody,
      };
      requests.push(record);

      if (state.hangForever) {
        return;
      }

      const customResult = state.onRequest ? await state.onRequest(record, state) : null;
      const effectiveDelay = customResult?.delayMs ?? state.delayMs;
      if (effectiveDelay > 0) {
        await new Promise((r) => setTimeout(r, effectiveDelay));
      }

      if (customResult?.status) {
        res.writeHead(customResult.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(customResult.body ?? {}));
        return;
      }

      if (state.overrideStatus) {
        res.writeHead(state.overrideStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(state.overrideBody ?? { error: `Forced HTTP ${state.overrideStatus}` }));
        return;
      }

      if (req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(state.suite));
        return;
      }

      if (req.method === 'POST') {
        if (!parsedBody || typeof parsedBody !== 'object') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Bad Request: Invalid JSON object.' }));
          return;
        }
        if (parsedBody.action === 'verify') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              datasetMode: state.suite.datasetMode,
              initialized: state.suite.initialized,
              canShipToClinicalProduction: false,
              touchesSafetyCriticalCode: true,
              affectedHazards: ['HAZ-101'],
            })
          );
          return;
        }
        if (parsedBody.action === 'remediate') {
          if (state.suite.datasetMode === 'LIVE') {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(
              JSON.stringify({
                error: 'Forbidden: Cannot auto-remediate gaps on a LIVE compliance suite via webtrigger.',
              })
            );
            return;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              success: true,
              summary: { ...state.suite, releaseBlocked: false },
            })
          );
          return;
        }
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request: Unknown action.' }));
        return;
      }

      res.writeHead(405, { 'Content-Type': 'application/json', Allow: 'GET, POST' });
      res.end(JSON.stringify({ error: 'Method Not Allowed' }));
    });
  });

  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  return {
    url: `http://127.0.0.1:${port}/webtrigger`,
    port,
    state,
    requests,
    seenNonces,
    async close() {
      for (const s of sockets) s.destroy();
      server.closeAllConnections?.();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

function createIsolatedMcpDir(envFileContent = null) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'medtrace-mcp-e2e-'));
  const mcpDir = path.join(tmpRoot, 'mcp-server');
  fs.mkdirSync(mcpDir, { recursive: true });
  const isolatedEntry = path.join(mcpDir, 'index.mjs');
  fs.copyFileSync(mcpEntry, isolatedEntry);
  if (envFileContent !== null) {
    fs.writeFileSync(path.join(tmpRoot, '.env'), envFileContent, 'utf8');
  }
  return { tmpRoot, mcpDir, isolatedEntry };
}

function spawnMcpChild(entryPath, cwd, envOverrides) {
  const child = spawn(process.execPath, [entryPath], {
    cwd,
    env: {
      PATH: process.env.PATH,
      ...envOverrides,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const lines = [];
  let stdoutBuffer = '';
  let stderr = '';
  const lineListeners = [];

  child.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk.toString('utf8');
    const parts = stdoutBuffer.split('\n');
    stdoutBuffer = parts.pop() || '';
    for (const part of parts) {
      if (!part.trim()) continue;
      lines.push(part);
      while (lineListeners.length > 0) {
        const listener = lineListeners.shift();
        listener();
      }
    }
  });

  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString('utf8');
  });

  async function waitForLineCount(expectedCount, timeoutMs = 5000) {
    const deadline = Date.now() + timeoutMs;
    while (lines.length < expectedCount) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new Error(`Timed out waiting for ${expectedCount} stdout lines (got ${lines.length}). stderr=${stderr}`);
      }
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, Math.min(remaining, 100));
        lineListeners.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  }

  async function rpc(id, method, params) {
    const before = lines.length;
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    await waitForLineCount(before + 1);
    return JSON.parse(lines[before]);
  }

  async function stop() {
    child.stdin.end();
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
    }
    await new Promise((resolve) => child.once('exit', resolve));
  }

  return {
    child,
    lines,
    getStderr: () => stderr,
    waitForLineCount,
    rpc,
    stop,
  };
}

test.describe('MCP Server Unit Helpers (Task MCP-1..MCP-3)', () => {
  test.it('exports hardened protocol, env, URL, error, and source helpers without autostart', () => {
    for (const fnName of [
      'parseEnvContent',
      'validateWebtriggerUrl',
      'resolveRequestTimeoutMs',
      'formatSourceLabel',
      'cloudErrorResult',
      'handleMessage',
      'signedCloudRequest',
      'createLineProcessor',
    ]) {
      assert.strictEqual(typeof mcpModule[fnName], 'function', `Expected export ${fnName}`);
    }
  });

  test.it('parseEnvContent handles quoted # values, escaped quotes, full-line comments, export prefix, and existing env precedence', () => {
    const targetEnv = { EXISTING_KEY: 'from-process-env' };
    const rawEnv = [
      '# Full-line comment',
      '',
      '  # Indented comment',
      'MEDTRACE_WEBTRIGGER_URL="http://127.0.0.1:8080/x#anchor" # inline comment',
      "export MEDTRACE_MCP_SECRET='abc#123\\'quoted' # trailing secret comment",
      'ESCAPED_DOUBLE="val\\"with\\\\slash#hash" # comment',
      'UNQUOTED_KEY=plain_value   # trailing unquoted comment',
      'EMPTY_WITH_COMMENT=   # empty comment',
      'EXISTING_KEY=should-not-override',
      'export MEDTRACE_ALLOW_INSECURE_LOCALHOST=true\r',
    ].join('\n');

    const result = mcpModule.parseEnvContent(rawEnv, targetEnv);
    assert.strictEqual(result.MEDTRACE_WEBTRIGGER_URL, 'http://127.0.0.1:8080/x#anchor');
    assert.strictEqual(result.MEDTRACE_MCP_SECRET, "abc#123'quoted");
    assert.strictEqual(result.ESCAPED_DOUBLE, 'val"with\\slash#hash');
    assert.strictEqual(result.UNQUOTED_KEY, 'plain_value');
    assert.strictEqual(result.EMPTY_WITH_COMMENT, '');
    assert.strictEqual(result.EXISTING_KEY, 'from-process-env');
    assert.strictEqual(result.MEDTRACE_ALLOW_INSECURE_LOCALHOST, 'true');
  });

  test.it('validateWebtriggerUrl enforces https:// unless MEDTRACE_ALLOW_INSECURE_LOCALHOST=true on loopback', () => {
    assert.strictEqual(mcpModule.validateWebtriggerUrl('https://app.hello.atlassian-dev.net/x1/abc', false).ok, true);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('', true).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('not-a-url', true).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('https://user:pass@example.com/x1', true).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('file:///etc/passwd', true).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('ftp://127.0.0.1:8080/x', true).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('http://example.com/x1', true).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('http://127.0.0.1.evil.com/x1', true).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('http://127.0.0.1:8080/x1', false).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('http://localhost:8080/x1', false).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('http://[::1]:8080/x1', false).ok, false);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('http://127.0.0.1:8080/x1', true).ok, true);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('http://localhost:8080/x1', true).ok, true);
    assert.strictEqual(mcpModule.validateWebtriggerUrl('http://[::1]:8080/x1', true).ok, true);
  });

  test.it('resolveRequestTimeoutMs defaults to 15000 and clamps valid inputs to 1000..60000', () => {
    assert.strictEqual(mcpModule.resolveRequestTimeoutMs(undefined), 15000);
    assert.strictEqual(mcpModule.resolveRequestTimeoutMs(''), 15000);
    assert.strictEqual(mcpModule.resolveRequestTimeoutMs('abc'), 15000);
    assert.strictEqual(mcpModule.resolveRequestTimeoutMs('0'), 15000);
    assert.strictEqual(mcpModule.resolveRequestTimeoutMs('-50'), 15000);
    assert.strictEqual(mcpModule.resolveRequestTimeoutMs('150'), 1000);
    assert.strictEqual(mcpModule.resolveRequestTimeoutMs('15000'), 15000);
    assert.strictEqual(mcpModule.resolveRequestTimeoutMs('120000'), 60000);
  });

  test.it('formatSourceLabel and cloudErrorResult map dataset modes and HTTP/network errors accurately', () => {
    assert.strictEqual(mcpModule.formatSourceLabel('LIVE'), 'Atlassian Cloud (Forge KVS - LIVE)');
    assert.strictEqual(mcpModule.formatSourceLabel('DEMO'), 'Atlassian Forge KVS (DEMO Dataset)');
    assert.strictEqual(mcpModule.formatSourceLabel(undefined), 'Atlassian Forge KVS (UNSPECIFIED)');

    const cases = [
      {
        input: { ok: false, status: 0, errorType: 'TIMEOUT', error: 'Timed out' },
        expectedSource: 'UNAVAILABLE',
        expectedErrorType: 'TIMEOUT',
      },
      {
        input: { ok: false, status: 401, error: 'Invalid HMAC' },
        expectedSource: 'ATLASSIAN_CLOUD_REJECTED',
        expectedErrorType: 'AUTH_FAILED',
      },
      {
        input: { ok: false, status: 409, error: 'Replay detected' },
        expectedSource: 'ATLASSIAN_CLOUD_REJECTED',
        expectedErrorType: 'REPLAY_DETECTED',
      },
      {
        input: { ok: false, status: 403, error: 'LIVE mode blocks remediate', data: { error: 'Forbidden' } },
        expectedSource: 'POLICY_OR_VALIDATION_ERROR',
        expectedErrorType: 'BACKEND_REJECTED',
      },
      {
        input: { ok: false, status: 500, error: 'Upstream failure' },
        expectedSource: 'BACKEND_ERROR',
        expectedErrorType: 'UPSTREAM_ERROR',
      },
    ];

    for (const c of cases) {
      const res = mcpModule.cloudErrorResult(99, c.input);
      assert.strictEqual(res.jsonrpc, '2.0');
      assert.strictEqual(res.id, 99);
      assert.strictEqual(res.result.isError, true);
      const parsed = JSON.parse(res.result.content[0].text);
      assert.strictEqual(parsed.source, c.expectedSource);
      assert.strictEqual(parsed.errorType, c.expectedErrorType);
      assert.strictEqual(parsed.httpStatus, c.input.status);
    }
  });

  test.it('handleMessage enforces JSON-RPC 2.0 envelope, ping, notifications, params validation, and local remediate checks with 0 HTTP calls', async () => {
    const batchRes = await mcpModule.handleMessage([{ jsonrpc: '2.0', id: 1, method: 'ping' }]);
    assert.strictEqual(batchRes.id, null);
    assert.strictEqual(batchRes.error.code, -32600);

    const badVersion = await mcpModule.handleMessage({ jsonrpc: '1.0', id: 1, method: 'ping' });
    assert.strictEqual(badVersion.id, 1);
    assert.strictEqual(badVersion.error.code, -32600);

    const badId = await mcpModule.handleMessage({ jsonrpc: '2.0', id: { bad: true }, method: 'ping' });
    assert.strictEqual(badId.id, null);
    assert.strictEqual(badId.error.code, -32600);

    const zeroIdPing = await mcpModule.handleMessage({ jsonrpc: '2.0', id: 0, method: 'ping' });
    assert.deepStrictEqual(zeroIdPing, { jsonrpc: '2.0', id: 0, result: {} });

    const nullIdPing = await mcpModule.handleMessage({ jsonrpc: '2.0', id: null, method: 'ping' });
    assert.deepStrictEqual(nullIdPing, { jsonrpc: '2.0', id: null, result: {} });

    const notif = await mcpModule.handleMessage({ jsonrpc: '2.0', method: 'notifications/initialized' });
    assert.strictEqual(notif, null);

    const unknownMethod = await mcpModule.handleMessage({ jsonrpc: '2.0', id: 2, method: 'does/not/exist' });
    assert.strictEqual(unknownMethod.error.code, -32601);

    const unknownTool = await mcpModule.handleMessage({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'no_such_tool', arguments: {} },
    });
    assert.strictEqual(unknownTool.error.code, -32601);

    for (const badArgs of [null, [], 'x', 42]) {
      const badParamsRes = await mcpModule.handleMessage({
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: { name: 'medtrace_get_hazard_lineage', arguments: badArgs },
      });
      assert.strictEqual(badParamsRes.error.code, -32602);
    }

    // Programmatic signedCloudRequest without secret returns CONFIG_ERROR cleanly
    const origSecret = process.env.MEDTRACE_MCP_SECRET;
    const origUrl = process.env.MEDTRACE_WEBTRIGGER_URL;
    try {
      delete process.env.MEDTRACE_MCP_SECRET;
      delete process.env.MEDTRACE_WEBTRIGGER_URL;
      const cfgErr = await mcpModule.signedCloudRequest('GET');
      assert.strictEqual(cfgErr.ok, false);
      assert.strictEqual(cfgErr.status, 0);
      assert.strictEqual(cfgErr.errorType, 'CONFIG_ERROR');

      // Local remediate validation rejects simulate !== true or attestationConfirmed !== true BEFORE HTTP
      for (const args of [
        { hazardKey: '', simulate: true, attestationConfirmed: true },
        { hazardKey: 'HAZ-101', simulate: false, attestationConfirmed: true },
        { hazardKey: 'HAZ-101', simulate: 'true', attestationConfirmed: true },
        { hazardKey: 'HAZ-101', simulate: true, attestationConfirmed: false },
      ]) {
        const res = await mcpModule.handleMessage({
          jsonrpc: '2.0',
          id: 5,
          method: 'tools/call',
          params: { name: 'medtrace_remediate_safety_gap', arguments: args },
        });
        assert.strictEqual(res.error.code, -32602);
      }
    } finally {
      if (origSecret === undefined) delete process.env.MEDTRACE_MCP_SECRET;
      else process.env.MEDTRACE_MCP_SECRET = origSecret;
      if (origUrl === undefined) delete process.env.MEDTRACE_WEBTRIGGER_URL;
      else process.env.MEDTRACE_WEBTRIGGER_URL = origUrl;
    }
  });

  test.it('createLineProcessor emits -32700 with id:null on malformed JSON and continues processing', async () => {
    const outputs = [];
    const errors = [];
    const processLine = mcpModule.createLineProcessor({
      write: (text) => outputs.push(text),
      onError: (msg) => errors.push(msg),
    });

    await processLine('{bad');
    await processLine(JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'ping' }));

    assert.strictEqual(outputs.length, 2);
    const first = JSON.parse(outputs[0]);
    assert.strictEqual(first.id, null);
    assert.strictEqual(first.error.code, -32700);
    const second = JSON.parse(outputs[1]);
    assert.deepStrictEqual(second, { jsonrpc: '2.0', id: 7, result: {} });
  });
});

test.describe('MCP Server Stdio E2E with Authenticated HMAC/Nonce Webtrigger (Task TEST-2)', () => {
  test.it('fails closed on missing secret, missing/invalid URL, remote http://, and loopback http:// without opt-in flag', async () => {
    const cases = [
      { name: 'missing secret', env: { MEDTRACE_WEBTRIGGER_URL: 'https://example.com/x' } },
      { name: 'missing URL', env: { MEDTRACE_MCP_SECRET: 'sec-123' } },
      { name: 'invalid URL', env: { MEDTRACE_MCP_SECRET: 'sec-123', MEDTRACE_WEBTRIGGER_URL: 'not-a-url' } },
      {
        name: 'http://example.com even with opt-in',
        env: {
          MEDTRACE_MCP_SECRET: 'sec-123',
          MEDTRACE_WEBTRIGGER_URL: 'http://example.com/x',
          MEDTRACE_ALLOW_INSECURE_LOCALHOST: 'true',
        },
      },
      {
        name: 'http://127.0.0.1 without opt-in',
        env: {
          MEDTRACE_MCP_SECRET: 'sec-123',
          MEDTRACE_WEBTRIGGER_URL: 'http://127.0.0.1:9999/x',
        },
      },
    ];

    for (const c of cases) {
      const { tmpRoot, mcpDir, isolatedEntry } = createIsolatedMcpDir();
      try {
        const child = spawn(process.execPath, [isolatedEntry], {
          cwd: mcpDir,
          env: { PATH: process.env.PATH, ...c.env },
          stdio: ['pipe', 'pipe', 'pipe'],
        });
        const exitCode = await new Promise((resolve) => {
          const timer = setTimeout(() => {
            child.kill('SIGKILL');
            resolve('TIMEOUT');
          }, 2000);
          child.once('exit', (code) => {
            clearTimeout(timer);
            resolve(code);
          });
        });
        assert.notStrictEqual(exitCode, 'TIMEOUT', `Server did not fail-closed at startup for ${c.name}`);
        assert.notStrictEqual(exitCode, 0, `Expected non-zero exit code for ${c.name}`);
      } finally {
        fs.rmSync(tmpRoot, { recursive: true, force: true });
      }
    }
  });

  test.it('loads .env quoted values with inline # comments, full-line comments, export prefix, and lets process.env win', async () => {
    const realSecret = 'abc#123';
    const srv = await startAuthenticatedWebtriggerServer(realSecret);
    const envContent = [
      '# Comment header',
      'export MEDTRACE_MCP_SECRET="abc#123" # inline secret comment',
      `MEDTRACE_WEBTRIGGER_URL="${srv.url}" # local tunnel`,
      'MEDTRACE_ALLOW_INSECURE_LOCALHOST=true # enable localhost',
    ].join('\n');

    const { tmpRoot, isolatedEntry } = createIsolatedMcpDir(envContent);
    const proc = spawnMcpChild(isolatedEntry, tmpRoot, {});
    try {
      const pingRes = await proc.rpc(1, 'ping', {});
      assert.deepStrictEqual(pingRes, { jsonrpc: '2.0', id: 1, result: {} });

      const lineageRes = await proc.rpc(2, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: { hazardKey: 'HAZ-101' },
      });
      const parsed = JSON.parse(lineageRes.result.content[0].text);
      assert.strictEqual(parsed.found, true);
      assert.strictEqual(srv.requests.length, 1);
    } finally {
      await proc.stop();
      fs.rmSync(tmpRoot, { recursive: true, force: true });
      await srv.close();
    }

    // Verify existing process.env is NOT overridden by .env
    const processSecret = 'process-env-wins-secret';
    const srv2 = await startAuthenticatedWebtriggerServer(processSecret);
    const overrideEnv = [
      'MEDTRACE_MCP_SECRET="wrong-secret-from-dotenv" # should be ignored',
      `MEDTRACE_WEBTRIGGER_URL="${srv2.url}" # local tunnel`,
      'MEDTRACE_ALLOW_INSECURE_LOCALHOST=true',
    ].join('\n');
    const iso2 = createIsolatedMcpDir(overrideEnv);
    const proc2 = spawnMcpChild(iso2.isolatedEntry, iso2.tmpRoot, {
      MEDTRACE_MCP_SECRET: processSecret,
    });
    try {
      const res = await proc2.rpc(1, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: {},
      });
      assert.strictEqual(res.result.isError, undefined);
      const parsed = JSON.parse(res.result.content[0].text);
      assert.strictEqual(parsed.datasetMode, 'DEMO');
    } finally {
      await proc2.stop();
      fs.rmSync(iso2.tmpRoot, { recursive: true, force: true });
      await srv2.close();
    }
  });

  test.it('enforces HMAC, nonce replay (409), 401 mismatch, JSON-RPC edge cases, and serialized FIFO lineQueue ordering', async () => {
    const secret = 'e2e-hmac-secret-01';
    const srv = await startAuthenticatedWebtriggerServer(secret);

    // Direct check that mock server itself rejects bad HMAC with 401 and nonce replay with 409
    const ts = Date.now().toString();
    const nonce = 'fixed-replay-nonce';
    const badResp = await fetch(srv.url, {
      method: 'GET',
      headers: {
        'x-medtrace-timestamp': ts,
        'x-medtrace-nonce': nonce,
        'x-medtrace-signature': `sha256=${'0'.repeat(64)}`,
      },
    });
    assert.strictEqual(badResp.status, 401);

    const goodSig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.`).digest('hex');
    const firstResp = await fetch(srv.url, {
      method: 'GET',
      headers: {
        'x-medtrace-timestamp': ts,
        'x-medtrace-nonce': nonce,
        'x-medtrace-signature': `sha256=${goodSig}`,
      },
    });
    assert.strictEqual(firstResp.status, 200);
    const replayResp = await fetch(srv.url, {
      method: 'GET',
      headers: {
        'x-medtrace-timestamp': ts,
        'x-medtrace-nonce': nonce,
        'x-medtrace-signature': `sha256=${goodSig}`,
      },
    });
    assert.strictEqual(replayResp.status, 409);

    // Delay GET (request 1) by 120ms and return POST verify (request 2) immediately (0ms)
    srv.state.onRequest = async (record) => {
      if (record.method === 'GET') {
        return { delayMs: 120 };
      }
      return { delayMs: 0 };
    };

    const { tmpRoot, isolatedEntry } = createIsolatedMcpDir('');
    const proc = spawnMcpChild(isolatedEntry, tmpRoot, {
      MEDTRACE_MCP_SECRET: secret,
      MEDTRACE_WEBTRIGGER_URL: srv.url,
      MEDTRACE_ALLOW_INSECURE_LOCALHOST: 'true',
    });

    try {
      const burst = [
        '{bad json',
        JSON.stringify({
          jsonrpc: '2.0',
          id: 101,
          method: 'tools/call',
          params: { name: 'medtrace_get_hazard_lineage', arguments: {} },
        }),
        JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
        JSON.stringify({
          jsonrpc: '2.0',
          id: 102,
          method: 'tools/call',
          params: { name: 'medtrace_verify_iec_compliance', arguments: { issueKey: 'MED-42' } },
        }),
        JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'ping' }),
        JSON.stringify([{ jsonrpc: '2.0', id: 103, method: 'ping' }]),
        JSON.stringify({
          jsonrpc: '2.0',
          id: 104,
          method: 'tools/call',
          params: { name: 'medtrace_get_hazard_lineage', arguments: null },
        }),
      ].join('\n') + '\n';

      proc.child.stdin.write(burst);
      await proc.waitForLineCount(6, 5000);

      // Give event loop a brief tick to verify the notification produced 0 extra lines
      await new Promise((r) => setTimeout(r, 50));
      assert.strictEqual(proc.lines.length, 6);

      const parsedLines = proc.lines.map((l) => JSON.parse(l));
      assert.strictEqual(parsedLines[0].id, null);
      assert.strictEqual(parsedLines[0].error.code, -32700);

      assert.strictEqual(parsedLines[1].id, 101);
      assert.strictEqual(parsedLines[2].id, 102);
      assert.deepStrictEqual(parsedLines[3], { jsonrpc: '2.0', id: 0, result: {} });
      assert.strictEqual(parsedLines[4].id, null);
      assert.strictEqual(parsedLines[4].error.code, -32600);
      assert.strictEqual(parsedLines[5].id, 104);
      assert.strictEqual(parsedLines[5].error.code, -32602);
    } finally {
      await proc.stop();
      fs.rmSync(tmpRoot, { recursive: true, force: true });
      await srv.close();
    }
  });

  test.it('aligns unified medtrace_get_hazard_lineage schema across 9 fields, availableKeys, and dynamic formatSourceLabel', async () => {
    const secret = 'lineage-schema-secret';
    const srv = await startAuthenticatedWebtriggerServer(secret);
    const { tmpRoot, isolatedEntry } = createIsolatedMcpDir('');
    const proc = spawnMcpChild(isolatedEntry, tmpRoot, {
      MEDTRACE_MCP_SECRET: secret,
      MEDTRACE_WEBTRIGGER_URL: srv.url,
      MEDTRACE_ALLOW_INSECURE_LOCALHOST: 'true',
    });

    try {
      const initRes = await proc.rpc(1, 'initialize', {});
      assert.strictEqual(initRes.result.protocolVersion, '2024-11-05');
      assert.strictEqual(initRes.result.serverInfo.name, 'medtrace-mcp-server');

      const listRes = await proc.rpc(2, 'tools/list', {});
      assert.strictEqual(listRes.result.tools.length, 3);

      // 1. DEMO summary
      const demoSummaryRes = await proc.rpc(3, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: {},
      });
      const demoSummary = JSON.parse(demoSummaryRes.result.content[0].text);
      assert.strictEqual(demoSummary.source, 'Atlassian Forge KVS (DEMO Dataset)');
      assert.strictEqual(demoSummary.datasetMode, 'DEMO');
      assert.strictEqual(demoSummary.initialized, true);

      // 2. 9-field match check
      for (const key of [
        'HAZ-101',
        'haz-id-101',
        'MED-42',
        'work-id-42',
        'TEST-88',
        'test-id-88',
        'srs-104',
        '98304',
        'sig-id-001',
      ]) {
        const res = await proc.rpc(`k-${key}`, 'tools/call', {
          name: 'medtrace_get_hazard_lineage',
          arguments: { hazardKey: key },
        });
        const found = JSON.parse(res.result.content[0].text);
        assert.strictEqual(found.found, true, `Expected 9-field match for ${key}`);
        assert.strictEqual(found.source, 'Atlassian Forge KVS (DEMO Dataset)');
        assert.strictEqual(found.datasetMode, 'DEMO');
        assert.strictEqual(found.initialized, true);
        assert.strictEqual(found.traceLink.hazard.key, 'HAZ-101');
        assert.strictEqual(found.regulatoryStatus, 'SAFETY_VIOLATION');
        assert.strictEqual(found.riskClass, 'CLASS_C');
        assert.strictEqual(found.safetyRequirement, 'SRS-104: Hardware Bolus Clamp');
        assert.strictEqual(found.testStatus, 'UNTESTED');
        assert.strictEqual(found.part11Valid, true);
      }

      // 3. Unknown key returns availableKeys
      const notFoundRes = await proc.rpc(10, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: { hazardKey: 'UNKNOWN-999' },
      });
      const notFound = JSON.parse(notFoundRes.result.content[0].text);
      assert.strictEqual(notFound.found, false);
      assert.strictEqual(notFound.queriedKey, 'UNKNOWN-999');
      assert.deepStrictEqual(notFound.availableKeys, [
        { hazardKey: 'HAZ-101', workKey: 'MED-42', specId: 'srs-104', testKey: 'TEST-88' },
        { hazardKey: 'HAZ-102', workKey: 'MED-43', specId: 'srs-105', testKey: 'TEST-89' },
      ]);

      // 4. Uninitialized empty LIVE suite
      srv.state.suite = makeSampleSuite('LIVE', {
        initialized: false,
        totalHazards: 0,
        classCCount: 0,
        classBCount: 0,
        verifiedPercentage: 0,
        traceLinks: [],
      });
      const liveEmptyRes = await proc.rpc(11, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: { hazardKey: 'HAZ-101' },
      });
      const liveEmpty = JSON.parse(liveEmptyRes.result.content[0].text);
      assert.strictEqual(liveEmpty.source, 'Atlassian Cloud (Forge KVS - LIVE)');
      assert.strictEqual(liveEmpty.initialized, false);
      assert.strictEqual(liveEmpty.found, false);
      assert.deepStrictEqual(liveEmpty.availableKeys, []);

      // 5. Missing/unspecified datasetMode
      srv.state.suite = { ...makeSampleSuite('LIVE'), datasetMode: undefined };
      const unspecRes = await proc.rpc(12, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: {},
      });
      const unspec = JSON.parse(unspecRes.result.content[0].text);
      assert.strictEqual(unspec.source, 'Atlassian Forge KVS (UNSPECIFIED)');
    } finally {
      await proc.stop();
      fs.rmSync(tmpRoot, { recursive: true, force: true });
      await srv.close();
    }
  });

  test.it('enforces local remediate -32602 (0 HTTP requests) and classifies HTTP 403, 500, and TIMEOUT cleanly', async () => {
    const secret = 'error-class-secret';
    const srv = await startAuthenticatedWebtriggerServer(secret);
    const { tmpRoot, isolatedEntry } = createIsolatedMcpDir('');
    const proc = spawnMcpChild(isolatedEntry, tmpRoot, {
      MEDTRACE_MCP_SECRET: secret,
      MEDTRACE_WEBTRIGGER_URL: srv.url,
      MEDTRACE_ALLOW_INSECURE_LOCALHOST: 'true',
      MEDTRACE_REQUEST_TIMEOUT_MS: '150', // clamped to 1000ms
    });

    try {
      // 1. Local -32602 must make 0 HTTP calls
      const beforeHttp = srv.requests.length;
      const badSim = await proc.rpc(1, 'tools/call', {
        name: 'medtrace_remediate_safety_gap',
        arguments: { hazardKey: 'HAZ-101', simulate: false, attestationConfirmed: true },
      });
      assert.strictEqual(badSim.error.code, -32602);
      const badAttest = await proc.rpc(2, 'tools/call', {
        name: 'medtrace_remediate_safety_gap',
        arguments: { hazardKey: 'HAZ-101', simulate: true, attestationConfirmed: false },
      });
      assert.strictEqual(badAttest.error.code, -32602);
      assert.strictEqual(srv.requests.length, beforeHttp);

      // 2. DEMO remediate succeeds cleanly when simulate & attestationConfirmed are true
      const demoRemRes = await proc.rpc(30, 'tools/call', {
        name: 'medtrace_remediate_safety_gap',
        arguments: {
          hazardKey: 'HAZ-101',
          simulate: true,
          attestationConfirmed: true,
          meaning: 'Clinical Safety Re-Certification',
        },
      });
      assert.strictEqual(demoRemRes.result.isError, undefined);
      const demoRemBody = JSON.parse(demoRemRes.result.content[0].text);
      assert.strictEqual(demoRemBody.remediated, true);
      assert.strictEqual(demoRemBody.source, 'Atlassian Forge KVS (DEMO Dataset)');
      assert.strictEqual(demoRemBody.datasetMode, 'DEMO');
      assert.strictEqual(demoRemBody.hazardKey, 'HAZ-101');

      // 3. LIVE mode 403 -> POLICY_OR_VALIDATION_ERROR
      srv.state.suite = makeSampleSuite('LIVE');
      const live403Res = await proc.rpc(3, 'tools/call', {
        name: 'medtrace_remediate_safety_gap',
        arguments: { hazardKey: 'HAZ-101', simulate: true, attestationConfirmed: true },
      });
      assert.strictEqual(live403Res.result.isError, true);
      const live403Body = JSON.parse(live403Res.result.content[0].text);
      assert.strictEqual(live403Body.source, 'POLICY_OR_VALIDATION_ERROR');
      assert.strictEqual(live403Body.errorType, 'BACKEND_REJECTED');
      assert.strictEqual(live403Body.httpStatus, 403);

      // 4. HTTP 401 & 409 -> ATLASSIAN_CLOUD_REJECTED
      srv.state.overrideStatus = 401;
      srv.state.overrideBody = { error: 'Unauthorized: HMAC mismatch' };
      const err401Res = await proc.rpc(31, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: {},
      });
      const err401Body = JSON.parse(err401Res.result.content[0].text);
      assert.strictEqual(err401Body.source, 'ATLASSIAN_CLOUD_REJECTED');
      assert.strictEqual(err401Body.errorType, 'AUTH_FAILED');
      assert.strictEqual(err401Body.httpStatus, 401);

      srv.state.overrideStatus = 409;
      srv.state.overrideBody = { error: 'Conflict: Replay detected' };
      const err409Res = await proc.rpc(32, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: {},
      });
      const err409Body = JSON.parse(err409Res.result.content[0].text);
      assert.strictEqual(err409Body.source, 'ATLASSIAN_CLOUD_REJECTED');
      assert.strictEqual(err409Body.errorType, 'REPLAY_DETECTED');
      assert.strictEqual(err409Body.httpStatus, 409);

      // 5. HTTP 500 -> BACKEND_ERROR
      srv.state.overrideStatus = 500;
      srv.state.overrideBody = { error: 'Upstream Forge failure' };
      const err500Res = await proc.rpc(4, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: {},
      });
      assert.strictEqual(err500Res.result.isError, true);
      const err500Body = JSON.parse(err500Res.result.content[0].text);
      assert.strictEqual(err500Body.source, 'BACKEND_ERROR');
      assert.strictEqual(err500Body.errorType, 'UPSTREAM_ERROR');
      assert.strictEqual(err500Body.httpStatus, 500);

      // 4. Timeout against hung server -> UNAVAILABLE + TIMEOUT
      srv.state.overrideStatus = null;
      srv.state.hangForever = true;
      const timeoutRes = await proc.rpc(5, 'tools/call', {
        name: 'medtrace_get_hazard_lineage',
        arguments: {},
      });
      assert.strictEqual(timeoutRes.result.isError, true);
      const timeoutBody = JSON.parse(timeoutRes.result.content[0].text);
      assert.strictEqual(timeoutBody.source, 'UNAVAILABLE');
      assert.strictEqual(timeoutBody.errorType, 'TIMEOUT');
      assert.strictEqual(timeoutBody.httpStatus, 0);
      assert.match(timeoutBody.error, /timed out after 1000ms/);
    } finally {
      await proc.stop();
      fs.rmSync(tmpRoot, { recursive: true, force: true });
      await srv.close();
    }
  });
});
