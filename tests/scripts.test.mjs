import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import {
  CONFIG,
  extractHeadingSlugs,
  findStrictListingPlaceholders,
  runDocsCheck,
  slugifyHeading,
} from '../scripts/docs-check.mjs';
import { validateManifest } from '../scripts/validate-manifest.mjs';

const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DOCS_CHECK_SCRIPT = path.join(REPO_ROOT, 'scripts', 'docs-check.mjs');
const ROTATE_SCRIPT = path.join(REPO_ROOT, 'scripts', 'rotate-mcp-secret.sh');
const VALIDATE_MANIFEST_SCRIPT = path.join(REPO_ROOT, 'scripts', 'validate-manifest.mjs');

/**
 * Runs a command and captures exit code, stdout, and stderr without throwing on non-zero exits.
 */
async function runProcess(cmd, args, options = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      ...options,
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    return {
      code: typeof err.code === 'number' ? err.code : 1,
      stdout: typeof err.stdout === 'string' ? err.stdout : '',
      stderr: typeof err.stderr === 'string' ? err.stderr : '',
    };
  }
}

/**
 * Creates an isolated temporary directory populated with relative file paths.
 */
function createTempTree(prefix, files = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  writeFixtureFiles(dir, files);
  return {
    dir,
    cleanup() {
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

/**
 * Writes relative files into a directory, creating parent folders as needed.
 */
function writeFixtureFiles(rootDir, files) {
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(rootDir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, 'utf8');
  }
}

/**
 * Returns a minimal, fully compliant repository documentation fixture.
 */
function makeValidDocsFixtureFiles(overrides = {}) {
  return {
    'package.json': JSON.stringify({ name: 'fixture-repo', version: '1.0.0' }, null, 2),
    'scripts/sample.mjs': 'export const ok = true;\n',
    'AGENTS.md': [
      '# Agent Router',
      '',
      'Start at [Overview](docs/00-guide/00-overview.md) and review [README](README.md).',
      '',
    ].join('\n'),
    'README.md': [
      '# Fixture Repository',
      '',
      'See [Guide Overview](docs/00-guide/00-overview.md), [Security](SECURITY.md), and [Privacy](marketplace/PRIVACY_POLICY.md).',
      '',
      'Entry points:',
      '- `package.json`',
      '- `scripts/sample.mjs`',
      '',
    ].join('\n'),
    'SECURITY.md': [
      '# Security Policy',
      '',
      'Contact security@example.test for coordinated vulnerability disclosure.',
      '',
    ].join('\n'),
    'marketplace/PRIVACY_POLICY.md': [
      '# Privacy Policy',
      '',
      'MedTrace processes only configured Jira and Confluence compliance data.',
      '',
    ].join('\n'),
    'docs/00-guide/00-overview.md': [
      '**Back:** [README](../../README.md)',
      '',
      '# Guide Overview',
      '',
      '- [Details](./details.md)',
      '- [Details Anchor](./details.md#expected-section)',
      '- [Duplicate Anchor](./details.md#repeated-title-1)',
      '',
    ].join('\n'),
    'docs/00-guide/details.md': [
      '[<- Guide Overview](./00-overview.md)',
      '',
      '# Details',
      '',
      '## Expected Section',
      '',
      '### Repeated Title',
      '',
      '### Repeated Title',
      '',
      'Valid backtick path: `scripts/sample.mjs`.',
      'Same-file anchor: [Jump](#expected-section) and [HTML Target](#custom-id).',
      '',
      '<a id="custom-id"></a>',
      '',
      '```markdown',
      '## Heading Inside Fenced Code Block',
      '```',
      '',
    ].join('\n'),
    ...overrides,
  };
}

/**
 * Builds a clean child environment for `rotate-mcp-secret.sh` tests so host vars cannot leak in.
 */
function buildCleanRotateEnv(extra = {}) {
  const env = {
    PATH: process.env.PATH || '/usr/local/bin:/usr/bin:/bin',
    HOME: process.env.HOME || os.tmpdir(),
    TMPDIR: os.tmpdir(),
  };
  for (const [k, v] of Object.entries(extra)) {
    if (v !== undefined && v !== null) {
      env[k] = String(v);
    }
  }
  return env;
}

/**
 * Starts a local HTTP webtrigger stub verifying HMAC-SHA256 signatures and single-use nonces,
 * backed by a shared JSON state file updated by the mocked FORGE_BIN script.
 */
async function startRotateTestHarness(initialEnvConfigs) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'medtrace-rotate-harness-'));
  const stateFile = path.join(dir, 'forge-state.json');
  const logFile = path.join(dir, 'forge-calls.jsonl');
  const missingForgeEnv = path.join(dir, 'nonexistent-forge-env');
  const mockForgeBin = path.join(dir, 'mock-forge');

  const sockets = new Set();
  const seenNoncesByEnv = new Map();
  const requests = [];

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks).toString('utf8');
      const parsedUrl = new URL(req.url || '/', 'http://127.0.0.1');
      const segments = parsedUrl.pathname.split('/').filter(Boolean);
      const envName = segments[1] || 'default';

      const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      const envCfg = state.envs[envName];
      if (!envCfg) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Unknown environment route: ${envName}` }));
        return;
      }

      const ts = String(req.headers['x-medtrace-timestamp'] || '');
      const nonce = String(req.headers['x-medtrace-nonce'] || '');
      const sigHeader = String(req.headers['x-medtrace-signature'] || '');
      const activeSecret = envCfg.activeSecret || '';

      let parsedBody = null;
      if (rawBody) {
        try {
          parsedBody = JSON.parse(rawBody);
        } catch {
          parsedBody = null;
        }
      }

      const expectedHex = crypto
        .createHmac('sha256', activeSecret)
        .update(`${ts}.${nonce}.${rawBody}`)
        .digest('hex');
      const expectedHeader = `sha256=${expectedHex}`;

      const sigValid =
        sigHeader.length === expectedHeader.length &&
        crypto.timingSafeEqual(Buffer.from(sigHeader, 'utf8'), Buffer.from(expectedHeader, 'utf8'));

      const record = {
        env: envName,
        method: req.method,
        action: parsedBody?.action ?? null,
        ts,
        nonce,
        sigValid,
        rawBody,
        status: 0,
      };
      requests.push(record);

      function sendJson(statusCode, payload) {
        record.status = statusCode;
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      }

      if (!ts || !nonce || !sigValid) {
        sendJson(401, { error: 'Invalid HMAC signature' });
        return;
      }

      let seen = seenNoncesByEnv.get(envName);
      if (!seen) {
        seen = new Set();
        seenNoncesByEnv.set(envName, seen);
      }
      if (seen.has(nonce)) {
        sendJson(409, { error: 'Nonce replay detected' });
        return;
      }
      seen.add(nonce);

      if (req.method === 'GET') {
        if (envCfg.failGetStatus) {
          sendJson(envCfg.failGetStatus, { error: 'Injected GET failure' });
          return;
        }
        sendJson(200, {
          summary: { datasetMode: envCfg.datasetMode || 'LIVE', totalHazards: 1 },
          traceLinks: [],
        });
        return;
      }

      if (req.method === 'POST') {
        if (!parsedBody || typeof parsedBody !== 'object') {
          sendJson(400, { error: 'Malformed JSON body' });
          return;
        }
        if (parsedBody.action === 'status') {
          sendJson(200, { ok: true, action: 'status', datasetMode: envCfg.datasetMode || 'LIVE' });
          return;
        }
        if (parsedBody.action === 'verify-release-gate') {
          const status = envCfg.gateStatus ?? 200;
          const body = envCfg.gateBody ?? { result: true };
          sendJson(status, body);
          return;
        }
        sendJson(400, { error: `Unknown action: ${String(parsedBody.action)}` });
        return;
      }

      sendJson(405, { error: 'Method not allowed' });
    });
  });

  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  const state = { envs: {} };
  for (const [envName, cfg] of Object.entries(initialEnvConfigs)) {
    state.envs[envName] = {
      activeSecret: cfg.activeSecret || 'old-secret',
      stagedSecret: cfg.stagedSecret || null,
      url: cfg.omitUrl ? '' : `${baseUrl}/wt/${envName}`,
      webtriggerListFormat: cfg.webtriggerListFormat || 'array',
      failGetStatus: cfg.failGetStatus || null,
      gateStatus: cfg.gateStatus ?? 200,
      gateBody: cfg.gateBody ?? { result: true },
      datasetMode: cfg.datasetMode || 'LIVE',
    };
  }
  fs.writeFileSync(stateFile, JSON.stringify(state, null, 2), 'utf8');

  const mockForgeScript = `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const statePath = process.env.MOCK_FORGE_STATE_FILE;
const logPath = process.env.MOCK_FORGE_LOG_FILE;
fs.appendFileSync(logPath, JSON.stringify(args) + '\\n', 'utf8');
const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));

function argValue(flags) {
  for (let i = 0; i < args.length; i += 1) {
    if (flags.includes(args[i]) && i + 1 < args.length) return args[i + 1];
  }
  return '';
}

const cmd = args[0] || '';
if (cmd === 'whoami') {
  process.stdout.write('mock-operator@example.test\\n');
  process.exit(0);
}
if (cmd === 'lint') {
  process.exit(0);
}
if (cmd === 'variables' && args[1] === 'set') {
  const varName = args[2];
  const varVal = args[3];
  const envName = argValue(['--environment', '-e']);
  if (!state.envs[envName]) process.exit(1);
  if (varName === 'MEDTRACE_MCP_SECRET') {
    state.envs[envName].stagedSecret = varVal;
    fs.writeFileSync(statePath, JSON.stringify(state, null, 2), 'utf8');
  }
  process.exit(0);
}
if (cmd === 'deploy') {
  const envName = argValue(['--environment', '-e']);
  if (!state.envs[envName]) process.exit(1);
  if (state.envs[envName].stagedSecret) {
    state.envs[envName].activeSecret = state.envs[envName].stagedSecret;
    fs.writeFileSync(statePath, JSON.stringify(state, null, 2), 'utf8');
  }
  process.exit(0);
}
if (cmd === 'webtrigger' && args[1] === 'list') {
  const envName = argValue(['-e', '--environment']);
  const cfg = state.envs[envName];
  if (!cfg || !cfg.url) {
    process.stdout.write('[]\\n');
    process.exit(0);
  }
  const item = { triggerKey: 'mcp-sync-webtrigger', url: cfg.url };
  if (cfg.webtriggerListFormat === 'wrapped') {
    process.stdout.write(JSON.stringify({ webtriggers: [item] }) + '\\n');
  } else {
    process.stdout.write(JSON.stringify([item]) + '\\n');
  }
  process.exit(0);
}
process.stderr.write('Unexpected mock forge args: ' + args.join(' ') + '\\n');
process.exit(1);
`;
  fs.writeFileSync(mockForgeBin, mockForgeScript, { encoding: 'utf8', mode: 0o755 });
  fs.chmodSync(mockForgeBin, 0o755);

  return {
    dir,
    baseUrl,
    stateFile,
    logFile,
    missingForgeEnv,
    mockForgeBin,
    requests,
    readForgeCalls() {
      if (!fs.existsSync(logFile)) return [];
      return fs
        .readFileSync(logFile, 'utf8')
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line));
    },
    readState() {
      return JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    },
    async cleanup() {
      for (const s of sockets) s.destroy();
      await new Promise((resolve) => server.close(resolve));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

// ============================================================================
// 1. scripts/docs-check.mjs tests
// ============================================================================

test('docs-check: valid fixture tree passes with 0 errors and 0 warnings (API & CLI)', async () => {
  const fixture = createTempTree('medtrace-docs-valid-', makeValidDocsFixtureFiles());
  try {
    const apiResult = runDocsCheck({ root: fixture.dir });
    assert.equal(apiResult.exitCode, 0);
    assert.deepEqual(apiResult.errors, []);
    assert.deepEqual(apiResult.warnings, []);
    assert.equal(apiResult.folders.length, 1);

    const cliRes = await runProcess(process.execPath, [DOCS_CHECK_SCRIPT, '--root', fixture.dir]);
    assert.equal(cliRes.code, 0, cliRes.stderr);
    assert.match(cliRes.stdout, /0 errors, 0 warnings/);

    const envRes = await runProcess(process.execPath, [DOCS_CHECK_SCRIPT], {
      env: { ...process.env, DOCS_CHECK_ROOT: fixture.dir },
    });
    assert.equal(envRes.code, 0, envRes.stderr);
  } finally {
    fixture.cleanup();
  }
});

test('docs-check: fails on broken relative link, escaping link, and broken backtick path', () => {
  const fixture = createTempTree(
    'medtrace-docs-broken-link-',
    makeValidDocsFixtureFiles({
      'docs/00-guide/details.md': [
        '[<- Guide Overview](./00-overview.md)',
        '',
        '# Details',
        '',
        '## Expected Section',
        '',
        '### Repeated Title',
        '',
        '### Repeated Title',
        '',
        'Broken file link: [Missing](./nonexistent-page.md)',
        'Escaping link: [Escape](../../../../etc/passwd)',
        'Broken backtick path: `src/does-not-exist.ts`',
        'Valid path: `scripts/sample.mjs`.',
        '',
      ].join('\n'),
    }),
  );

  try {
    const res = runDocsCheck({ root: fixture.dir });
    assert.equal(res.exitCode, 1);
    assert.ok(
      res.errors.some((e) => e.includes('link: broken relative link -> ./nonexistent-page.md')),
      `Expected broken relative link error, got: ${res.errors.join(' | ')}`,
    );
    assert.ok(
      res.errors.some((e) => e.includes('link: relative link escapes repository root -> ../../../../etc/passwd')),
      `Expected root-escape link error, got: ${res.errors.join(' | ')}`,
    );
    assert.ok(
      res.errors.some((e) => e.includes('path: backticked path not on disk -> src/does-not-exist.ts')),
      `Expected missing backtick path error, got: ${res.errors.join(' | ')}`,
    );
  } finally {
    fixture.cleanup();
  }
});

test('docs-check: fails on broken #anchor links (cross-file, same-file, and fenced-code headings)', () => {
  const fixture = createTempTree(
    'medtrace-docs-anchor-',
    makeValidDocsFixtureFiles({
      'docs/00-guide/00-overview.md': [
        '**Back:** [README](../../README.md)',
        '',
        '# Guide Overview',
        '',
        '- [Details](./details.md)',
        '- [Broken Cross Anchor](./details.md#missing-anchor-heading)',
        '- [Broken Duplicate Overflow](./details.md#repeated-title-2)',
        '',
      ].join('\n'),
      'docs/00-guide/details.md': [
        '[<- Guide Overview](./00-overview.md)',
        '',
        '# Details',
        '',
        '## Expected Section',
        '',
        '### Repeated Title',
        '',
        '### Repeated Title',
        '',
        'Valid path: `scripts/sample.mjs`.',
        'Broken self anchor: [Self](#does-not-exist)',
        'Fenced heading anchor must fail: [Fenced](#heading-inside-fenced-code-block)',
        '',
        '```markdown',
        '## Heading Inside Fenced Code Block',
        '```',
        '',
      ].join('\n'),
    }),
  );

  try {
    assert.equal(slugifyHeading('Hello `my_var` World!'), 'hello-my_var-world');
    const slugs = extractHeadingSlugs('# One\n# One\n```md\n# CodeOnly\n```');
    assert.equal(slugs.has('one'), true);
    assert.equal(slugs.has('one-1'), true);
    assert.equal(slugs.has('codeonly'), false);

    const res = runDocsCheck({ root: fixture.dir });
    assert.equal(res.exitCode, 1);
    assert.ok(
      res.errors.some((e) => e.includes('link-anchor: broken anchor link -> ./details.md#missing-anchor-heading')),
    );
    assert.ok(
      res.errors.some((e) => e.includes('link-anchor: broken anchor link -> ./details.md#repeated-title-2')),
    );
    assert.ok(
      res.errors.some((e) => e.includes('link-anchor: broken anchor link -> #does-not-exist')),
    );
    assert.ok(
      res.errors.some((e) => e.includes('link-anchor: broken anchor link -> #heading-inside-fenced-code-block')),
    );
  } finally {
    fixture.cleanup();
  }
});

test('docs-check: rejects relative links that exist only via repository root fallback', () => {
  const fixture = createTempTree(
    'medtrace-docs-root-fallback-',
    makeValidDocsFixtureFiles({
      'root-only.md': '# Root Only File\n',
      'docs/00-guide/details.md': [
        '[<- Guide Overview](./00-overview.md)',
        '',
        '# Details',
        '',
        '## Expected Section',
        '',
        '### Repeated Title',
        '',
        '### Repeated Title',
        '',
        'Valid path: `scripts/sample.mjs`.',
        'Must fail because root-only.md is NOT in docs/00-guide/: [RootOnly](root-only.md)',
        'Must fail because package.json is NOT in docs/00-guide/: [Pkg](package.json)',
        '',
      ].join('\n'),
    }),
  );

  try {
    const res = runDocsCheck({ root: fixture.dir });
    assert.equal(res.exitCode, 1);
    assert.ok(
      res.errors.some((e) => e.includes('docs/00-guide/details.md:') && e.includes('broken relative link -> root-only.md')),
      `Expected root-fallback rejection for root-only.md, got: ${res.errors.join(' | ')}`,
    );
    assert.ok(
      res.errors.some((e) => e.includes('docs/00-guide/details.md:') && e.includes('broken relative link -> package.json')),
      `Expected root-fallback rejection for package.json, got: ${res.errors.join(' | ')}`,
    );
  } finally {
    fixture.cleanup();
  }
});

test('docs-check: fails on missing 00-overview.md, unlinked sibling doc, and missing/late top backlink', () => {
  const fixture = createTempTree(
    'medtrace-docs-overview-backlink-',
    makeValidDocsFixtureFiles({
      'docs/01-no-overview/orphan.md': '# Orphan without overview\n',
      'docs/02-unlisted/00-overview.md': '**Back:** [README](../../README.md)\n\n# Unlisted Subject\n',
      'docs/02-unlisted/hidden.md': '[<- Overview](./00-overview.md)\n\n# Hidden\n',
      'docs/03-bad-backlink/00-overview.md': '**Back:** [README](../../README.md)\n\n- [Child](./child.md)\n',
      'docs/03-bad-backlink/child.md': [
        '# Missing Top Backlink',
        ...Array.from({ length: 16 }, () => 'Filler line before backlink'),
        '[<- Late Backlink](./00-overview.md)',
        '',
      ].join('\n'),
    }),
  );

  try {
    const res = runDocsCheck({ root: fixture.dir });
    assert.equal(res.exitCode, 1);
    assert.ok(res.errors.some((e) => e.includes('docs/01-no-overview: overview: missing 00-overview.md')));
    assert.ok(res.errors.some((e) => e.includes('docs/02-unlisted/00-overview.md: overview: does not link hidden.md')));
    assert.ok(res.errors.some((e) => e.includes('docs/03-bad-backlink/child.md: backlink: missing top backlink to 00-overview.md')));
  } finally {
    fixture.cleanup();
  }
});

test('docs-check: flags stray Markdown under docs/ (layout) and unlinked subject folders in AGENTS.md (router)', () => {
  const fixture = createTempTree(
    'medtrace-docs-layout-router-',
    makeValidDocsFixtureFiles({
      'docs/STRAY.md': '# Stray top-level doc outside any NN-* folder\n',
      'AGENTS.md': [
        '# Agent Router',
        '',
        'Start at [Overview](docs/00-guide/00-overview.md).',
        '',
      ].join('\n'),
      'docs/02-unrouted/00-overview.md': '**Back:** [README](../../README.md)\n\n# Unrouted Subject\n',
    }),
  );

  try {
    const res = runDocsCheck({ root: fixture.dir });
    assert.equal(res.exitCode, 1);
    assert.ok(
      res.errors.some((e) => e.includes('docs/STRAY.md: layout: stray Markdown outside a NN-* folder')),
      `expected layout error, got: ${JSON.stringify(res.errors)}`,
    );
    assert.ok(
      res.errors.some((e) => e.includes('AGENTS.md: router: AGENTS.md does not link subject folder -> docs/02-unrouted/00-overview.md')),
      `expected router error, got: ${JSON.stringify(res.errors)}`,
    );
  } finally {
    fixture.cleanup();
  }
});

test('docs-check: reverse-coverage flags undocumented tracked entry files across entryGlobs', () => {
  assert.ok(CONFIG.entryGlobs.includes('tests/*.test.*'));
  assert.ok(CONFIG.entryGlobs.includes('scripts/*.sh'));

  const undocumentedEntries = {
    'manifest.yml': 'app:\n  id: ari:cloud:ecosystem::app/test\n',
    '.github/workflows/ci.yml': 'name: CI\n',
    'scripts/undocumented.sh': '#!/usr/bin/env bash\n',
    'src/undocumented.ts': 'export const y = 2;\n',
    'tests/undocumented.test.mjs': 'import test from "node:test";\n',
    'static/frontend/src/components/UndocumentedPanel.tsx': 'export const Panel = () => null;\n',
  };

  const fixture = createTempTree(
    'medtrace-docs-reverse-cov-',
    makeValidDocsFixtureFiles(undocumentedEntries),
  );

  try {
    const res = runDocsCheck({ root: fixture.dir });
    assert.equal(res.exitCode, 1);
    for (const relPath of Object.keys(undocumentedEntries)) {
      assert.ok(
        res.errors.some((e) => e.includes(`${relPath}: reverse-coverage: entry point referenced by no doc`)),
        `Expected reverse-coverage error for ${relPath}, got: ${res.errors.join(' | ')}`,
      );
    }
  } finally {
    fixture.cleanup();
  }
});

test('docs-check: --strict-listing exits 1 on [CONFIGURE BEFORE LISTING] and 0 when absent while normal mode exits 0', async () => {
  const placeholderFiles = makeValidDocsFixtureFiles({
    'SECURITY.md': [
      '# Security Policy',
      '',
      'Security Contact: [CONFIGURE BEFORE LISTING: security@vendor.example]',
      '',
    ].join('\n'),
    'marketplace/PRIVACY_POLICY.md': [
      '# Privacy Policy',
      '',
      'Entity: [CONFIGURE BEFORE LISTING: Vendor Legal Name]',
      '',
    ].join('\n'),
  });

  const fixture = createTempTree('medtrace-docs-strict-listing-', placeholderFiles);
  try {
    assert.equal(findStrictListingPlaceholders(placeholderFiles['SECURITY.md']).length, 1);

    // Normal mode without --strict-listing must still exit 0
    const normalCli = await runProcess(process.execPath, [DOCS_CHECK_SCRIPT, '--root', fixture.dir]);
    assert.equal(normalCli.code, 0, normalCli.stderr);

    // Strict mode via CLI flag exits 1 and cites both placeholder files
    const strictCli = await runProcess(process.execPath, [
      DOCS_CHECK_SCRIPT,
      '--root',
      fixture.dir,
      '--strict-listing',
    ]);
    assert.equal(strictCli.code, 1);
    assert.match(strictCli.stderr, /SECURITY\.md:3: strict-listing:/);
    assert.match(strictCli.stderr, /marketplace\/PRIVACY_POLICY\.md:3: strict-listing:/);

    // Strict mode via environment variable also exits 1
    const envStrictCli = await runProcess(process.execPath, [DOCS_CHECK_SCRIPT, '--root', fixture.dir], {
      env: { ...process.env, DOCS_CHECK_STRICT_LISTING: '1' },
    });
    assert.equal(envStrictCli.code, 1);

    // Removing placeholders makes --strict-listing exit 0
    writeFixtureFiles(fixture.dir, {
      'SECURITY.md': '# Security Policy\n\nSecurity Contact: security@acme-med.example\n',
      'marketplace/PRIVACY_POLICY.md': '# Privacy Policy\n\nEntity: Acme Medical Inc.\n',
    });
    const cleanStrictCli = await runProcess(process.execPath, [
      DOCS_CHECK_SCRIPT,
      '--root',
      fixture.dir,
      '--strict-listing',
    ]);
    assert.equal(cleanStrictCli.code, 0, cleanStrictCli.stderr);
  } finally {
    fixture.cleanup();
  }
});

test('docs-check: CLI --help exits 0 and invalid CLI/missing-docs exits 1', async () => {
  const helpRes = await runProcess(process.execPath, [DOCS_CHECK_SCRIPT, '--help']);
  assert.equal(helpRes.code, 0);
  assert.match(helpRes.stdout, /--strict-listing/);

  const badFlag = await runProcess(process.execPath, [DOCS_CHECK_SCRIPT, '--nonexistent-flag']);
  assert.equal(badFlag.code, 1);

  const emptyDir = createTempTree('medtrace-docs-missing-', {});
  try {
    const missingDocs = await runProcess(process.execPath, [DOCS_CHECK_SCRIPT, '--root', emptyDir.dir]);
    assert.equal(missingDocs.code, 1);
    assert.match(missingDocs.stderr, /docs does not exist/);
  } finally {
    emptyDir.cleanup();
  }
});

// ============================================================================
// 2. scripts/rotate-mcp-secret.sh tests
// ============================================================================

test('rotate-mcp-secret.sh: bash -n syntax, --help exit 0, unknown flag exit 2, and static regression guards', async () => {
  const syntaxRes = await runProcess('bash', ['-n', ROTATE_SCRIPT]);
  assert.equal(syntaxRes.code, 0, syntaxRes.stderr);

  const helpRes = await runProcess(ROTATE_SCRIPT, ['--help']);
  assert.equal(helpRes.code, 0, helpRes.stderr);
  assert.match(helpRes.stdout, /--skip-rotate/);
  assert.match(helpRes.stdout, /--approve-major/);
  assert.match(helpRes.stdout, /MEDTRACE_PART11_SECRET/);
  assert.match(helpRes.stdout, /git filter-repo/);

  const unknownRes = await runProcess(ROTATE_SCRIPT, ['--not-a-valid-option']);
  assert.equal(unknownRes.code, 2);

  const scriptSource = fs.readFileSync(ROTATE_SCRIPT, 'utf8');
  assert.equal(scriptSource.includes('one-atlas-feur.atlassian.net'), false);
  assert.equal(scriptSource.includes('date +%s%3N'), false);
  assert.equal(/\bdate\s+\+%s%3N/.test(scriptSource), false);
  assert.equal(scriptSource.includes('sed -i'), false);
  assert.equal(/\bsed\s+-i\b/.test(scriptSource), false);
});

test('rotate-mcp-secret.sh: E2E multi-env rotation updates .env atomically (0600) and verifies LIVE 200 & DEMO 403', async () => {
  const oldSecret = 'old-leaked-secret#999';
  const harness = await startRotateTestHarness({
    production: {
      activeSecret: oldSecret,
      datasetMode: 'LIVE',
      gateStatus: 200,
      gateBody: { result: true, datasetMode: 'LIVE', releaseBlocked: false },
      webtriggerListFormat: 'array',
    },
    development: {
      activeSecret: oldSecret,
      datasetMode: 'DEMO',
      gateStatus: 403,
      gateBody: { result: false, datasetMode: 'DEMO', releaseBlocked: true },
      webtriggerListFormat: 'wrapped',
    },
  });

  const envFilePath = path.join(harness.dir, '.env');
  fs.writeFileSync(
    envFilePath,
    [
      '# MedTrace MCP configuration',
      `MEDTRACE_MCP_SECRET="${oldSecret}" # preserve secret comment`,
      'MEDTRACE_WEBTRIGGER_URL="http://127.0.0.1:1/stale" # preserve url comment',
      'UNRELATED_FLAG="keep#value"',
      '',
    ].join('\n'),
    { encoding: 'utf8', mode: 0o644 },
  );

  try {
    const res = await runProcess('bash', [ROTATE_SCRIPT], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        ENVIRONMENTS: 'production development',
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: '1',
        LEAKED_SECRET: oldSecret,
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });

    assert.equal(res.code, 0, `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
    assert.match(res.stdout, /ALL LIVE CHECKS PASSED across 2 target\(s\)/);
    assert.match(res.stdout, /MEDTRACE_PART11_SECRET/);
    assert.match(res.stdout, /git filter-repo/);

    // Verify Forge CLI calls: no hardcoded -s one-atlas-feur, no default --approve MAJOR_VERSION_RULE
    const calls = harness.readForgeCalls();
    assert.ok(calls.some((c) => c[0] === 'whoami'));
    assert.ok(calls.some((c) => c.length === 1 && c[0] === 'lint'));
    assert.equal(calls.some((c) => c.includes('MAJOR_VERSION_RULE')), false);
    assert.equal(calls.some((c) => c.includes('-s')), false);

    const setProd = calls.find(
      (c) => c[0] === 'variables' && c[1] === 'set' && c.includes('production'),
    );
    const setDev = calls.find(
      (c) => c[0] === 'variables' && c[1] === 'set' && c.includes('development'),
    );
    assert.ok(setProd && setDev);
    const rotatedSecret = setProd[3];
    assert.match(rotatedSecret, /^[0-9a-f]{64}$/);
    assert.notEqual(rotatedSecret, oldSecret);
    assert.equal(setDev[3], rotatedSecret);

    assert.ok(calls.some((c) => c[0] === 'deploy' && c.includes('production')));
    assert.ok(calls.some((c) => c[0] === 'deploy' && c.includes('development')));
    assert.ok(
      calls.some(
        (c) =>
          c[0] === 'webtrigger' &&
          c[1] === 'list' &&
          c.includes('-f') &&
          c.includes('mcp-sync-webtrigger') &&
          c.includes('production') &&
          c.includes('--json'),
      ),
    );
    assert.ok(
      calls.some(
        (c) =>
          c[0] === 'webtrigger' &&
          c[1] === 'list' &&
          c.includes('development') &&
          c.includes('--json'),
      ),
    );

    // Verify .env permissions (0600), preserved comments/unrelated keys, and updated values
    const envStat = fs.statSync(envFilePath);
    assert.equal(envStat.mode & 0o777, 0o600);
    const envText = fs.readFileSync(envFilePath, 'utf8');
    assert.ok(envText.includes('# MedTrace MCP configuration'));
    assert.ok(envText.includes('UNRELATED_FLAG="keep#value"'));
    assert.ok(envText.includes(`MEDTRACE_MCP_SECRET="${rotatedSecret}" # preserve secret comment`));
    assert.ok(
      envText.includes(
        `MEDTRACE_WEBTRIGGER_URL="${harness.baseUrl}/wt/production" # preserve url comment`,
      ),
    );
    const leftoverTmps = fs.readdirSync(harness.dir).filter((f) => f.includes('.tmp.'));
    assert.deepEqual(leftoverTmps, []);

    // Verify all Step 6 verification requests hit BOTH production and development
    for (const envName of ['production', 'development']) {
      const envReqs = harness.requests.filter((r) => r.env === envName);
      const invalidSigGets = envReqs.filter((r) => r.method === 'GET' && !r.sigValid);
      const validGets = envReqs.filter((r) => r.method === 'GET' && r.sigValid);
      const statusPosts = envReqs.filter((r) => r.method === 'POST' && r.action === 'status');
      const unknownPosts = envReqs.filter(
        (r) => r.method === 'POST' && r.action === '__unknown_action_probe__',
      );
      const gatePosts = envReqs.filter(
        (r) => r.method === 'POST' && r.action === 'verify-release-gate',
      );

      assert.equal(invalidSigGets.length, 2, `${envName} should probe leaked + forged GET (2x 401)`);
      assert.equal(validGets.length, 1, `${envName} should pass valid GET (200)`);
      assert.equal(statusPosts.length, 4, `${envName} should run 4-step status replay proof`);
      assert.equal(statusPosts[0].nonce, statusPosts[1].nonce);
      assert.equal(statusPosts[1].nonce, statusPosts[2].nonce);
      assert.notEqual(statusPosts[2].ts, '');
      assert.notEqual(statusPosts[3].nonce, statusPosts[0].nonce);
      assert.equal(unknownPosts.length, 1, `${envName} should probe unknown action (400)`);
      assert.equal(gatePosts.length, 1, `${envName} should probe verify-release-gate`);
      assert.deepEqual(
        envReqs.map((r) => r.status),
        [401, 401, 200, 200, 409, 409, 200, 400, envName === 'production' ? 200 : 403],
        `${envName} should observe exact HTTP status sequence across all Step 6 probes`,
      );
    }
  } finally {
    await harness.cleanup();
  }
});

test('rotate-mcp-secret.sh: multi-env does not exit early on first env failure and supports --force on missing URL', async () => {
  const harness = await startRotateTestHarness({
    production: {
      activeSecret: 'init-secret',
      failGetStatus: 500,
      gateStatus: 200,
      gateBody: { result: true },
    },
    development: {
      activeSecret: 'init-secret',
      gateStatus: 403,
      gateBody: { result: false },
    },
  });

  const envFilePath = path.join(harness.dir, '.env');

  try {
    // 1. Even when production fails GET (500), development MUST still be verified before exiting 1
    const failRes = await runProcess('bash', [ROTATE_SCRIPT], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        ENVIRONMENTS: 'production development',
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: '1',
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });
    assert.equal(failRes.code, 1);
    assert.ok(
      harness.requests.some((r) => r.env === 'development' && r.action === 'verify-release-gate'),
      'development must still be verified when production fails',
    );
    // Also verify new .env created from scratch received 0600 mode
    assert.equal(fs.statSync(envFilePath).mode & 0o777, 0o600);

    // 2. When production has no webtrigger URL yet, non-force fails while --force succeeds after verifying development
    const state = harness.readState();
    state.envs.production.url = '';
    fs.writeFileSync(harness.stateFile, JSON.stringify(state, null, 2), 'utf8');

    const noForceRes = await runProcess('bash', [ROTATE_SCRIPT], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        ENVIRONMENTS: 'production development',
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: '1',
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });
    assert.equal(noForceRes.code, 1);
    assert.match(noForceRes.stdout, /Re-run with --force/);

    const forceRes = await runProcess('bash', [ROTATE_SCRIPT, '--force'], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        ENVIRONMENTS: 'production development',
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: '1',
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });
    assert.equal(forceRes.code, 0, forceRes.stderr);
  } finally {
    await harness.cleanup();
  }
});

test('rotate-mcp-secret.sh: SKIP_ROTATE=1 is strictly read-only on .env and parses quoted URL + # comments', async () => {
  const dotenvSecret = 'quoted#secret#with#hashes';
  const harness = await startRotateTestHarness({
    development: {
      activeSecret: dotenvSecret,
      datasetMode: 'DEMO',
      gateStatus: 403,
      gateBody: { result: false, datasetMode: 'DEMO' },
    },
  });

  const envFilePath = path.join(harness.dir, '.env');
  const initialDotenv = [
    '# Read-only verification dotenv',
    `export MEDTRACE_MCP_SECRET="${dotenvSecret}" # secret trailing comment`,
    `MEDTRACE_WEBTRIGGER_URL='${harness.baseUrl}/wt/development' # single-quoted URL with trailing comment`,
    '',
  ].join('\n');
  fs.writeFileSync(envFilePath, initialDotenv, { encoding: 'utf8', mode: 0o644 });
  const statBefore = fs.statSync(envFilePath);

  try {
    const res = await runProcess('bash', [ROTATE_SCRIPT, '--skip-rotate'], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: 'true',
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });

    assert.equal(res.code, 0, `stdout:\n${res.stdout}\nstderr:\n${res.stderr}`);
    assert.match(res.stdout, /SKIP_ROTATE=1 — read-only verification mode/);
    assert.match(res.stdout, /403 \(BLOCKED\/DEMO\/UNINITIALIZED \(result: false\)\)/);

    // FORGE_BIN must not have been called at all (no forge lint / set / deploy)
    assert.deepEqual(harness.readForgeCalls(), []);

    // .env file must remain byte-for-byte, inode, mtime, and permission untouched
    const statAfter = fs.statSync(envFilePath);
    assert.equal(fs.readFileSync(envFilePath, 'utf8'), initialDotenv);
    assert.equal(statAfter.ino, statBefore.ino);
    assert.equal(statAfter.mtimeMs, statBefore.mtimeMs);
    assert.equal(statAfter.mode & 0o777, 0o644);

    // Stub must have received valid HMAC probes signed with quoted#secret#with#hashes
    const validGets = harness.requests.filter((r) => r.method === 'GET' && r.sigValid);
    const gatePosts = harness.requests.filter((r) => r.action === 'verify-release-gate' && r.sigValid);
    assert.equal(validGets.length, 1);
    assert.equal(gatePosts.length, 1);
  } finally {
    await harness.cleanup();
  }
});

test('rotate-mcp-secret.sh: rejects mismatched verify-release-gate payloads and insecure URLs', async () => {
  const harness = await startRotateTestHarness({
    production: {
      activeSecret: 'gate-check-secret',
      gateStatus: 200,
      gateBody: { result: false }, // Invalid combination: HTTP 200 must have result: true
    },
  });

  const envFilePath = path.join(harness.dir, '.env');
  fs.writeFileSync(
    envFilePath,
    [
      'MEDTRACE_MCP_SECRET="gate-check-secret"',
      `MEDTRACE_WEBTRIGGER_URL="${harness.baseUrl}/wt/production"`,
      '',
    ].join('\n'),
    'utf8',
  );

  try {
    // 1. 200 with result: false must fail verification
    const badGate = await runProcess('bash', [ROTATE_SCRIPT], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        SKIP_ROTATE: '1',
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: '1',
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });
    assert.equal(badGate.code, 1);
    assert.match(badGate.stdout, /verify-release-gate failed validation/);

    // 2. http://127.0.0.1 without MEDTRACE_ALLOW_INSECURE_LOCALHOST=1 must fail closed
    const reqCountBefore = harness.requests.length;
    const noLoopbackOptIn = await runProcess('bash', [ROTATE_SCRIPT, '--skip-rotate'], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: '0',
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });
    assert.equal(noLoopbackOptIn.code, 1);
    assert.match(noLoopbackOptIn.stdout, /https:\/\/ required/);
    assert.equal(harness.requests.length, reqCountBefore);

    // 3. Non-loopback http://example.com must fail even when MEDTRACE_ALLOW_INSECURE_LOCALHOST=1
    const remoteHttp = await runProcess('bash', [ROTATE_SCRIPT, '--skip-rotate'], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        MEDTRACE_WEBTRIGGER_URL: 'http://example.com/wt',
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: '1',
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });
    assert.equal(remoteHttp.code, 1);
    assert.match(remoteHttp.stdout, /https:\/\/ required/);
    assert.equal(harness.requests.length, reqCountBefore);
  } finally {
    await harness.cleanup();
  }
});

test('rotate-mcp-secret.sh: honors ENVIRONMENT fallback, --skip-deploy, --approve-major, and optional FORGE_SITE', async () => {
  const harness = await startRotateTestHarness({
    staging: {
      activeSecret: 'staging-secret',
      gateStatus: 200,
      gateBody: { result: true },
    },
  });

  const envFilePath = path.join(harness.dir, '.env');
  try {
    const res = await runProcess('bash', [ROTATE_SCRIPT, '--skip-deploy', '--approve-major'], {
      cwd: harness.dir,
      env: buildCleanRotateEnv({
        FORGE_BIN: harness.mockForgeBin,
        FORGE_ENV_FILE: harness.missingForgeEnv,
        ENV_FILE: envFilePath,
        ENVIRONMENT: 'staging',
        FORGE_SITE: 'custom-site.atlassian.net',
        FORGE_PRODUCT: 'Jira',
        MEDTRACE_ALLOW_INSECURE_LOCALHOST: '1',
        MOCK_FORGE_STATE_FILE: harness.stateFile,
        MOCK_FORGE_LOG_FILE: harness.logFile,
      }),
    });
    // Because deploy was skipped in this test, mock activeSecret stayed 'staging-secret' so GET with new secret returns 401;
    // verify the CLI invocations and skip-deploy / ENVIRONMENT / FORGE_SITE wiring precisely.
    assert.equal(res.code, 1);

    const calls = harness.readForgeCalls();
    assert.ok(calls.some((c) => c[0] === 'lint' && c.includes('--approve') && c.includes('MAJOR_VERSION_RULE')));
    assert.ok(calls.some((c) => c[0] === 'variables' && c[1] === 'set' && c.includes('staging')));
    assert.equal(calls.some((c) => c[0] === 'deploy'), false);
    assert.ok(
      calls.some(
        (c) =>
          c[0] === 'webtrigger' &&
          c[1] === 'list' &&
          c.includes('staging') &&
          c.includes('-s') &&
          c.includes('custom-site.atlassian.net') &&
          c.includes('-p') &&
          c.includes('Jira'),
      ),
    );
  } finally {
    await harness.cleanup();
  }
});

// ============================================================================
// 3. scripts/validate-manifest.mjs tests
// ============================================================================

test('validate-manifest.mjs: passes on built repository and rejects remote icon URLs or missing manifest', async () => {
  const repoResult = await validateManifest({ rootDir: REPO_ROOT });
  assert.equal(repoResult.ok, true, repoResult.errors.join('\n'));
  assert.equal(repoResult.errors.length, 0);
  assert.equal(repoResult.verifiedHandlers.length, 5);

  const cliRes = await runProcess(process.execPath, [VALIDATE_MANIFEST_SCRIPT], {
    cwd: REPO_ROOT,
  });
  assert.equal(cliRes.code, 0, cliRes.stderr);
  assert.match(cliRes.stdout, /validate-manifest: OK/);
  assert.match(cliRes.stdout, /5 handler exports verified; 0 remote icon URLs/);

  const missingFixture = createTempTree('medtrace-manifest-missing-', {});
  try {
    const missingRes = await validateManifest({ rootDir: missingFixture.dir });
    assert.equal(missingRes.ok, false);
    assert.ok(missingRes.errors.some((e) => e.includes('Manifest file not found')));
  } finally {
    missingFixture.cleanup();
  }

  const badIconManifest = fs
    .readFileSync(path.join(REPO_ROOT, 'manifest.yml'), 'utf8')
    .replace('resource:icons;medtrace-icon.svg', 'https://example.com/remote-icon.svg');
  const badIconFixture = createTempTree('medtrace-manifest-bad-icon-', {
    'manifest.yml': badIconManifest,
    'static/frontend/dist/index.html': '<!doctype html><html></html>\n',
    'static/icons/medtrace-icon.svg': '<svg xmlns="http://www.w3.org/2000/svg"></svg>\n',
    'dist/index.js': [
      'export function resolverHandler() {}',
      'export function workflowValidatorHandler() {}',
      'export function rovoActionHandler() {}',
      'export function mcpWebtriggerHandler() {}',
      'export function confluencePageUpdatedTrigger() {}',
      '',
    ].join('\n'),
  });
  try {
    const iconRes = await validateManifest({ rootDir: badIconFixture.dir });
    assert.equal(iconRes.ok, false);
    assert.ok(
      iconRes.errors.some((e) => e.includes('[icon-policy]') && e.includes('https://example.com/remote-icon.svg')),
      `Expected [icon-policy] error, got: ${iconRes.errors.join(' | ')}`,
    );
  } finally {
    badIconFixture.cleanup();
  }
});
