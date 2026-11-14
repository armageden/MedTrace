const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const forgeApi = require('@forge/api');
const forgeKvs = require('@forge/kvs');
const {
  resolverHandler,
  mcpWebtriggerHandler,
  verifyHmacSignature,
  claimNonce,
  claimNonceDetailed,
  setNonceStore,
  createInMemoryNonceStore,
} = require('../dist/index.js');
const { SeederService } = require('../dist/seeder.js');
const { LiveIngestionService } = require('../dist/ingestion.js');
const { TeamworkGraphService } = require('../dist/teamwork-graph.js');
const { MAX_TIMESTAMP_AGE_MS, MAX_FUTURE_SKEW_MS, NONCE_TTL_MS } = require('../dist/nonce-store.js');
const { PART11_ATTESTATION_PHRASE } = require('../dist/types.js');
const { resetInMemoryAuditStorage, setAuditStorageAdapter } = require('../dist/audit-log.js');

function routeToString(urlObj) {
  if (typeof urlObj === 'string') return urlObj;
  if (urlObj && typeof urlObj.value_ === 'string') return urlObj.value_;
  return String(urlObj || '');
}

function makeHttpResponse(status, bodyObj = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => bodyObj,
    text: async () => JSON.stringify(bodyObj),
  };
}

function cloneJson(val) {
  return val === undefined ? undefined : JSON.parse(JSON.stringify(val));
}

function createInMemoryForgeKvs() {
  const store = new Map();
  return {
    store,
    async get(key) {
      return cloneJson(store.get(key));
    },
    async set(key, value, options) {
      if (options && options.keyPolicy === 'FAIL_IF_EXISTS' && store.has(key)) {
        throw new forgeKvs.ForgeKvsAPIError(
          { status: 409, statusText: 'Conflict' },
          { code: 'KEY_EXISTS', message: 'Key already exists' }
        );
      }
      const previous = store.has(key) ? cloneJson(store.get(key)) : undefined;
      store.set(key, cloneJson(value));
      if (options && options.keyPolicy === 'OVERRIDE' && options.returnValue === 'PREVIOUS') {
        return previous !== undefined ? { key, value: previous } : undefined;
      }
      return undefined;
    },
    async delete(key) {
      store.delete(key);
    },
    async batchGet(items) {
      const successfulKeys = [];
      for (const item of items) {
        if (store.has(item.key)) {
          successfulKeys.push({ key: item.key, value: cloneJson(store.get(item.key)) });
        }
      }
      return { successfulKeys, failedKeys: [] };
    },
    async batchSet(items) {
      for (const item of items) {
        store.set(item.key, cloneJson(item.value));
      }
      return { successfulKeys: items.map((i) => ({ key: i.key })), failedKeys: [] };
    },
    async batchDelete(items) {
      for (const item of items) {
        store.delete(item.key);
      }
      return { successfulKeys: items.map((i) => ({ key: i.key })), failedKeys: [] };
    },
    transact() {
      const sets = [];
      const deletes = [];
      const builder = {
        set(key, value) {
          sets.push({ key, value: cloneJson(value) });
          return builder;
        },
        delete(key) {
          deletes.push(key);
          return builder;
        },
        async execute() {
          for (const s of sets) {
            store.set(s.key, cloneJson(s.value));
          }
          for (const d of deletes) {
            store.delete(d);
          }
        },
      };
      return builder;
    },
    query() {
      let prefix = '';
      let maxResults = 50;
      return {
        where(field, cond) {
          if (field === 'key' && cond && typeof cond.value === 'string') {
            prefix = cond.value;
          }
          return this;
        },
        limit(n) {
          maxResults = n;
          return this;
        },
        cursor() {
          return this;
        },
        async getMany() {
          const results = [];
          for (const [k, v] of store.entries()) {
            if (!prefix || k.startsWith(prefix)) {
              results.push({ key: k, value: cloneJson(v) });
            }
          }
          return { results: results.slice(0, maxResults), nextCursor: undefined };
        },
      };
    },
  };
}

async function withForgeMocks({ requestJira, requestConfluence, onAsAppCall, kvsMock }, fn) {
  const apiDefault = forgeApi.default || forgeApi;
  const origDefaultAsUser = apiDefault.asUser;
  const origDefaultAsApp = apiDefault.asApp;
  const origTopAsUser = forgeApi.asUser;
  const origTopAsApp = forgeApi.asApp;
  const origKvsGet = forgeKvs.kvs.get;
  const origKvsSet = forgeKvs.kvs.set;
  const origKvsDelete = forgeKvs.kvs.delete;
  const origKvsBatchGet = forgeKvs.kvs.batchGet;
  const origKvsBatchSet = forgeKvs.kvs.batchSet;
  const origKvsBatchDelete = forgeKvs.kvs.batchDelete;
  const origKvsTransact = forgeKvs.kvs.transact;
  const origKvsQuery = forgeKvs.kvs.query;
  const origRuntime = globalThis.__forge_runtime__;

  const kvs = kvsMock || createInMemoryForgeKvs();
  const mockAsUser = () => ({
    requestJira: async (url, opts) =>
      requestJira ? requestJira(routeToString(url), opts, 'USER') : makeHttpResponse(404, { error: 'Not mocked' }),
    requestConfluence: async (url, opts) =>
      requestConfluence
        ? requestConfluence(routeToString(url), opts, 'USER')
        : makeHttpResponse(404, { error: 'Not mocked' }),
  });
  const mockAsApp = () => {
    if (onAsAppCall) onAsAppCall();
    return {
      requestJira: async (url, opts) =>
        requestJira ? requestJira(routeToString(url), opts, 'APP') : makeHttpResponse(404, { error: 'Not mocked' }),
      requestConfluence: async (url, opts) =>
        requestConfluence
          ? requestConfluence(routeToString(url), opts, 'APP')
          : makeHttpResponse(404, { error: 'Not mocked' }),
    };
  };

  globalThis.__forge_runtime__ = true;
  apiDefault.asUser = mockAsUser;
  apiDefault.asApp = mockAsApp;
  forgeApi.asUser = mockAsUser;
  forgeApi.asApp = mockAsApp;
  forgeKvs.kvs.get = kvs.get.bind(kvs);
  forgeKvs.kvs.set = kvs.set.bind(kvs);
  forgeKvs.kvs.delete = kvs.delete.bind(kvs);
  forgeKvs.kvs.batchGet = kvs.batchGet.bind(kvs);
  forgeKvs.kvs.batchSet = kvs.batchSet.bind(kvs);
  forgeKvs.kvs.batchDelete = kvs.batchDelete.bind(kvs);
  forgeKvs.kvs.transact = kvs.transact.bind(kvs);
  forgeKvs.kvs.query = kvs.query.bind(kvs);

  try {
    return await fn(kvs);
  } finally {
    apiDefault.asUser = origDefaultAsUser;
    apiDefault.asApp = origDefaultAsApp;
    forgeApi.asUser = origTopAsUser;
    forgeApi.asApp = origTopAsApp;
    forgeKvs.kvs.get = origKvsGet;
    forgeKvs.kvs.set = origKvsSet;
    forgeKvs.kvs.delete = origKvsDelete;
    forgeKvs.kvs.batchGet = origKvsBatchGet;
    forgeKvs.kvs.batchSet = origKvsBatchSet;
    forgeKvs.kvs.batchDelete = origKvsBatchDelete;
    forgeKvs.kvs.transact = origKvsTransact;
    forgeKvs.kvs.query = origKvsQuery;
    if (origRuntime === undefined) {
      delete globalThis.__forge_runtime__;
    } else {
      globalThis.__forge_runtime__ = origRuntime;
    }
  }
}

function signWebtriggerHeaders(secret, bodyStr, nonce, ts = Date.now().toString()) {
  const sig = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${bodyStr}`).digest('hex');
  return {
    'x-medtrace-timestamp': ts,
    'x-medtrace-nonce': nonce,
    'x-medtrace-signature': `sha256=${sig}`,
  };
}

function buildMinimalTraceLink({
  id,
  hazardKey = 'HAZ-101',
  specId = 'srs-1',
  workKey = 'MED-10',
  workStatus = 'Done',
  testKey = 'TST-1',
  testStatus = 'UNTESTED',
  evidenceUrl = '',
}) {
  const sha = crypto.createHash('sha256').update(`${hazardKey}:${specId}`).digest('hex');
  return {
    id,
    hazard: {
      key: hazardKey,
      title: 'Infusion Rate Overdose',
      severity: 'Catastrophic',
      riskClass: 'CLASS_C',
      safetyClass: 'Class C',
      status: 'ACTION_REQUIRED',
    },
    spec: {
      id: specId,
      title: 'Flow Limiter Spec',
      version: 1,
      sha256Hash: sha,
      url: `https://confluence.medtrace.internal/wiki/pages/${specId}`,
      approved: true,
    },
    work: {
      key: workKey,
      summary: `Mitigation ${workKey}`,
      status: workStatus,
    },
    test: {
      testKey,
      status: testStatus,
      evidenceUrl,
    },
    signature: {
      artifactSha256: sha,
      isValid: false,
    },
    complianceState: 'ACTION_REQUIRED',
    violations: ['Test evidence pending'],
  };
}

const ALL_RESOLVERS = [
  'getComplianceSuite',
  'seedDemoSuite',
  'syncLiveSuite',
  'remediateGap',
  'recordTestResult',
  'signOffPart11',
  'queryGraphContext',
  'bindIssueToHazard',
  'simulateTransition',
  'analyzeBlastRadius',
  'getAuditLog',
  'verifyAuditChain',
];

const READER_RESOLVERS = [
  'getComplianceSuite',
  'queryGraphContext',
  'simulateTransition',
  'analyzeBlastRadius',
  'getAuditLog',
  'verifyAuditChain',
];

const OPERATOR_RESOLVERS = [
  'seedDemoSuite',
  'syncLiveSuite',
  'remediateGap',
  'recordTestResult',
  'signOffPart11',
  'bindIssueToHazard',
];

test.describe('SEC-01 & SEC-03: Resolver RBAC, Confused-Deputy, Part 11 & Webtrigger Security', () => {
  const origMcpSecret = process.env.MEDTRACE_MCP_SECRET;
  const origPart11Secret = process.env.MEDTRACE_PART11_SECRET;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState();
    setNonceStore(null);
    process.env.MEDTRACE_MCP_SECRET = 'sec03-unit-test-secret';
    process.env.MEDTRACE_PART11_SECRET = 'sec01-part11-test-secret';
  });

  test.afterEach(() => {
    setNonceStore(null);
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState();
    if (origMcpSecret === undefined) delete process.env.MEDTRACE_MCP_SECRET;
    else process.env.MEDTRACE_MCP_SECRET = origMcpSecret;
    if (origPart11Secret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
    else process.env.MEDTRACE_PART11_SECRET = origPart11Secret;
  });

  // =========================================================================
  // 1. Unauthenticated access rejected on all 12 resolvers
  // =========================================================================
  test.it('rejects missing or blank accountId across all 12 resolvers before calling Atlassian APIs', async () => {
    let apiCalls = 0;
    await withForgeMocks(
      {
        requestJira: async () => {
          apiCalls += 1;
          return makeHttpResponse(200, {});
        },
        requestConfluence: async () => {
          apiCalls += 1;
          return makeHttpResponse(200, {});
        },
      },
      async () => {
        for (const fnKey of ALL_RESOLVERS) {
          await assert.rejects(
            () => resolverHandler({ call: { functionKey: fnKey, payload: {} }, context: {} }, {}),
            /Unauthorized: Authenticated Atlassian accountId is required/
          );
          await assert.rejects(
            () =>
              resolverHandler(
                { call: { functionKey: fnKey, payload: {} }, context: {} },
                { principal: { accountId: '   ' } }
              ),
            /Unauthorized: Authenticated Atlassian accountId is required/
          );
        }
      }
    );
    assert.strictEqual(apiCalls, 0);
  });

  // =========================================================================
  // 2. Confluence RBAC (Reader vs Operator + Personal-Space Trap)
  // =========================================================================
  test.it('Confluence read-only viewer (even with personal-space write) passes permitted reads and fails all 6 mutators', async () => {
    await withForgeMocks(
      {
        requestConfluence: async (url) => {
          if (url === '/wiki/rest/api/user/current') {
            return makeHttpResponse(200, { accountId: 'conf-viewer', type: 'known' });
          }
          if (url.startsWith('/wiki/api/v2/spaces?type=global')) {
            // Includes a personal space AND a read-only global space
            return makeHttpResponse(200, {
              results: [
                { id: 'sp-personal', key: '~viewer', type: 'personal' },
                { id: 'sp-global', key: 'MED', type: 'global' },
              ],
            });
          }
          if (url === '/wiki/api/v2/spaces/sp-personal/operations') {
            return makeHttpResponse(200, {
              operations: [
                { operation: 'administer', targetType: 'space' },
                { operation: 'update', targetType: 'page' },
              ],
            });
          }
          if (url === '/wiki/api/v2/spaces/sp-global/operations') {
            return makeHttpResponse(200, {
              operations: [
                { operation: 'read', targetType: 'page' },
                { operation: 'create', targetType: 'comment' },
              ],
            });
          }
          if (url.startsWith('/wiki/api/v2/spaces?limit=1')) {
            return makeHttpResponse(200, { results: [{ id: 'sp-global', type: 'global' }] });
          }
          if (url === '/wiki/api/v2/pages/pg-1') {
            return makeHttpResponse(200, { id: 'pg-1' });
          }
          if (url === '/wiki/api/v2/pages/pg-1/operations') {
            return makeHttpResponse(200, {
              operations: [
                { operation: 'read', targetType: 'page' },
                { operation: 'create', targetType: 'comment' },
              ],
            });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        await SeederService.seedEnterpriseDemoSuite('op-seed', 'SYSTEM_INIT');

        // Confluence globalPage reader resolvers succeed for viewer
        const suite = await resolverHandler(
          {
            call: { functionKey: 'getComplianceSuite', payload: {} },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-viewer' } }
        );
        assert.ok(suite.totalHazards >= 1);

        const blast = await resolverHandler(
          {
            call: { functionKey: 'analyzeBlastRadius', payload: { triggerKey: 'HAZ-101' } },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-viewer' } }
        );
        assert.strictEqual(blast.triggerArtifact.key, 'HAZ-101');

        const logs = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 5 } },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-viewer' } }
        );
        assert.ok(Array.isArray(logs));

        const chain = await resolverHandler(
          {
            call: { functionKey: 'verifyAuditChain', payload: {} },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-viewer' } }
        );
        assert.strictEqual(chain.valid, true);

        const qGraph = await resolverHandler(
          {
            call: { functionKey: 'queryGraphContext', payload: {} },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-viewer' } }
        );
        assert.strictEqual(qGraph, null);

        const simTrans = await resolverHandler(
          {
            call: { functionKey: 'simulateTransition', payload: { scope: 'global' } },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-viewer' } }
        );
        assert.strictEqual(simTrans.evaluatedIssueKey, undefined);
        assert.ok(READER_RESOLVERS.includes('simulateTransition'));

        // Confluence viewer MUST fail all 6 operator mutators despite personal space admin rights
        const payloads = {
          seedDemoSuite: {},
          syncLiveSuite: {},
          remediateGap: { hazardKey: 'HAZ-101', simulate: false, attestationConfirmed: true },
          recordTestResult: { hazardKey: 'HAZ-101', status: 'PASSED' },
          signOffPart11: {
            hazardKey: 'HAZ-101',
            meaning: 'Clinical Safety Approval',
            attestationConfirmed: true,
            passwordConfirmed: true,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
          },
          bindIssueToHazard: { hazardKey: 'HAZ-101', issueKey: 'MED-200' },
        };
        for (const fnKey of OPERATOR_RESOLVERS) {
          await assert.rejects(
            () =>
              resolverHandler(
                {
                  call: { functionKey: fnKey, payload: payloads[fnKey] },
                  context: { extension: { type: 'confluence:globalPage' } },
                },
                { principal: { accountId: 'conf-viewer' } }
              ),
            /Forbidden/
          );
        }

        // Content byline viewer (comment-only) fails operator on target page
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'seedDemoSuite', payload: {} },
                context: {
                  extension: {
                    type: 'confluence:contentBylineItem',
                    content: { id: 'pg-1' },
                    space: { id: 'sp-global' },
                  },
                },
              },
              { principal: { accountId: 'conf-viewer' } }
            ),
          /Forbidden/
        );
      }
    );
  });

  test.it('Confluence page/global-space editor succeeds and user/current mismatch fails', async () => {
    await withForgeMocks(
      {
        requestConfluence: async (url) => {
          if (url === '/wiki/rest/api/user/current') {
            return makeHttpResponse(200, { accountId: 'conf-editor', type: 'known' });
          }
          if (url.startsWith('/wiki/api/v2/spaces?type=global')) {
            return makeHttpResponse(200, { results: [{ id: 'sp-global', key: 'MED', type: 'global' }] });
          }
          if (url === '/wiki/api/v2/spaces/sp-global/operations') {
            return makeHttpResponse(200, {
              operations: [{ operation: 'create', targetType: 'page' }],
            });
          }
          if (url === '/wiki/api/v2/pages/pg-edit/operations') {
            return makeHttpResponse(200, {
              operations: [{ operation: 'update', targetType: 'page' }],
            });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        // Editor succeeds on globalPage
        const res1 = await resolverHandler(
          {
            call: { functionKey: 'seedDemoSuite', payload: {} },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-editor' } }
        );
        assert.strictEqual(res1.success, true);

        // Editor succeeds on page-scoped byline item
        const res2 = await resolverHandler(
          {
            call: { functionKey: 'seedDemoSuite', payload: {} },
            context: {
              extension: {
                type: 'confluence:contentBylineItem',
                content: { id: 'pg-edit' },
              },
            },
          },
          { principal: { accountId: 'conf-editor' } }
        );
        assert.strictEqual(res2.success, true);

        // Identity spoof (principal !== /user/current.accountId) fails
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'getComplianceSuite', payload: {} },
                context: { extension: { type: 'confluence:globalPage' } },
              },
              { principal: { accountId: 'spoofed-user' } }
            ),
          /Forbidden: Authenticated Confluence user identity mismatch/
        );
      }
    );
  });

  // =========================================================================
  // 3. Jira RBAC, Cross-Project / JQL Confused-Deputy & callerMode USER
  // =========================================================================
  test.it('Jira viewer passes reads and fails all 6 mutators; myself mismatch rejected', async () => {
    await withForgeMocks(
      {
        requestJira: async (url) => {
          if (url === '/rest/api/3/myself') {
            return makeHttpResponse(200, { accountId: 'jira-viewer', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: true },
                EDIT_ISSUES: { havePermission: false },
                ADMINISTER_PROJECTS: { havePermission: false },
              },
            });
          }
          return makeHttpResponse(200, {});
        },
      },
      async () => {
        await SeederService.seedEnterpriseDemoSuite('init', 'SYSTEM_INIT');

        // Reader calls pass
        const suite = await resolverHandler(
          {
            call: { functionKey: 'getComplianceSuite', payload: {} },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'jira-viewer' } }
        );
        assert.ok(suite.totalHazards >= 1);

        // All 6 operators fail
        for (const fnKey of OPERATOR_RESOLVERS) {
          await assert.rejects(
            () =>
              resolverHandler(
                {
                  call: {
                    functionKey: fnKey,
                    payload: { hazardKey: 'HAZ-101', issueKey: 'MED-10', status: 'PASSED' },
                  },
                  context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
                },
                { principal: { accountId: 'jira-viewer' } }
              ),
            /Forbidden: Requires Jira EDIT_ISSUES or ADMINISTER_PROJECTS permission/
          );
        }

        // Identity mismatch fails even on reader
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'getComplianceSuite', payload: {} },
                context: { extension: { type: 'jira:globalPage' } },
              },
              { principal: { accountId: 'wrong-user' } }
            ),
          /Forbidden: Authenticated Jira session account mismatch/
        );
      }
    );
  });

  test.it('blocks cross-project projectKey/issueKey/JQL overrides, forwards callerMode USER, and drops hardcoded fallbacks', async () => {
    const origSync = LiveIngestionService.syncFromAtlassian;
    const origQueryGraph = TeamworkGraphService.queryIssueGraphContext;
    const syncCalls = [];
    const graphCalls = [];

    LiveIngestionService.syncFromAtlassian = async (options, actorId) => {
      syncCalls.push({ options, actorId });
      return {
        success: true,
        projectKey: options.projectKey || 'MED',
        syncedCount: 1,
        unverifiedCount: 0,
        confluenceEnabled: false,
        summary: await SeederService.getActiveComplianceSuite(),
        message: 'ok',
      };
    };
    TeamworkGraphService.queryIssueGraphContext = async (issueKey, options) => {
      graphCalls.push({ issueKey, options });
      return {
        issueKey,
        summary: 'Graph node',
        linkedHazards: [],
        specPages: [],
        repositories: [],
        complianceImpact: 'NONE',
      };
    };

    try {
      await withForgeMocks(
        {
          requestJira: async (url) => {
            if (url === '/rest/api/3/myself') {
              return makeHttpResponse(200, { accountId: 'jira-op', active: true });
            }
            if (url.includes('issueKey=SEC-5')) {
              return makeHttpResponse(200, {
                permissions: {
                  BROWSE_PROJECTS: { havePermission: false },
                  EDIT_ISSUES: { havePermission: false },
                  ADMINISTER_PROJECTS: { havePermission: false },
                },
              });
            }
            if (url.startsWith('/rest/api/3/mypermissions')) {
              return makeHttpResponse(200, {
                permissions: {
                  BROWSE_PROJECTS: { havePermission: true },
                  EDIT_ISSUES: { havePermission: true },
                  ADMINISTER_PROJECTS: { havePermission: false },
                },
              });
            }
            if (url.startsWith('/rest/api/3/issue/MED-500')) {
              return makeHttpResponse(200, {
                key: 'MED-500',
                fields: { summary: 'Clamp Fix', status: { name: 'Done' } },
              });
            }
            return makeHttpResponse(404, {});
          },
        },
        async () => {
          await SeederService.seedEnterpriseDemoSuite('init', 'SYSTEM_INIT');

          // 1) Cross-project projectKey override inside projectPage(MED) rejected
          await assert.rejects(
            () =>
              resolverHandler(
                {
                  call: { functionKey: 'syncLiveSuite', payload: { projectKey: 'SECRET' } },
                  context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
                },
                { principal: { accountId: 'jira-op' } }
              ),
            /Forbidden: Cross-project override/
          );

          // 2) Cross-project JQL clause rejected across all operators
          for (const badJql of ['project = SECRET', 'status = Open AND PROJECT in (A, B)', 'project != MED']) {
            await assert.rejects(
              () =>
                resolverHandler(
                  {
                    call: { functionKey: 'syncLiveSuite', payload: { jql: badJql } },
                    context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
                  },
                  { principal: { accountId: 'jira-op' } }
                ),
              /Forbidden: Custom JQL cannot specify or override project scope/
            );
          }
          assert.strictEqual(syncCalls.length, 0);

          // 3) Valid syncLiveSuite scopes JQL to project="MED" and forwards includeUntaggedIssues & callerMode:'USER'
          await resolverHandler(
            {
              call: {
                functionKey: 'syncLiveSuite',
                payload: {
                  jql: 'status = "In Progress" ORDER BY updated DESC',
                  includeUntaggedIssues: true,
                },
              },
              context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
            },
            { principal: { accountId: 'jira-op' } }
          );
          assert.strictEqual(syncCalls.length, 1);
          assert.deepStrictEqual(syncCalls[0].options, {
            projectKey: 'MED',
            spaceId: undefined,
            jql: 'project = "MED" AND (status = "In Progress") ORDER BY updated DESC',
            includeUntaggedIssues: true,
            callerMode: 'USER',
          });

          // 4) Cross-project issueKey overrides rejected on bindIssueToHazard, queryGraphContext, simulateTransition
          for (const fnKey of ['bindIssueToHazard', 'queryGraphContext', 'simulateTransition']) {
            await assert.rejects(
              () =>
                resolverHandler(
                  {
                    call: {
                      functionKey: fnKey,
                      payload: { hazardKey: 'HAZ-101', issueKey: 'OTHER-99' },
                    },
                    context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
                  },
                  { principal: { accountId: 'jira-op' } }
                ),
              /Forbidden: Cross-project issue access/
            );
          }

          // 5) Unauthorized issueKey (SEC-5) fails even in globalPage context
          for (const fnKey of ['bindIssueToHazard', 'queryGraphContext', 'simulateTransition']) {
            await assert.rejects(
              () =>
                resolverHandler(
                  {
                    call: {
                      functionKey: fnKey,
                      payload: { hazardKey: 'HAZ-101', issueKey: 'SEC-5' },
                    },
                    context: { extension: { type: 'jira:globalPage' } },
                  },
                  { principal: { accountId: 'jira-op' } }
                ),
              /Forbidden/
            );
          }

          // 6) queryGraphContext forwards callerMode:'USER' and returns null when issueKey omitted (no 'MED-42' fallback)
          const emptyGraph = await resolverHandler(
            {
              call: { functionKey: 'queryGraphContext', payload: {} },
              context: { extension: { type: 'jira:globalPage' } },
            },
            { principal: { accountId: 'jira-op' } }
          );
          assert.strictEqual(emptyGraph, null);
          assert.strictEqual(graphCalls.length, 0);

          const validGraph = await resolverHandler(
            {
              call: { functionKey: 'queryGraphContext', payload: { issueKey: 'med-500' } },
              context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
            },
            { principal: { accountId: 'jira-op' } }
          );
          assert.strictEqual(validGraph.issueKey, 'MED-500');
          assert.strictEqual(graphCalls[0].options.callerMode, 'USER');

          // 7) No 'HAZ-101' / 'MED-42' fallbacks on bindIssueToHazard, remediateGap, signOffPart11
          await assert.rejects(
            () =>
              resolverHandler(
                {
                  call: { functionKey: 'bindIssueToHazard', payload: { hazardKey: '' } },
                  context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
                },
                { principal: { accountId: 'jira-op' } }
              ),
            /Bad Request/
          );
          await assert.rejects(
            () =>
              resolverHandler(
                {
                  call: {
                    functionKey: 'remediateGap',
                    payload: { hazardKey: '  ', simulate: false, attestationConfirmed: true },
                  },
                  context: { extension: { type: 'jira:globalPage' } },
                },
                { principal: { accountId: 'jira-op' } }
              ),
            /Bad Request/
          );
          await assert.rejects(
            () =>
              resolverHandler(
                {
                  call: {
                    functionKey: 'signOffPart11',
                    payload: {
                      hazardKey: '',
                      meaning: 'Valid clinical meaning',
                      attestationConfirmed: true,
                      passwordConfirmed: true,
                      attestationPhrase: PART11_ATTESTATION_PHRASE,
                    },
                  },
                  context: { extension: { type: 'jira:globalPage' } },
                },
                { principal: { accountId: 'jira-op' } }
              ),
            /Bad Request/
          );
        }
      );
    } finally {
      LiveIngestionService.syncFromAtlassian = origSync;
      TeamworkGraphService.queryIssueGraphContext = origQueryGraph;
    }
  });

  test.it('simulateTransition honors scope:"global" inside issuePanel and returns evaluatedIssueKey:undefined when omitted', async () => {
    await withForgeMocks(
      {
        requestJira: async (url) => {
          if (url === '/rest/api/3/myself') {
            return makeHttpResponse(200, { accountId: 'jira-user', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: { BROWSE_PROJECTS: { havePermission: true } },
            });
          }
          return makeHttpResponse(200, {});
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          {
            projectName: 'MedTrace Global',
            datasetMode: 'DEMO',
            initialized: true,
            standards: ['IEC 62304'],
            totalHazards: 1,
            classCCount: 1,
            classBCount: 0,
            classACount: 0,
            verifiedPercentage: 0,
            releaseBlocked: true,
            blockingReasons: ['HAZ-101 unverified'],
            signatureDriftCount: 0,
            lastAuditTimestamp: new Date().toISOString(),
            traceLinks: [
              buildMinimalTraceLink({
                id: 'l-1',
                hazardKey: 'HAZ-101',
                workKey: 'MED-10',
              }),
            ],
          },
          0
        );

        // Even though extension.issue.key is 'MED-999' (unrelated issue that would pass issue-level check),
        // scope: 'global' must evaluate globally and return evaluatedIssueKey: undefined.
        const globalRes = await resolverHandler(
          {
            call: { functionKey: 'simulateTransition', payload: { scope: 'global' } },
            context: {
              extension: {
                type: 'jira:issuePanel',
                project: { key: 'MED' },
                issue: { key: 'MED-999' },
              },
            },
          },
          { principal: { accountId: 'jira-user' } }
        );
        assert.strictEqual(globalRes.evaluatedIssueKey, undefined);
        assert.strictEqual(globalRes.result, false);

        // Default inside issuePanel binds to extension.issue.key 'MED-999'
        const issueRes = await resolverHandler(
          {
            call: { functionKey: 'simulateTransition', payload: {} },
            context: {
              extension: {
                type: 'jira:issuePanel',
                project: { key: 'MED' },
                issue: { key: 'MED-999' },
              },
            },
          },
          { principal: { accountId: 'jira-user' } }
        );
        assert.strictEqual(issueRes.evaluatedIssueKey, 'MED-999');
        assert.strictEqual(issueRes.result, true);

        // GlobalPage with omitted issueKey does NOT fall back to 'MED-42'
        const noKeyRes = await resolverHandler(
          {
            call: { functionKey: 'simulateTransition', payload: {} },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'jira-user' } }
        );
        assert.strictEqual(noKeyRes.evaluatedIssueKey, undefined);
        assert.strictEqual(noKeyRes.result, false);
      }
    );
  });

  // =========================================================================
  // 4. Part 11, recordTestResult HTTPS/clearing, seedDemoSuite overwrite, M:N linkId, beforeSeq
  // =========================================================================
  test.it('enforces Part 11 role/signedBy stripping, recordTestResult HTTPS & empty-string clearing, and M:N linkId isolation', async () => {
    let seenAsAppCalls = 0;
    await withForgeMocks(
      {
        onAsAppCall: () => {
          seenAsAppCalls += 1;
        },
        requestJira: async (url) => {
          if (url.startsWith('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'op-1', displayName: 'QA Operator', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: true },
                EDIT_ISSUES: { havePermission: true },
                ADMINISTER_PROJECTS: { havePermission: false },
              },
            });
          }
          if (url.startsWith('/rest/api/3/issue/MED-299')) {
            return makeHttpResponse(200, {
              key: 'MED-299',
              fields: {
                summary: 'Bound issue 299',
                status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
              },
            });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        // Seed initial M:N LIVE suite with two trace links sharing HAZ-101
        await SeederService.saveComplianceSuite(
          {
            projectName: 'Dual Hazard Suite',
            datasetMode: 'LIVE',
            initialized: true,
            standards: ['IEC 62304'],
            totalHazards: 2,
            classCCount: 2,
            classBCount: 0,
            classACount: 0,
            verifiedPercentage: 0,
            releaseBlocked: true,
            blockingReasons: ['Pending'],
            signatureDriftCount: 0,
            lastAuditTimestamp: new Date().toISOString(),
            traceLinks: [
              buildMinimalTraceLink({
                id: 'link-1',
                hazardKey: 'HAZ-101',
                specId: 'srs-1',
                workKey: 'MED-10',
                testKey: 'TST-1',
              }),
              buildMinimalTraceLink({
                id: 'link-2',
                hazardKey: 'HAZ-101',
                specId: 'srs-2',
                workKey: 'MED-20',
                testKey: 'TST-2',
              }),
            ],
          },
          0
        );

        // seedDemoSuite respects confirmOverwriteLive
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'seedDemoSuite', payload: {} },
                context: { extension: { type: 'jira:globalPage' } },
              },
              { principal: { accountId: 'op-1' } }
            ),
          /LIVE/
        );

        // 1) bindIssueToHazard with linkId targets ONLY link-2 and forwards callerMode:'USER' (never asApp)
        const bindRes = await resolverHandler(
          {
            call: {
              functionKey: 'bindIssueToHazard',
              payload: { hazardKey: 'HAZ-101', issueKey: 'MED-299', linkId: 'link-2' },
            },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'op-1' } }
        );
        assert.strictEqual(bindRes.success, true);
        assert.strictEqual(seenAsAppCalls, 0);
        assert.strictEqual(bindRes.summary.traceLinks.find((l) => l.id === 'link-1').work.key, 'MED-10');
        assert.strictEqual(bindRes.summary.traceLinks.find((l) => l.id === 'link-2').work.key, 'MED-299');

        // 2) recordTestResult rejects unsafe schemes
        for (const badUrl of ['javascript:alert(1)', 'http://insecure.medtrace.internal/1']) {
          await assert.rejects(
            () =>
              resolverHandler(
                {
                  call: {
                    functionKey: 'recordTestResult',
                    payload: {
                      hazardKey: 'HAZ-101',
                      linkId: 'link-2',
                      status: 'PASSED',
                      evidenceUrl: badUrl,
                    },
                  },
                  context: { extension: { type: 'jira:globalPage' } },
                },
                { principal: { accountId: 'op-1' } }
              ),
            /https/i
          );
        }

        // Valid HTTPS url on link-2 leaves link-1 untouched
        const recorded = await resolverHandler(
          {
            call: {
              functionKey: 'recordTestResult',
              payload: {
                hazardKey: 'HAZ-101',
                linkId: 'link-2',
                status: 'PASSED',
                evidenceUrl: 'https://ci.medtrace.internal/run/42',
                notes: 'Initial note',
              },
            },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'op-1' } }
        );
        assert.strictEqual(recorded.traceLinks.find((l) => l.id === 'link-1').test.status, 'UNTESTED');
        assert.strictEqual(recorded.traceLinks.find((l) => l.id === 'link-2').test.status, 'PASSED');

        // signOffPart11 requires passwordConfirmed & exact phrase (trimmed), and ignores spoofed signedBy/role
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'signOffPart11',
                  payload: {
                    hazardKey: 'HAZ-101',
                    linkId: 'link-2',
                    meaning: 'QA Safety Sign-off',
                    attestationConfirmed: true,
                    passwordConfirmed: false,
                    attestationPhrase: PART11_ATTESTATION_PHRASE,
                  },
                },
                context: { extension: { type: 'jira:globalPage' } },
              },
              { principal: { accountId: 'op-1' } }
            ),
          /passwordConfirmed/
        );

        const signed = await resolverHandler(
          {
            call: {
              functionKey: 'signOffPart11',
              payload: {
                hazardKey: 'HAZ-101',
                linkId: 'link-2',
                signedBy: 'spoofed-admin',
                role: 'Chief Medical Officer',
                meaning: 'QA Safety Sign-off',
                attestationConfirmed: true,
                passwordConfirmed: true,
                attestationPhrase: `  ${PART11_ATTESTATION_PHRASE}  `,
              },
            },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'op-1' } }
        );
        const link2AfterSign = signed.traceLinks.find((l) => l.id === 'link-2');
        const link1AfterSign = signed.traceLinks.find((l) => l.id === 'link-1');
        assert.strictEqual(link2AfterSign.signature.signedByAccountId, 'op-1');
        assert.notStrictEqual(link2AfterSign.signature.signedBy, 'spoofed-admin');
        assert.notStrictEqual(link2AfterSign.signature.role, 'Chief Medical Officer');
        assert.strictEqual(link2AfterSign.signature.isValid, true);
        assert.strictEqual(link2AfterSign.complianceState, 'VERIFIED');
        assert.strictEqual(link1AfterSign.signature.isValid, false);

        // Clearing evidenceUrl and notes via empty string "" works, and LIVE requireTestEvidence flags missing evidence
        const cleared = await resolverHandler(
          {
            call: {
              functionKey: 'recordTestResult',
              payload: {
                hazardKey: 'HAZ-101',
                linkId: 'link-2',
                status: 'PASSED',
                evidenceUrl: '',
                notes: '',
              },
            },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'op-1' } }
        );
        const link2AfterClear = cleared.traceLinks.find((l) => l.id === 'link-2');
        assert.strictEqual(link2AfterClear.test.evidenceUrl, undefined);
        assert.strictEqual(link2AfterClear.test.notes, undefined);
        assert.notStrictEqual(
          link2AfterClear.complianceState,
          'VERIFIED',
          'LIVE mode PASSED test without evidenceUrl must NOT be VERIFIED'
        );

        // getAuditLog supports beforeSeq cursor pagination
        const page1 = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 2 } },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'op-1' } }
        );
        assert.strictEqual(page1.length, 2);
        const minSeqPage1 = Math.min(...page1.map((e) => e.seq));
        const page2 = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 2, beforeSeq: minSeqPage1 } },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'op-1' } }
        );
        assert.ok(page2.length >= 1);
        assert.ok(page2.every((e) => e.seq < minSeqPage1));

        // confirmOverwriteLive: true allows overwriting LIVE suite
        const overwriteRes = await resolverHandler(
          {
            call: { functionKey: 'seedDemoSuite', payload: { confirmOverwriteLive: true } },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'op-1' } }
        );
        assert.strictEqual(overwriteRes.success, true);
      }
    );
  });

  // =========================================================================
  // 5. MCP Webtrigger Strict HTTP/Auth/Replay/LIVE/Sanitized-500 Contract
  // =========================================================================
  test.it('mcpWebtriggerHandler enforces 500 secret, 405 Allow before nonce, 401 bounds/HMAC/nonce-len, and verifyHmacSignature fail-closed', async () => {
    const secret = process.env.MEDTRACE_MCP_SECRET;

    // verifyHmacSignature fails closed on empty/whitespace secret or invalid inputs
    const tsNow = Date.now().toString();
    const emptySig = crypto.createHmac('sha256', '').update(`${tsNow}.n1.{}`).digest('hex');
    assert.strictEqual(verifyHmacSignature('{}', tsNow, `sha256=${emptySig}`, '', 'n1'), false);
    assert.strictEqual(verifyHmacSignature('{}', tsNow, `sha256=${emptySig}`, '   ', 'n1'), false);
    assert.strictEqual(verifyHmacSignature('{}', '12.34', `sha256=${emptySig}`, secret, 'n1'), false);

    // 500 when MEDTRACE_MCP_SECRET is missing or whitespace
    delete process.env.MEDTRACE_MCP_SECRET;
    const missingSecResp = await mcpWebtriggerHandler({ method: 'GET', headers: {} });
    assert.strictEqual(missingSecResp.statusCode, 500);
    process.env.MEDTRACE_MCP_SECRET = '   ';
    const blankSecResp = await mcpWebtriggerHandler({ method: 'GET', headers: {} });
    assert.strictEqual(blankSecResp.statusCode, 500);
    process.env.MEDTRACE_MCP_SECRET = secret;

    // claimNonceDetailed & claimNonce single-hash contract
    const memStore = createInMemoryNonceStore();
    assert.strictEqual(await claimNonceDetailed('n-direct-1', memStore, NONCE_TTL_MS), 'CLAIMED');
    assert.strictEqual(await claimNonceDetailed('n-direct-1', memStore, NONCE_TTL_MS), 'REPLAY');
    assert.strictEqual(await claimNonce('n-direct-2', memStore, NONCE_TTL_MS), true);
    assert.strictEqual(await claimNonce('n-direct-2', memStore, NONCE_TTL_MS), false);

    // 405 with Allow: GET, POST BEFORE nonce check (re-using same nonce on GET succeeds with 200!)
    const reusableNonce = 'method-nonce-' + crypto.randomUUID();
    for (const badMethod of ['PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      const mResp = await mcpWebtriggerHandler({
        method: badMethod,
        headers: signWebtriggerHeaders(secret, '', reusableNonce),
      });
      assert.strictEqual(mResp.statusCode, 405);
      assert.deepStrictEqual(mResp.headers.Allow, ['GET, POST']);
    }
    const after405Resp = await mcpWebtriggerHandler({
      method: 'GET',
      headers: signWebtriggerHeaders(secret, '', reusableNonce),
    });
    assert.strictEqual(after405Resp.statusCode, 200, 'Nonce must NOT be consumed by 405 rejection');

    // 401 header validation & >256 nonce
    const longNonce = 'x'.repeat(257);
    const rLongNonce = await mcpWebtriggerHandler({
      method: 'GET',
      headers: signWebtriggerHeaders(secret, '', longNonce),
    });
    assert.strictEqual(rLongNonce.statusCode, 401);

    const rBadTs = await mcpWebtriggerHandler({
      method: 'GET',
      headers: signWebtriggerHeaders(secret, '', 'n-bad-ts', 'not-digits'),
    });
    assert.strictEqual(rBadTs.statusCode, 401);

    // Asymmetric timestamp bounds [-300_000, +30_000]
    const nowMs = Date.now();
    const origDateNow = Date.now;
    Date.now = () => nowMs;
    try {
      const okOld = await mcpWebtriggerHandler({
        method: 'GET',
        headers: signWebtriggerHeaders(secret, '', 'n-old-ok', String(nowMs - MAX_TIMESTAMP_AGE_MS)),
      });
      assert.strictEqual(okOld.statusCode, 200);

      const failOld = await mcpWebtriggerHandler({
        method: 'GET',
        headers: signWebtriggerHeaders(secret, '', 'n-old-fail', String(nowMs - MAX_TIMESTAMP_AGE_MS - 1)),
      });
      assert.strictEqual(failOld.statusCode, 401);

      const okFuture = await mcpWebtriggerHandler({
        method: 'GET',
        headers: signWebtriggerHeaders(secret, '', 'n-fut-ok', String(nowMs + MAX_FUTURE_SKEW_MS)),
      });
      assert.strictEqual(okFuture.statusCode, 200);

      const failFuture = await mcpWebtriggerHandler({
        method: 'GET',
        headers: signWebtriggerHeaders(secret, '', 'n-fut-fail', String(nowMs + MAX_FUTURE_SKEW_MS + 1)),
      });
      assert.strictEqual(failFuture.statusCode, 401);
    } finally {
      Date.now = origDateNow;
    }

    // Verbatim string body HMAC check (reformatted JSON whitespace fails 401)
    const canonicalBody = '{"action":"status"}';
    const spacedBody = '{ "action": "status" }';
    const rTamperedWs = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signWebtriggerHeaders(secret, canonicalBody, 'n-ws-1'),
      body: spacedBody,
    });
    assert.strictEqual(rTamperedWs.statusCode, 401);

    // Custom failing NonceStore triggers 500 STORAGE_ERROR
    setNonceStore({
      async get() {
        throw new Error('KVS timeout');
      },
      async set() {
        throw new Error('KVS timeout');
      },
      async delete() {},
      async claimDetailed() {
        return 'STORAGE_ERROR';
      },
    });
    const errLogOrig = console.error;
    console.error = () => {};
    try {
      const rStoreErr = await mcpWebtriggerHandler({
        method: 'GET',
        headers: signWebtriggerHeaders(secret, '', 'n-store-err'),
      });
      assert.strictEqual(rStoreErr.statusCode, 500);
    } finally {
      console.error = errLogOrig;
      setNonceStore(createInMemoryNonceStore());
    }
  });

  test.it('mcpWebtriggerHandler enforces 400 validation, LIVE 403 guards, DEMO 404, verify-release-gate requireLiveMode, and sanitized 500', async () => {
    const secret = process.env.MEDTRACE_MCP_SECRET;

    // GET with non-empty body -> 400
    const getWithBody = await mcpWebtriggerHandler({
      method: 'GET',
      headers: signWebtriggerHeaders(secret, '{}', 'n-get-body'),
      body: '{}',
    });
    assert.strictEqual(getWithBody.statusCode, 400);

    // GET with ?action=seed -> 400; GET with ?action=status -> 200
    const getSeed = await mcpWebtriggerHandler({
      method: 'GET',
      headers: signWebtriggerHeaders(secret, '', 'n-get-seed'),
      queryParameters: { action: ['seed'] },
    });
    assert.strictEqual(getSeed.statusCode, 400);

    const getStatus = await mcpWebtriggerHandler({
      method: 'GET',
      headers: signWebtriggerHeaders(secret, '', 'n-get-status'),
      queryParameters: { action: ['status'] },
    });
    assert.strictEqual(getStatus.statusCode, 200);

    // Malformed JSON, JSON array, and unknown POST action -> 400
    for (const badBody of ['{not-json', '["seed"]', '123', JSON.stringify({ action: 'sync-status' })]) {
      const r = await mcpWebtriggerHandler({
        method: 'POST',
        headers: signWebtriggerHeaders(secret, badBody, 'n-bad-' + crypto.randomUUID()),
        body: badBody,
      });
      assert.strictEqual(r.statusCode, 400);
    }

    // Seed LIVE suite and verify seed/remediate are blocked with 403
    const liveCleanSuite = {
      projectName: 'Live Clinical',
      datasetMode: 'LIVE',
      initialized: true,
      standards: ['IEC 62304'],
      totalHazards: 1,
      classCCount: 1,
      classBCount: 0,
      classACount: 0,
      verifiedPercentage: 100,
      releaseBlocked: false,
      blockingReasons: [],
      signatureDriftCount: 0,
      lastAuditTimestamp: new Date().toISOString(),
      traceLinks: [
        {
          ...buildMinimalTraceLink({
            id: 'live-1',
            hazardKey: 'HAZ-101',
            workKey: 'MED-1',
            testStatus: 'PASSED',
            evidenceUrl: 'https://ci.medtrace.internal/1',
          }),
          complianceState: 'VERIFIED',
          violations: [],
        },
      ],
    };
    await SeederService.saveComplianceSuite(liveCleanSuite, 0);

    for (const payload of [{ action: 'seed' }, { action: 'remediate', hazardKey: 'HAZ-101' }]) {
      const b = JSON.stringify(payload);
      const r = await mcpWebtriggerHandler({
        method: 'POST',
        headers: signWebtriggerHeaders(secret, b, 'n-live-' + crypto.randomUUID()),
        body: b,
      });
      assert.strictEqual(r.statusCode, 403);
    }

    // verify-release-gate with requireLiveMode: true passes 200 on initialized LIVE clean suite
    const gateBody = JSON.stringify({ action: 'verify-release-gate', requireLiveMode: true });
    const liveGateOk = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signWebtriggerHeaders(secret, gateBody, 'n-gate-live-ok'),
      body: gateBody,
    });
    assert.strictEqual(liveGateOk.statusCode, 200);
    assert.strictEqual(JSON.parse(liveGateOk.body).result, true);
    assert.strictEqual(JSON.parse(liveGateOk.body).evaluatedIssueKey, undefined);

    // Switch to clean DEMO suite -> requireLiveMode: true MUST reject 403!
    await SeederService.saveComplianceSuite({ ...liveCleanSuite, datasetMode: 'DEMO' }, 1);
    const demoGate = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signWebtriggerHeaders(secret, gateBody, 'n-gate-demo-fail'),
      body: gateBody,
    });
    assert.strictEqual(demoGate.statusCode, 403);
    assert.strictEqual(JSON.parse(demoGate.body).result, false);

    // Uninitialized LIVE suite (initialized: false / totalHazards: 0) -> requireLiveMode: true MUST reject 403!
    await SeederService.saveComplianceSuite(
      { ...liveCleanSuite, datasetMode: 'LIVE', initialized: false, totalHazards: 0, traceLinks: [] },
      2
    );
    const uninitGate = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signWebtriggerHeaders(secret, gateBody, 'n-gate-uninit-fail'),
      body: gateBody,
    });
    assert.strictEqual(uninitGate.statusCode, 403);

    // validate / simulate_transition without issueKey does NOT default to 'MED-42'
    const simBody = JSON.stringify({ action: 'simulate_transition' });
    const simResp = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signWebtriggerHeaders(secret, simBody, 'n-sim-no-key'),
      body: simBody,
    });
    assert.strictEqual(simResp.statusCode, 200);
    assert.strictEqual(JSON.parse(simResp.body).evaluatedIssueKey, undefined);

    // Sanitized 500 error never leaks internal exception details
    const origGet = SeederService.getActiveComplianceSuite;
    const origConsoleErr = console.error;
    console.error = () => {};
    SeederService.getActiveComplianceSuite = async () => {
      throw new Error('SENSITIVE_DB_PASSWORD_OR_STACK_LEAK');
    };
    try {
      const statusBody = JSON.stringify({ action: 'status' });
      const errResp = await mcpWebtriggerHandler({
        method: 'POST',
        headers: signWebtriggerHeaders(secret, statusBody, 'n-err-500'),
        body: statusBody,
      });
      assert.strictEqual(errResp.statusCode, 500);
      assert.ok(!errResp.body.includes('SENSITIVE_DB_PASSWORD_OR_STACK_LEAK'));
      const parsed = JSON.parse(errResp.body);
      assert.match(parsed.error, /Internal Server Error/);
      assert.ok(typeof parsed.errorId === 'string' && parsed.errorId.length > 0);
    } finally {
      console.error = origConsoleErr;
      SeederService.getActiveComplianceSuite = origGet;
    }
  });
});
