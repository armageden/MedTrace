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
  'createReverificationTask',
  'createLiveProofScenario',
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
  'createReverificationTask',
  'createLiveProofScenario',
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
  // 1. Unauthenticated access rejected on all 14 resolvers
  // =========================================================================
  test.it('rejects missing or blank accountId across all 14 resolvers before calling Atlassian APIs', async () => {
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
  test.it('Confluence read-only viewer (even with personal-space write) passes permitted reads and fails all 8 mutators', async () => {
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

        // Confluence viewer MUST fail all 8 operator mutators despite personal space admin rights
        const payloads = {
          seedDemoSuite: {},
          syncLiveSuite: {},
          remediateGap: { hazardKey: 'HAZ-101', simulate: false, attestationConfirmed: true },
          recordTestResult: { hazardKey: 'HAZ-101', status: 'PASSED' },
          signOffPart11: {
            hazardKey: 'HAZ-101',
            meaning: 'Clinical Safety Approval',
            attestationConfirmed: true,
            attestationChecked: true,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
          },
          bindIssueToHazard: { hazardKey: 'HAZ-101', issueKey: 'MED-200' },
          createReverificationTask: { issueKey: 'MED-200' },
          createLiveProofScenario: { projectKey: 'MED' },
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
  test.it('Jira viewer passes reads and fails all 8 mutators; myself mismatch rejected', async () => {
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

        // All 8 operators fail
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
                      attestationChecked: true,
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

        // signOffPart11 requires attestationChecked & exact phrase (trimmed), and ignores spoofed signedBy/role
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
                    attestationChecked: false,
                    attestationPhrase: PART11_ATTESTATION_PHRASE,
                  },
                },
                context: { extension: { type: 'jira:globalPage' } },
              },
              { principal: { accountId: 'op-1' } }
            ),
          /attestationChecked/
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
                attestationChecked: true,
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

        // Project operator WITHOUT Jira ADMINISTER permission CANNOT overwrite initialized LIVE suite even with confirmOverwriteLive: true
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'seedDemoSuite', payload: { confirmOverwriteLive: true } },
                context: { extension: { type: 'jira:globalPage' } },
              },
              { principal: { accountId: 'op-1' } }
            ),
          /ADMINISTER/
        );
      }
    );

    // Verified Jira site administrator (ADMINISTER: true) CAN overwrite initialized LIVE suite with confirmOverwriteLive: true,
    // and pre-overwrite LIVE backup + audit record are persisted.
    await withForgeMocks(
      {
        requestJira: async (url) => {
          if (url.startsWith('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'site-admin-1', displayName: 'Site Admin', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: true },
                EDIT_ISSUES: { havePermission: true },
                ADMINISTER_PROJECTS: { havePermission: true },
                ADMINISTER: { havePermission: true },
              },
            });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          {
            projectName: 'Site Admin Live Suite',
            datasetMode: 'LIVE',
            initialized: true,
            standards: ['IEC 62304'],
            totalHazards: 1,
            classCCount: 1,
            classBCount: 0,
            classACount: 0,
            verifiedPercentage: 0,
            releaseBlocked: true,
            blockingReasons: ['Pending'],
            signatureDriftCount: 0,
            lastAuditTimestamp: new Date().toISOString(),
            traceLinks: [
              buildMinimalTraceLink({
                id: 'link-live-1',
                hazardKey: 'HAZ-101',
                specId: 'srs-1',
                workKey: 'MED-10',
                testKey: 'TST-1',
              }),
            ],
          },
          0
        );

        const overwriteRes = await resolverHandler(
          {
            call: { functionKey: 'seedDemoSuite', payload: { confirmOverwriteLive: true } },
            context: { extension: { type: 'jira:globalPage' } },
          },
          { principal: { accountId: 'site-admin-1' } }
        );
        assert.strictEqual(overwriteRes.success, true);
        assert.strictEqual(overwriteRes.summary.datasetMode, 'DEMO');

        const backup = await SeederService.getLastLiveBackup();
        assert.ok(backup, 'LIVE backup snapshot must be saved before DEMO overwrite');
        assert.strictEqual(backup.backedUpBy, 'site-admin-1');
        assert.strictEqual(backup.previousTraceLinkCount, 1);
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

    // GET with ?action=seed -> 400; status reads never return trace links
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
    assert.strictEqual(Object.hasOwn(JSON.parse(getStatus.body), 'traceLinks'), false);

    const getSuite = await mcpWebtriggerHandler({
      method: 'GET',
      headers: signWebtriggerHeaders(secret, '', 'n-get-suite'),
      queryParameters: { action: ['get-suite'] },
    });
    assert.strictEqual(getSuite.statusCode, 400);

    const postStatusBody = JSON.stringify({ action: 'status' });
    const postStatus = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signWebtriggerHeaders(secret, postStatusBody, 'n-post-status'),
      body: postStatusBody,
    });
    assert.strictEqual(postStatus.statusCode, 200);
    assert.strictEqual(Object.hasOwn(JSON.parse(postStatus.body), 'traceLinks'), false);

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

    const lineageBody = JSON.stringify({ action: 'get-hazard-lineage', issueKey: 'MED-1' });
    const lineageResponse = await mcpWebtriggerHandler({
      method: 'POST',
      headers: signWebtriggerHeaders(secret, lineageBody, 'n-lineage-query'),
      body: lineageBody,
    });
    assert.strictEqual(lineageResponse.statusCode, 200);
    const lineageResult = JSON.parse(lineageResponse.body);
    assert.strictEqual(lineageResult.found, true);
    assert.strictEqual(lineageResult.work.key, 'MED-1');
    assert.strictEqual(Object.hasOwn(lineageResult, 'traceLinks'), false);

    // Webtrigger get-hazard-lineage with empty/omitted lookup keys MUST NOT dump full traceLinks
    for (const emptyQuery of [{ action: 'get-hazard-lineage' }, { action: 'get-hazard-lineage', hazardKey: '   ', issueKey: '' }]) {
      const emptyBody = JSON.stringify(emptyQuery);
      const emptyResp = await mcpWebtriggerHandler({
        method: 'POST',
        headers: signWebtriggerHeaders(secret, emptyBody, `n-lineage-empty-${crypto.randomUUID()}`),
        body: emptyBody,
      });
      assert.strictEqual(emptyResp.statusCode, 200);
      const emptyResult = JSON.parse(emptyResp.body);
      assert.strictEqual(Object.hasOwn(emptyResult, 'traceLinks'), false);
      assert.strictEqual(emptyResult.totalHazards, 1);
      assert.strictEqual(emptyResult.datasetMode, 'LIVE');
    }

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

  // =========================================================================
  // 6. Cross-Project LIVE Read Isolation, Target-Issue IDOR & Confluence-Only Sync RBAC
  // =========================================================================
  test.it('isolates LIVE suites per project while keeping DEMO visible, blocks cross-project write IDOR, and blocks Confluence-only syncLiveSuite without Jira access', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine');
    const {
      PART11_ATTESTATION_PHRASE,
    } = require('../dist/types');

    await withForgeMocks(
      {
        requestJira: async (url) => {
          if (url === '/rest/api/3/myself') {
            return makeHttpResponse(200, { accountId: 'op-acme', active: true });
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
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        // DEMO remains visible inside non-MED project ACME
        await SeederService.seedEnterpriseDemoSuite('op-acme', 'FORGE_USER_SESSION');
        const demoFromAcme = await resolverHandler(
          {
            call: { functionKey: 'getComplianceSuite', payload: {} },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(demoFromAcme.datasetMode, 'DEMO');
        assert.ok(demoFromAcme.traceLinks.some((l) => l.work.key === 'MED-42'));

        // Switch to LIVE multi-project suite (MED-20 + ACME-1)
        const baseSpec = {
          pageId: '777',
          version: 1,
          sha256Hash: 'a'.repeat(64),
          lastSignedHash: 'a'.repeat(64),
          isSignatureInvalidated: false,
          contentSnippet: 'Spec text',
          lastUpdated: '2026-01-01T00:00:00.000Z',
        };
        const baseSig = {
          id: 'sig-base',
          signedBy: '',
          signedAt: '',
          role: 'QA',
          meaning: '',
          artifactSha256: '',
          isValid: false,
        };
        const medLink = ComplianceEngine.evaluateTraceLink(
          {
            id: 'haz-med',
            key: 'HAZ-MED',
            title: 'MED hazard',
            riskClass: 'CLASS_C',
            severity: 'CATASTROPHIC',
            probability: 'REMOTE',
            mitigationRequirementId: 'SRS-MED',
            status: 'ACTION_REQUIRED',
          },
          { ...baseSpec, id: 'spec-med', title: 'SRS-MED' },
          { id: 'w-med', key: 'MED-20', title: 'MED issue', status: 'In Progress', assignee: 'Alice' },
          { id: 't-med', testKey: 'TEST-MED', title: 'MED test', testType: 'Unit', status: 'UNTESTED' },
          { ...baseSig, id: 'sig-med' },
          undefined,
          { linkId: 'link-med', requireTestEvidence: true }
        );
        const acmeLink = ComplianceEngine.evaluateTraceLink(
          {
            id: 'haz-acme',
            key: 'HAZ-ACME',
            title: 'ACME hazard',
            riskClass: 'CLASS_A',
            severity: 'MINOR',
            probability: 'REMOTE',
            mitigationRequirementId: 'SRS-ACME',
            status: 'SAFE',
          },
          { ...baseSpec, id: 'spec-acme', title: 'SRS-ACME' },
          { id: 'w-acme', key: 'ACME-1', title: 'ACME issue', status: 'Done', assignee: 'Bob' },
          {
            id: 't-acme',
            testKey: 'TEST-ACME',
            title: 'ACME test',
            testType: 'Unit',
            status: 'PASSED',
            evidenceUrl: 'https://ci.example.com/acme/1',
          },
          { ...baseSig, id: 'sig-acme' },
          undefined,
          { linkId: 'link-acme', requireTestEvidence: true }
        );
        const multiProjectLive = ComplianceEngine.generateComplianceReport(
          [medLink, acmeLink],
          'LIVE',
          'Multi Project',
          { initialized: true }
        );
        await SeederService.saveComplianceSuite(multiProjectLive, 1);

        // LIVE read resolvers filter strictly to caller's project ACME
        const acmeSuite = await resolverHandler(
          {
            call: { functionKey: 'getComplianceSuite', payload: {} },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(acmeSuite.datasetMode, 'LIVE');
        assert.deepStrictEqual(
          acmeSuite.traceLinks.map((l) => l.work.key),
          ['ACME-1']
        );

        const acmeBlast = await resolverHandler(
          {
            call: { functionKey: 'analyzeBlastRadius', payload: { triggerKey: 'MED-20' } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.deepStrictEqual(acmeBlast.affectedHazardKeys, []);
        assert.deepStrictEqual(acmeBlast.blockedWorkItemKeys, []);

        // Cross-project write IDOR blocked before mutating target link bound to MED-20
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'recordTestResult',
                  payload: {
                    linkId: 'link-med',
                    hazardKey: 'HAZ-MED',
                    testKey: 'TEST-MED',
                    status: 'PASSED',
                    evidenceUrl: 'https://ci.example.com/spoof',
                  },
                },
                context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
              },
              { principal: { accountId: 'op-acme' } }
            ),
          /Forbidden: Cross-project issue access/
        );

        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'signOffPart11',
                  payload: {
                    linkId: 'link-med',
                    hazardKey: 'HAZ-MED',
                    specId: 'spec-med',
                    meaning: 'Unauthorized cross-project approval',
                    attestationConfirmed: true,
                    attestationChecked: true,
                    attestationPhrase: PART11_ATTESTATION_PHRASE,
                  },
                },
                context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
              },
              { principal: { accountId: 'op-acme' } }
            ),
          /Forbidden: Cross-project issue access/
        );

        const persisted = await SeederService.getActiveComplianceSuite();
        const untouchedMed = persisted.traceLinks.find((l) => l.id === 'link-med');
        assert.strictEqual(untouchedMed.test.status, 'UNTESTED');
        assert.strictEqual(untouchedMed.signature.isValid, false);
      }
    );

    // Confluence-only user without Jira access fails cleanly in syncLiveSuite RBAC before syncing
    const origSync = LiveIngestionService.syncFromAtlassian;
    let syncInvoked = false;
    LiveIngestionService.syncFromAtlassian = async () => {
      syncInvoked = true;
      throw new Error('Should not reach syncFromAtlassian');
    };
    try {
      await withForgeMocks(
        {
          requestConfluence: async (url) => {
            if (url === '/wiki/rest/api/user/current') {
              return makeHttpResponse(200, { accountId: 'conf-only', type: 'known' });
            }
            if (url.startsWith('/wiki/api/v2/spaces?type=global')) {
              return makeHttpResponse(200, { results: [{ id: 'sp-1', type: 'global' }] });
            }
            if (url === '/wiki/api/v2/spaces/sp-1/operations') {
              return makeHttpResponse(200, { operations: [{ operation: 'administer', targetType: 'space' }] });
            }
            return makeHttpResponse(404, {});
          },
          requestJira: async (url) => {
            if (url === '/rest/api/3/myself') {
              return makeHttpResponse(403, { message: 'Product access denied' });
            }
            return makeHttpResponse(404, {});
          },
        },
        async () => {
          await assert.rejects(
            () =>
              resolverHandler(
                {
                  call: { functionKey: 'syncLiveSuite', payload: {} },
                  context: { extension: { type: 'confluence:globalPage' } },
                },
                { principal: { accountId: 'conf-only' } }
              ),
            /Forbidden: Jira user session validation failed/
          );
          assert.strictEqual(syncInvoked, false);
        }
      );
    } finally {
      LiveIngestionService.syncFromAtlassian = origSync;
    }
  });

  test.it('tightens Confluence-to-Jira RBAC on cross-project LIVE reads, unbound-hazard writes, and bindIssueToHazard hijacks', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine');

    const baseSpec = {
      pageId: '888',
      version: 1,
      sha256Hash: 'b'.repeat(64),
      lastSignedHash: '',
      isSignatureInvalidated: false,
      contentSnippet: 'Spec text',
      lastUpdated: '2026-01-01T00:00:00.000Z',
    };
    const baseSig = {
      id: 'sig-base',
      signedBy: '',
      signedAt: '',
      role: 'QA',
      meaning: '',
      artifactSha256: '',
      isValid: false,
    };

    const medLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-med-20',
        key: 'HAZ-MED-20',
        title: 'MED-20 critical hazard',
        riskClass: 'CLASS_C',
        severity: 'CATASTROPHIC',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-med',
        status: 'ACTION_REQUIRED',
      },
      { ...baseSpec, id: 'srs-med', title: 'SRS-MED' },
      { id: 'w-med', key: 'MED-20', title: 'MED issue', status: 'In Progress', assignee: 'Alice' },
      { id: 't-med', testKey: 'TEST-MED', title: 'MED test', testType: 'Unit', status: 'UNTESTED' },
      { ...baseSig, id: 'sig-med' },
      undefined,
      { linkId: 'link-med-20', requireTestEvidence: true }
    );
    const acmeLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-acme-1',
        key: 'HAZ-ACME-1',
        title: 'ACME-1 hazard',
        riskClass: 'CLASS_A',
        severity: 'MINOR',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-acme',
        status: 'MITIGATED',
      },
      { ...baseSpec, id: 'srs-acme', title: 'SRS-ACME' },
      { id: 'w-acme', key: 'ACME-1', title: 'ACME issue', status: 'Done', assignee: 'Bob' },
      {
        id: 't-acme',
        testKey: 'TEST-ACME',
        title: 'ACME test',
        testType: 'Unit',
        status: 'PASSED',
        evidenceUrl: 'https://ci.example.com/acme/1',
        executionDate: '2026-01-02T00:00:00.000Z',
      },
      {
        id: 'sig-acme',
        signedBy: 'QA (op-acme)',
        signedByAccountId: 'op-acme',
        signedAt: '2026-01-02T00:00:00.000Z',
        role: 'Authorized Signatory',
        meaning: 'Approved',
        artifactSha256: baseSpec.sha256Hash,
        isValid: true,
        authMethod: 'PART11_ATTESTATION',
        signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
        signatureSeal: ComplianceEngine.computePart11Seal(
          {
            hazardKey: 'HAZ-ACME-1',
            specId: 'srs-acme',
            artifactSha256: baseSpec.sha256Hash,
            signedByAccountId: 'op-acme',
            signedBy: 'QA (op-acme)',
            role: 'Authorized Signatory',
            meaning: 'Approved',
            signedAt: '2026-01-02T00:00:00.000Z',
            authMethod: 'PART11_ATTESTATION',
          },
          process.env.MEDTRACE_PART11_SECRET
        ),
      },
      undefined,
      { linkId: 'link-acme-1', requireTestEvidence: true, requireCryptographicSeal: true }
    );
    const unboundLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-unbound-1',
        key: 'HAZ-UNBOUND',
        title: 'Unbound safety hazard',
        riskClass: 'CLASS_B',
        severity: 'CRITICAL',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-unbound',
        status: 'UNVERIFIED_RISK',
      },
      { ...baseSpec, id: 'srs-unbound', title: 'SRS-UNBOUND' },
      { id: 'w-unbound', key: '', title: 'Unbound work', status: 'To Do', assignee: 'Unassigned' },
      { id: 't-unbound', testKey: 'TEST-UNBOUND', title: 'Unbound test', testType: 'Unit', status: 'UNTESTED' },
      { ...baseSig, id: 'sig-unbound' },
      undefined,
      { linkId: 'link-unbound-1', requireTestEvidence: true }
    );

    // 1. Confluence editor with Jira BROWSE on ACME only (no MED browse, no Jira EDIT_ISSUES):
    //    - LIVE reads return ONLY ACME-1 (hiding MED-20 & unbound hazard)
    //    - Unbound-hazard writes from Confluence context fail closed without Jira EDIT_ISSUES
    await withForgeMocks(
      {
        requestConfluence: async (url) => {
          if (url === '/wiki/rest/api/user/current') {
            return makeHttpResponse(200, { accountId: 'conf-acme-reader', type: 'known' });
          }
          if (url.startsWith('/wiki/api/v2/spaces?limit=1')) {
            return makeHttpResponse(200, { results: [{ id: 'sp-1', type: 'global' }] });
          }
          if (url.startsWith('/wiki/api/v2/spaces?type=global')) {
            return makeHttpResponse(200, { results: [{ id: 'sp-1', type: 'global' }] });
          }
          if (url === '/wiki/api/v2/spaces/sp-1/operations') {
            return makeHttpResponse(200, { operations: [{ operation: 'update', targetType: 'page' }] });
          }
          return makeHttpResponse(404, {});
        },
        requestJira: async (url) => {
          if (url === '/rest/api/3/myself') {
            return makeHttpResponse(200, { accountId: 'conf-acme-reader', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            const parsed = new URL(`https://jira.invalid${url}`);
            const proj = parsed.searchParams.get('projectKey');
            const canBrowse = proj === null || proj === 'ACME';
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: canBrowse },
                EDIT_ISSUES: { havePermission: false },
                ADMINISTER_PROJECTS: { havePermission: false },
              },
            });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport(
            [medLink, acmeLink, unboundLink],
            'LIVE',
            'Cross-Product LIVE Suite',
            { initialized: true }
          ),
          0
        );

        const confSuite = await resolverHandler(
          {
            call: { functionKey: 'getComplianceSuite', payload: {} },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-acme-reader' } }
        );
        assert.deepStrictEqual(
          confSuite.traceLinks.map((l) => l.work.key),
          ['ACME-1', ''],
          'Confluence LIVE read must filter out unauthorized MED-20 while preserving authorized ACME-1'
        );

        const confBlast = await resolverHandler(
          {
            call: { functionKey: 'analyzeBlastRadius', payload: { triggerKey: 'MED-20' } },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-acme-reader' } }
        );
        assert.deepStrictEqual(confBlast.affectedHazardKeys, []);

        const confGate = await resolverHandler(
          {
            call: { functionKey: 'simulateTransition', payload: { scope: 'global' } },
            context: { extension: { type: 'confluence:globalPage' } },
          },
          { principal: { accountId: 'conf-acme-reader' } }
        );
        assert.strictEqual(confGate.result, false);
        assert.ok(
          !String(confGate.errorMessage || '').includes('MED-20'),
          'Filtered LIVE gate must not leak unauthorized MED-20 violation'
        );

        // Unbound-hazard writes from Confluence context without Jira EDIT_ISSUES MUST fail closed
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'recordTestResult',
                  payload: {
                    linkId: 'link-unbound-1',
                    hazardKey: 'HAZ-UNBOUND',
                    status: 'PASSED',
                    evidenceUrl: 'https://ci.example.com/spoof',
                  },
                },
                context: { extension: { type: 'confluence:globalPage' } },
              },
              { principal: { accountId: 'conf-acme-reader' } }
            ),
          /Forbidden: Requires Jira EDIT_ISSUES/
        );

        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'signOffPart11',
                  payload: {
                    linkId: 'link-unbound-1',
                    hazardKey: 'HAZ-UNBOUND',
                    meaning: 'Unauthorized Confluence-only signoff',
                    attestationConfirmed: true,
                    attestationChecked: true,
                    attestationPhrase: PART11_ATTESTATION_PHRASE,
                  },
                },
                context: { extension: { type: 'confluence:globalPage' } },
              },
              { principal: { accountId: 'conf-acme-reader' } }
            ),
          /Forbidden: Requires Jira EDIT_ISSUES/
        );
      }
    );

    // 2. Confluence-only user without Jira identity is rejected on LIVE getComplianceSuite
    await withForgeMocks(
      {
        requestConfluence: async (url) => {
          if (url === '/wiki/rest/api/user/current') {
            return makeHttpResponse(200, { accountId: 'conf-no-jira', type: 'known' });
          }
          if (url.startsWith('/wiki/api/v2/spaces?limit=1')) {
            return makeHttpResponse(200, { results: [{ id: 'sp-1', type: 'global' }] });
          }
          return makeHttpResponse(404, {});
        },
        requestJira: async (url) => {
          if (url === '/rest/api/3/myself') {
            return makeHttpResponse(403, { message: 'No Jira license' });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([medLink], 'LIVE', 'Jira-Restricted LIVE Suite', {
            initialized: true,
          }),
          0
        );
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'getComplianceSuite', payload: {} },
                context: { extension: { type: 'confluence:globalPage' } },
              },
              { principal: { accountId: 'conf-no-jira' } }
            ),
          /Forbidden: Jira user session validation failed/
        );
      }
    );

    // 3. bindIssueToHazard blocks ACME projectPage operator from hijacking HAZ-MED-20 (currently bound to MED-20)
    await withForgeMocks(
      {
        requestJira: async (url) => {
          if (url === '/rest/api/3/myself') {
            return makeHttpResponse(200, { accountId: 'op-acme', active: true });
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
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([medLink, acmeLink], 'LIVE', 'Hijack Guard Suite', {
            initialized: true,
          }),
          0
        );
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'bindIssueToHazard',
                  payload: { hazardKey: 'HAZ-MED-20', issueKey: 'ACME-2', linkId: 'link-med-20' },
                },
                context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
              },
              { principal: { accountId: 'op-acme' } }
            ),
          /Forbidden: Cross-project issue access is not permitted/
        );
      }
    );
  });

  test.it('isolates two Jira projects across syncLiveSuite, mutations, createReverificationTask, and getAuditLog', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine');
    const createdJiraIssues = [];
    const createdIssueLinks = [];

    const makeLiveIssue = (key, projectKey, summary, label, pageId) => ({
      id: `id-${key.toLowerCase()}`,
      key,
      fields: {
        summary,
        status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
        assignee: { displayName: 'Engineer' },
        labels: [label],
        issuetype: { name: 'Story' },
        project: { key: projectKey, name: `${projectKey} Project` },
        issuelinks: [],
      },
      _pageId: pageId,
    });

    await withForgeMocks(
      {
        requestJira: async (url, opts) => {
          if (url.startsWith('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'op-two-proj', displayName: 'Dual Op', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: true },
                EDIT_ISSUES: { havePermission: true },
                CREATE_ISSUES: { havePermission: true },
                ADMINISTER_PROJECTS: { havePermission: false },
              },
            });
          }
          if (url.startsWith('/rest/api/3/search/jql')) {
            const isAcme = url.includes('ACME');
            const issues = isAcme
              ? [makeLiveIssue('ACME-10', 'ACME', 'Acme Pump Spec', 'class-c', '9101')]
              : [makeLiveIssue('MED-10', 'MED', 'Med Pump Spec', 'class-c', '9102')];
            return makeHttpResponse(200, { issues, isLast: true });
          }
          if (url === '/rest/api/3/issue/ACME-10/remotelink') {
            return makeHttpResponse(200, [
              { object: { url: 'https://site.atlassian.net/wiki/spaces/ACME/pages/9101', title: 'SRS-9101' } },
            ]);
          }
          if (url === '/rest/api/3/issue/MED-10/remotelink') {
            return makeHttpResponse(200, [
              { object: { url: 'https://site.atlassian.net/wiki/spaces/MED/pages/9102', title: 'SRS-9102' } },
            ]);
          }
          if (url === '/rest/api/3/issue/ACME-10?fields=summary,status,issuelinks') {
            return makeHttpResponse(200, { id: 'id-acme-10', fields: { summary: 'Acme Pump Spec', status: { name: 'Done' }, issuelinks: [] } });
          }
          if (url === '/rest/api/3/issue/MED-10?fields=summary,status,issuelinks') {
            return makeHttpResponse(200, { id: 'id-med-10', fields: { summary: 'Med Pump Spec', status: { name: 'Done' }, issuelinks: [] } });
          }
          if (url.startsWith('/rest/api/3/issue/MED-11?fields=summary,status,assignee')) {
            return makeHttpResponse(200, {
              id: 'id-med-11',
              key: 'MED-11',
              fields: { summary: 'Med Rebound Issue', status: { name: 'Done', statusCategory: { key: 'done' } }, assignee: { displayName: 'Alice' } },
            });
          }
          if (url === '/rest/api/3/issue/createmeta/MED/issuetypes') {
            return makeHttpResponse(200, { issueTypes: [{ id: '10001', name: 'Task', subtask: false }] });
          }
          if (url === '/rest/api/3/issue' && opts?.method === 'POST') {
            const body = JSON.parse(opts.body);
            createdJiraIssues.push(body);
            return makeHttpResponse(201, { id: '99001', key: 'MED-99' });
          }
          if (url === '/rest/api/3/issueLinkType') {
            return makeHttpResponse(200, { issueLinkTypes: [{ name: 'Relates' }] });
          }
          if (url === '/rest/api/3/issueLink' && opts?.method === 'POST') {
            createdIssueLinks.push(JSON.parse(opts.body));
            return makeHttpResponse(201, {});
          }
          return makeHttpResponse(404, {});
        },
        requestConfluence: async (url) => {
          if (url.includes('/wiki/api/v2/pages/9101')) {
            return makeHttpResponse(200, {
              id: '9101',
              title: 'SRS-9101 Acme Spec',
              version: { number: 1, createdAt: '2026-11-01T00:00:00Z' },
              body: { storage: { value: '<p>Acme limit 1.0</p>' } },
            });
          }
          if (url.includes('/wiki/api/v2/pages/9102')) {
            return makeHttpResponse(200, {
              id: '9102',
              title: 'SRS-9102 Med Spec',
              version: { number: 1, createdAt: '2026-11-01T00:00:00Z' },
              body: { storage: { value: '<p>Med limit 5.0</p>' } },
            });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        // 1. Sync ACME first
        const acmeSync = await resolverHandler(
          {
            call: { functionKey: 'syncLiveSuite', payload: {} },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-two-proj' } }
        );
        assert.deepStrictEqual(acmeSync.summary.traceLinks.map((l) => l.work.key), ['ACME-10']);

        // 2. Sync MED second — must preserve ACME in KVS, but MUST NOT return ACME in syncLiveSuite response or warnings!
        const medSync = await resolverHandler(
          {
            call: { functionKey: 'syncLiveSuite', payload: {} },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'op-two-proj' } }
        );
        assert.deepStrictEqual(medSync.summary.traceLinks.map((l) => l.work.key), ['MED-10']);
        assert.ok(
          !medSync.warnings.some((w) => /other Jira project/i.test(w)),
          'syncLiveSuite must not leak cross-project preservation warnings'
        );

        // Full persisted KVS still contains both ACME-10 and MED-10
        const fullPersisted = await SeederService.getActiveComplianceSuite();
        assert.strictEqual(fullPersisted.traceLinks.length, 2);

        // 3. recordTestResult in MED returns ONLY MED-10
        const medAfterTest = await resolverHandler(
          {
            call: {
              functionKey: 'recordTestResult',
              payload: {
                hazardKey: 'HAZ-MED-10',
                status: 'PASSED',
                evidenceUrl: 'https://ci.example.com/med-10',
                notes: 'Secret MED test note',
              },
            },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'op-two-proj' } }
        );
        assert.deepStrictEqual(medAfterTest.traceLinks.map((l) => l.work.key), ['MED-10']);

        // 4. signOffPart11 in MED returns ONLY MED-10
        const medAfterSign = await resolverHandler(
          {
            call: {
              functionKey: 'signOffPart11',
              payload: {
                hazardKey: 'HAZ-MED-10',
                specId: 'srs-9102',
                meaning: 'Med clinical approval',
                attestationConfirmed: true,
                attestationChecked: true,
                attestationPhrase: PART11_ATTESTATION_PHRASE,
              },
            },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'op-two-proj' } }
        );
        assert.deepStrictEqual(medAfterSign.traceLinks.map((l) => l.work.key), ['MED-10']);

        // 5. createReverificationTask in MED creates MED-99, links MED-10, and returns ONLY MED
        const revTaskRes = await resolverHandler(
          {
            call: {
              functionKey: 'createReverificationTask',
              payload: {
                hazardKey: 'HAZ-MED-10',
                issueKey: 'MED-10',
                reason: 'Requirement 5.0 -> 5.5 mL/hr',
              },
            },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'op-two-proj' } }
        );
        assert.strictEqual(revTaskRes.success, true);
        assert.strictEqual(revTaskRes.createdIssueKey, 'MED-99');
        assert.deepStrictEqual(revTaskRes.linkedIssueKeys, ['MED-10']);
        assert.deepStrictEqual(revTaskRes.summary.traceLinks.map((l) => l.work.key), ['MED-10']);
        assert.strictEqual(createdJiraIssues.length, 1);
        assert.strictEqual(createdIssueLinks.length, 1);

        // 6. bindIssueToHazard in MED returns ONLY MED
        const bindRes = await resolverHandler(
          {
            call: {
              functionKey: 'bindIssueToHazard',
              payload: { hazardKey: 'HAZ-MED-10', issueKey: 'MED-11' },
            },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'op-two-proj' } }
        );
        assert.strictEqual(bindRes.success, true);
        assert.deepStrictEqual(bindRes.summary.traceLinks.map((l) => l.work.key), ['MED-11']);

        // 7. getAuditLog in ACME projectPage MUST NOT return any MED entries (notes, evidenceUrl, MED-99, MED-11, etc.)
        const acmeAudit = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 50 } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-two-proj' } }
        );
        assert.strictEqual(acmeAudit.length, 1, 'ACME caller should only see ACME SYNC_LIVE audit entry');
        assert.strictEqual(acmeAudit[0].targetKey, 'ACME');
        const acmeSerialized = JSON.stringify(acmeAudit);
        assert.ok(!acmeSerialized.includes('MED-10') && !acmeSerialized.includes('MED-99') && !acmeSerialized.includes('Secret MED test note'));

        // 8. getAuditLog in MED projectPage MUST NOT return ACME entries
        const medAudit = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 50 } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'op-two-proj' } }
        );
        assert.strictEqual(medAudit.length, 5);
        assert.ok(!JSON.stringify(medAudit).includes('ACME'));

        // Suppress unused import lint warning if ComplianceEngine wasn't needed directly
        assert.ok(ComplianceEngine);
      }
    );
  });

  test.it('enforces per-page Confluence authorization, preserves entryHash integrity by omitting cross-project audit entries, and makes createReverificationTask idempotent', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine');
    const { AuditLogService, computeAuditEntryHash } = require('../dist/audit-log');

    let revCreateCount = 0;
    let revTaskStatus = 'In Progress';
    let revTaskHttpStatus = 200;

    const makeIssue = (key, projectKey, summary) => ({
      id: `id-${key.toLowerCase()}`,
      key,
      fields: {
        summary,
        status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
        assignee: { displayName: 'Engineer' },
        labels: ['class-c'],
        issuetype: { name: 'Story' },
        project: { key: projectKey, name: projectKey },
        issuelinks: [],
      },
    });

    await withForgeMocks(
      {
        requestJira: async (url, opts) => {
          if (url.startsWith('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'op-acme', displayName: 'ACME Op', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            const disallowed = url.includes('MED') || url.includes('SRS');
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: !disallowed },
                EDIT_ISSUES: { havePermission: !disallowed },
                CREATE_ISSUES: { havePermission: !disallowed },
                ADMINISTER_PROJECTS: { havePermission: false },
              },
            });
          }
          if (url.startsWith('/rest/api/3/issue/ACME-99?fields=status')) {
            if (revTaskHttpStatus !== 200) {
              return makeHttpResponse(revTaskHttpStatus, {});
            }
            return makeHttpResponse(200, {
              id: '9901',
              key: 'ACME-99',
              fields: {
                status: {
                  name: revTaskStatus,
                  statusCategory: { key: revTaskStatus === 'Done' ? 'done' : 'indeterminate', name: revTaskStatus },
                },
              },
            });
          }
          if (url === '/rest/api/3/issue/createmeta/ACME/issuetypes') {
            return makeHttpResponse(200, { issueTypes: [{ id: '1', name: 'Task', subtask: false }] });
          }
          if (url === '/rest/api/3/issue' && opts?.method === 'POST') {
            revCreateCount++;
            return makeHttpResponse(201, { id: String(9900 + revCreateCount), key: `ACME-${98 + revCreateCount}` });
          }
          if (url === '/rest/api/3/issueLinkType') {
            return makeHttpResponse(200, { issueLinkTypes: [{ name: 'Relates' }] });
          }
          if (url === '/rest/api/3/issueLink' && opts?.method === 'POST') {
            return makeHttpResponse(201, {});
          }
          return makeHttpResponse(404, makeIssue('NA-0', 'NA', 'missing'));
        },
        requestConfluence: async (url) => {
          if (url === '/wiki/rest/api/user/current') {
            return makeHttpResponse(200, { accountId: 'op-acme', type: 'known' });
          }
          if (url.includes('/wiki/api/v2/pages/9101')) {
            return makeHttpResponse(200, { id: '9101', title: 'Public SRS-9101' });
          }
          if (url.includes('/wiki/api/v2/pages/9199')) {
            return makeHttpResponse(403, { message: 'Page restricted' });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        const publicLink = ComplianceEngine.evaluateTraceLink(
          {
            id: 'haz-acme-10',
            key: 'HAZ-ACME-10',
            title: 'ACME-10 Hazard',
            riskClass: 'CLASS_C',
            severity: 'CATASTROPHIC',
            probability: 'REMOTE',
            mitigationRequirementId: 'srs-9101',
            status: 'ACTION_REQUIRED',
          },
          {
            id: 'srs-9101',
            pageId: '9101',
            title: 'Public SRS-9101',
            version: 1,
            sha256Hash: 'a'.repeat(64),
            lastSignedHash: 'a'.repeat(64),
            isSignatureInvalidated: false,
            contentSnippet: 'Allowed public excerpt',
            lastUpdated: '2026-11-20T00:00:00Z',
          },
          { id: 'w-10', key: 'ACME-10', title: 'ACME-10 Work', status: 'Done', assignee: 'Alice' },
          { id: 't-10', testKey: 'TEST-ACME-10', title: 'Test 10', testType: 'Unit Test', status: 'UNTESTED' },
          { id: 'sig-10', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
          undefined,
          { linkId: 'link-acme-10', requireTestEvidence: true }
        );

        const restrictedSpecSha = 'e'.repeat(64);
        const restrictedSpecLink = ComplianceEngine.evaluateTraceLink(
          {
            id: 'haz-acme-11',
            key: 'HAZ-ACME-11',
            title: 'ACME-11 Hazard',
            riskClass: 'CLASS_A',
            severity: 'MINOR',
            probability: 'REMOTE',
            mitigationRequirementId: 'srs-9199',
            status: 'MITIGATED',
          },
          {
            id: 'srs-9199',
            pageId: '9199',
            title: 'Secret Confluence Spec 9199',
            version: 4,
            sha256Hash: restrictedSpecSha,
            lastSignedHash: restrictedSpecSha,
            isSignatureInvalidated: false,
            contentSnippet: 'CONFIDENTIAL_CONF_BODY_LEAK',
            lastUpdated: '2026-11-20T00:00:00Z',
          },
          { id: 'w-11', key: 'ACME-11', title: 'ACME-11 Work', status: 'Done', assignee: 'Bob' },
          { id: 't-11', testKey: 'TEST-ACME-11', title: 'Test 11', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/11', executionDate: '2026-11-20T00:00:00Z' },
          {
            id: 'sig-11',
            signedBy: 'Bob (op-acme)',
            signedByAccountId: 'op-acme',
            signedAt: '2026-11-20T00:00:00Z',
            role: 'Authorized Signatory',
            meaning: 'Approved',
            artifactSha256: restrictedSpecSha,
            isValid: true,
            authMethod: 'PART11_ATTESTATION',
            signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
            signatureSeal: ComplianceEngine.computePart11Seal(
              {
                hazardKey: 'HAZ-ACME-11',
                specId: 'srs-9199',
                artifactSha256: restrictedSpecSha,
                signedByAccountId: 'op-acme',
                signedBy: 'Bob (op-acme)',
                role: 'Authorized Signatory',
                meaning: 'Approved',
                signedAt: '2026-11-20T00:00:00Z',
                authMethod: 'PART11_ATTESTATION',
              },
              process.env.MEDTRACE_PART11_SECRET
            ),
          },
          undefined,
          {
            linkId: 'link-acme-11',
            part11Secret: process.env.MEDTRACE_PART11_SECRET,
            requireTestEvidence: true,
            requireCryptographicSeal: true,
          }
        );
        assert.strictEqual(restrictedSpecLink.complianceState, 'VERIFIED');

        // Verify restricted-spec projection preserves VERIFIED server-side metrics (0 manufactured drift, 100% verified, artifactSha256 scrubbed)
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([restrictedSpecLink], 'LIVE', 'Verified Restricted Single Link', { initialized: true }),
          0
        );
        const verifiedOnlySuite = await resolverHandler(
          {
            call: { functionKey: 'getComplianceSuite', payload: {} },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(verifiedOnlySuite.signatureDriftCount, 0, 'Must not manufacture signatureDriftCount from redacted spec hash');
        assert.strictEqual(verifiedOnlySuite.verifiedPercentage, 100);
        assert.strictEqual(verifiedOnlySuite.releaseBlocked, false);
        assert.strictEqual(verifiedOnlySuite.traceLinks[0].spec.specRestricted, true);
        assert.strictEqual(verifiedOnlySuite.traceLinks[0].spec.sha256Hash, '');
        assert.strictEqual(verifiedOnlySuite.traceLinks[0].signature.artifactSha256, '');

        const blastRestricted = await resolverHandler(
          {
            call: { functionKey: 'analyzeBlastRadius', payload: { triggerKey: 'ACME-11' } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(blastRestricted.invalidatedSignatureIds.length, 0);
        assert.ok(!JSON.stringify(blastRestricted).includes('Secret Confluence Spec 9199'));
        assert.ok(!JSON.stringify(blastRestricted).includes(restrictedSpecSha.slice(0, 8)));

        const medLink = ComplianceEngine.evaluateTraceLink(
          {
            id: 'haz-med-20',
            key: 'HAZ-MED-20',
            title: 'MED Hazard',
            riskClass: 'CLASS_C',
            severity: 'CATASTROPHIC',
            probability: 'REMOTE',
            mitigationRequirementId: 'srs-9101',
            status: 'ACTION_REQUIRED',
          },
          {
            id: 'srs-9101',
            pageId: '9101',
            title: 'Public SRS-9101',
            version: 1,
            sha256Hash: 'a'.repeat(64),
            lastSignedHash: '',
            isSignatureInvalidated: false,
            contentSnippet: 'Allowed public excerpt',
            lastUpdated: '2026-11-20T00:00:00Z',
          },
          { id: 'w-med-20', key: 'MED-20', title: 'MED-20 Work', status: 'In Progress', assignee: 'Carol' },
          { id: 't-med-20', testKey: 'TEST-MED-20', title: 'Test MED', testType: 'Unit Test', status: 'UNTESTED' },
          { id: 'sig-med-20', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
          undefined,
          { linkId: 'link-med-20', requireTestEvidence: true }
        );

        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([publicLink, restrictedSpecLink, medLink], 'LIVE', 'Confluence Per-Page Suite', { initialized: true }),
          1
        );

        // 1. Custom UI getComplianceSuite redacts page 9199 while keeping readable page 9101 intact
        const acmeSuite = await resolverHandler(
          {
            call: { functionKey: 'getComplianceSuite', payload: {} },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(acmeSuite.traceLinks.length, 2);
        const l10 = acmeSuite.traceLinks.find((l) => l.work.key === 'ACME-10');
        const l11 = acmeSuite.traceLinks.find((l) => l.work.key === 'ACME-11');
        assert.strictEqual(l10.spec.title, 'Public SRS-9101');
        assert.strictEqual(l10.spec.specRestricted, undefined);
        assert.strictEqual(l11.spec.specRestricted, true);
        assert.strictEqual(l11.spec.title, 'Restricted Confluence Specification');
        assert.strictEqual(l11.spec.sha256Hash, '');
        assert.strictEqual(l11.signature.artifactSha256, '');
        assert.ok(!JSON.stringify(acmeSuite).includes('CONFIDENTIAL_CONF_BODY_LEAK'));
        assert.ok(!JSON.stringify(acmeSuite).includes('Secret Confluence Spec 9199'));

        // 2. Multi-project audit entry referencing ACME + MED is OMITTED (not mutated) so all returned entryHashes verify
        await AuditLogService.append({
          actorAccountId: 'op-acme',
          action: 'RECORD_TEST_RESULT',
          targetKey: 'TEST-ACME-10',
          details: { projectKey: 'ACME', hazardKey: 'HAZ-ACME-10', notes: 'Single project event' },
          authMethod: 'FORGE_USER_SESSION',
        });
        await AuditLogService.append({
          actorAccountId: 'confluence-event-trigger',
          action: 'CONFLUENCE_PAGE_DRIFT',
          targetKey: 'page:9101',
          details: {
            pageId: '9101',
            affectedHazards: ['HAZ-ACME-10', 'HAZ-MED-20'],
            affectedWorkKeys: ['ACME-10', 'MED-20'],
            projectKeys: ['ACME', 'MED'],
          },
          authMethod: 'CONFLUENCE_EVENT_TRIGGER',
        });

        const acmeLogs = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 20 } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(acmeLogs.length, 1, 'Multi-project drift entry must be omitted rather than hash-broken');
        assert.strictEqual(acmeLogs[0].action, 'RECORD_TEST_RESULT');
        assert.strictEqual(
          computeAuditEntryHash({
            seq: acmeLogs[0].seq,
            timestamp: acmeLogs[0].timestamp,
            actorAccountId: acmeLogs[0].actorAccountId,
            action: acmeLogs[0].action,
            targetKey: acmeLogs[0].targetKey,
            details: acmeLogs[0].details,
            prevHash: acmeLogs[0].prevHash,
            authMethod: acmeLogs[0].authMethod,
          }),
          acmeLogs[0].entryHash
        );

        // 3. Idempotent createReverificationTask skips duplicate Jira task while ACME-99 is open, creates ACME-100 after Done
        const firstTask = await resolverHandler(
          {
            call: { functionKey: 'createReverificationTask', payload: { hazardKey: 'HAZ-ACME-10', issueKey: 'ACME-10' } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(firstTask.createdIssueKey, 'ACME-99');
        assert.strictEqual(revCreateCount, 1);

        // Regression: audit entries referencing Confluence specId "srs-9199" must NOT treat "SRS" as a foreign Jira project
        await AuditLogService.append({
          actorAccountId: 'op-acme',
          action: 'PART11_SIGNOFF',
          targetKey: 'HAZ-ACME-11',
          details: { projectKey: 'ACME', hazardKey: 'HAZ-ACME-11', workKey: 'ACME-11', specId: 'srs-9199' },
          authMethod: 'PART11_ATTESTATION',
        });
        const acmeLogsWithSpecId = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 20 } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.ok(
          acmeLogsWithSpecId.some((e) => e.action === 'PART11_SIGNOFF' && e.targetKey === 'HAZ-ACME-11'),
          'PART11_SIGNOFF with specId srs-9199 must remain visible to ACME caller'
        );

        const secondTask = await resolverHandler(
          {
            call: { functionKey: 'createReverificationTask', payload: { hazardKey: 'HAZ-ACME-10', issueKey: 'ACME-10' } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(secondTask.createdIssueKey, 'ACME-99');
        assert.strictEqual(secondTask.alreadyExisted, true);
        assert.strictEqual(revCreateCount, 1);

        // Fails closed (does not create duplicate) when existing-task status lookup returns transient 500
        revTaskHttpStatus = 500;
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'createReverificationTask', payload: { hazardKey: 'HAZ-ACME-10', issueKey: 'ACME-10' } },
                context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
              },
              { principal: { accountId: 'op-acme' } }
            ),
          /Unable to verify status of existing re-verification task ACME-99/
        );
        assert.strictEqual(revCreateCount, 1);

        // Confirmed Done (or 404 deleted) allows creating replacement ACME-100
        revTaskHttpStatus = 200;
        revTaskStatus = 'Done';
        const thirdTask = await resolverHandler(
          {
            call: { functionKey: 'createReverificationTask', payload: { hazardKey: 'HAZ-ACME-10', issueKey: 'ACME-10' } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(thirdTask.createdIssueKey, 'ACME-100');
        assert.strictEqual(revCreateCount, 2);
      }
    );
  });

  test.it('honors getComplianceSuite skipReconcile=true and reconciles stale Confluence pages on verify-release-gate & keyless workflowValidator', async () => {
    const secret = 'reconcile-gate-secret-999';
    process.env.MEDTRACE_MCP_SECRET = secret;
    process.env.MEDTRACE_PART11_SECRET = 'part11-gate-secret-999';
    setNonceStore(createInMemoryNonceStore());

    const origBody = '<p>Approved Gate Spec v1</p>';
    const modifiedBody = '<p>Modified Unsigned Gate Spec v2</p>';
    const crypto = require('node:crypto');
    const origHash = crypto.createHash('sha256').update(origBody).digest('hex');
    const signedAt = '2026-11-20T00:00:00.000Z';
    const { ComplianceEngine } = require('../dist/compliance-engine');
    const { LiveIngestionService } = require('../dist/ingestion');
    const { workflowValidatorHandler } = require('../dist/workflow-validator');

    const seal = ComplianceEngine.computePart11Seal(
      {
        hazardKey: 'HAZ-GATE-1',
        specId: '92001',
        artifactSha256: origHash,
        signedByAccountId: 'op-gate',
        signedBy: 'Gate Approver',
        role: 'QA',
        meaning: 'Approved',
        signedAt,
        authMethod: 'PART11_ATTESTATION',
      },
      process.env.MEDTRACE_PART11_SECRET
    );
    const verifiedLink = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-gate-1', key: 'HAZ-GATE-1', title: 'Gate Hazard', riskClass: 'CLASS_C', mitigationRequirementId: '92001', status: 'MITIGATED' },
      { id: '92001', pageId: '92001', title: 'SRS-92001', version: 1, sha256Hash: origHash, lastSignedHash: origHash, isSignatureInvalidated: false, contentSnippet: 'Approved', lastUpdated: signedAt },
      { id: 'w-gate-1', key: 'GATE-1', title: 'Gate Work', status: 'Done', assignee: 'Dev' },
      { id: 't-gate-1', testKey: 'TEST-GATE-1', title: 'Test', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/g1', executionDate: signedAt },
      { id: 'sig-gate-1', signedBy: 'Gate Approver', signedByAccountId: 'op-gate', signedAt, role: 'QA', meaning: 'Approved', artifactSha256: origHash, isValid: true, authMethod: 'PART11_ATTESTATION', signatureAlgorithm: 'HMAC-SHA256-SEAL-V1', signatureSeal: seal },
      undefined,
      { linkId: 'link-gate-1', part11Secret: process.env.MEDTRACE_PART11_SECRET, requireCryptographicSeal: true, requireTestEvidence: true }
    );
    assert.strictEqual(verifiedLink.complianceState, 'VERIFIED');

    const origReconcile = LiveIngestionService.reconcileConfluenceSpecs;
    let reconcileCalls = 0;
    await withForgeMocks(
      {
        appContext: { installation: { contexts: [{ cloudId: '11111111-2222-3333-4444-555555555555' }] } },
        requestJira: async (url) => {
          if (url === '/rest/api/3/myself') {
            return makeHttpResponse(200, { accountId: 'op-gate', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: { BROWSE_PROJECTS: { havePermission: true }, EDIT_ISSUES: { havePermission: true } },
            });
          }
          return makeHttpResponse(200, {});
        },
        requestConfluence: async (routeObj) => {
          const r = String(routeObj?.value_ || routeObj?.value || routeObj);
          if (r.includes('/wiki/api/v2/pages/92001')) {
            return makeHttpResponse(200, {
              id: '92001',
              title: 'SRS-92001',
              version: { number: 2, createdAt: '2026-11-24T12:00:00.000Z' },
              body: { storage: { value: modifiedBody } },
            });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([verifiedLink], 'LIVE', 'Gate Suite', { initialized: true }),
          0
        );

        LiveIngestionService.reconcileConfluenceSpecs = async (suite, opts) => {
          reconcileCalls += 1;
          return origReconcile.call(LiveIngestionService, suite, opts);
        };
        try {
          // Polling skipReconcile=true must not invoke reconcileConfluenceSpecs
          await resolverHandler(
            {
              call: { functionKey: 'getComplianceSuite', payload: { skipReconcile: true } },
              context: { extension: { type: 'jira:projectPage', project: { key: 'GATE' } } },
            },
            { principal: { accountId: 'op-gate' } }
          );
          assert.strictEqual(reconcileCalls, 0);

          // verify-release-gate webtrigger must detect modified Confluence page via reconcileConfluenceSpecs
          const gateBody = JSON.stringify({ action: 'verify-release-gate' });
          const gateResp = await mcpWebtriggerHandler({
            method: 'POST',
            headers: signWebtriggerHeaders(secret, gateBody, 'n-reconcile-gate-1'),
            body: gateBody,
          });
          assert.strictEqual(gateResp.statusCode, 403);
          assert.strictEqual(JSON.parse(gateResp.body).result, false);
          assert.ok(reconcileCalls >= 1);

          // Reset to verified baseline, then verify keyless workflowValidatorHandler also detects drift
          const { version: postGateVersion } = await SeederService.getSuiteWithVersion();
          await SeederService.saveComplianceSuite(
            ComplianceEngine.generateComplianceReport([verifiedLink], 'LIVE', 'Gate Suite', { initialized: true }),
            postGateVersion
          );
          const beforeValCalls = reconcileCalls;
          const valOutcome = await workflowValidatorHandler({ transition: { name: 'Done' } });
          assert.strictEqual(valOutcome.result, false);
          assert.ok(reconcileCalls > beforeValCalls);
        } finally {
          LiveIngestionService.reconcileConfluenceSpecs = origReconcile;
        }
      }
    );
  });

  test.it('recordTestResult blocks ACME operator from updating shared testKey also linked to MED project', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine.js');
    const linkAcme = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-a1', key: 'HAZ-ACME-1', title: 'ACME Haz', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-1', status: 'UNVERIFIED_RISK' },
      { id: 'srs-1', pageId: '101', title: 'SRS-1', version: 1, sha256Hash: 'h1', lastSignedHash: 'h1', isSignatureInvalidated: false, contentSnippet: 'Spec', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-a1', key: 'ACME-1', title: 'ACME Work', status: 'Done', assignee: 'Alice' },
      { id: 't-shared', testKey: 'TEST-SHARED-1', title: 'Shared Test', testType: 'Unit Test', status: 'UNTESTED' },
      { id: 'sig-1', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
      undefined,
      { linkId: 'link-acme-shared', requireTestEvidence: true }
    );
    const linkMed = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-m1', key: 'HAZ-MED-1', title: 'MED Haz', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-1', status: 'UNVERIFIED_RISK' },
      { id: 'srs-1', pageId: '101', title: 'SRS-1', version: 1, sha256Hash: 'h1', lastSignedHash: 'h1', isSignatureInvalidated: false, contentSnippet: 'Spec', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-m1', key: 'MED-1', title: 'MED Work', status: 'Done', assignee: 'Bob' },
      { id: 't-shared', testKey: 'TEST-SHARED-1', title: 'Shared Test', testType: 'Unit Test', status: 'UNTESTED' },
      { id: 'sig-1', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
      undefined,
      { linkId: 'link-med-shared', requireTestEvidence: true }
    );

    await withForgeMocks(
      {
        requestJira: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'op-acme-only', active: true });
          }
          if (r.includes('/rest/api/3/mypermissions')) {
            const hasMedAccess = r.includes('MED-1') || r.includes('projectKey=MED');
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: !hasMedAccess },
                EDIT_ISSUES: { havePermission: !hasMedAccess },
              },
            });
          }
          return makeHttpResponse(200, {});
        },
        requestConfluence: async () => makeHttpResponse(200, { accountId: 'op-acme-only' }),
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([linkAcme, linkMed], 'LIVE', 'Cross Proj Test', { initialized: true }),
          0
        );
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'recordTestResult',
                  payload: {
                    hazardKey: 'HAZ-ACME-1',
                    linkId: 'link-acme-shared',
                    testKey: 'TEST-SHARED-1',
                    status: 'PASSED',
                    evidenceUrl: 'https://ci.example/1',
                  },
                },
                context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
              },
              { principal: { accountId: 'op-acme-only' } }
            ),
          /Forbidden/i
        );
      }
    );
  });

  test.it('assertOperatorAuthorizedForTarget enforces fallback Jira permissions for non-Confluence callers on unlinked targets', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine.js');
    const { assertOperatorAuthorizedForTarget } = require('../dist/index.js');
    assert.strictEqual(typeof assertOperatorAuthorizedForTarget, 'function');

    const linkMed = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-m1', key: 'HAZ-MED-1', title: 'MED Haz', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-1', status: 'UNVERIFIED_RISK' },
      { id: 'srs-1', pageId: '101', title: 'SRS-1', version: 1, sha256Hash: 'h1', lastSignedHash: 'h1', isSignatureInvalidated: false, contentSnippet: 'Spec', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-m1', key: 'MED-1', title: 'MED Work', status: 'Done', assignee: 'Bob' },
      { id: 't-1', testKey: 'TEST-1', title: 'Test 1', testType: 'Unit Test', status: 'UNTESTED' },
      { id: 'sig-1', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
      undefined,
      { linkId: 'link-med-only' }
    );

    await withForgeMocks(
      {
        requestJira: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'readonly-jira', active: true });
          }
          if (r.includes('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: true },
                EDIT_ISSUES: { havePermission: false },
              },
            });
          }
          return makeHttpResponse(200, {});
        },
        requestConfluence: async () => makeHttpResponse(200, { accountId: 'readonly-jira' }),
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([linkMed], 'LIVE', 'Fallback RBAC Suite', { initialized: true }),
          0
        );
        await assert.rejects(
          () =>
            assertOperatorAuthorizedForTarget(
              {
                context: {
                  accountId: 'readonly-jira',
                  extension: { type: 'jira:projectPage', project: { key: 'MED' } },
                },
              },
              { hazardKey: 'HAZ-UNLINKED-999' }
            ),
          /Forbidden/i
        );
        await assert.rejects(
          () =>
            assertOperatorAuthorizedForTarget(
              {
                context: {
                  accountId: 'readonly-jira',
                  extension: { type: 'jira:globalPage' },
                },
              },
              { hazardKey: 'HAZ-UNLINKED-999' }
            ),
          /Forbidden/i
        );
      }
    );
  });

  test.it('getAuditLog omits CONFLUENCE_PAGE_DRIFT and pageId entries for restricted Confluence pages while preserving hash integrity', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine.js');
    const { AuditLogService, computeAuditEntryHash } = require('../dist/audit-log.js');

    const linkAcme = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-a1', key: 'HAZ-ACME-1', title: 'ACME Haz', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-9199', status: 'ACTION_REQUIRED' },
      { id: 'srs-9199', pageId: '9199', title: 'Secret Confluence Spec 9199', version: 2, sha256Hash: 'a'.repeat(64), lastSignedHash: 'a'.repeat(64), isSignatureInvalidated: false, contentSnippet: 'TOP SECRET', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-a1', key: 'ACME-1', title: 'ACME Work', status: 'Done', assignee: 'Alice' },
      { id: 't-a1', testKey: 'TEST-ACME-1', title: 'Test 1', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/1', executionDate: '2026-11-24T00:00:00Z' },
      { id: 'sig-1', signedBy: 'Alice', signedAt: '2026-11-24T00:00:00Z', role: 'QA', meaning: 'OK', artifactSha256: 'a'.repeat(64), isValid: true },
      undefined,
      { linkId: 'link-acme-conf' }
    );

    await withForgeMocks(
      {
        requestJira: async (url) => {
          if (url.startsWith('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'op-acme', active: true });
          }
          if (url.startsWith('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: true },
                EDIT_ISSUES: { havePermission: true },
              },
            });
          }
          return makeHttpResponse(404, {});
        },
        requestConfluence: async (url) => {
          if (url === '/wiki/rest/api/user/current') {
            return makeHttpResponse(200, { accountId: 'op-acme', type: 'known' });
          }
          if (url.includes('/wiki/api/v2/pages/9101')) {
            return makeHttpResponse(200, { id: '9101', title: 'Allowed Page' });
          }
          if (url.includes('/wiki/api/v2/pages/9199')) {
            return makeHttpResponse(403, { message: 'Restricted' });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([linkAcme], 'LIVE', 'Conf Audit Redaction Suite', { initialized: true }),
          0
        );
        await AuditLogService.append({
          actorAccountId: 'op-acme',
          action: 'RECORD_TEST_RESULT',
          targetKey: 'TEST-ACME-1',
          details: { projectKey: 'ACME', hazardKey: 'HAZ-ACME-1' },
          authMethod: 'FORGE_USER_SESSION',
        });
        await AuditLogService.append({
          actorAccountId: 'confluence-event-trigger',
          action: 'CONFLUENCE_PAGE_DRIFT',
          targetKey: 'page:9199',
          details: {
            pageId: '9199',
            newSha256: 'f'.repeat(64),
            affectedHazards: ['HAZ-ACME-1'],
            affectedWorkKeys: ['ACME-1'],
            projectKeys: ['ACME'],
          },
          authMethod: 'CONFLUENCE_EVENT_TRIGGER',
        });
        await AuditLogService.append({
          actorAccountId: 'confluence-event-trigger',
          action: 'CONFLUENCE_PAGE_DRIFT',
          targetKey: 'page:9101',
          details: {
            pageId: '9101',
            newSha256: 'b'.repeat(64),
            affectedHazards: ['HAZ-ACME-1'],
            affectedWorkKeys: ['ACME-1'],
            projectKeys: ['ACME'],
          },
          authMethod: 'CONFLUENCE_EVENT_TRIGGER',
        });

        const logs = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 20 } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'ACME' } } },
          },
          { principal: { accountId: 'op-acme' } }
        );
        assert.strictEqual(logs.length, 2, 'Restricted page:9199 CONFLUENCE_PAGE_DRIFT must be omitted');
        assert.ok(!logs.some((e) => e.details?.pageId === '9199' || e.targetKey === 'page:9199'));
        assert.ok(logs.some((e) => e.details?.pageId === '9101'));
        for (const entry of logs) {
          assert.strictEqual(
            computeAuditEntryHash({
              seq: entry.seq,
              timestamp: entry.timestamp,
              actorAccountId: entry.actorAccountId,
              action: entry.action,
              targetKey: entry.targetKey,
              details: entry.details,
              prevHash: entry.prevHash,
              authMethod: entry.authMethod,
            }),
            entry.entryHash
          );
        }
      }
    );
  });

  test.it('assertOperatorAuthorizedForTarget blocks ACME editor when linked native JIRA_ISSUE Test belongs to forbidden MED project', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine.js');
    const { assertOperatorAuthorizedForTarget } = require('../dist/index.js');

    const crossLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-cross-1',
        key: 'HAZ-ACME-9',
        title: 'ACME Hazard',
        riskClass: 'CLASS_C',
        mitigationRequirementId: 'srs-cross',
        status: 'ACTION_REQUIRED',
      },
      {
        id: 'srs-cross',
        pageId: '501',
        title: 'SRS Cross',
        version: 1,
        sha256Hash: 'a'.repeat(64),
        lastSignedHash: 'a'.repeat(64),
        isSignatureInvalidated: false,
        contentSnippet: 'Spec',
        lastUpdated: '2026-11-24T00:00:00Z',
      },
      { id: 'w-a9', key: 'ACME-9', title: 'ACME Work', status: 'Done', assignee: 'Alice' },
      {
        id: 't-m9',
        testKey: 'MED-9',
        title: 'Native MED Test',
        testType: 'Automated HIL',
        status: 'UNTESTED',
        source: 'JIRA_ISSUE',
      },
      { id: 'sig-c', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
      undefined,
      { linkId: 'link-cross-acme-med-test' }
    );

    await withForgeMocks(
      {
        requestJira: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'acme-editor', active: true });
          }
          if (r.includes('/rest/api/3/mypermissions')) {
            const isMed = r.includes('MED-9') || r.includes('projectKey=MED');
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: true },
                EDIT_ISSUES: { havePermission: !isMed },
              },
            });
          }
          return makeHttpResponse(200, {});
        },
        requestConfluence: async () => makeHttpResponse(200, { accountId: 'acme-editor' }),
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([crossLink], 'LIVE', 'Cross Project Test Key RBAC', {
            initialized: true,
          }),
          0
        );
        await assert.rejects(
          () =>
            assertOperatorAuthorizedForTarget(
              {
                context: {
                  accountId: 'acme-editor',
                  extension: { type: 'jira:globalPage' },
                },
              },
              { hazardKey: 'HAZ-ACME-9', linkId: 'link-cross-acme-med-test' }
            ),
          /Forbidden/i
        );
      }
    );
  });

  test.it('getAuditLog scans past 1,000 cross-project entries to return older project-scoped entries', async () => {
    const { AuditLogService } = require('../dist/audit-log.js');
    await withForgeMocks(
      {
        requestJira: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'reader-med', active: true });
          }
          if (r.includes('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: { BROWSE_PROJECTS: { havePermission: true } },
            });
          }
          return makeHttpResponse(200, {});
        },
        requestConfluence: async () => makeHttpResponse(200, { accountId: 'reader-med' }),
      },
      async () => {
        await AuditLogService.append({
          actorAccountId: 'u1',
          action: 'SYNC_LIVE',
          targetKey: 'MED-1',
          details: { projectKey: 'MED', issueKey: 'MED-1' },
          authMethod: 'FORGE_USER_SESSION',
        });
        for (let i = 0; i < 1050; i++) {
          await AuditLogService.append({
            actorAccountId: 'u2',
            action: 'SYNC_LIVE',
            targetKey: `OTHER-${i + 1}`,
            details: { projectKey: 'OTHER', issueKey: `OTHER-${i + 1}` },
            authMethod: 'FORGE_USER_SESSION',
          });
        }
        const logs = await resolverHandler(
          {
            call: { functionKey: 'getAuditLog', payload: { limit: 20 } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'reader-med' } }
        );
        assert.strictEqual(logs.length, 1);
        assert.strictEqual(logs[0].targetKey, 'MED-1');
      }
    );
  });

  test.it('assertOperatorAuthorizedForTarget blocks signOffPart11 when a shared-spec sibling belongs to an unauthorized Jira project', async () => {
    const { assertOperatorAuthorizedForTarget } = require('../dist/index.js');
    const { ComplianceEngine } = require('../dist/compliance-engine.js');
    const { SeederService } = require('../dist/seeder.js');

    const linkA = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-shared', key: 'HAZ-SHARED-1', title: 'Shared Hazard', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-50', status: 'UNVERIFIED_RISK' },
      { id: 'srs-50', pageId: '50', title: 'SRS-50', version: 1, sha256Hash: 'abc12345'.repeat(8), lastSignedHash: '', isSignatureInvalidated: false, contentSnippet: 'Spec', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-a', key: 'PROJA-1', title: 'Work A', status: 'Done', assignee: 'Alice' },
      { id: 't-a', testKey: 'TEST-A', title: 'Test A', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/a', executionDate: '2026-11-24T00:00:00Z' },
      { id: 'sig-50', signedBy: '', signedAt: '', role: 'QA', meaning: 'Pending', artifactSha256: '', isValid: false }
    );
    const linkB = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-shared', key: 'HAZ-SHARED-1', title: 'Shared Hazard', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-50', status: 'UNVERIFIED_RISK' },
      { id: 'srs-50', pageId: '50', title: 'SRS-50', version: 1, sha256Hash: 'abc12345'.repeat(8), lastSignedHash: '', isSignatureInvalidated: false, contentSnippet: 'Spec', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-b', key: 'PROJB-1', title: 'Work B', status: 'Done', assignee: 'Bob' },
      { id: 't-b', testKey: 'TEST-B', title: 'Test B', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/b', executionDate: '2026-11-24T00:00:00Z' },
      { id: 'sig-50', signedBy: '', signedAt: '', role: 'QA', meaning: 'Pending', artifactSha256: '', isValid: false }
    );

    await withForgeMocks(
      {
        requestJira: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'proja-editor', active: true });
          }
          if (r.includes('/rest/api/3/mypermissions')) {
            const isProjB = r.includes('PROJB-1') || r.includes('projectKey=PROJB');
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: !isProjB },
                EDIT_ISSUES: { havePermission: !isProjB },
              },
            });
          }
          return makeHttpResponse(200, {});
        },
        requestConfluence: async () => makeHttpResponse(200, { accountId: 'proja-editor' }),
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([linkA, linkB], 'LIVE', 'Shared Spec RBAC', { initialized: true }),
          0
        );
        await assert.rejects(
          () =>
            assertOperatorAuthorizedForTarget(
              { context: { accountId: 'proja-editor', extension: { type: 'jira:globalPage' } } },
              { hazardKey: 'HAZ-SHARED-1', specId: 'srs-50', linkId: linkA.id, includeSharedSpecSiblings: true }
            ),
          /Forbidden/i
        );
      }
    );
  });

  test.it('syncLiveSuite rejects unbalanced parentheses in custom JQL', async () => {
    await assert.rejects(
      () =>
        resolverHandler(
          {
            call: { functionKey: 'syncLiveSuite', payload: { jql: 'status = Done) OR (key != EMPTY' } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'acc-jql' } }
        ),
      /unbalanced/i
    );
  });

  test.it('getComplianceSuite reuses Confluence page permissions checked during reconcileConfluenceSpecs without duplicate page fetches', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine.js');
    const { sha256Hex } = require('../dist/crypto-utils.js');
    const { SeederService } = require('../dist/seeder.js');
    const origSpec = '<p>Single fetch spec</p>';
    const shaOrig = sha256Hex(origSpec);
    const link = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-df', key: 'HAZ-DF-1', title: 'Double Fetch Haz', riskClass: 'CLASS_C', mitigationRequirementId: '93001', status: 'MITIGATED' },
      { id: '93001', pageId: '93001', title: 'SRS-93001', version: 1, sha256Hash: shaOrig, lastSignedHash: shaOrig, isSignatureInvalidated: false, contentSnippet: 'Single fetch spec', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-df', key: 'DF-1', title: 'Work DF-1', status: 'Done', assignee: 'Alice' },
      { id: 't-df', testKey: 'TST-DF-1', title: 'Test DF-1', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/1', executionDate: '2026-11-24T00:00:00Z' },
      { id: 'sig-df', signedBy: 'Alice', signedAt: '2026-11-24T00:00:00Z', role: 'QA', meaning: 'Approved', artifactSha256: shaOrig, isValid: true }
    );
    let confluencePageFetches = 0;

    await withForgeMocks(
      {
        requestJira: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, { permissions: { BROWSE_PROJECTS: { havePermission: true } } });
          }
          return makeHttpResponse(200, {});
        },
        requestConfluence: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/wiki/api/v2/pages/93001')) {
            confluencePageFetches += 1;
            return makeHttpResponse(200, {
              id: '93001',
              title: 'SRS-93001',
              version: { number: 1 },
              body: { storage: { value: origSpec } },
            });
          }
          return makeHttpResponse(404, {});
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([link], 'LIVE', 'Double Fetch Suite', { initialized: true }),
          0
        );
        const res = await resolverHandler(
          {
            call: { functionKey: 'getComplianceSuite', payload: {} },
            context: { extension: { type: 'jira:projectPage', project: { key: 'DF' } } },
          },
          { principal: { accountId: 'reader-df' } }
        );
        assert.strictEqual(res.traceLinks.length, 1);
        assert.strictEqual(res.traceLinks[0].spec.specRestricted, undefined);
        assert.strictEqual(confluencePageFetches, 1, 'Expected single Confluence fetch reused across reconcile + RBAC filter');
      }
    );
  });

  test.it('syncLiveSuite scopes JQL ORDER BY safely, blocks project is empty, and webtrigger rejects dotted or whitespace nonces', async () => {
    const { setNonceStore, createInMemoryNonceStore } = require('../dist/nonce-store.js');
    const { mcpWebtriggerHandler } = require('../dist/index.js');
    const secret = 'wt-nonce-chars-secret';
    process.env.MEDTRACE_MCP_SECRET = secret;
    setNonceStore(createInMemoryNonceStore());
    const observedJqls = [];

    await withForgeMocks(
      {
        requestJira: async (routeObj, opts) => {
          const r = routeToString(routeObj);
          if (r.includes('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'acc-jql-guard', active: true });
          }
          if (r.includes('/rest/api/3/mypermissions')) {
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: true },
                EDIT_ISSUES: { havePermission: true },
              },
            });
          }
          if (r.includes('/rest/api/3/search/jql')) {
            const jqlParam = new URL(r, 'https://jira.example').searchParams.get('jql');
            if (jqlParam) observedJqls.push(jqlParam);
            return makeHttpResponse(200, { issues: [] });
          }
          return makeHttpResponse(200, {});
        },
      },
      async () => {
        await resolverHandler(
          {
            call: { functionKey: 'syncLiveSuite', payload: { jql: 'status = Done ORDER BY key DESC' } },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'acc-jql-guard' } }
        );
        assert.strictEqual(
          observedJqls[0],
          'project = "MED" AND (status = Done) ORDER BY key DESC'
        );

        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: { functionKey: 'syncLiveSuite', payload: { jql: 'project is empty AND status = Done' } },
                context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
              },
              { principal: { accountId: 'acc-jql-guard' } }
            ),
          /Forbidden: Custom JQL/i
        );
      }
    );

    const body = JSON.stringify({ action: 'status' });
    for (const badNonce of ['nonce.with.dots', 'nonce with space']) {
      const res = await mcpWebtriggerHandler({
        method: 'POST',
        headers: signWebtriggerHeaders(secret, body, badNonce),
        body,
      });
      assert.strictEqual(res.statusCode, 401);
    }

    // Throwing custom fallback NonceStore (get/set only) returns STORAGE_ERROR -> 500 cleanly
    const throwingStore = {
      get: async () => {
        throw new Error('kvs timeout');
      },
      set: async () => {},
      delete: async () => {},
    };
    const { claimNonceDetailed } = require('../dist/webtrigger.js');
    assert.strictEqual(await claimNonceDetailed('valid-fallback-nonce', throwingStore), 'STORAGE_ERROR');
  });

  test.it('workflowValidatorHandler & safeParseJson fail closed on HTTP 200 malformed JSON responses', async () => {
    const { safeParseJson } = require('../dist/crypto-utils.js');
    assert.strictEqual(
      await safeParseJson({ json: async () => { throw new SyntaxError('Unexpected token <'); } }),
      null
    );

    const { SeederService } = require('../dist/seeder.js');
    const { ComplianceEngine } = require('../dist/compliance-engine.js');
    const { workflowValidatorHandler } = require('../dist/index.js');

    const dummyLink = ComplianceEngine.evaluateTraceLink(
      { id: 'h-j1', key: 'HAZ-J1', title: 'Other Haz', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-j1', status: 'ACTION_REQUIRED' },
      { id: 'srs-j1', pageId: '71001', title: 'SRS', version: 1, sha256Hash: 'a'.repeat(64), isSignatureInvalidated: false, contentSnippet: 'Spec', lastUpdated: '2026-11-20T00:00:00Z' },
      { id: 'w-j1', key: 'MED-999', title: 'Work', status: 'Done', assignee: 'Alice' },
      { id: 't-j1', testKey: 'TST-999', title: 'Test', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/1', executionDate: '2026-11-20T00:00:00Z' },
      { id: 'sig-j1', signedBy: 'Alice', signedAt: '2026-11-20T00:00:00Z', role: 'QA', meaning: 'OK', artifactSha256: 'a'.repeat(64), isValid: true }
    );

    await withForgeMocks(
      {
        requestJira: async () => ({
          status: 200,
          ok: true,
          json: async () => {
            throw new SyntaxError('Unexpected token <');
          },
          text: async () => '<html>gateway</html>',
        }),
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([dummyLink], 'LIVE', 'Malformed JSON Suite', { initialized: true }),
          0
        );
        const gateRes = await workflowValidatorHandler({
          issue: { key: 'MED-UNSYNCED-JSON' },
          transition: { name: 'Done', to: { name: 'Done', statusCategory: { key: 'done' } } },
        });
        assert.strictEqual(gateRes.result, false);
        assert.match(gateRes.errorMessage || '', /malformed Jira response/i);
      }
    );
  });

  test.it('enforces && matching in recordTestResult RBAC, link-scope checks in createReverificationTask by issueKey only, and omits availableKeys on webtrigger misses', async () => {
    const { ComplianceEngine } = require('../dist/compliance-engine.js');
    const { SeederService } = require('../dist/seeder.js');
    const { resolverHandler, mcpWebtriggerHandler } = require('../dist/index.js');

    const linkA = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-shared', key: 'HAZ-SHARED', title: 'Shared Haz', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-a', status: 'ACTION_REQUIRED' },
      { id: 'srs-a', pageId: '5101', title: 'SRS-A', version: 1, sha256Hash: 'a'.repeat(64), isSignatureInvalidated: false, contentSnippet: 'Spec A', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-a', key: 'ACME-1', title: 'ACME Work', status: 'In Progress', assignee: 'Alice' },
      { id: 't-a', testKey: 'TEST-A', title: 'Test A', testType: 'Unit Test', status: 'UNTESTED' },
      { id: 'sig-a', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
      undefined,
      { linkId: 'link-shared-acme' }
    );
    const linkB = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-shared', key: 'HAZ-SHARED', title: 'Shared Haz', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-b', status: 'ACTION_REQUIRED' },
      { id: 'srs-b', pageId: '5102', title: 'SRS-B', version: 1, sha256Hash: 'b'.repeat(64), isSignatureInvalidated: false, contentSnippet: 'Spec B', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-b', key: 'MED-1', title: 'MED Work', status: 'In Progress', assignee: 'Bob' },
      { id: 't-b', testKey: 'TEST-B', title: 'Test B', testType: 'Unit Test', status: 'UNTESTED' },
      { id: 'sig-b', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
      undefined,
      { linkId: 'link-shared-med' }
    );

    const secret = 'rbac-and-webtrigger-secret-32-bytes-ok';
    process.env.MEDTRACE_MCP_SECRET = secret;

    await withForgeMocks(
      {
        requestJira: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/rest/api/3/myself')) {
            return makeHttpResponse(200, { accountId: 'acc-acme-editor', active: true });
          }
          if (r.includes('/rest/api/3/mypermissions')) {
            const isMed = r.includes('MED-1') || r.includes('projectKey=MED');
            return makeHttpResponse(200, {
              permissions: {
                BROWSE_PROJECTS: { havePermission: !isMed },
                EDIT_ISSUES: { havePermission: !isMed },
                CREATE_ISSUES: { havePermission: !isMed },
              },
            });
          }
          return makeHttpResponse(200, {});
        },
        requestConfluence: async (routeObj) => {
          const r = routeToString(routeObj);
          if (r.includes('/wiki/rest/api/user/current')) {
            return makeHttpResponse(200, { accountId: 'acc-acme-editor' });
          }
          return makeHttpResponse(200, { id: '5101', title: 'SRS' });
        },
      },
      async () => {
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport([linkA, linkB], 'LIVE', 'Cross Project RBAC', { initialized: true }),
          0
        );

        // 1. Cross-project recordTestResult bypass via OR must fail on linkB (TEST-B belongs to MED-1)
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'recordTestResult',
                  payload: { hazardKey: 'HAZ-SHARED', testKey: 'TEST-B', status: 'PASSED', evidenceUrl: 'https://ci.example/1' },
                },
                context: { extension: { type: 'jira:globalPage' } },
              },
              { principal: { accountId: 'acc-acme-editor' } }
            ),
          /Forbidden/i
        );

        // 2. createReverificationTask with only issueKey='MED-1' (no hazardKey) must check linkB scope and reject
        await assert.rejects(
          () =>
            resolverHandler(
              {
                call: {
                  functionKey: 'createReverificationTask',
                  payload: { issueKey: 'MED-1' },
                },
                context: { extension: { type: 'jira:globalPage' } },
              },
              { principal: { accountId: 'acc-acme-editor' } }
            ),
          /Forbidden/i
        );

        // 3. Webtrigger get-hazard-lineage miss must NOT leak availableKeys
        const missBody = JSON.stringify({ action: 'get-hazard-lineage', hazardKey: 'NO-SUCH-HAZARD' });
        const missResp = await mcpWebtriggerHandler({
          method: 'POST',
          headers: signWebtriggerHeaders(secret, missBody, 'n-miss-no-enum'),
          body: missBody,
        });
        assert.strictEqual(missResp.statusCode, 200);
        const missJson = JSON.parse(missResp.body);
        assert.strictEqual(missJson.found, false);
        assert.strictEqual(Object.hasOwn(missJson, 'availableKeys'), false);
      }
    );
  });
});
