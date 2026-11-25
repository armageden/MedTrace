const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const forgeApi = require('@forge/api');
const forgeKvs = require('@forge/kvs');
const { ComplianceEngine } = require('../dist/compliance-engine');
const { AuditLogService, setAuditStorageAdapter, resetInMemoryAuditStorage } = require('../dist/audit-log');
const seederMod = require('../dist/seeder');
const { SeederService } = seederMod;
const { TeamworkGraphService, resolveCloudId, resolveConfluenceCloudId } = require('../dist/teamwork-graph');
const ingestionMod = require('../dist/ingestion');
const { LiveIngestionService } = ingestionMod;
const { PART11_ATTESTATION_PHRASE } = require('../dist/types');

const { ForgeKvsAPIError } = forgeKvs;
const KVS_KEY_REGEX = /^(?!\s+$)[a-zA-Z0-9:._\s-#]+$/;

function cloneJson(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function sha256Hex(content) {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

function makeJsonResponse(status, data) {
  return {
    status,
    json: async () => data,
    text: async () => (typeof data === 'string' ? data : JSON.stringify(data)),
  };
}

function createFullMockForgeKvs(seed = {}, options = {}) {
  const store = new Map(Object.entries(seed).map(([k, v]) => [k, cloneJson(v)]));
  const calls = {
    get: [],
    set: [],
    delete: [],
    batchGet: [],
    batchSet: [],
    batchDelete: [],
    transact: [],
  };

  function assertValidKey(key) {
    assert.ok(typeof key === 'string' && key.length > 0 && key.length <= 500, `Invalid KVS key length: ${key}`);
    assert.match(key, KVS_KEY_REGEX, `Invalid KVS key format: ${key}`);
  }

  return {
    store,
    calls,
    get: async (key) => {
      assertValidKey(key);
      calls.get.push(key);
      if (typeof options.onGet === 'function') {
        const override = await options.onGet(key, store);
        if (override !== undefined) return cloneJson(override);
      }
      return cloneJson(store.get(key));
    },
    set: async (key, val, opts) => {
      assertValidKey(key);
      calls.set.push({ key, val: cloneJson(val), opts: opts ? { ...opts } : undefined });
      if (typeof options.onSet === 'function') {
        await options.onSet(key, val, opts, store);
      }
      if (opts && opts.keyPolicy === 'FAIL_IF_EXISTS' && store.has(key)) {
        throw new ForgeKvsAPIError(
          { status: 409, statusText: 'Conflict' },
          { code: 'KEY_ALREADY_EXISTS', message: 'Key already exists' }
        );
      }
      const previous = store.has(key) ? cloneJson(store.get(key)) : undefined;
      store.set(key, cloneJson(val));
      if (opts && opts.keyPolicy === 'OVERRIDE' && opts.returnValue === 'PREVIOUS') {
        return previous !== undefined ? { key, value: previous } : undefined;
      }
      return undefined;
    },
    delete: async (key) => {
      assertValidKey(key);
      calls.delete.push(key);
      store.delete(key);
    },
    batchGet: async (items) => {
      assert.ok(items.length <= 25, `batchGet exceeded 25-item ceiling: ${items.length}`);
      const keys = items.map((i) => {
        assertValidKey(i.key);
        return i.key;
      });
      calls.batchGet.push(keys);
      const successfulKeys = [];
      for (const item of items) {
        if (store.has(item.key)) {
          successfulKeys.push({ key: item.key, value: cloneJson(store.get(item.key)) });
        }
      }
      return { successfulKeys, failedKeys: [] };
    },
    batchSet: async (items) => {
      assert.ok(items.length <= 25, `batchSet exceeded 25-item ceiling: ${items.length}`);
      const keys = items.map((i) => {
        assertValidKey(i.key);
        return i.key;
      });
      calls.batchSet.push(keys);
      for (const item of items) {
        store.set(item.key, cloneJson(item.value));
      }
      return { successfulKeys: items.map((i) => ({ key: i.key })), failedKeys: [] };
    },
    batchDelete: async (items) => {
      assert.ok(items.length <= 25, `batchDelete exceeded 25-item ceiling: ${items.length}`);
      const keys = items.map((i) => {
        assertValidKey(i.key);
        return i.key;
      });
      calls.batchDelete.push(keys);
      for (const item of items) {
        store.delete(item.key);
      }
      return { successfulKeys: items.map((i) => ({ key: i.key })), failedKeys: [] };
    },
    transact: () => {
      const sets = [];
      const deletes = [];
      const builder = {
        set: (key, value, entity, opts) => {
          assertValidKey(key);
          sets.push({ key, value: cloneJson(value), entity, opts });
          return builder;
        },
        delete: (key, entity) => {
          assertValidKey(key);
          deletes.push({ key, entity });
          return builder;
        },
        execute: async () => {
          const totalOps = sets.length + deletes.length;
          assert.ok(totalOps <= 25, `kvs.transact() exceeded 25-op ceiling: ${totalOps}`);
          if (typeof options.onTransact === 'function') {
            await options.onTransact({ sets, deletes }, store);
          }
          for (const s of sets) store.set(s.key, cloneJson(s.value));
          for (const d of deletes) store.delete(d.key);
        },
      };
      return builder;
    },
  };
}

async function withForgeMocks({ kvsMock, asAppImpl, asUserImpl, appContext }, fn) {
  const origRuntime = globalThis.__forge_runtime__;
  const origKvs = {
    get: forgeKvs.kvs.get,
    set: forgeKvs.kvs.set,
    delete: forgeKvs.kvs.delete,
    batchGet: forgeKvs.kvs.batchGet,
    batchSet: forgeKvs.kvs.batchSet,
    batchDelete: forgeKvs.kvs.batchDelete,
    transact: forgeKvs.kvs.transact,
  };
  const origAsApp = forgeApi.default.asApp;
  const origAsUser = forgeApi.default.asUser;
  const origGetAppContextDesc = Object.getOwnPropertyDescriptor(forgeApi, 'getAppContext');

  globalThis.__forge_runtime__ = true;
  if (kvsMock) {
    forgeKvs.kvs.get = kvsMock.get;
    forgeKvs.kvs.set = kvsMock.set;
    forgeKvs.kvs.delete = kvsMock.delete;
    forgeKvs.kvs.batchGet = kvsMock.batchGet;
    forgeKvs.kvs.batchSet = kvsMock.batchSet;
    forgeKvs.kvs.batchDelete = kvsMock.batchDelete;
    forgeKvs.kvs.transact = kvsMock.transact;
  }
  if (asAppImpl) forgeApi.default.asApp = asAppImpl;
  if (asUserImpl) forgeApi.default.asUser = asUserImpl;
  if (appContext !== undefined) {
    Object.defineProperty(forgeApi, 'getAppContext', {
      configurable: true,
      enumerable: true,
      value: () => appContext,
    });
  }

  try {
    return await fn();
  } finally {
    if (origRuntime === undefined) delete globalThis.__forge_runtime__;
    else globalThis.__forge_runtime__ = origRuntime;
    forgeKvs.kvs.get = origKvs.get;
    forgeKvs.kvs.set = origKvs.set;
    forgeKvs.kvs.delete = origKvs.delete;
    forgeKvs.kvs.batchGet = origKvs.batchGet;
    forgeKvs.kvs.batchSet = origKvs.batchSet;
    forgeKvs.kvs.batchDelete = origKvs.batchDelete;
    forgeKvs.kvs.transact = origKvs.transact;
    forgeApi.default.asApp = origAsApp;
    forgeApi.default.asUser = origAsUser;
    if (origGetAppContextDesc) {
      Object.defineProperty(forgeApi, 'getAppContext', origGetAppContextDesc);
    }
  }
}

test.describe('TeamworkGraphService Unit Tests (CS-08)', () => {
  test.it('queryIssueGraphContext honors callerMode USER vs APP and handles empty keys', async () => {
    assert.strictEqual(await TeamworkGraphService.queryIssueGraphContext('   '), null);

    let asUserCalls = 0;
    let asAppCalls = 0;

    const makeClient = (counterFn) => ({
      requestJira: async (routeObj) => {
        counterFn();
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'appId=c1&pageId=81001',
              relationship: 'relates to',
              object: { title: 'SRS-81001: Watchdog', url: 'https://example.atlassian.net/wiki/pages/81001' },
            },
          ]);
        }
        return makeJsonResponse(200, {
          id: '10901',
          key: 'MED-901',
          self: 'https://api.atlassian.com/ex/jira/12345678-1234-1234-1234-1234567890ab/rest/api/3/issue/10901',
          fields: {
            summary: 'Watchdog Clamp',
            status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
            issuelinks: [{ id: 'rest-link-1' }],
          },
        });
      },
      requestTeamworkGraph: async () => {
        throw new Error('requestTeamworkGraph must not be called without includeSpecOwners');
      },
    });

    await withForgeMocks(
      {
        asUserImpl: () => makeClient(() => { asUserCalls++; }),
        asAppImpl: () => makeClient(() => { asAppCalls++; }),
      },
      async () => {
        const defaultRes = await TeamworkGraphService.queryIssueGraphContext('MED-901');
        assert.ok(asUserCalls > 0, 'Default callerMode must use api.asUser()');
        assert.strictEqual(asAppCalls, 0, 'Default callerMode must not call api.asApp()');
        assert.strictEqual(defaultRes.source, 'JIRA_REST');
        assert.strictEqual(defaultRes.confluenceSource, 'JIRA_REMOTELINK_REST');

        asUserCalls = 0;
        asAppCalls = 0;
        const userRes = await TeamworkGraphService.queryIssueGraphContext('MED-901', { callerMode: 'USER' });
        assert.ok(asUserCalls > 0);
        assert.strictEqual(asAppCalls, 0);
        assert.strictEqual(userRes.issueAri, 'ari:cloud:jira:12345678-1234-1234-1234-1234567890ab:issue/10901');

        asUserCalls = 0;
        asAppCalls = 0;
        const appRes = await TeamworkGraphService.queryIssueGraphContext('MED-901', { callerMode: 'APP' });
        assert.strictEqual(asUserCalls, 0, 'APP callerMode must not call api.asUser()');
        assert.ok(asAppCalls > 0, 'APP callerMode must use api.asApp()');
        assert.strictEqual(appRes.source, 'JIRA_REST');
      }
    );
  });

  test.it('includeSpecOwners queries Teamwork Graph confluencePageOwners (USER only, opt-in)', async () => {
    const twgCalls = [];
    const makeClient = (twgImpl) => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'appId=c1&pageId=81001',
              relationship: 'relates to',
              object: { title: 'SRS-81001: Watchdog', url: 'https://example.atlassian.net/wiki/pages/81001' },
            },
          ]);
        }
        return makeJsonResponse(200, {
          id: '10901',
          key: 'MED-901',
          self: 'https://api.atlassian.com/ex/jira/12345678-1234-1234-1234-1234567890ab/rest/api/3/issue/10901',
          fields: {
            summary: 'Watchdog Clamp',
            status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
            issuelinks: [],
          },
        });
      },
      requestTeamworkGraph: twgImpl,
    });
    const ownersResponse = () =>
      makeJsonResponse(200, {
        data: {
          confluencePageOwners: {
            edges: [{ node: { __typename: 'AtlassianUser', accountId: 'acc-1', name: 'Ada' } }],
          },
        },
      });

    // (a) USER + includeSpecOwners: one TWG call per pageId, owners parsed
    await withForgeMocks(
      {
        asUserImpl: () =>
          makeClient(async (query, variables, operationName) => {
            twgCalls.push({ query, variables, operationName });
            return ownersResponse();
          }),
      },
      async () => {
        const res = await TeamworkGraphService.queryIssueGraphContext('MED-901', {
          includeSpecOwners: true,
        });
        assert.strictEqual(twgCalls.length, 1);
        assert.strictEqual(twgCalls[0].operationName, 'medtrace_specPageOwners');
        assert.strictEqual(
          twgCalls[0].variables.id,
          'ari:cloud:confluence:12345678-1234-1234-1234-1234567890ab:page/81001'
        );
        assert.ok(twgCalls[0].query.includes('confluencePageOwners'));
        assert.ok(!twgCalls[0].query.includes('email'), 'query must not request email');
        assert.deepStrictEqual(res.specOwners, [{ pageId: '81001', accountId: 'acc-1', name: 'Ada' }]);
        assert.strictEqual(res.teamworkGraphStatus, 'OK');
      }
    );

        // (b) GraphQL errors array with no valid data -> ERROR status, no throw
    twgCalls.length = 0;
    await withForgeMocks(
      {
        asUserImpl: () =>
          makeClient(async (query, variables, operationName) => {
            twgCalls.push({ query, variables, operationName });
            return makeJsonResponse(200, { errors: [{ message: 'x' }] });
          }),
      },
      async () => {
        const res = await TeamworkGraphService.queryIssueGraphContext('MED-901', {
          includeSpecOwners: true,
        });
        assert.strictEqual(twgCalls.length, 1);
        assert.strictEqual(res.teamworkGraphStatus, 'ERROR');
        assert.deepStrictEqual(res.specOwners, []);
      }
    );

    // (b2) Partial GraphQL errors alongside valid AtlassianUser edges -> keeps owners & OK status
    twgCalls.length = 0;
    await withForgeMocks(
      {
        asUserImpl: () =>
          makeClient(async (query, variables, operationName) => {
            twgCalls.push({ query, variables, operationName });
            return makeJsonResponse(200, {
              errors: [{ message: 'AppUser cannot be resolved (thread 103766)' }],
              data: {
                confluencePageOwners: {
                  edges: [
                    { node: null },
                    { node: { __typename: 'AppUser', id: 'app-1' } },
                    { node: { __typename: 'AtlassianUser', accountId: 'acc-real', name: 'farhan tanvir' } },
                  ],
                },
              },
            });
          }),
      },
      async () => {
        const res = await TeamworkGraphService.queryIssueGraphContext('MED-901', {
          includeSpecOwners: true,
        });
        assert.strictEqual(twgCalls.length, 1);
        assert.strictEqual(res.teamworkGraphStatus, 'OK');
        assert.deepStrictEqual(res.specOwners, [
          { pageId: '81001', accountId: 'acc-real', name: 'farhan tanvir' },
        ]);
      }
    );

    // (c) APP mode -> TWG never called, SKIPPED_APP_MODE
    twgCalls.length = 0;
    await withForgeMocks(
      {
        asAppImpl: () =>
          makeClient(async (query, variables, operationName) => {
            twgCalls.push({ query, variables, operationName });
            return ownersResponse();
          }),
      },
      async () => {
        const res = await TeamworkGraphService.queryIssueGraphContext('MED-901', {
          callerMode: 'APP',
          includeSpecOwners: true,
        });
        assert.strictEqual(twgCalls.length, 0, 'APP mode must not call requestTeamworkGraph');
        assert.strictEqual(res.teamworkGraphStatus, 'SKIPPED_APP_MODE');
        assert.strictEqual(res.specOwners, undefined);
      }
    );

    // (d) includeSpecOwners omitted -> TWG never called, fields absent
    twgCalls.length = 0;
    await withForgeMocks(
      {
        asUserImpl: () =>
          makeClient(async (query, variables, operationName) => {
            twgCalls.push({ query, variables, operationName });
            return ownersResponse();
          }),
      },
      async () => {
        const res = await TeamworkGraphService.queryIssueGraphContext('MED-901');
        assert.strictEqual(twgCalls.length, 0);
        assert.strictEqual(res.specOwners, undefined);
        assert.strictEqual(res.teamworkGraphStatus, undefined);
      }
    );
  });

  test.it('resolveCloudId prioritizes /ex/jira/<uuid> and ignores /ex/confluence or non-Jira contexts', async () => {
    const jiraUuid = '11111111-2222-3333-4444-555555555555';
    const confUuid = '99999999-8888-7777-6666-555555555555';
    const ctxJiraUuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

    await withForgeMocks(
      {
        appContext: {
          installation: {
            contexts: [
              { cloudId: confUuid, toString: () => `ari:cloud:confluence::site/${confUuid}` },
              { cloudId: ctxJiraUuid, toString: () => `ari:cloud:jira::site/${ctxJiraUuid}` },
            ],
          },
        },
      },
      async () => {
        // 1. Direct /ex/jira/<uuid> in self URL takes priority over appContext
        assert.strictEqual(
          resolveCloudId(`https://api.atlassian.com/ex/jira/${jiraUuid}/rest/api/3/issue/100`),
          jiraUuid
        );

        // 2. /ex/confluence/<uuid> is ignored, falls back to Jira installation context (ignoring Confluence context)
        assert.strictEqual(
          resolveCloudId(`https://api.atlassian.com/ex/confluence/${confUuid}/wiki/api/v2/pages/1`),
          ctxJiraUuid
        );

        // 3. javascript: scheme is ignored, falls back to Jira installation context
        assert.strictEqual(resolveCloudId('javascript:alert(1)'), ctxJiraUuid);
      }
    );

    // When only Confluence ARI exists in contexts, returns undefined
    await withForgeMocks(
      {
        appContext: {
          installation: {
            contexts: [{ cloudId: confUuid, toString: () => `ari:cloud:confluence::site/${confUuid}` }],
          },
        },
      },
      async () => {
        assert.strictEqual(resolveCloudId(undefined), undefined);
        assert.strictEqual(resolveConfluenceCloudId(undefined), confUuid);
      }
    );

    // Split Jira & Confluence UUIDs: includeSpecOwners queries TWG with Confluence UUID, not Jira UUID
    const twgIds = [];
    await withForgeMocks(
      {
        appContext: {
          installation: {
            contexts: [
              { cloudId: ctxJiraUuid, toString: () => `ari:cloud:jira::site/${ctxJiraUuid}` },
              { cloudId: confUuid, toString: () => `ari:cloud:confluence::site/${confUuid}` },
            ],
          },
        },
        asUserImpl: () => ({
          requestJira: async (routeObj) => {
            const r = String(routeObj?.value || routeObj);
            if (r.includes('/remotelink')) {
              return makeJsonResponse(200, [
                {
                  application: { type: 'com.atlassian.confluence' },
                  globalId: 'appId=c1&pageId=81001',
                  object: { title: 'SRS-81001', url: 'https://example.atlassian.net/wiki/pages/81001' },
                },
              ]);
            }
            return makeJsonResponse(200, {
              id: '10901',
              key: 'MED-901',
              self: `https://api.atlassian.com/ex/jira/${jiraUuid}/rest/api/3/issue/10901`,
              fields: { summary: 'Test', status: { name: 'In Progress' }, issuelinks: [] },
            });
          },
          requestTeamworkGraph: async (_q, vars) => {
            twgIds.push(vars.id);
            return makeJsonResponse(200, { data: { confluencePageOwners: { edges: [] } } });
          },
        }),
      },
      async () => {
        await TeamworkGraphService.queryIssueGraphContext('MED-901', { includeSpecOwners: true });
        assert.deepStrictEqual(twgIds, [`ari:cloud:confluence:${confUuid}:page/81001`]);
      }
    );
  });
});

test.describe('Task 1C-Ingestion: Pagination, Filtering, M:N Specs, Concurrency & Budget (CS-07)', () => {
  const origPart11Secret = process.env.MEDTRACE_PART11_SECRET;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState?.();
    seederMod.setUserIdentityResolver?.(null);
    process.env.MEDTRACE_PART11_SECRET = 'ingestion-test-part11-secret';
  });

  test.afterEach(() => {
    seederMod.setUserIdentityResolver?.(null);
    if (origPart11Secret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
    else process.env.MEDTRACE_PART11_SECRET = origPart11Secret;
  });

  test.it('paginates Jira nextPageToken (>50) and Confluence _links.next (>50), filters untagged issues, and supports includeUntaggedIssues', async () => {
    const kvsMock = createFullMockForgeKvs();
    const allIssues = Array.from({ length: 65 }, (_, idx) => {
      const n = idx + 1;
      const isTagged = n <= 55;
      return {
        id: String(20000 + n),
        key: `MED-${n}`,
        fields: {
          summary: `Issue ${n}`,
          status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
          assignee: { displayName: 'Engineer' },
          labels: isTagged ? ['class-b'] : ['chore'],
          priority: { name: 'Medium' },
          issuetype: { name: 'Task' },
          project: { name: 'MedTrace Paginated' },
        },
      };
    });
    const allPages = Array.from({ length: 62 }, (_, idx) => {
      const n = idx + 1;
      return {
        id: String(90000 + n),
        title: `SRS-${n}: Safety Spec ${n}`,
        version: { number: 1, createdAt: '2026-11-01T00:00:00Z' },
        body: { storage: { value: `<p>Spec ${n}</p>` } },
      };
    });

    const jiraPagesSeen = [];
    const confCursorsSeen = [];

    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          const parsed = new URL(r, 'https://jira.invalid');
          const token = parsed.searchParams.get('nextPageToken') || 'PAGE_1';
          jiraPagesSeen.push(token);
          if (token === 'PAGE_1') {
            return makeJsonResponse(200, {
              issues: allIssues.slice(0, 50),
              nextPageToken: 'tok-page-2',
              isLast: false,
            });
          }
          return makeJsonResponse(200, {
            issues: allIssues.slice(50),
            isLast: true,
          });
        }
        if (r.includes('/remotelink')) {
          return makeJsonResponse(200, []);
        }
        const keyMatch = r.match(/\/rest\/api\/3\/issue\/([^/?]+)/);
        const key = keyMatch?.[1] || 'MED-1';
        return makeJsonResponse(200, {
          id: '20001',
          key,
          fields: { summary: key, status: { name: 'Done' }, issuelinks: [] },
        });
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/spaces/SPACE1/pages') || r.includes('/wiki/api/v2/pages')) {
          const parsed = new URL(r, 'https://conf.invalid');
          const cursor = parsed.searchParams.get('cursor') || 'CONF_1';
          confCursorsSeen.push(cursor);
          if (cursor === 'CONF_1') {
            return makeJsonResponse(200, {
              results: allPages.slice(0, 50),
              _links: { next: '/wiki/api/v2/spaces/SPACE1/pages?body-format=storage&limit=50&cursor=cur-page-2' },
            });
          }
          return makeJsonResponse(200, {
            results: allPages.slice(50),
            _links: {},
          });
        }
        return makeJsonResponse(404, {});
      },
    });

    await withForgeMocks(
      { kvsMock, asUserImpl: mockClient, asAppImpl: mockClient },
      async () => {
        const res = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'MED', spaceId: 'SPACE1', callerMode: 'USER' },
          'acc-sync'
        );
        assert.deepStrictEqual(jiraPagesSeen, ['PAGE_1', 'tok-page-2']);
        assert.deepStrictEqual(confCursorsSeen, ['CONF_1', 'cur-page-2']);
        assert.strictEqual(res.jiraIssuesScanned, 65);
        assert.strictEqual(res.confluencePagesScanned, 62);
        assert.strictEqual(res.skippedUntaggedCount, 10);
        assert.strictEqual(res.summary.traceLinks.length, 55);
        assert.strictEqual(res.truncated, false);

        // Now includeUntaggedIssues: true brings in all 65
        const resAll = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'MED', spaceId: 'SPACE1', includeUntaggedIssues: true, callerMode: 'USER' },
          'acc-sync'
        );
        assert.strictEqual(resAll.skippedUntaggedCount, 0);
        assert.strictEqual(resAll.summary.traceLinks.length, 65);
      }
    );
  });

  test.it('enforces bounded concurrency (batch size 5) and 15_000ms budget returning truncated: true', async () => {
    const kvsMock = createFullMockForgeKvs();
    const issues12 = Array.from({ length: 12 }, (_, idx) => ({
      id: String(30000 + idx),
      key: `CONC-${idx + 1}`,
      fields: {
        summary: `Hazard ${idx + 1}`,
        status: { name: 'Done', statusCategory: { name: 'Done' } },
        labels: ['class-a'],
        issuetype: { name: 'Hazard' },
        project: { name: 'Concurrency Project' },
      },
    }));

    let activeInFlight = 0;
    let maxInFlight = 0;

    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, { issues: issues12, isLast: true });
        }
        activeInFlight++;
        maxInFlight = Math.max(maxInFlight, activeInFlight);
        await new Promise((resolve) => setTimeout(resolve, 15));
        activeInFlight--;
        if (r.includes('/remotelink')) return makeJsonResponse(200, []);
        return makeJsonResponse(200, {
          id: '30001',
          key: 'CONC-1',
          fields: { summary: 'Hazard', status: { name: 'Done' }, issuelinks: [] },
        });
      },
      requestConfluence: async () => makeJsonResponse(200, { results: [] }),
    });

    await withForgeMocks({ kvsMock, asUserImpl: mockClient }, async () => {
      const res = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'CONC', callerMode: 'USER' },
        'acc-conc'
      );
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.summary.traceLinks.length, 12);
      assert.ok(maxInFlight <= 5, `Expected bounded concurrency <= 5, observed ${maxInFlight}`);
    });

    // Test 15_000ms budget truncation during pagination/batching
    const origDateNow = Date.now;
    let fakeNow = 1_700_000_000_000;
    Date.now = () => fakeNow;
    try {
      const kvsBudget = createFullMockForgeKvs();
      const budgetClient = () => ({
        requestJira: async (routeObj) => {
          const r = String(routeObj?.value || routeObj);
          if (r.includes('/rest/api/3/search/jql')) {
            fakeNow += 16_000; // Exceed 15_000ms budget after first Jira page
            return makeJsonResponse(200, {
              issues: issues12.slice(0, 5),
              nextPageToken: 'should-not-fetch-page-2',
              isLast: false,
            });
          }
          if (r.includes('/remotelink')) return makeJsonResponse(200, []);
          return makeJsonResponse(200, {
            id: '30001',
            key: 'CONC-1',
            fields: { summary: 'Hazard', status: { name: 'Done' }, issuelinks: [] },
          });
        },
        requestConfluence: async () => makeJsonResponse(200, { results: [] }),
        });

      await withForgeMocks({ kvsMock: kvsBudget, asUserImpl: budgetClient }, async () => {
        const resBudget = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'CONC', callerMode: 'USER' },
          'acc-budget'
        );
        assert.strictEqual(resBudget.truncated, true);
        assert.ok(resBudget.warnings.some((w) => /budget|15000|15_000|truncated/i.test(w)));
      });
    } finally {
      Date.now = origDateNow;
    }
  });

  test.it('emits M:N TraceLinks, forwards callerMode, caches Confluence fetches, distinguishes empty-body vs unlinked sentinel, and sets truthful graphMetadata', async () => {
    const kvsMock = createFullMockForgeKvs();
    const singlePageFetchCounts = new Map();
    let userCalls = 0;
    let appCalls = 0;

    const makeClient = (onCall) => ({
      requestJira: async (routeObj) => {
        onCall();
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, {
            issues: [
              {
                id: '401',
                key: 'MN-1',
                fields: {
                  summary: 'Multi-spec Hazard',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-c'],
                  issuetype: { name: 'Hazard' },
                  project: { name: 'MN Project' },
                },
              },
              {
                id: '402',
                key: 'MN-2',
                fields: {
                  summary: 'Shares cached page 6001',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-b'],
                  issuetype: { name: 'Hazard' },
                },
              },
              {
                id: '403',
                key: 'MN-3',
                fields: {
                  summary: 'Empty body spec page',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-a'],
                  issuetype: { name: 'Hazard' },
                },
              },
              {
                id: '404',
                key: 'MN-4',
                fields: {
                  summary: 'Unlinked hazard',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-a'],
                  issuetype: { name: 'Hazard' },
                },
              },
              {
                id: '405',
                key: 'MN-5',
                fields: {
                  summary: 'Heuristic SRS-999 match',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-a'],
                  issuetype: { name: 'Hazard' },
                },
              },
            ],
            isLast: true,
          });
        }
        if (r.includes('/MN-1/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=6001',
              object: { title: 'SRS-6001', url: 'https://example.atlassian.net/wiki/pages/6001' },
            },
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=6002',
              object: { title: 'SRS-6002', url: 'https://example.atlassian.net/wiki/pages/6002' },
            },
          ]);
        }
        if (r.includes('/MN-2/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=6001',
              object: { title: 'SRS-6001', url: 'https://example.atlassian.net/wiki/pages/6001' },
            },
          ]);
        }
        if (r.includes('/MN-3/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=6003',
              object: { title: 'SRS-6003 Empty Spec', url: 'https://example.atlassian.net/wiki/pages/6003' },
            },
          ]);
        }
        if (r.includes('/remotelink')) return makeJsonResponse(200, []);
        const key = r.match(/\/issue\/([^/?]+)/)?.[1] || 'MN-1';
        return makeJsonResponse(200, {
          id: '401',
          key,
          self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/401',
          fields: { summary: key, status: { name: 'Done' }, issuelinks: [] },
        });
      },
      requestConfluence: async (routeObj) => {
        onCall();
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages?')) {
          // Only page 9999 is in bulk list; 6001, 6002, 6003 must be fetched on-demand and cached
          return makeJsonResponse(200, {
            results: [
              {
                id: '9999',
                title: 'SRS-999: Heuristic Matched Spec',
                version: { number: 2 },
                body: { storage: { value: '<p>Heuristic body</p>' } },
              },
            ],
          });
        }
        const m = r.match(/\/wiki\/api\/v2\/pages\/(\d+)/);
        if (m) {
          const pid = m[1];
          singlePageFetchCounts.set(pid, (singlePageFetchCounts.get(pid) || 0) + 1);
          if (pid === '6003') {
            return makeJsonResponse(200, {
              id: '6003',
              title: 'SRS-6003: Empty Body Spec',
              version: { number: 1 },
              body: { storage: { value: '' } },
            });
          }
          return makeJsonResponse(200, {
            id: pid,
            title: `SRS-${pid}`,
            version: { number: 1 },
            body: { storage: { value: `<p>Body ${pid}</p>` } },
          });
        }
        return makeJsonResponse(404, {});
      },
      // Live sync must never call Teamwork Graph (spec owners are interactive-only, off the sync budget)
      requestTeamworkGraph: async () => {
        throw new Error('requestTeamworkGraph must not be called by live sync');
      },
    });

    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => makeClient(() => { userCalls++; }),
        asAppImpl: () => makeClient(() => { appCalls++; }),
      },
      async () => {
        const res = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'MN', callerMode: 'USER' },
          'acc-user'
        );
        assert.ok(userCalls > 0);
        assert.strictEqual(appCalls, 0, 'USER callerMode must never call api.asApp()');

        // MN-1 produced 2 links (M:N), MN-2/3/4/5 produced 1 each = 6 total
        assert.strictEqual(res.summary.traceLinks.length, 6);
        const mn1Links = res.summary.traceLinks.filter((l) => l.work.key === 'MN-1');
        assert.strictEqual(mn1Links.length, 2);
        assert.notStrictEqual(mn1Links[0].id, mn1Links[1].id);
        assert.strictEqual(
          mn1Links[0].id,
          ComplianceEngine.buildTraceLinkId('HAZ-MN-1', 'srs-6001', 'MN-1')
        );
        assert.strictEqual(
          mn1Links[1].id,
          ComplianceEngine.buildTraceLinkId('HAZ-MN-1', 'srs-6002', 'MN-1')
        );
        assert.strictEqual(mn1Links[0].graphMetadata.edgeType, 'REST:jira-remotelink');
        assert.strictEqual(mn1Links[0].graphMetadata.aggTraversalStatus, 'LIVE (JIRA_REST)');

        // Confluence page 6001 shared by MN-1 and MN-2 must only be fetched ONCE
        assert.strictEqual(singlePageFetchCounts.get('6001'), 1, 'Confluence page 6001 must be cached across batch');

        // Empty-body spec vs unlinked sentinel
        const emptyBodyLink = res.summary.traceLinks.find((l) => l.work.key === 'MN-3');
        assert.strictEqual(emptyBodyLink.spec.sha256Hash, sha256Hex(''));
        assert.notStrictEqual(emptyBodyLink.spec.isMissingSentinel, true);
        assert.strictEqual(emptyBodyLink.graphMetadata.edgeType, 'REST:jira-remotelink');

        const unlinkedLink = res.summary.traceLinks.find((l) => l.work.key === 'MN-4');
        assert.strictEqual(unlinkedLink.spec.isMissingSentinel, true);
        assert.strictEqual(unlinkedLink.spec.sha256Hash, '');
        assert.strictEqual(unlinkedLink.graphMetadata.edgeType, 'NONE:unlinked');

        const heuristicLink = res.summary.traceLinks.find((l) => l.work.key === 'MN-5');
        assert.strictEqual(heuristicLink.spec.id, 'srs-9999');
        assert.strictEqual(heuristicLink.graphMetadata.edgeType, 'HEURISTIC:summary-srs-title');
      }
    );

    // Also test callerMode: 'APP' calls api.asApp() exclusively (0 asUser calls)
    userCalls = 0;
    appCalls = 0;
    await withForgeMocks(
      {
        kvsMock: createFullMockForgeKvs(),
        asUserImpl: () => makeClient(() => { userCalls++; }),
        asAppImpl: () => makeClient(() => { appCalls++; }),
      },
      async () => {
        const appRes = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'MN', callerMode: 'APP' },
          'acc-app-sync'
        );
        assert.strictEqual(appRes.success, true);
        assert.ok(appCalls > 0, 'APP callerMode must call api.asApp()');
        assert.strictEqual(userCalls, 0, 'APP callerMode must never call api.asUser()');
      }
    );
  });

  test.it('tracks untagged issues when linked to Confluence SRS or already tracked, honors custom hazardLabels/hazardIssueTypes and maxIssues truncation', async () => {
    const kvsMock = createFullMockForgeKvs();
    const makeIssues = Array.from({ length: 65 }, (_, idx) => ({
      id: String(700 + idx),
      key: `CAP-${idx + 1}`,
      fields: {
        summary: `Issue ${idx + 1}`,
        status: { name: 'Done', statusCategory: { name: 'Done' } },
        labels: idx === 0 ? ['custom-med-label'] : [],
        issuetype: { name: idx === 1 ? 'CustomSafetyType' : 'Task' },
        project: { name: 'Cap Project' },
      },
    }));

    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          const parsed = new URL(r, 'https://jira.invalid');
          const tok = parsed.searchParams.get('nextPageToken');
          if (!tok) {
            return makeJsonResponse(200, {
              issues: makeIssues.slice(0, 50),
              nextPageToken: 'page-2',
              isLast: false,
            });
          }
          return makeJsonResponse(200, { issues: makeIssues.slice(50), isLast: true });
        }
        if (r.includes('/CAP-3/remotelink')) {
          // Untagged CAP-3 has a linked Confluence SRS page -> MUST be tracked!
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=91003',
              object: { title: 'SRS-91003', url: 'https://example.atlassian.net/wiki/pages/91003' },
            },
          ]);
        }
        if (r.includes('/remotelink')) return makeJsonResponse(200, []);
        const key = r.match(/\/issue\/([^/?]+)/)?.[1] || 'CAP-1';
        return makeJsonResponse(200, {
          id: '700',
          key,
          fields: { summary: key, status: { name: 'Done' }, issuelinks: [] },
        });
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/91003')) {
          return makeJsonResponse(200, {
            id: '91003',
            title: 'SRS-91003',
            version: { number: 1 },
            body: { storage: { value: '<p>Tracked via remotelink</p>' } },
          });
        }
        return makeJsonResponse(200, { results: [] });
      },
    });

    await withForgeMocks({ kvsMock, asUserImpl: mockClient }, async () => {
      const res = await LiveIngestionService.syncFromAtlassian(
        {
          projectKey: 'CAP',
          callerMode: 'USER',
          hazardLabels: ['custom-med-label'],
          hazardIssueTypes: ['CustomSafetyType'],
          maxIssues: 55,
        },
        'acc-cap'
      );
      assert.strictEqual(res.truncated, true);
      assert.strictEqual(res.jiraIssuesScanned, 55);
      assert.strictEqual(res.skippedUntaggedCount, 52);
      assert.deepStrictEqual(
        res.summary.traceLinks.map((l) => l.work.key).sort(),
        ['CAP-1', 'CAP-2', 'CAP-3']
      );

      // Next sync without CAP-4 labels still keeps CAP-1..3 + any already-tracked link (simulate CAP-4 already tracked)
      res.summary.traceLinks.push({
        ...res.summary.traceLinks[0],
        id: ComplianceEngine.buildTraceLinkId('HAZ-CAP-4', 'unlinked-cap-4', 'CAP-4'),
        hazard: { ...res.summary.traceLinks[0].hazard, key: 'HAZ-CAP-4' },
        work: { ...res.summary.traceLinks[0].work, key: 'CAP-4' },
      });
      await SeederService.saveComplianceSuite(res.summary, 1);

      const res2 = await LiveIngestionService.syncFromAtlassian(
        {
          projectKey: 'CAP',
          callerMode: 'USER',
          hazardLabels: ['custom-med-label'],
          hazardIssueTypes: ['CustomSafetyType'],
          maxIssues: 55,
        },
        'acc-cap'
      );
      assert.ok(res2.summary.traceLinks.some((l) => l.work.key === 'CAP-4'), 'Already-tracked issue CAP-4 must remain tracked');
    });
  });

  test.it('preserves non-200 Confluence warnings, single-page 404 warnings, throws on Jira non-200, and rejects unsafe projectKey', async () => {
    const kvsMock = createFullMockForgeKvs();
    await withForgeMocks({ kvsMock }, async () => {
      await assert.rejects(
        () => LiveIngestionService.syncFromAtlassian({ projectKey: 'bad-key!' }),
        /projectKey/i
      );
    });

    const jiraErrClient = () => ({
      requestJira: async () => makeJsonResponse(500, { errorMessages: ['Jira down'] }),
      requestConfluence: async () => makeJsonResponse(200, { results: [] }),
    });
    await withForgeMocks({ kvsMock, asUserImpl: jiraErrClient }, async () => {
      await assert.rejects(
        () => LiveIngestionService.syncFromAtlassian({ projectKey: 'SAFE' }, 'acc-err'),
        /Jira search failed \(HTTP 500\)/
      );
    });

    const warnClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, {
            issues: [
              {
                id: '888',
                key: 'WARN-1',
                fields: {
                  summary: 'Missing page 404',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-a'],
                  issuetype: { name: 'Hazard' },
                },
              },
            ],
          });
        }
        if (r.includes('/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=404404',
              object: { title: 'Restricted Page', url: 'https://example.atlassian.net/wiki/pages/404404' },
            },
          ]);
        }
        return makeJsonResponse(200, { id: '888', key: 'WARN-1', fields: { summary: 'x', issuelinks: [] } });
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/404404')) {
          return makeJsonResponse(404, { message: 'Not Found' });
        }
        return makeJsonResponse(403, { message: 'Forbidden' });
      },
    });

    await withForgeMocks({ kvsMock, asUserImpl: warnClient }, async () => {
      const res = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'WARN', spaceId: 'WARNSPACE' },
        'acc-warn'
      );
      assert.strictEqual(res.success, true);
      assert.ok(res.warnings.some((w) => /403/.test(w)));
      assert.ok(res.warnings.some((w) => /404404.*404|404/.test(w)));
      assert.strictEqual(res.summary.traceLinks[0].spec.isMissingSentinel, true);
    });
  });
});

test.describe('Task 1C-Ingestion: Confluence Revert Non-Resurrection & 3-Attempt CAS Retry (CS-03 / CS-05)', () => {
  const origPart11Secret = process.env.MEDTRACE_PART11_SECRET;

  test.beforeEach(() => {
    resetInMemoryAuditStorage();
    setAuditStorageAdapter(null);
    SeederService.resetInMemoryState?.();
    seederMod.setUserIdentityResolver?.(null);
    process.env.MEDTRACE_PART11_SECRET = 'revert-test-part11-secret';
  });

  test.afterEach(() => {
    seederMod.setUserIdentityResolver?.(null);
    if (origPart11Secret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
    else process.env.MEDTRACE_PART11_SECRET = origPart11Secret;
  });

  test.it('sign hashA -> drift hashB -> revert hashA preserves isValid === false & isSignatureInvalidated === true across M:N links in both trigger & live sync', async () => {
    const bodyA = '<p>Clause 4.2.1: Max 5.0 mL/hr</p>';
    const bodyB = '<p>Clause 4.2.1: Max 9.0 mL/hr</p>';
    const bodyOther = '<p>Unrelated spec 70002</p>';
    let activeBody70001 = bodyA;
    let activeVersion70001 = 1;

    const kvsMock = createFullMockForgeKvs();
    seederMod.setUserIdentityResolver({
      resolveSignerIdentity: async ({ actorAccountId }) => ({
        accountId: actorAccountId,
        displayName: `Dr. Approver (${actorAccountId})`,
        role: 'Clinical Safety Officer',
        authSource: 'LOCAL_TEST',
      }),
    });

    const makeCloudClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, {
            issues: [
              {
                id: '501',
                key: 'REV-1',
                fields: {
                  summary: 'Hazard REV-1',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-c'],
                  issuetype: { name: 'Hazard' },
                  project: { name: 'Revert Guard Project' },
                },
              },
              {
                id: '502',
                key: 'REV-2',
                fields: {
                  summary: 'Hazard REV-2 sharing 70001',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-b'],
                  issuetype: { name: 'Hazard' },
                },
              },
            ],
            isLast: true,
          });
        }
        if (r.includes('/REV-1/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=70001',
              object: { title: 'SRS-70001: Shared Spec', url: 'https://example.atlassian.net/wiki/pages/70001' },
            },
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=70002',
              object: { title: 'SRS-70002: Independent Spec', url: 'https://example.atlassian.net/wiki/pages/70002' },
            },
          ]);
        }
        if (r.includes('/REV-2/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=70001',
              object: { title: 'SRS-70001: Shared Spec', url: 'https://example.atlassian.net/wiki/pages/70001' },
            },
          ]);
        }
        const key = r.match(/\/issue\/([^/?]+)/)?.[1] || 'REV-1';
        return makeJsonResponse(200, {
          id: key === 'REV-1' ? '501' : '502',
          key,
          fields: { summary: key, status: { name: 'Done' }, issuelinks: [] },
        });
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/70001')) {
          return makeJsonResponse(200, {
            id: '70001',
            title: 'SRS-70001: Shared Spec',
            version: { number: activeVersion70001, createdAt: '2026-11-12T00:00:00Z' },
            body: { storage: { value: activeBody70001 } },
          });
        }
        if (r.includes('/wiki/api/v2/pages/70002')) {
          return makeJsonResponse(200, {
            id: '70002',
            title: 'SRS-70002: Independent Spec',
            version: { number: 1, createdAt: '2026-11-12T00:00:00Z' },
            body: { storage: { value: bodyOther } },
          });
        }
        if (r.includes('/wiki/api/v2/pages?')) {
          return makeJsonResponse(200, {
            results: [
              {
                id: '70001',
                title: 'SRS-70001: Shared Spec',
                version: { number: activeVersion70001, createdAt: '2026-11-12T00:00:00Z' },
                body: { storage: { value: activeBody70001 } },
              },
              {
                id: '70002',
                title: 'SRS-70002: Independent Spec',
                version: { number: 1, createdAt: '2026-11-12T00:00:00Z' },
                body: { storage: { value: bodyOther } },
              },
            ],
          });
        }
        return makeJsonResponse(404, {});
      },
    });

    await withForgeMocks(
      { kvsMock, asUserImpl: makeCloudClient, asAppImpl: makeCloudClient },
      async () => {
        // 1. Initial sync (3 M:N links: (HAZ-REV-1, srs-70001), (HAZ-REV-1, srs-70002), (HAZ-REV-2, srs-70001))
        const initSync = await LiveIngestionService.syncFromAtlassian({ projectKey: 'REV', callerMode: 'USER' }, 'acc-sync');
        assert.strictEqual(initSync.summary.traceLinks.length, 3);

        // Pass tests with valid evidence on all 3 links and sign all 3 at hashA / bodyOther
        for (const l of initSync.summary.traceLinks) {
          l.test.status = 'PASSED';
          l.test.evidenceUrl = 'https://ci.example.internal/run/1';
          l.test.executionDate = '2026-11-12T00:00:00Z';
        }
        await SeederService.saveComplianceSuite(
          ComplianceEngine.generateComplianceReport(initSync.summary.traceLinks, 'LIVE', 'Revert Guard Project', {
            initialized: true,
          }),
          1
        );

        for (const target of [
          { hazardKey: 'HAZ-REV-1', specId: 'srs-70001' },
          { hazardKey: 'HAZ-REV-1', specId: 'srs-70002' },
          { hazardKey: 'HAZ-REV-2', specId: 'srs-70001' },
        ]) {
          await SeederService.signOffPart11({
            ...target,
            attestation: {
              meaning: 'Approved for production',
              attestationConfirmed: true,
              attestationChecked: true,
              attestationPhrase: PART11_ATTESTATION_PHRASE,
            },
            actorAccountId: 'acc-cmo',
          });
        }

        const verifiedSuite = await SeederService.getActiveComplianceSuite();
        assert.strictEqual(verifiedSuite.traceLinks.every((l) => l.complianceState === 'VERIFIED'), true);

        // 2. Edit page 70001 to bodyB (hashB) -> trigger invalidates BOTH REV-1 & REV-2 links on 70001, leaving 70002 VERIFIED
        activeBody70001 = bodyB;
        activeVersion70001 = 2;
        const driftTrigger = await LiveIngestionService.handleConfluencePageUpdated({
          content: { id: '70001' },
          atlassianId: 'acc-editor',
        });
        assert.strictEqual(driftTrigger.processed, true);
        assert.deepStrictEqual(driftTrigger.affectedHazards.sort(), ['HAZ-REV-1', 'HAZ-REV-2']);

        const afterDrift = await SeederService.getActiveComplianceSuite();
        for (const l of afterDrift.traceLinks.filter((x) => x.spec.pageId === '70001')) {
          assert.strictEqual(l.signature.isValid, false);
          assert.strictEqual(l.spec.isSignatureInvalidated, true);
          assert.ok(l.signature.invalidatedAt);
        }
        assert.strictEqual(
          afterDrift.traceLinks.find((x) => x.spec.pageId === '70002').complianceState,
          'VERIFIED'
        );

        // 3. REVERT page 70001 back to bodyA (hashA) -> handleConfluencePageUpdated MUST NOT resurrect signature!
        activeBody70001 = bodyA;
        activeVersion70001 = 3;
        await LiveIngestionService.handleConfluencePageUpdated({
          content: { id: '70001' },
          atlassianId: 'acc-reverter',
        });

        const afterRevertTrigger = await SeederService.getActiveComplianceSuite();
        for (const l of afterRevertTrigger.traceLinks.filter((x) => x.spec.pageId === '70001')) {
          assert.strictEqual(l.spec.sha256Hash, sha256Hex(bodyA));
          assert.strictEqual(l.signature.isValid, false, 'Trigger revert MUST NOT resurrect signature.isValid');
          assert.strictEqual(l.spec.isSignatureInvalidated, true, 'Trigger revert MUST keep isSignatureInvalidated === true');
          assert.strictEqual(l.complianceState, 'SIGNATURE_DRIFT');
        }
        assert.strictEqual(
          afterRevertTrigger.traceLinks.find((x) => x.spec.pageId === '70002').complianceState,
          'VERIFIED'
        );

        // 4. Run syncFromAtlassian while page 70001 still serves reverted bodyA -> MUST STILL NOT resurrect!
        const afterRevertSync = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'REV', callerMode: 'USER' },
          'acc-sync-2'
        );
        for (const l of afterRevertSync.summary.traceLinks.filter((x) => x.spec.pageId === '70001')) {
          assert.strictEqual(l.spec.sha256Hash, sha256Hex(bodyA));
          assert.strictEqual(l.signature.isValid, false, 'Live sync revert MUST NOT resurrect signature.isValid');
          assert.strictEqual(l.spec.isSignatureInvalidated, true, 'Live sync revert MUST keep isSignatureInvalidated === true');
          assert.strictEqual(l.complianceState, 'SIGNATURE_DRIFT');
        }
        assert.strictEqual(
          afterRevertSync.summary.traceLinks.find((x) => x.spec.pageId === '70002').complianceState,
          'VERIFIED'
        );

        // 5. Re-sign ONLY (HAZ-REV-1, srs-70001) -> signedAt > invalidatedAt restores HAZ-REV-1 only, leaving HAZ-REV-2 drifted
        await SeederService.signOffPart11({
          hazardKey: 'HAZ-REV-1',
          specId: 'srs-70001',
          attestation: {
            meaning: 'Re-approved after revert review',
            attestationConfirmed: true,
            attestationChecked: true,
            attestationPhrase: PART11_ATTESTATION_PHRASE,
          },
          actorAccountId: 'acc-cmo',
        });

        const afterResignSync = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'REV', callerMode: 'USER' },
          'acc-sync-3'
        );
        const rev1Spec70001 = afterResignSync.summary.traceLinks.find(
          (l) => l.hazard.key === 'HAZ-REV-1' && l.spec.id === 'srs-70001'
        );
        const rev2Spec70001 = afterResignSync.summary.traceLinks.find(
          (l) => l.hazard.key === 'HAZ-REV-2' && l.spec.id === 'srs-70001'
        );
        assert.strictEqual(rev1Spec70001.signature.isValid, true);
        assert.strictEqual(rev1Spec70001.spec.isSignatureInvalidated, false);
        assert.strictEqual(rev1Spec70001.complianceState, 'VERIFIED');
        assert.strictEqual(rev2Spec70001.signature.isValid, false);
        assert.strictEqual(rev2Spec70001.spec.isSignatureInvalidated, true);

        // 6. Also test sync-detected drift (no trigger first): edit 70001 to bodyB -> syncFromAtlassian detects drift -> revert to bodyA -> sync + trigger keep isValid === false
        activeBody70001 = bodyB;
        activeVersion70001 = 4;
        const syncDrift = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'REV', callerMode: 'USER' },
          'acc-sync-4'
        );
        assert.strictEqual(
          syncDrift.summary.traceLinks.find((l) => l.hazard.key === 'HAZ-REV-1' && l.spec.id === 'srs-70001').signature.isValid,
          false
        );

        activeBody70001 = bodyA;
        activeVersion70001 = 5;
        const syncAfterRevert2 = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'REV', callerMode: 'USER' },
          'acc-sync-5'
        );
        const rev1AfterSyncRevert = syncAfterRevert2.summary.traceLinks.find(
          (l) => l.hazard.key === 'HAZ-REV-1' && l.spec.id === 'srs-70001'
        );
        assert.strictEqual(rev1AfterSyncRevert.signature.isValid, false);
        assert.strictEqual(rev1AfterSyncRevert.spec.isSignatureInvalidated, true);
      }
    );
  });

  test.it('handleConfluencePageUpdated retries CAS version conflicts up to 3 attempts and fails on persistent conflict', async () => {
    const link = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-cas',
        key: 'HAZ-CAS',
        title: 'CAS Hazard',
        riskClass: 'CLASS_C',
        severity: 'CATASTROPHIC',
        probability: 'REMOTE',
        mitigationRequirementId: 'srs-80001',
        status: 'MITIGATED',
      },
      {
        id: 'srs-80001',
        pageId: '80001',
        title: 'SRS-80001',
        version: 1,
        sha256Hash: sha256Hex('<p>v1</p>'),
        lastSignedHash: sha256Hex('<p>v1</p>'),
        isSignatureInvalidated: false,
        contentSnippet: 'v1',
        lastUpdated: '2026-11-12T00:00:00Z',
      },
      { id: 'w1', key: 'CAS-1', title: 'Work', status: 'Done', assignee: 'QA' },
      { id: 't1', testKey: 'TEST-1', title: 'Test', testType: 'Unit Test', status: 'PASSED' },
      {
        id: 'sig-cas',
        signedBy: 'CMO',
        signedAt: '2026-11-12T00:00:00Z',
        role: 'CMO',
        meaning: 'Approved',
        artifactSha256: sha256Hex('<p>v1</p>'),
        isValid: true,
      }
    );

    let vlockInjectionsRemaining = 0;
    const kvsMock = createFullMockForgeKvs(
      {},
      {
        onSet: async (key, _val, opts, store) => {
          // Inject 2 concurrent vlock conflicts before allowing attempt 3 to succeed
          if (vlockInjectionsRemaining > 0 && key.startsWith('medtrace:compliance:vlock:') && opts?.keyPolicy === 'FAIL_IF_EXISTS') {
            vlockInjectionsRemaining--;
            store.set(key, { claimedAt: Date.now() });
            const meta = store.get('medtrace:compliance:suite_meta');
            if (meta) {
              meta.version += 1;
              store.set('medtrace:compliance:suite_meta', meta);
            }
          }
        },
      }
    );

    const mockClient = () => ({
      requestConfluence: async () =>
        makeJsonResponse(200, {
          id: '80001',
          title: 'SRS-80001',
          version: { number: 2 },
          body: { storage: { value: '<p>v2 modified</p>' } },
        }),
    });

    await withForgeMocks({ kvsMock, asAppImpl: mockClient }, async () => {
      await SeederService.saveComplianceSuite(
        ComplianceEngine.generateComplianceReport([link], 'LIVE', 'CAS Suite', { initialized: true }),
        0
      );
      vlockInjectionsRemaining = 2;

      const res = await LiveIngestionService.handleConfluencePageUpdated({
        content: { id: '80001' },
        atlassianId: 'acc-conf',
      });
      assert.strictEqual(res.processed, true);
      assert.strictEqual(vlockInjectionsRemaining, 0, 'Expected 2 CAS retries before succeeding on attempt 3');

      const latest = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(latest.traceLinks[0].signature.isValid, false);
      assert.strictEqual(latest.traceLinks[0].spec.isSignatureInvalidated, true);
    });

    // Persistent conflict across all 3 attempts must throw
    let alwaysCollide = true;
    const failKvsMock = createFullMockForgeKvs(
      {},
      {
        onSet: async (key, _val, opts, store) => {
          if (alwaysCollide && key.startsWith('medtrace:compliance:vlock:') && opts?.keyPolicy === 'FAIL_IF_EXISTS') {
            store.set(key, { claimedAt: Date.now() });
          }
        },
      }
    );

    await withForgeMocks({ kvsMock: failKvsMock, asAppImpl: mockClient }, async () => {
      alwaysCollide = false;
      await SeederService.saveComplianceSuite(
        ComplianceEngine.generateComplianceReport([link], 'LIVE', 'CAS Fail Suite', { initialized: true }),
        0
      );
      alwaysCollide = true;
      await assert.rejects(
        () =>
          LiveIngestionService.handleConfluencePageUpdated({
            content: { id: '80001' },
            atlassianId: 'acc-conf',
          }),
        /Concurrent modification|version lock conflict/i
      );
    });
  });

  test.it('short-circuits /issue fetch on untagged issues without Confluence links and preserves unreached/other-project LIVE links', async () => {
    const kvsMock = createFullMockForgeKvs();
    const issueDetailCalls = [];

    const existingOtherProjectLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-beta-1',
        key: 'BETA-1',
        title: 'Beta Infusion Hazard',
        riskClass: 'CLASS_B',
        severity: 'CRITICAL',
        probability: 'REMOTE',
        mitigationRequirementId: '90001',
        status: 'UNVERIFIED_RISK',
      },
      {
        id: '90001',
        pageId: '90001',
        title: 'SRS-BETA: Clamp',
        version: 1,
        sha256Hash: sha256Hex('<p>beta spec</p>'),
        lastSignedHash: '',
        isSignatureInvalidated: false,
        contentSnippet: 'beta',
        lastUpdated: '2026-11-12T00:00:00Z',
      },
      { id: 'work-beta-1', key: 'BETA-1', title: 'Beta Work', status: 'Done' },
      { id: 'test-beta-1', testKey: 'BETA-1', status: 'PASSED', evidenceUrl: 'https://ci.example/b1', executionDate: '2026-11-12' },
      { id: 'sig-beta-1', signerName: 'Pending', signedAt: '', signatureHash: '', isValid: false, meaning: 'Pending' }
    );
    const existingUnreachedSameProjectLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-alfa-99',
        key: 'ALFA-99',
        title: 'Unreached Alfa Hazard',
        riskClass: 'CLASS_B',
        severity: 'MAJOR',
        probability: 'OCCASIONAL',
        mitigationRequirementId: '90002',
        status: 'UNVERIFIED_RISK',
      },
      {
        id: '90002',
        pageId: '90002',
        title: 'SRS-ALFA-99',
        version: 1,
        sha256Hash: sha256Hex('<p>alfa99</p>'),
        lastSignedHash: '',
        isSignatureInvalidated: false,
        contentSnippet: 'alfa99',
        lastUpdated: '2026-11-12T00:00:00Z',
      },
      { id: 'work-alfa-99', key: 'ALFA-99', title: 'Alfa 99', status: 'Done' },
      { id: 'test-alfa-99', testKey: 'ALFA-99', status: 'UNTESTED' },
      { id: 'sig-alfa-99', signerName: 'Pending', signedAt: '', signatureHash: '', isValid: false, meaning: 'Pending' }
    );

    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, {
            issues: [
              {
                id: '101',
                key: 'ALFA-1',
                fields: {
                  summary: 'Safety Hazard ALFA-1',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-c'],
                  issuetype: { name: 'Hazard' },
                  project: { name: 'Alfa Project' },
                },
              },
              {
                id: '102',
                key: 'ALFA-2',
                fields: {
                  summary: 'Everyday chore without labels',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: [],
                  issuetype: { name: 'Task' },
                  project: { name: 'Alfa Project' },
                },
              },
            ],
            nextPageToken: 'truncated-page-2',
          });
        }
        if (r.includes('/remotelink')) {
          if (r.includes('/ALFA-1/')) {
            return makeJsonResponse(200, [
              {
                application: { type: 'com.atlassian.confluence' },
                globalId: 'pageId=90003',
                object: { title: 'SRS-ALFA-1', url: 'https://example.atlassian.net/wiki/pages/90003' },
              },
            ]);
          }
          // Untagged ALFA-2 has no Confluence links -> should short-circuit the /issue call
          return makeJsonResponse(200, []);
        }
        if (r.includes('/rest/api/3/issue/')) {
          issueDetailCalls.push(r);
          return makeJsonResponse(200, {
            id: '101',
            key: 'ALFA-1',
            self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/101',
            fields: { summary: 'x', issuelinks: [] },
          });
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/90003')) {
          return makeJsonResponse(200, {
            id: '90003',
            title: 'SRS-ALFA-1',
            version: { number: 1 },
            body: { storage: { value: '<p>alfa 1 spec</p>' } },
          });
        }
        return makeJsonResponse(200, { results: [] });
      },
    });

    await withForgeMocks({ kvsMock, asAppImpl: mockClient }, async () => {
      await SeederService.saveComplianceSuite(
        ComplianceEngine.generateComplianceReport(
          [existingOtherProjectLink, existingUnreachedSameProjectLink],
          'LIVE',
          'Multi Project Initial',
          { initialized: true }
        ),
        0
      );

      // maxIssues: 2 causes truncation after returning ALFA-1 & ALFA-2 with nextPageToken present
      const syncRes = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'ALFA', maxIssues: 2, callerMode: 'APP' },
        'acc-multi'
      );
      assert.strictEqual(syncRes.success, true);
      assert.strictEqual(syncRes.skippedUntaggedCount, 1);

      // ALFA-2 short-circuited: /rest/api/3/issue/ALFA-2 was never called
      assert.ok(
        !issueDetailCalls.some((u) => u.includes('ALFA-2')),
        `Untagged ALFA-2 should short-circuit /issue fetch, saw: ${JSON.stringify(issueDetailCalls)}`
      );

      // Synced HAZ-ALFA-1 (work ALFA-1) + preserved BETA-1 (other project) + preserved ALFA-99 (unreached before truncation)
      const hazKeys = syncRes.summary.traceLinks.map((l) => l.hazard.key).sort();
      const workKeys = syncRes.summary.traceLinks.map((l) => l.work.key).sort();
      assert.deepStrictEqual(hazKeys, ['ALFA-99', 'BETA-1', 'HAZ-ALFA-1']);
      assert.deepStrictEqual(workKeys, ['ALFA-1', 'ALFA-99', 'BETA-1']);
      assert.ok(syncRes.warnings.some((w) => /other Jira project/i.test(w)));
      assert.ok(syncRes.warnings.some((w) => /not reached before sync truncation/i.test(w)));
    });
  });

  test.it('persists resumable nextPageToken sync cursor across truncated invocations, merges prior pages, clears cursor on completion, and preserves hybrid ECDSA baseline metadata', async () => {
    const kvsMock = createFullMockForgeKvs();
    const requestedTokens = [];

    const prevSecret = process.env.MEDTRACE_PART11_SECRET;
    process.env.MEDTRACE_PART11_SECRET = 'cursor-ecdsa-secret';

    const makeMockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          const parsed = new URL(`https://mock.local${r}`);
          const token = parsed.searchParams.get('nextPageToken') || 'PAGE_1';
          requestedTokens.push(token);
          if (token === 'PAGE_1') {
            return makeJsonResponse(200, {
              issues: [
                {
                  id: '201',
                  key: 'CUR-1',
                  fields: {
                    summary: 'Cursor Hazard 1',
                    status: { name: 'Done', statusCategory: { name: 'Done' } },
                    labels: ['class-c'],
                    issuetype: { name: 'Hazard' },
                    project: { name: 'Cursor Project' },
                  },
                },
                {
                  id: '202',
                  key: 'CUR-2',
                  fields: {
                    summary: 'Cursor Hazard 2',
                    status: { name: 'Done', statusCategory: { name: 'Done' } },
                    labels: ['class-b'],
                    issuetype: { name: 'Hazard' },
                    project: { name: 'Cursor Project' },
                  },
                },
              ],
              nextPageToken: 'cursor-tok-2',
              isLast: false,
            });
          }
          if (token === 'cursor-tok-2') {
            return makeJsonResponse(200, {
              issues: [
                {
                  id: '203',
                  key: 'CUR-3',
                  fields: {
                    summary: 'Cursor Hazard 3',
                    status: { name: 'Done', statusCategory: { name: 'Done' } },
                    labels: ['class-a'],
                    issuetype: { name: 'Hazard' },
                    project: { name: 'Cursor Project' },
                  },
                },
              ],
              isLast: true,
            });
          }
        }
        if (r.includes('/remotelink')) {
          const match = r.match(/issue\/(CUR-\d+)\/remotelink/);
          const key = match ? match[1] : 'CUR-1';
          const pageMap = { 'CUR-1': '91001', 'CUR-2': '91002', 'CUR-3': '91003' };
          const pageId = pageMap[key];
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: `pageId=${pageId}`,
              object: { title: `SRS-${key}`, url: `https://example.atlassian.net/wiki/pages/${pageId}` },
            },
          ]);
        }
        if (r.includes('/rest/api/3/issue/')) {
          const key = r.split('/rest/api/3/issue/')[1].split('?')[0];
          return makeJsonResponse(200, {
            id: key,
            key,
            self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/' + key,
            fields: { summary: key, issuelinks: [] },
          });
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        const pageMatch = r.match(/\/wiki\/api\/v2\/pages\/(\d+)/);
        if (pageMatch) {
          const pid = pageMatch[1];
          return makeJsonResponse(200, {
            id: pid,
            title: `SRS-PAGE-${pid}`,
            version: { number: 1 },
            body: { storage: { value: `<p>srs body for ${pid}</p>` } },
          });
        }
        return makeJsonResponse(200, { results: [] });
      },
    });

    try {
      const mockClient = makeMockClient();
      await withForgeMocks({ kvsMock, asAppImpl: () => mockClient }, async () => {
        // Seed a standard HMAC-SHA256-SEAL-V1 baseline for CUR-1 / SRS 91001 so live sync re-hydration can be verified too
        const specHash = sha256Hex('<p>srs body for 91001</p>');
        const meaning = 'Initial HMAC signoff';
        const signedAt = '2026-11-15T00:00:00.000Z';
        const seal = ComplianceEngine.computePart11Seal(
          {
            hazardKey: 'HAZ-CUR-1',
            specId: 'srs-91001',
            artifactSha256: specHash,
            signedByAccountId: 'acc-hmac-live',
            signedBy: 'Dr. Live Signer',
            role: 'Authorized Atlassian User',
            meaning,
            signedAt,
            authMethod: 'PART11_ATTESTATION',
          },
          'cursor-ecdsa-secret'
        );
        await SeederService.setSignedSpecBaseline({
          hazardKey: 'HAZ-CUR-1',
          specId: 'srs-91001',
          pageId: '91001',
          sha256Hash: specHash,
          signedBy: 'Dr. Live Signer',
          signedByAccountId: 'acc-hmac-live',
          signedAt,
          role: 'Authorized Atlassian User',
          meaning,
          authMethod: 'PART11_ATTESTATION',
          signatureAlgorithm: 'HMAC-SHA256-SEAL-V1',
          signatureSeal: seal,
          sealKeyId: 'env:MEDTRACE_PART11_SECRET',
        });

        // Invocation 1: exact page-size cap maxIssues: 2 -> truncates and persists cursor-tok-2 + incompleteProjectKeys
        const pass1 = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'CUR', maxIssues: 2, callerMode: 'APP' },
          'acc-cur'
        );
        assert.strictEqual(pass1.truncated, true);
        assert.strictEqual(pass1.nextPageToken, 'cursor-tok-2');
        assert.strictEqual(pass1.resumedFromCursor, undefined);
        assert.deepStrictEqual(pass1.summary.incompleteProjectKeys, ['CUR']);
        const savedCursor = kvsMock.store.get('medtrace:ingestion:cursor:CUR');
        assert.strictEqual(savedCursor?.nextPageToken, 'cursor-tok-2');

        const cur1Link = pass1.summary.traceLinks.find((l) => l.work.key === 'CUR-1');
        assert.ok(cur1Link, 'Expected CUR-1 link in pass1');
        assert.strictEqual(cur1Link.signature.signatureAlgorithm, 'HMAC-SHA256-SEAL-V1');
        assert.strictEqual(cur1Link.signature.isValid, true);
        assert.strictEqual(pass1.driftDetectedCount, 0);

        // Invocation 2: resumeFromCursor: true reads cursor-tok-2 from KVS, merges CUR-1/CUR-2 + CUR-3, clears cursor & incompleteProjectKeys
        const pass2 = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'CUR', maxIssues: 2, resumeFromCursor: true, callerMode: 'APP' },
          'acc-cur'
        );
        assert.strictEqual(pass2.truncated, false);
        assert.strictEqual(pass2.nextPageToken, undefined);
        assert.strictEqual(pass2.resumedFromCursor, true);
        assert.strictEqual(pass2.summary.incompleteProjectKeys, undefined);
        assert.strictEqual(kvsMock.store.has('medtrace:ingestion:cursor:CUR'), false, 'Completed sync must clear stored cursor');
        assert.deepStrictEqual(requestedTokens, ['PAGE_1', 'cursor-tok-2']);
        assert.deepStrictEqual(
          pass2.summary.traceLinks.map((l) => l.work.key).sort(),
          ['CUR-1', 'CUR-2', 'CUR-3']
        );
      });
    } finally {
      if (prevSecret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
      else process.env.MEDTRACE_PART11_SECRET = prevSecret;
    }
  });

  test.it('does not leak prior DEMO hazard keys or PASSED test state into LIVE syncFromAtlassian when Jira shares MED-43 key', async () => {
    const kvsMock = createFullMockForgeKvs();
    const mockClient = {
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, {
            issues: [
              {
                id: '4300',
                key: 'MED-43',
                fields: {
                  summary: 'Live Med-43 issue sharing DEMO key',
                  status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
                  labels: ['class-b'],
                  issuetype: { name: 'Hazard' },
                  project: { name: 'Live Med Project' },
                },
              },
            ],
            isLast: true,
          });
        }
        if (r.includes('/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=92043',
              object: { title: 'SRS-92043', url: 'https://example.atlassian.net/wiki/pages/92043' },
            },
          ]);
        }
        if (r.includes('/rest/api/3/issue/MED-43')) {
          return makeJsonResponse(200, {
            id: '4300',
            key: 'MED-43',
            self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/MED-43',
            fields: { summary: 'Live Med-43 issue sharing DEMO key', issuelinks: [] },
          });
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/92043')) {
          return makeJsonResponse(200, {
            id: '92043',
            title: 'SRS-92043',
            version: { number: 1 },
            body: { storage: { value: '<p>Live SRS content</p>' } },
          });
        }
        return makeJsonResponse(200, { results: [] });
      },
    };

    await withForgeMocks({ kvsMock, asAppImpl: () => mockClient }, async () => {
      // Seed DEMO first (in DEMO, MED-43 is mapped to HAZ-102 with PASSED test status)
      const demoResp = await SeederService.seedEnterpriseDemoSuite('op-demo', 'FORGE_USER_SESSION');
      const demo = demoResp.summary || (await SeederService.getActiveComplianceSuite());
      const demoMed43 = demo.traceLinks.find((l) => l.work.key === 'MED-43');
      assert.strictEqual(demoMed43.hazard.key, 'HAZ-102');
      assert.strictEqual(demoMed43.test.status, 'PASSED');

      // Live sync for MED-43 must NOT inherit DEMO's HAZ-102 or PASSED test status
      const syncRes = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'MED', maxIssues: 10, callerMode: 'APP' },
        'op-live'
      );
      assert.strictEqual(syncRes.summary.datasetMode, 'LIVE');
      const liveMed43 = syncRes.summary.traceLinks.find((l) => l.work.key === 'MED-43');
      assert.ok(liveMed43, 'Expected MED-43 in synced LIVE suite');
      assert.strictEqual(liveMed43.hazard.key, 'HAZ-MED-43');
      assert.strictEqual(liveMed43.test.status, 'UNTESTED');
      assert.strictEqual(liveMed43.signature.isValid, false);
    });
  });

  test.it('infers software safety class from labels only, fails closed on unlabelled tracked issues, and ignores Jira priority', async () => {
    const kvsMock = createFullMockForgeKvs();
    const mockClient = {
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, {
            issues: [
              {
                id: '6101',
                key: 'CLS-1',
                fields: {
                  summary: 'Tracked hazard without a class label',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['iec-62304'],
                  issuetype: { name: 'Hazard' },
                  priority: { name: 'Low' },
                  project: { name: 'Class Project' },
                },
              },
              {
                id: '6102',
                key: 'CLS-2',
                fields: {
                  summary: 'Class A hazard with Highest priority',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-a'],
                  issuetype: { name: 'Hazard' },
                  priority: { name: 'Highest' },
                  project: { name: 'Class Project' },
                },
              },
              {
                id: '6103',
                key: 'CLS-3',
                fields: {
                  summary: 'Class B hazard',
                  status: { name: 'Done', statusCategory: { name: 'Done' } },
                  labels: ['class-b'],
                  issuetype: { name: 'Hazard' },
                  project: { name: 'Class Project' },
                },
              },
            ],
            isLast: true,
          });
        }
        if (r.includes('/remotelink')) {
          const key = r.match(/issue\/(CLS-\d+)\/remotelink/)?.[1] || 'CLS-1';
          const pageId = { 'CLS-1': '96101', 'CLS-2': '96102', 'CLS-3': '96103' }[key];
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: `pageId=${pageId}`,
              object: { title: `SRS-${key}`, url: `https://example.atlassian.net/wiki/pages/${pageId}` },
            },
          ]);
        }
        if (r.includes('/rest/api/3/issue/')) {
          const key = r.split('/rest/api/3/issue/')[1].split('?')[0];
          return makeJsonResponse(200, {
            id: key,
            key,
            self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/' + key,
            fields: { summary: key, issuelinks: [] },
          });
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        const pageMatch = r.match(/\/wiki\/api\/v2\/pages\/(\d+)/);
        if (pageMatch) {
          const pid = pageMatch[1];
          return makeJsonResponse(200, {
            id: pid,
            title: `SRS-PAGE-${pid}`,
            version: { number: 1 },
            body: { storage: { value: `<p>srs body for ${pid}</p>` } },
          });
        }
        return makeJsonResponse(200, { results: [] });
      },
    };

    await withForgeMocks({ kvsMock, asAppImpl: () => mockClient }, async () => {
      const syncRes = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'CLS', maxIssues: 10, callerMode: 'APP' },
        'acc-cls'
      );
      assert.strictEqual(syncRes.success, true);

      // 1. iec-62304 label only -> treated as CLASS_C, marked unassigned, flagged with a Classification Gap
      const cls1 = syncRes.summary.traceLinks.find((l) => l.work.key === 'CLS-1');
      assert.ok(cls1, 'Expected CLS-1 link in synced suite');
      assert.strictEqual(cls1.hazard.riskClass, 'CLASS_C');
      assert.strictEqual(cls1.hazard.safetyClassAssigned, false);
      assert.ok(
        cls1.violations.some((v) =>
          v.includes('IEC 62304 Classification Gap: Hazard [HAZ-CLS-1] has no software safety class label')
        ),
        `Expected Classification Gap violation, saw: ${JSON.stringify(cls1.violations)}`
      );
      assert.notStrictEqual(cls1.complianceState, 'VERIFIED');

      // 2. priority Highest + class-a label -> CLASS_A (priority is ignored)
      const cls2 = syncRes.summary.traceLinks.find((l) => l.work.key === 'CLS-2');
      assert.ok(cls2, 'Expected CLS-2 link in synced suite');
      assert.strictEqual(cls2.hazard.riskClass, 'CLASS_A');
      assert.strictEqual('safetyClassAssigned' in cls2.hazard, false);

      // 3. class-b label -> CLASS_B with no safetyClassAssigned field and no Classification Gap
      const cls3 = syncRes.summary.traceLinks.find((l) => l.work.key === 'CLS-3');
      assert.ok(cls3, 'Expected CLS-3 link in synced suite');
      assert.strictEqual(cls3.hazard.riskClass, 'CLASS_B');
      assert.strictEqual('safetyClassAssigned' in cls3.hazard, false);
      assert.ok(
        !cls3.violations.some((v) => v.includes('Classification Gap')),
        `Expected no Classification Gap violation, saw: ${JSON.stringify(cls3.violations)}`
      );
    });
  });

  test.it('skips full-tenant Confluence pagination when spaceId is unset, preserves filtered-JQL links, and hardens persistOrClearCursor', async () => {
    const kvsMock = createFullMockForgeKvs();
    const confluenceListCalls = [];
    let activeIssues = [
      {
        id: '901',
        key: 'JQL-1',
        fields: {
          summary: 'Bolus Clamp Hazard',
          status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
          labels: ['class-c'],
          issuetype: { name: 'Hazard' },
          project: { name: 'JQL Project' },
        },
      },
      {
        id: '902',
        key: 'JQL-2',
        fields: {
          summary: 'Sensor Hazard',
          status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
          labels: ['class-b'],
          issuetype: { name: 'Hazard' },
          project: { name: 'JQL Project' },
        },
      },
    ];

    const makeClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          const parsed = new URL(`https://mock.local${r}`);
          const jqlParam = parsed.searchParams.get('jql') || '';
          if (jqlParam.includes('labels = "class-c"')) {
            return makeJsonResponse(200, { issues: [activeIssues[0]], isLast: true });
          }
          return makeJsonResponse(200, { issues: activeIssues, isLast: true });
        }
        if (r.includes('/remotelink')) {
          const m = r.match(/issue\/(JQL-\d+)\/remotelink/);
          const key = m?.[1] || 'JQL-1';
          const pid = key === 'JQL-1' ? '5001' : '5002';
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: `pageId=${pid}`,
              object: { title: `SRS-${pid}`, url: `https://example.atlassian.net/wiki/pages/${pid}` },
            },
          ]);
        }
        if (r.includes('/rest/api/3/issue/')) {
          const key = r.split('/rest/api/3/issue/')[1].split('?')[0];
          return makeJsonResponse(200, {
            id: key,
            key,
            self: `https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/${key}`,
            fields: { summary: key, issuelinks: [] },
          });
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        const pageMatch = r.match(/\/wiki\/api\/v2\/pages\/(\d+)/);
        if (pageMatch) {
          const pid = pageMatch[1];
          return makeJsonResponse(200, {
            id: pid,
            title: `SRS-${pid}`,
            version: { number: 1 },
            body: { storage: { value: `<p>Spec ${pid}</p>` } },
          });
        }
        confluenceListCalls.push(r);
        return makeJsonResponse(200, { results: [] });
      },
    });

    await withForgeMocks({ kvsMock, asUserImpl: makeClient }, async () => {
      // 1. Jira-project mode without spaceId skips /wiki/api/v2/pages list pagination
      const fullRes = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'JQL', callerMode: 'USER' },
        'acc-jql'
      );
      assert.strictEqual(confluenceListCalls.length, 0, 'Must not paginate Confluence pages when spaceId is unset');
      assert.strictEqual(fullRes.confluencePagesScanned, 2);
      assert.deepStrictEqual(
        fullRes.summary.traceLinks.map((l) => l.work.key).sort(),
        ['JQL-1', 'JQL-2']
      );

      // 2. Filtered custom JQL preserves JQL-2 even when truncated=false
      const filteredRes = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'JQL', jql: 'project = "JQL" AND labels = "class-c"', callerMode: 'USER' },
        'acc-jql'
      );
      assert.strictEqual(filteredRes.truncated, false);
      assert.deepStrictEqual(
        filteredRes.summary.traceLinks.map((l) => l.work.key).sort(),
        ['JQL-1', 'JQL-2']
      );
      assert.ok(
        filteredRes.warnings.some((w) => /filtered JQL query scope/i.test(w)),
        `Expected filtered JQL preservation warning, saw: ${JSON.stringify(filteredRes.warnings)}`
      );

      // 3. persistOrClearCursor: if resumedFromCursor=true and enrichment truncates after Jira finished,
      // cursor is retained; if non-resumed sync truncates without nextPageToken, stale cursor is deleted.
      const cursorKey = 'medtrace:ingestion:cursor:JQL';
      await kvsMock.set(cursorKey, {
        nextPageToken: 'tok-resume-1',
        jql: 'project = "JQL" ORDER BY updated DESC',
        projectKey: 'JQL',
        updatedAt: new Date().toISOString(),
      });

      const origDateNow = Date.now;
      let fakeNow = 1_700_000_000_000;
      let searchDone = false;
      Date.now = () => {
        if (searchDone) {
          fakeNow += 20_000; // exceed LIVE_SYNC_BUDGET_MS right when enrichment starts
        }
        return fakeNow;
      };
      try {
        const enrichTruncClient = () => ({
          requestJira: async (routeObj) => {
            const r = String(routeObj?.value || routeObj);
            if (r.includes('/rest/api/3/search/jql')) {
              searchDone = true;
              return makeJsonResponse(200, { issues: activeIssues, isLast: true });
            }
            return makeJsonResponse(200, []);
          },
          requestConfluence: async () => makeJsonResponse(200, { results: [] }),
        });

        await withForgeMocks({ kvsMock, asUserImpl: enrichTruncClient }, async () => {
          const resumedTrunc = await LiveIngestionService.syncFromAtlassian(
            { projectKey: 'JQL', resumeFromCursor: true, callerMode: 'USER' },
            'acc-jql'
          );
          assert.strictEqual(resumedTrunc.truncated, true);
          assert.strictEqual(
            kvsMock.store.get(cursorKey)?.nextPageToken,
            'tok-resume-1',
            'Cursor must be retained when enrichment truncates after resuming'
          );
        });
      } finally {
        Date.now = origDateNow;
      }

      // Non-resumed truncation without nextPageToken (maxIssues: 1 when Jira returns 2 issues in one page) overwrites stale token and tracks overflow key
      const freshTrunc = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'JQL', maxIssues: 1, callerMode: 'USER' },
        'acc-jql'
      );
      assert.strictEqual(freshTrunc.truncated, true);
      assert.strictEqual(freshTrunc.nextPageToken, undefined);
      assert.strictEqual(
        kvsMock.store.get(cursorKey)?.nextPageToken,
        undefined,
        'Stale nextPageToken must be cleared when a fresh sync truncates without a nextPageToken'
      );
      assert.deepStrictEqual(
        kvsMock.store.get(cursorKey)?.pendingIssueKeys,
        ['JQL-2'],
        'Overflowed issues from a non-50-aligned maxIssues slice must be queued in pendingIssueKeys'
      );
    });
  });

  test.it('resolves real Jira issuelinks into native Hazard and Verification Test nodes and syncs avi:jira:updated:issue', async () => {
    const kvsMock = createFullMockForgeKvs();
    const srsBody = '<p>Clause 4.2.1: Bolus limit 5.0 mL/hr</p>';

    const workIssue = {
      id: '10001',
      key: 'MEDTRACE-1',
      self: 'https://api.atlassian.com/ex/jira/11111111-1111-1111-1111-111111111111/rest/api/3/issue/10001',
      fields: {
        summary: 'Implement Bolus Clamp',
        status: { name: 'In Progress', statusCategory: { key: 'indeterminate', name: 'In Progress' } },
        assignee: { displayName: 'Dr. Lin' },
        labels: ['class-c'],
        issuetype: { name: 'Story' },
        project: { key: 'MEDTRACE', name: 'MedTrace Live' },
        issuelinks: [
          {
            type: { name: 'Mitigates', inward: 'is mitigated by', outward: 'mitigates' },
            outwardIssue: {
              id: '10010',
              key: 'MEDTRACE-10',
              fields: {
                summary: 'Over-Infusion Bolus Hazard',
                status: { name: 'Open' },
                issuetype: { name: 'Hazard' },
              },
            },
          },
          {
            type: { name: 'Tests', inward: 'is tested by', outward: 'tests' },
            inwardIssue: {
              id: '10020',
              key: 'MEDTRACE-20',
              fields: {
                summary: 'HIL Over-Infusion Bench Test',
                status: { name: 'To Do' },
                issuetype: { name: 'Test' },
              },
            },
          },
        ],
      },
    };
    const hazardIssue = {
      id: '10010',
      key: 'MEDTRACE-10',
      fields: {
        summary: 'Over-Infusion Bolus Hazard',
        status: { name: 'Open' },
        labels: ['class-c', 'medtrace-hazard'],
        issuetype: { name: 'Hazard' },
        project: { key: 'MEDTRACE', name: 'MedTrace Live' },
        issuelinks: [],
      },
    };
    const testIssue = {
      id: '10020',
      key: 'MEDTRACE-20',
      fields: {
        summary: 'HIL Over-Infusion Bench Test',
        status: { name: 'To Do' },
        labels: ['medtrace-test', 'hil-test'],
        issuetype: { name: 'Test' },
        project: { key: 'MEDTRACE', name: 'MedTrace Live' },
        issuelinks: [],
      },
    };

    let currentWorkStatus = 'In Progress';

    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, { issues: [workIssue, hazardIssue, testIssue], isLast: true });
        }
        if (r.includes('/rest/api/3/issue/MEDTRACE-1/remotelink')) {
          return makeJsonResponse(200, [
            { object: { url: 'https://site.atlassian.net/wiki/spaces/MT/pages/7701', title: 'SRS-201' } },
          ]);
        }
        if (r.includes('/rest/api/3/issue/MEDTRACE-1')) {
          return makeJsonResponse(200, {
            id: '10001',
            key: 'MEDTRACE-1',
            self: workIssue.self,
            fields: {
              ...workIssue.fields,
              status: {
                name: currentWorkStatus,
                statusCategory: { key: currentWorkStatus === 'Done' ? 'done' : 'indeterminate', name: currentWorkStatus },
              },
            },
          });
        }
        return makeJsonResponse(200, []);
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/7701')) {
          return makeJsonResponse(200, {
            id: '7701',
            title: 'SRS-201 Bolus Clamp',
            version: { number: 1, createdAt: '2026-11-10T00:00:00Z' },
            body: { storage: { value: srsBody } },
          });
        }
        return makeJsonResponse(404, {});
      },
    });

    await withForgeMocks({ kvsMock, asUserImpl: mockClient, asAppImpl: mockClient }, async () => {
      const syncRes = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'MEDTRACE', callerMode: 'USER' },
        'acc-native'
      );
      assert.strictEqual(syncRes.success, true);
      assert.strictEqual(
        syncRes.summary.traceLinks.length,
        1,
        'Linked Hazard MEDTRACE-10 and Test MEDTRACE-20 must not emit duplicate standalone trace links'
      );
      const link = syncRes.summary.traceLinks[0];
      assert.strictEqual(link.hazard.key, 'MEDTRACE-10');
      assert.strictEqual(link.hazard.source, 'JIRA_ISSUE');
      assert.strictEqual(link.work.key, 'MEDTRACE-1');
      assert.strictEqual(link.test.testKey, 'MEDTRACE-20');
      assert.strictEqual(link.test.source, 'JIRA_ISSUE');
      assert.strictEqual(link.test.testType, 'Automated HIL (Hardware-in-Loop)');
      assert.ok(link.graphMetadata.hazardAri.includes(':issue/10010'));
      assert.ok(syncRes.summary.lastSyncedAt);

      // Simulate Jira issue transition event (avi:jira:updated:issue) moving MEDTRACE-1 -> Done
      currentWorkStatus = 'Done';
      const triggerRes = await LiveIngestionService.handleJiraIssueUpdated({
        eventType: 'avi:jira:updated:issue',
        issue: { key: 'MEDTRACE-1' },
        atlassianId: 'acc-native',
      });
      assert.strictEqual(triggerRes.processed, true);
      assert.strictEqual(triggerRes.issueKey, 'MEDTRACE-1');
      assert.deepStrictEqual(triggerRes.affectedHazards, ['MEDTRACE-10']);

      const refreshed = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(refreshed.traceLinks[0].work.status, 'Done');
    });
  });

  test.it('handleJiraIssueUpdated upgrades on created issuelink and downgrades/clears removed native Hazard, Test, and Reverification links on deleted issuelink', async () => {
    const kvsMock = createFullMockForgeKvs();

    let workLinks = [];
    const workIssue = {
      id: '10001',
      key: 'MEDTRACE-1',
      self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/10001',
      fields: {
        summary: 'Pump Rate Controller',
        status: { name: 'In Progress', statusCategory: { key: 'indeterminate', name: 'In Progress' } },
        assignee: { displayName: 'Engineer' },
        labels: ['class-c'],
        issuetype: { name: 'Story' },
        project: { key: 'MEDTRACE', name: 'MedTrace' },
      },
    };
    const hazardIssue = {
      id: '10010',
      key: 'MEDTRACE-10',
      self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/10010',
      fields: {
        summary: 'Over-infusion Hazard',
        status: { name: 'Open', statusCategory: { key: 'new', name: 'To Do' } },
        labels: ['class-c', 'medtrace-hazard'],
        issuetype: { name: 'Hazard' },
        project: { key: 'MEDTRACE', name: 'MedTrace' },
        issuelinks: [],
      },
    };
    const testIssue = {
      id: '10020',
      key: 'MEDTRACE-20',
      self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/10020',
      fields: {
        summary: 'HIL Over-infusion Suite',
        status: { name: 'In Progress', statusCategory: { key: 'indeterminate', name: 'In Progress' } },
        labels: ['hil-test', 'medtrace-test'],
        issuetype: { name: 'Test' },
        project: { key: 'MEDTRACE', name: 'MedTrace' },
        issuelinks: [],
      },
    };
    const revIssue = {
      id: '10030',
      key: 'MEDTRACE-30',
      self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/10030',
      fields: {
        summary: '[MedTrace Re-Verification] MEDTRACE-10',
        status: { name: 'To Do', statusCategory: { key: 'new', name: 'To Do' } },
        labels: ['medtrace-reverification'],
        issuetype: { name: 'Task' },
        project: { key: 'MEDTRACE', name: 'MedTrace' },
        issuelinks: [],
      },
    };

    const seedLink = ComplianceEngine.evaluateTraceLink(
      {
        id: 'haz-medtrace-1',
        key: 'HAZ-MEDTRACE-1',
        title: 'Pump Rate Controller',
        riskClass: 'CLASS_C',
        severity: 'CATASTROPHIC',
        probability: 'OCCASIONAL',
        mitigationRequirementId: '7701',
        status: 'ACTION_REQUIRED',
        source: 'APP_MANAGED',
      },
      {
        id: '7701',
        pageId: '7701',
        title: 'SRS-201',
        version: 1,
        sha256Hash: sha256Hex('<p>5.0 mL/hr</p>'),
        lastSignedHash: '',
        isSignatureInvalidated: false,
        contentSnippet: '5.0 mL/hr',
        lastUpdated: '2026-11-10T00:00:00Z',
      },
      { id: '10001', key: 'MEDTRACE-1', title: 'Pump Rate Controller', status: 'In Progress', assignee: 'Engineer' },
      { id: 'test-medtrace-1', testKey: 'TEST-MEDTRACE-1', title: 'Verification Test for MEDTRACE-1', testType: 'Automated HIL (Hardware-in-Loop)', status: 'UNTESTED', source: 'APP_MANAGED' },
      { id: 'sig-1', signedBy: '', signedAt: '', role: 'QA', meaning: '', artifactSha256: '', isValid: false },
      {
        hazardAri: 'ari:cloud:medtrace::iso14971-hazard/HAZ-MEDTRACE-1',
        specAri: 'ari:cloud:confluence::page/7701',
        workAri: 'jira:issue:MEDTRACE-1',
        edgeType: 'mitigates',
        traversalStatus: 'LIVE (JIRA_REST)',
      },
      { linkId: 'link-medtrace-1', requireTestEvidence: true }
    );

    const byRef = (ref) => {
      if (ref === '10001' || ref === 'MEDTRACE-1') {
        return { ...workIssue, fields: { ...workIssue.fields, issuelinks: workLinks } };
      }
      if (ref === '10010' || ref === 'MEDTRACE-10') return hazardIssue;
      if (ref === '10020' || ref === 'MEDTRACE-20') return testIssue;
      if (ref === '10030' || ref === 'MEDTRACE-30') return revIssue;
      return null;
    };

    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        const m = r.match(/\/rest\/api\/3\/issue\/([^?]+)/);
        if (m) {
          const found = byRef(m[1]);
          return found ? makeJsonResponse(200, found) : makeJsonResponse(404, {});
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async () => makeJsonResponse(404, {}),
    });

    await withForgeMocks({ kvsMock, asAppImpl: mockClient }, async () => {
      await SeederService.saveComplianceSuite(
        ComplianceEngine.generateComplianceReport([seedLink], 'LIVE', 'Link Trigger Suite', { initialized: true }),
        0
      );

      // 1. created:issuelink (source=10010 hazard -> destination=10001 work; plus test 10020 & reverification 10030)
      workLinks = [
        { type: { name: 'Mitigates', inward: 'mitigates', outward: 'is mitigated by' }, inwardIssue: hazardIssue },
        { type: { name: 'Verification', inward: 'tests', outward: 'is verified by' }, inwardIssue: testIssue },
        { type: { name: 'Relates', inward: 'relates to', outward: 'relates to' }, inwardIssue: revIssue },
      ];
      const createdRes = await LiveIngestionService.handleJiraIssueUpdated({
        eventType: 'avi:jira:created:issuelink',
        issueLink: { sourceIssueId: '10010', destinationIssueId: '10001' },
        atlassianId: 'acc-trigger',
      });
      assert.strictEqual(createdRes.processed, true);
      let suite = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(suite.traceLinks[0].hazard.key, 'MEDTRACE-10');
      assert.strictEqual(suite.traceLinks[0].hazard.source, 'JIRA_ISSUE');
      assert.strictEqual(suite.traceLinks[0].test.testKey, 'MEDTRACE-20');
      assert.strictEqual(suite.traceLinks[0].test.source, 'JIRA_ISSUE');
      assert.strictEqual(suite.traceLinks[0].reverificationTaskKey, 'MEDTRACE-30');

      // 2. deleted:issuelink (hazard 10010 unlinked, direction source=10010, dest=10001) -> downgrades hazard to APP_MANAGED, keeps MEDTRACE-20
      workLinks = [
        { type: { name: 'Verification', inward: 'tests', outward: 'is verified by' }, inwardIssue: testIssue },
        { type: { name: 'Relates', inward: 'relates to', outward: 'relates to' }, inwardIssue: revIssue },
      ];
      const delHazRes = await LiveIngestionService.handleJiraIssueUpdated({
        eventType: 'avi:jira:deleted:issuelink',
        issueLink: { sourceIssueId: '10010', destinationIssueId: '10001' },
        atlassianId: 'acc-trigger',
      });
      assert.strictEqual(delHazRes.processed, true);
      suite = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(suite.traceLinks[0].hazard.key, 'HAZ-MEDTRACE-1');
      assert.strictEqual(suite.traceLinks[0].hazard.source, 'APP_MANAGED');
      assert.strictEqual(suite.traceLinks[0].test.testKey, 'MEDTRACE-20');
      assert.strictEqual(suite.traceLinks[0].reverificationTaskKey, 'MEDTRACE-30');

      // 3. deleted:issuelink (reverse direction source=10001 work, dest=10020 test; reverification 10030 also removed)
      workLinks = [];
      const delTestRes = await LiveIngestionService.handleJiraIssueUpdated({
        eventType: 'avi:jira:deleted:issuelink',
        issueLink: { sourceIssueId: '10001', destinationIssueId: '10020' },
        atlassianId: 'acc-trigger',
      });
      assert.strictEqual(delTestRes.processed, true);
      suite = await SeederService.getActiveComplianceSuite();
      assert.strictEqual(suite.traceLinks[0].test.testKey, 'TEST-MEDTRACE-1');
      assert.strictEqual(suite.traceLinks[0].test.source, 'APP_MANAGED');
      assert.strictEqual(suite.traceLinks[0].test.status, 'UNTESTED');
      assert.strictEqual(suite.traceLinks[0].reverificationTaskKey, undefined);
    });
  });

  test.it('syncFromAtlassian resumes across multi-page + mid-enrichment timeout, blocks global gate while syncIncomplete, and omits fabricated severity/probability', async () => {
    const kvsMock = createFullMockForgeKvs();
    const page1Issues = [
      {
        id: '20001',
        key: 'RES-1',
        fields: {
          summary: 'Page 1 Issue 1',
          status: { name: 'Done', statusCategory: { key: 'done' } },
          labels: ['class-c'],
          issuetype: { name: 'Story' },
          project: { key: 'RES', name: 'Resume Project' },
          issuelinks: [],
        },
      },
      {
        id: '20002',
        key: 'RES-2',
        fields: {
          summary: 'Page 1 Issue 2',
          status: { name: 'Done', statusCategory: { key: 'done' } },
          labels: ['class-b'],
          issuetype: { name: 'Story' },
          project: { key: 'RES', name: 'Resume Project' },
          issuelinks: [],
        },
      },
      {
        id: '20003',
        key: 'RES-3',
        fields: {
          summary: 'Page 1 Issue 3',
          status: { name: 'Done', statusCategory: { key: 'done' } },
          labels: ['class-a'],
          issuetype: { name: 'Story' },
          project: { key: 'RES', name: 'Resume Project' },
          issuelinks: [],
        },
      },
      {
        id: '20004',
        key: 'RES-4',
        fields: {
          summary: 'Page 1 Issue 4',
          status: { name: 'Done', statusCategory: { key: 'done' } },
          labels: ['class-a'],
          issuetype: { name: 'Story' },
          project: { key: 'RES', name: 'Resume Project' },
          issuelinks: [],
        },
      },
      {
        id: '20005',
        key: 'RES-5',
        fields: {
          summary: 'Page 1 Issue 5',
          status: { name: 'Done', statusCategory: { key: 'done' } },
          labels: ['class-a'],
          issuetype: { name: 'Story' },
          project: { key: 'RES', name: 'Resume Project' },
          issuelinks: [],
        },
      },
      {
        id: '20006',
        key: 'RES-6',
        fields: {
          summary: 'Page 1 Issue 6 (unprocessed on timeout)',
          status: { name: 'Done', statusCategory: { key: 'done' } },
          labels: ['class-c'],
          issuetype: { name: 'Story' },
          project: { key: 'RES', name: 'Resume Project' },
          issuelinks: [],
        },
      },
    ];
    const page2Issues = [
      {
        id: '20007',
        key: 'RES-7',
        fields: {
          summary: 'Page 2 Issue 7',
          status: { name: 'Done', statusCategory: { key: 'done' } },
          labels: ['class-b'],
          issuetype: { name: 'Story' },
          project: { key: 'RES', name: 'Resume Project' },
          issuelinks: [],
        },
      },
    ];

    const origDateNow = Date.now;
    let fakeNow = 1_700_000_000_000;
    let remoteLinksSeen = 0;
    Date.now = () => fakeNow;

    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          if (r.includes('key%20in') || r.includes('key in')) {
            return makeJsonResponse(200, { issues: [page1Issues[5]], isLast: true });
          }
          if (r.includes('nextPageToken=page2-tok')) {
            return makeJsonResponse(200, { issues: page2Issues, isLast: true });
          }
          return makeJsonResponse(200, {
            issues: page1Issues,
            nextPageToken: 'page2-tok',
            isLast: false,
          });
        }
        if (r.includes('/remotelink')) {
          remoteLinksSeen += 1;
          // After first enrichment batch (5 issues -> 5 remotelink calls), trigger budget timeout before batch 2 (RES-6)
          if (remoteLinksSeen >= 5) {
            fakeNow += 20_000;
          }
          return makeJsonResponse(200, [
            {
              object: {
                url: 'https://example.atlassian.net/wiki/spaces/RES/pages/71001/SRS-71001',
                title: 'SRS-71001',
              },
            },
          ]);
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/71001')) {
          return makeJsonResponse(200, {
            id: '71001',
            title: 'SRS-71001: Bolus Limit',
            version: { number: 1, createdAt: '2026-11-20T00:00:00Z' },
            body: { storage: { value: '<p>Limit 5.0 mL/hr</p>' } },
          });
        }
        return makeJsonResponse(200, { results: [] });
      },
    });

    try {
      await withForgeMocks({ kvsMock, asUserImpl: mockClient }, async () => {
        // 1. Initial sync (maxIssues: 6) fetches page 1 + receives page2-tok, times out mid-enrichment before RES-6
        const firstRun = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'RES', maxIssues: 6, callerMode: 'USER' },
          'acc-res'
        );
        assert.strictEqual(firstRun.truncated, true);
        assert.strictEqual(firstRun.summary.syncIncomplete, true);
        assert.deepStrictEqual(
          firstRun.summary.traceLinks.map((l) => l.work.key).sort(),
          ['RES-1', 'RES-2', 'RES-3', 'RES-4', 'RES-5']
        );

        // Ingested live hazards must NOT fabricate severity or probability
        assert.strictEqual(firstRun.summary.traceLinks[0].hazard.severity, undefined);
        assert.strictEqual(firstRun.summary.traceLinks[0].hazard.probability, undefined);

        // Global release gate remains blocked while syncIncomplete === true
        const globalGate = ComplianceEngine.evaluateIssueReleaseGate(undefined, firstRun.summary);
        assert.strictEqual(globalGate.result, false);
        assert.match(globalGate.errorMessage || '', /synchronization is incomplete|Resume Sync/i);

        const savedCursor = kvsMock.store.get('medtrace:ingestion:cursor:RES');
        assert.strictEqual(savedCursor?.nextPageToken, 'page2-tok');
        assert.deepStrictEqual(savedCursor?.pendingIssueKeys, ['RES-6']);

        // 2. Resume Sync finishes pending RES-6 + page 2 RES-7, clears cursor & syncIncomplete
        fakeNow = 1_700_000_000_000;
        remoteLinksSeen = -100; // no timeout on resumed run
        const resumedRun = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'RES', resumeFromCursor: true, callerMode: 'USER' },
          'acc-res'
        );
        assert.strictEqual(resumedRun.truncated, false);
        assert.strictEqual(resumedRun.resumedFromCursor, true);
        assert.strictEqual(resumedRun.summary.syncIncomplete, undefined);
        assert.strictEqual(kvsMock.store.has('medtrace:ingestion:cursor:RES'), false);
        assert.deepStrictEqual(
          resumedRun.summary.traceLinks.map((l) => l.work.key).sort(),
          ['RES-1', 'RES-2', 'RES-3', 'RES-4', 'RES-5', 'RES-6', 'RES-7']
        );

        // 3. Cross-partition Confluence drift reconciliation invalidates signature when Confluence page changes
        const prevSecret = process.env.MEDTRACE_PART11_SECRET;
        process.env.MEDTRACE_PART11_SECRET = 'reconcile-secret-001';
        try {
          const v1Body = '<p>Limit 5.0 mL/hr</p>';
          const v1Hash = sha256Hex(v1Body);
          const signedAt = '2026-11-24T10:00:00Z';
          const seal = ComplianceEngine.computePart11Seal(
            {
              hazardKey: 'HAZ-REC-1',
              specId: '71001',
              artifactSha256: v1Hash,
              signedByAccountId: 'acc-res',
              signedBy: 'QA Lead',
              role: 'QA',
              meaning: 'Approved 5.0',
              signedAt,
              authMethod: 'PART11_ATTESTATION',
            },
            process.env.MEDTRACE_PART11_SECRET
          );
          const cleanLink = ComplianceEngine.evaluateTraceLink(
            { id: 'haz-rec-1', key: 'HAZ-REC-1', title: 'Bolus', riskClass: 'CLASS_C', mitigationRequirementId: '71001', status: 'MITIGATED' },
            { id: '71001', pageId: '71001', title: 'SRS-71001', version: 1, sha256Hash: v1Hash, lastSignedHash: v1Hash, isSignatureInvalidated: false, contentSnippet: 'Limit 5.0 mL/hr', lastUpdated: signedAt },
            { id: 'w-rec-1', key: 'REC-1', title: 'Bolus Work', status: 'Done', assignee: 'Dev' },
            { id: 't-rec-1', testKey: 'TEST-REC-1', title: 'HIL', testType: 'Automated HIL (Hardware-in-Loop)', status: 'PASSED', evidenceUrl: 'https://ci.example/rec-1', executionDate: signedAt },
            { id: 'sig-rec-1', signedBy: 'QA Lead', signedByAccountId: 'acc-res', signedAt, role: 'QA', meaning: 'Approved 5.0', artifactSha256: v1Hash, isValid: true, authMethod: 'PART11_ATTESTATION', signatureAlgorithm: 'HMAC-SHA256-SEAL-V1', signatureSeal: seal },
            undefined,
            { linkId: 'link-rec-1', part11Secret: process.env.MEDTRACE_PART11_SECRET, requireCryptographicSeal: true, requireTestEvidence: true }
          );
          const cleanSuite = ComplianceEngine.generateComplianceReport([cleanLink], 'LIVE', 'Reconcile Project', { initialized: true });
          const { version: currentVer } = await SeederService.getSuiteWithVersion();
          await SeederService.saveComplianceSuite(cleanSuite, currentVer);

          const driftedClient = () => ({
            requestConfluence: async () =>
              makeJsonResponse(200, {
                id: '71001',
                title: 'SRS-71001: Bolus Limit',
                version: { number: 2, createdAt: '2026-11-24T12:00:00Z' },
                body: { storage: { value: '<p>Limit 5.5 mL/hr</p>' } },
              }),
          });
          await withForgeMocks({ kvsMock, asUserImpl: driftedClient }, async () => {
            const reconciled = await LiveIngestionService.reconcileConfluenceSpecs(cleanSuite, {
              actorAccountId: 'acc-res',
            });
            assert.strictEqual(reconciled.traceLinks[0].complianceState, 'SIGNATURE_DRIFT');
            assert.strictEqual(reconciled.traceLinks[0].signature.isValid, false);
            assert.strictEqual(reconciled.traceLinks[0].spec.version, 2);
            assert.strictEqual(reconciled.releaseBlocked, true);
          });
        } finally {
          if (prevSecret === undefined) delete process.env.MEDTRACE_PART11_SECRET;
          else process.env.MEDTRACE_PART11_SECRET = prevSecret;
        }
      });
    } finally {
      Date.now = origDateNow;
    }
  });

  test.it('keeps medtrace-reverification tasks out of Stage 4 link.test and isolates incompleteProjectKeys per Jira project', async () => {
    const kvsMock = createFullMockForgeKvs();
    const specBody = '<p>SRS 81001 Verification Spec</p>';
    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, {
            issues: [
              {
                id: '9001',
                key: 'REVX-1',
                self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/9001',
                fields: {
                  summary: 'Infusion Rate Guard',
                  status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
                  labels: ['class-c'],
                  issuetype: { name: 'Task' },
                  project: { key: 'REVX', name: 'Rev Test' },
                  issuelinks: [
                    {
                      type: { name: 'Relates', inward: 'relates to', outward: 'relates to' },
                      outwardIssue: {
                        id: '9002',
                        key: 'REVX-2',
                        fields: {
                          summary: '[MedTrace Re-Verification] REVX-1',
                          status: { name: 'To Do', statusCategory: { key: 'new', name: 'To Do' } },
                          labels: ['medtrace-reverification'],
                          issuetype: { name: 'Task' },
                        },
                      },
                    },
                    {
                      type: { name: 'Test', inward: 'tested by', outward: 'tests' },
                      outwardIssue: {
                        id: '9003',
                        key: 'REVX-3',
                        fields: {
                          summary: 'HIL Verification Test REVX-3',
                          status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
                          labels: ['medtrace-test'],
                          issuetype: { name: 'Test' },
                        },
                      },
                    },
                  ],
                },
              },
              {
                id: '9002',
                key: 'REVX-2',
                fields: {
                  summary: '[MedTrace Re-Verification] REVX-1',
                  status: { name: 'To Do', statusCategory: { key: 'new', name: 'To Do' } },
                  labels: ['medtrace-reverification'],
                  issuetype: { name: 'Task' },
                  project: { key: 'REVX', name: 'Rev Test' },
                  issuelinks: [],
                },
              },
              {
                id: '9003',
                key: 'REVX-3',
                fields: {
                  summary: 'HIL Verification Test REVX-3',
                  status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
                  labels: ['medtrace-test'],
                  issuetype: { name: 'Test' },
                  project: { key: 'REVX', name: 'Rev Test' },
                  issuelinks: [],
                },
              },
            ],
          });
        }
        if (r.includes('/rest/api/3/issue/REVX-2?')) {
          return makeJsonResponse(200, {
            id: '9002',
            key: 'REVX-2',
            fields: {
              summary: '[MedTrace Re-Verification] REVX-1',
              status: { name: 'To Do' },
              labels: ['medtrace-reverification'],
              issuetype: { name: 'Task' },
              issuelinks: [],
            },
          });
        }
        if (r.includes('/rest/api/3/issue/REVX-3?')) {
          return makeJsonResponse(200, {
            id: '9003',
            key: 'REVX-3',
            fields: {
              summary: 'HIL Verification Test REVX-3',
              status: { name: 'Done' },
              labels: ['medtrace-test'],
              issuetype: { name: 'Test' },
              issuelinks: [],
            },
          });
        }
        if (r.includes('/remotelink')) {
          return makeJsonResponse(200, [
            {
              application: { type: 'com.atlassian.confluence' },
              globalId: 'pageId=81001',
              object: { title: 'SRS-81001', url: 'https://example.atlassian.net/wiki/pages/81001' },
            },
          ]);
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/81001')) {
          return makeJsonResponse(200, {
            id: '81001',
            title: 'SRS-81001',
            version: { number: 1, createdAt: '2026-11-24T00:00:00Z' },
            body: { storage: { value: specBody } },
          });
        }
        return makeJsonResponse(200, { results: [] });
      },
    });

    await withForgeMocks({ kvsMock, asAppImpl: mockClient }, async () => {
      const syncRes = await LiveIngestionService.syncFromAtlassian({ projectKey: 'REVX', callerMode: 'APP' }, 'acc-rev');
      assert.strictEqual(syncRes.summary.traceLinks.length, 1);
      const link = syncRes.summary.traceLinks[0];
      assert.strictEqual(link.reverificationTaskKey, 'REVX-2');
      assert.strictEqual(link.test.testKey, 'REVX-3', 'Re-verification task must NOT hijack Stage 4 link.test');

      // Per-project syncIncomplete isolation via incompleteProjectKeys
      const otherLink = ComplianceEngine.evaluateTraceLink(
        { id: 'haz-p2', key: 'HAZ-P2-1', title: 'Other Hazard', riskClass: 'CLASS_A', mitigationRequirementId: 'p2-spec', status: 'MITIGATED' },
        { id: 'p2-spec', title: 'SRS-P2', version: 1, sha256Hash: sha256Hex('p2'), lastSignedHash: '', isSignatureInvalidated: false, contentSnippet: 'p2', lastUpdated: '2026-11-24T00:00:00Z' },
        { id: 'w-p2', key: 'MED-1', title: 'MED task', status: 'Done', assignee: 'QA' },
        { id: 't-p2', testKey: 'TEST-P2', title: 'Test', testType: 'Unit Test', status: 'PASSED' },
        { id: 'sig-p2', signedBy: 'QA', signedByAccountId: 'acc', signedAt: '2026-11-24T00:00:00Z', role: 'QA', meaning: 'OK', artifactSha256: sha256Hex('p2'), isValid: true }
      );
      const multiSuite = ComplianceEngine.generateComplianceReport([link, otherLink], 'LIVE', 'Multi', {
        initialized: true,
        syncIncomplete: true,
        incompleteProjectKeys: ['REVX'],
      });
      await SeederService.saveComplianceSuite(multiSuite, 1);

      const medScoped = await SeederService.getActiveComplianceSuite({ projectKey: 'MED' });
      const revxScoped = await SeederService.getActiveComplianceSuite({ projectKey: 'REVX' });
      assert.strictEqual(medScoped.syncIncomplete, undefined, 'MED must NOT inherit REVX truncation');
      assert.strictEqual(revxScoped.syncIncomplete, true, 'REVX must retain syncIncomplete: true');
    });
  });

  test.it('reconcileConfluenceSpecs reconciles >20 unique Confluence pages, falls back to asApp on HTTP 403, and uses <=11000ms LIVE_SYNC_BUDGET_MS', async () => {
    const { LIVE_SYNC_BUDGET_MS } = require('../dist/ingestion.js');
    assert.ok(LIVE_SYNC_BUDGET_MS <= 11_000, `Expected LIVE_SYNC_BUDGET_MS <= 11000, got ${LIVE_SYNC_BUDGET_MS}`);

    const kvsMock = createFullMockForgeKvs();
    const specOrig = '<p>signed spec body</p>';
    const specDrifted = '<p>modified after signoff!</p>';
    const shaOrig = sha256Hex(specOrig);
    const links = [];

    for (let i = 1; i <= 25; i++) {
      const pid = String(70000 + i);
      links.push(
        ComplianceEngine.evaluateTraceLink(
          { id: `haz-p25-${i}`, key: `HAZ-P25-${i}`, title: `Haz ${i}`, riskClass: 'CLASS_C', mitigationRequirementId: `srs-${pid}`, status: 'MITIGATED' },
          { id: `srs-${pid}`, pageId: pid, title: `SRS-${pid}`, version: 1, sha256Hash: shaOrig, lastSignedHash: shaOrig, isSignatureInvalidated: false, contentSnippet: 'signed spec body', lastUpdated: '2026-11-24T00:00:00Z' },
          { id: `w-p25-${i}`, key: `MED-${i}`, title: `Work ${i}`, status: 'Done', assignee: 'Alice' },
          { id: `t-p25-${i}`, testKey: `TST-${i}`, title: `Test ${i}`, testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/1', executionDate: '2026-11-24T00:00:00Z' },
          { id: `sig-p25-${i}`, signedBy: 'Alice', signedByAccountId: 'acc-1', signedAt: '2026-11-24T00:00:00Z', role: 'QA', meaning: 'Approved', artifactSha256: shaOrig, isValid: true }
        )
      );
    }

    const userRequests = [];
    const appRequests = [];
    const makeConfluenceMock = (mode) => async (routeObj) => {
      const r = String(routeObj?.value_ || routeObj?.value || routeObj);
      const match = r.match(/\/wiki\/api\/v2\/pages\/(\d+)/);
      const pid = match?.[1] || '';
      if (mode === 'USER') {
        userRequests.push(pid);
        if (pid === '70025') {
          return makeJsonResponse(403, { message: 'User lacks permission, requires app fallback' });
        }
      } else {
        appRequests.push(pid);
      }
      return makeJsonResponse(200, {
        id: pid,
        title: `SRS-${pid}`,
        version: { number: pid === '70025' ? 2 : 1 },
        body: { storage: { value: pid === '70025' ? specDrifted : specOrig } },
      });
    };

    const initialSuite = ComplianceEngine.generateComplianceReport(links, 'LIVE', 'Paginated Reconcile Suite', {
      initialized: true,
    });

    await withForgeMocks(
      {
        kvsMock,
        asUserImpl: () => ({
          requestJira: async () => makeJsonResponse(404, {}),
          requestConfluence: makeConfluenceMock('USER'),
        }),
        asAppImpl: () => ({
          requestJira: async () => makeJsonResponse(404, {}),
          requestConfluence: makeConfluenceMock('APP'),
        }),
      },
      async () => {
        await SeederService.saveComplianceSuite(initialSuite, 0);
        const reconciled = await LiveIngestionService.reconcileConfluenceSpecs(initialSuite, {
          allowAppFallback: true,
          actorAccountId: 'gate-reconcile',
        });
        assert.ok(userRequests.includes('70025'), `Page 25 (70025) must be fetched, saw ${userRequests.length} user fetches`);
        assert.ok(appRequests.includes('70025'), 'HTTP 403 from asUser must fall back to asApp when allowAppFallback: true');
        const link25 = reconciled.traceLinks.find((l) => l.spec.pageId === '70025');
        assert.strictEqual(link25.complianceState, 'SIGNATURE_DRIFT', 'Page 25 drift must be detected');
      }
    );
  });

  test.it('syncFromAtlassian Resume Sync clears syncIncomplete when trailing pages hold 0 safety issues and avoids duplicating linked Hazard issues across pages', async () => {
    const kvsMock = createFullMockForgeKvs();
    const specBody = '<p>SRS-901</p>';

    const workPage1 = {
      id: '9001',
      key: 'TRL-1',
      fields: {
        summary: 'Pump safety control',
        status: { name: 'Done', statusCategory: { key: 'done' } },
        assignee: { displayName: 'Alice' },
        labels: ['class-c'],
        issuetype: { name: 'Task' },
        project: { key: 'TRL', name: 'TRL' },
        issuelinks: [
          {
            type: { name: 'Mitigates', inward: 'mitigated by', outward: 'mitigates' },
            outwardIssue: {
              id: '9002',
              key: 'TRL-2',
              fields: {
                summary: 'Hazard TRL-2',
                status: { name: 'Open' },
                issuetype: { name: 'Hazard' },
                labels: ['class-c', 'medtrace-hazard'],
              },
            },
          },
        ],
      },
    };
    const hazardPage2 = {
      id: '9002',
      key: 'TRL-2',
      fields: {
        summary: 'Hazard TRL-2',
        status: { name: 'Open' },
        issuetype: { name: 'Hazard' },
        labels: ['class-c', 'medtrace-hazard'],
        project: { key: 'TRL', name: 'TRL' },
        issuelinks: [],
      },
    };
    const plainTaskPage2 = {
      id: '9003',
      key: 'TRL-3',
      fields: {
        summary: 'Update README',
        status: { name: 'To Do' },
        issuetype: { name: 'Task' },
        labels: [],
        project: { key: 'TRL', name: 'TRL' },
        issuelinks: [],
      },
    };

    const mockClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/search/jql')) {
          if (r.includes('nextPageToken=page-2')) {
            return makeJsonResponse(200, { issues: [hazardPage2, plainTaskPage2], isLast: true });
          }
          return makeJsonResponse(200, { issues: [workPage1], nextPageToken: 'page-2', isLast: false });
        }
        if (r.includes('/remotelink')) {
          if (r.includes('/TRL-1/')) {
            return makeJsonResponse(200, [
              { object: { url: 'https://site.atlassian.net/wiki/spaces/MED/pages/90101', title: 'SRS-901' } },
            ]);
          }
          return makeJsonResponse(200, []);
        }
        if (r.includes('/rest/api/3/issue/TRL-1')) {
          return makeJsonResponse(200, workPage1);
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/90101')) {
          return makeJsonResponse(200, {
            id: '90101',
            title: 'SRS-901',
            version: { number: 1, createdAt: '2026-11-24T00:00:00Z' },
            body: { storage: { value: specBody } },
          });
        }
        return makeJsonResponse(200, { results: [] });
      },
    });

    await withForgeMocks({ kvsMock, asAppImpl: mockClient }, async () => {
      const first = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'TRL', maxIssues: 1, callerMode: 'APP' },
        'acc-trl'
      );
      assert.strictEqual(first.truncated, true);
      assert.strictEqual(first.summary.syncIncomplete, true);
      assert.strictEqual(first.summary.traceLinks.length, 1);

      const resumed = await LiveIngestionService.syncFromAtlassian(
        { projectKey: 'TRL', maxIssues: 50, resumeFromCursor: true, callerMode: 'APP' },
        'acc-trl'
      );
      assert.strictEqual(resumed.success, true);
      assert.strictEqual(resumed.truncated, false);
      assert.strictEqual(resumed.summary.syncIncomplete, undefined);
      assert.strictEqual(resumed.summary.traceLinks.length, 1, 'Linked Hazard on page 2 must not be duplicated and page 1 link must be preserved');
      assert.strictEqual(resumed.summary.traceLinks[0].work.key, 'TRL-1');
    });
  });

  test.it('reconcileConfluenceSpecs fails closed when drift persistence throws instead of returning stale VERIFIED state', async () => {
    const kvsMock = createFullMockForgeKvs();
    const specOrig = '<p>signed spec</p>';
    const shaOrig = sha256Hex(specOrig);
    const signedLink = ComplianceEngine.evaluateTraceLink(
      { id: 'haz-fc', key: 'HAZ-FC-1', title: 'Fail Closed Haz', riskClass: 'CLASS_C', mitigationRequirementId: 'srs-8001', status: 'MITIGATED' },
      { id: 'srs-8001', pageId: '8001', title: 'SRS-8001', version: 1, sha256Hash: shaOrig, lastSignedHash: shaOrig, isSignatureInvalidated: false, contentSnippet: 'signed spec', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: 'w-fc', key: 'FC-1', title: 'Work FC-1', status: 'Done', assignee: 'Alice' },
      { id: 't-fc', testKey: 'TST-FC-1', title: 'Test FC-1', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/1', executionDate: '2026-11-24T00:00:00Z' },
      { id: 'sig-fc', signedBy: 'Alice', signedByAccountId: 'acc-1', signedAt: '2026-11-24T00:00:00Z', role: 'QA', meaning: 'Approved', artifactSha256: shaOrig, isValid: true }
    );
    const suite = ComplianceEngine.generateComplianceReport([signedLink], 'LIVE', 'Fail Closed Suite', { initialized: true });
    const { reconcileConfluenceSpecsTrigger } = require('../dist/triggers.js');

    await withForgeMocks(
      {
        kvsMock,
        asAppImpl: () => ({
          requestJira: async () => makeJsonResponse(404, {}),
          requestConfluence: async () =>
            makeJsonResponse(200, {
              id: '8001',
              title: 'SRS-8001',
              version: { number: 2 },
              body: { storage: { value: '<p>drifted body</p>' } },
            }),
        }),
      },
      async () => {
        await assert.rejects(
          () =>
            reconcileConfluenceSpecsTrigger(suite, {
              allowAppFallback: true,
              onDriftDetected: async () => {
                throw new Error('CAS conflict persisting drift');
              },
            }),
          /CAS conflict persisting drift/
        );
      }
    );
  });

  test.it('syncFromAtlassian sets syncIncomplete: true when truncated with 0 safety matches on uninitialized workspace', async () => {
    const kvsMock = createFullMockForgeKvs();
    const plainTask = {
      id: '9101',
      key: 'EMP-1',
      fields: {
        summary: 'Plain task without safety labels',
        status: { name: 'To Do' },
        issuetype: { name: 'Task' },
        labels: [],
        project: { key: 'EMP', name: 'EMP' },
        issuelinks: [],
      },
    };

    await withForgeMocks(
      {
        kvsMock,
        asAppImpl: () => ({
          requestJira: async () =>
            makeJsonResponse(200, { issues: [plainTask], nextPageToken: 'emp-page-2', isLast: false }),
          requestConfluence: async () => makeJsonResponse(200, { results: [] }),
        }),
      },
      async () => {
        const res = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'EMP', maxIssues: 1, callerMode: 'APP' },
          'acc-emp'
        );
        assert.strictEqual(res.success, false);
        assert.strictEqual(res.truncated, true);
        assert.strictEqual(res.summary.syncIncomplete, true);
        assert.deepStrictEqual(res.summary.incompleteProjectKeys, ['EMP']);
      }
    );
  });

  test.it('unscoped USER sync preserves unbrowsable project links and scopes shared-spec signature IDs per hazard', async () => {
    const kvsMock = createFullMockForgeKvs();
    const { ComplianceEngine: CE } = require('../dist/compliance-engine.js');
    const sharedBody = '<p>Shared clinical alarm limit 5.0 mL/hr</p>';
    const sharedHash = sha256Hex(sharedBody);

    const hiddenBetaLink = CE.evaluateTraceLink(
      { id: 'haz-beta-1', key: 'HAZ-BETA-1', title: 'Hidden Beta Hazard', riskClass: 'CLASS_C', mitigationRequirementId: '9100', status: 'ACTION_REQUIRED' },
      { id: '9100', pageId: '9100', title: 'SRS-9100', version: 1, sha256Hash: sharedHash, lastSignedHash: '', isSignatureInvalidated: false, contentSnippet: 'Shared spec', lastUpdated: '2026-11-24T00:00:00Z' },
      { id: '2001', key: 'BETA-1', title: 'Hidden Beta Work', status: 'In Progress', assignee: 'Bob' },
      { id: 'test-beta-1', testKey: 'TEST-BETA-1', title: 'Beta Test', testType: 'Unit Test', status: 'UNTESTED' },
      { id: 'sig-HAZ-BETA-1--9100', signedBy: '', signedAt: '', role: 'QA', meaning: 'Pending', artifactSha256: '', isValid: false },
      undefined,
      { linkId: 'live-beta-1-9100' }
    );
    const seedSuite = CE.generateComplianceReport([hiddenBetaLink], 'LIVE', 'Multi-Project Workspace', {
      initialized: true,
    });

    const alfaIssue = {
      id: '1001',
      key: 'ALFA-1',
      self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/1001',
      fields: {
        summary: 'Alfa Pump Task',
        status: { name: 'In Progress', statusCategory: { key: 'indeterminate', name: 'In Progress' } },
        labels: ['class-c'],
        issuetype: { name: 'Task' },
        project: { key: 'ALFA', name: 'Alfa Project' },
        issuelinks: [],
      },
    };
    const gammaIssue = {
      id: '3001',
      key: 'GAMMA-1',
      self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/3001',
      fields: {
        summary: 'Gamma Valve Task',
        status: { name: 'In Progress', statusCategory: { key: 'indeterminate', name: 'In Progress' } },
        labels: ['class-b'],
        issuetype: { name: 'Task' },
        project: { key: 'GAMMA', name: 'Gamma Project' },
        issuelinks: [],
      },
    };

    const userClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.startsWith('/rest/api/3/mypermissions')) {
          const isBeta = r.includes('projectKey=BETA');
          return makeJsonResponse(200, {
            permissions: { BROWSE_PROJECTS: { havePermission: !isBeta } },
          });
        }
        if (r.startsWith('/rest/api/3/search/jql')) {
          return makeJsonResponse(200, { issues: [alfaIssue, gammaIssue], isLast: true });
        }
        if (r.includes('/rest/api/3/issue/ALFA-1/remotelink') || r.includes('/rest/api/3/issue/GAMMA-1/remotelink')) {
          return makeJsonResponse(200, [
            { object: { url: 'https://site.atlassian.net/wiki/spaces/MED/pages/9100', title: 'SRS-9100' } },
          ]);
        }
        return makeJsonResponse(404, {});
      },
      requestConfluence: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.includes('/wiki/api/v2/pages/9100')) {
          return makeJsonResponse(200, {
            id: '9100',
            title: 'SRS-9100',
            version: { number: 1, createdAt: '2026-11-24T00:00:00Z' },
            body: { storage: { value: sharedBody } },
          });
        }
        return makeJsonResponse(404, {});
      },
    });

    await withForgeMocks({ kvsMock, asUserImpl: userClient, asAppImpl: userClient }, async () => {
      await SeederService.saveComplianceSuite(seedSuite, 0);
      const syncRes = await LiveIngestionService.syncFromAtlassian({ callerMode: 'USER' }, 'acc-alfa');
      assert.strictEqual(syncRes.success, true);

      const keys = syncRes.summary.traceLinks.map((l) => l.work.key).sort();
      assert.deepStrictEqual(keys, ['ALFA-1', 'BETA-1', 'GAMMA-1']);
      assert.strictEqual(syncRes.summary.projectName, 'Multi-Project Workspace');

      const alfaSig = syncRes.summary.traceLinks.find((l) => l.work.key === 'ALFA-1').signature.id;
      const gammaSig = syncRes.summary.traceLinks.find((l) => l.work.key === 'GAMMA-1').signature.id;
      assert.notStrictEqual(alfaSig, gammaSig);
      assert.match(alfaSig, /^sig-HAZ-ALFA-1--srs-9100$/);
      assert.match(gammaSig, /^sig-HAZ-GAMMA-1--srs-9100$/);
    });
  });

  test.it('handleJiraIssueUpdated fails closed (CLASS_C, safetyClassAssigned: false) when safety labels are removed from native Jira Hazard', async () => {
    const kvsMock = createFullMockForgeKvs();
    const { ComplianceEngine: CE } = require('../dist/compliance-engine.js');
    const seedLink = CE.evaluateTraceLink(
      {
        id: '10010',
        key: 'MED-10',
        title: 'Over-infusion Hazard',
        riskClass: 'CLASS_B',
        mitigationRequirementId: '7701',
        status: 'ACTION_REQUIRED',
        source: 'JIRA_ISSUE',
      },
      {
        id: '7701',
        pageId: '7701',
        title: 'SRS-7701',
        version: 1,
        sha256Hash: 'a'.repeat(64),
        lastSignedHash: '',
        isSignatureInvalidated: false,
        contentSnippet: 'Spec',
        lastUpdated: '2026-11-24T00:00:00Z',
      },
      { id: '10001', key: 'MED-1', title: 'Pump Driver', status: 'Done', assignee: 'Alice' },
      { id: 'test-med-1', testKey: 'TEST-MED-1', title: 'HIL Test', testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/1', executionDate: '2026-11-24T00:00:00Z' },
      { id: 'sig-1', signedBy: '', signedAt: '', role: 'QA', meaning: 'Pending', artifactSha256: '', isValid: false },
      undefined,
      { linkId: 'link-native-label-removal' }
    );
    const seedSuite = CE.generateComplianceReport([seedLink], 'LIVE', 'Native Label Suite', { initialized: true });

    const appClient = () => ({
      requestJira: async (routeObj) => {
        const r = String(routeObj?.value_ || routeObj?.value || routeObj);
        if (r.includes('/rest/api/3/issue/MED-10')) {
          return makeJsonResponse(200, {
            id: '10010',
            key: 'MED-10',
            fields: {
              summary: 'Over-infusion Hazard',
              status: { name: 'Open' },
              labels: [],
              issuetype: { name: 'Hazard' },
              issuelinks: [{ outwardIssue: { key: 'MED-1' } }],
            },
          });
        }
        if (r.includes('/rest/api/3/issue/MED-1')) {
          return makeJsonResponse(200, {
            id: '10001',
            key: 'MED-1',
            fields: {
              summary: 'Pump Driver',
              status: { name: 'Done', statusCategory: { key: 'done', name: 'Done' } },
              labels: [],
              issuetype: { name: 'Task' },
              issuelinks: [],
            },
          });
        }
        return makeJsonResponse(404, {});
      },
    });

    await withForgeMocks({ kvsMock, asAppImpl: appClient }, async () => {
      await SeederService.saveComplianceSuite(seedSuite, 0);
      const triggerRes = await LiveIngestionService.handleJiraIssueUpdated({
        eventType: 'avi:jira:updated:issue',
        issue: { key: 'MED-10' },
        atlassianId: 'acc-haz-editor',
      });
      assert.strictEqual(triggerRes.processed, true);
      const updated = await SeederService.getActiveComplianceSuite();
      const link = updated.traceLinks[0];
      assert.strictEqual(link.hazard.riskClass, 'CLASS_C');
      assert.strictEqual(link.hazard.safetyClassAssigned, false);
      assert.notStrictEqual(link.complianceState, 'VERIFIED');
      assert.ok(link.violations.some((v) => /no software safety class label/i.test(v)));
    });
  });

  test.it('reconcileConfluenceSpecsTrigger throws fail-closed when failClosedOnBudget is true and time budget is exceeded', async () => {
    const kvsMock = createFullMockForgeKvs();
    const { ComplianceEngine: CE } = require('../dist/compliance-engine.js');
    const { reconcileConfluenceSpecsTrigger } = require('../dist/triggers.js');
    const links = Array.from({ length: 6 }, (_, idx) => {
      const pageId = String(8100 + idx);
      return CE.evaluateTraceLink(
        { id: `haz-${idx}`, key: `HAZ-${idx}`, title: `Hazard ${idx}`, riskClass: 'CLASS_C', mitigationRequirementId: pageId, status: 'MITIGATED' },
        { id: pageId, pageId, title: `SRS-${pageId}`, version: 1, sha256Hash: sha256Hex(`<p>body ${idx}</p>`), lastSignedHash: sha256Hex(`<p>body ${idx}</p>`), isSignatureInvalidated: false, contentSnippet: 'Spec', lastUpdated: '2026-11-24T00:00:00Z' },
        { id: `w-${idx}`, key: `MED-${idx}`, title: `Work ${idx}`, status: 'Done', assignee: 'Alice' },
        { id: `t-${idx}`, testKey: `TST-${idx}`, title: `Test ${idx}`, testType: 'Unit Test', status: 'PASSED', evidenceUrl: 'https://ci.example/1', executionDate: '2026-11-24T00:00:00Z' },
        { id: `sig-${idx}`, signedBy: 'Alice', signedAt: '2026-11-24T00:00:00Z', role: 'QA', meaning: 'Approved', artifactSha256: sha256Hex(`<p>body ${idx}</p>`), isValid: true },
        undefined,
        { linkId: `link-budget-${idx}` }
      );
    });
    const suite = CE.generateComplianceReport(links, 'LIVE', 'Budget Gate Suite', { initialized: true });

    const origDateNow = Date.now;
    let fakeClock = 1_000_000;
    let batchReads = 0;
    Date.now = () => {
      fakeClock += batchReads > 0 ? 10_000 : 1;
      return fakeClock;
    };

    try {
      await withForgeMocks(
        {
          kvsMock,
          asAppImpl: () => ({
            requestJira: async () => makeJsonResponse(404, {}),
            requestConfluence: async (routeObj) => {
              batchReads += 1;
              const m = String(routeObj?.value_ || routeObj).match(/pages\/(\d+)/);
              const idx = Number(m?.[1] || 8100) - 8100;
              return makeJsonResponse(200, {
                id: String(8100 + idx),
                title: `SRS-${8100 + idx}`,
                version: { number: 1 },
                body: { storage: { value: `<p>body ${idx}</p>` } },
              });
            },
          }),
        },
        async () => {
          await assert.rejects(
            () =>
              reconcileConfluenceSpecsTrigger(suite, {
                allowAppFallback: true,
                failClosedOnBudget: true,
              }),
            /budget.*exhausted/i
          );
        }
      );
    } finally {
      Date.now = origDateNow;
    }
  });

  test.it('prunes deleted scoped projects, classifies unlabeled [MedTrace Re-Verification] stubs as reverificationTaskKey, and skips redundant /issue calls', async () => {
    const kvsMock = createFullMockForgeKvs();
    const issueDetailCalls = [];
    let alfaDeleted = false;
    let betaDeleted = false;

    await withForgeMocks(
      {
        kvsMock,
        asAppImpl: () => ({
          requestJira: async (routeObj) => {
            const r = String(routeObj?.value_ || routeObj);
            if (r.includes('/rest/api/3/search/jql')) {
              if (r.includes('ALFA')) {
                if (alfaDeleted) {
                  return makeJsonResponse(200, { issues: [], isLast: true });
                }
                return makeJsonResponse(200, {
                  issues: [
                    {
                      id: '101',
                      key: 'ALFA-1',
                      self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/101',
                      fields: {
                        summary: 'Infusion Valve Control',
                        status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
                        labels: ['class-c'],
                        issuetype: { name: 'Task' },
                        project: { key: 'ALFA', name: 'Alfa Project' },
                        issuelinks: [
                          {
                            type: { name: 'Tests', inward: 'tested by', outward: 'tests' },
                            outwardIssue: {
                              id: '909',
                              key: 'ALFA-9',
                              fields: {
                                summary: '[MedTrace Re-Verification] HAZ-ALFA-1: Valve Control',
                                issuetype: { name: 'Task' },
                              },
                            },
                          },
                        ],
                      },
                    },
                  ],
                  isLast: true,
                });
              }
              if (r.includes('BETA')) {
                if (betaDeleted) {
                  return makeJsonResponse(200, { issues: [], isLast: true });
                }
                return makeJsonResponse(200, {
                  issues: [
                    {
                      id: '201',
                      key: 'BETA-1',
                      self: 'https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/201',
                      fields: {
                        summary: 'Battery Monitor',
                        status: { name: 'In Progress', statusCategory: { name: 'In Progress' } },
                        labels: ['class-b'],
                        issuetype: { name: 'Task' },
                        project: { key: 'BETA', name: 'Beta Project' },
                        issuelinks: [],
                      },
                    },
                  ],
                  isLast: true,
                });
              }
            }
            if (r.includes('/remotelink')) {
              return makeJsonResponse(200, []);
            }
            if (r.includes('/rest/api/3/issue/')) {
              issueDetailCalls.push(r);
              return makeJsonResponse(200, {});
            }
            return makeJsonResponse(404, {});
          },
          requestConfluence: async () => makeJsonResponse(200, { results: [] }),
        }),
      },
      async () => {
        const resA = await LiveIngestionService.syncFromAtlassian({ projectKey: 'ALFA', callerMode: 'APP' }, 'acc-1');
        assert.strictEqual(resA.success, true);
        assert.strictEqual(issueDetailCalls.length, 0, 'syncFromAtlassian should skip redundant /rest/api/3/issue/{key} calls');
        assert.strictEqual(resA.summary.traceLinks[0].reverificationTaskKey, 'ALFA-9');
        assert.strictEqual(resA.summary.traceLinks[0].test.testKey, 'TEST-ALFA-1');

        const resB = await LiveIngestionService.syncFromAtlassian({ projectKey: 'BETA', callerMode: 'APP' }, 'acc-1');
        assert.deepStrictEqual(resB.summary.traceLinks.map((l) => l.work.key).sort(), ['ALFA-1', 'BETA-1']);

        // Delete ALFA-1 -> scoped sync ALFA prunes ALFA-1 while preserving BETA-1
        alfaDeleted = true;
        const prunedA = await LiveIngestionService.syncFromAtlassian({ projectKey: 'ALFA', callerMode: 'APP' }, 'acc-1');
        assert.strictEqual(prunedA.success, true);
        assert.deepStrictEqual(prunedA.summary.traceLinks.map((l) => l.work.key), ['BETA-1']);

        // Delete BETA-1 -> scoped sync BETA prunes last link and resets to uninitialized LIVE
        betaDeleted = true;
        const prunedB = await LiveIngestionService.syncFromAtlassian({ projectKey: 'BETA', callerMode: 'APP' }, 'acc-1');
        assert.strictEqual(prunedB.success, true);
        assert.strictEqual(prunedB.summary.initialized, false);
        assert.strictEqual(prunedB.summary.traceLinks.length, 0);
      }
    );
  });
});
