const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const forgeApi = require('@forge/api');
const forgeKvs = require('@forge/kvs');
const { ComplianceEngine } = require('../dist/compliance-engine');
const { AuditLogService, setAuditStorageAdapter, resetInMemoryAuditStorage } = require('../dist/audit-log');
const seederMod = require('../dist/seeder');
const { SeederService } = seederMod;
const { TeamworkGraphService, resolveCloudId } = require('../dist/teamwork-graph');
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
      requestGraph: async () =>
        makeJsonResponse(200, {
          data: {
            jira: {
              issue: {
                id: 'ari:cloud:jira:12345678-1234-1234-1234-1234567890ab:issue/10901',
                key: 'MED-901',
                summary: 'Watchdog Clamp (AGG)',
                status: { name: 'Done', category: 'Done' },
                links: [
                  { id: 'agg-1', type: { name: 'Blocks', inward: 'is blocked by', outward: 'blocks' } },
                  { id: 42, type: { name: 'Relates' } },
                ],
              },
            },
          },
        }),
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
        assert.strictEqual(defaultRes.source, 'JIRA_AGG_AND_REST');
        assert.strictEqual(defaultRes.confluenceSource, 'JIRA_REMOTELINK_REST');
        assert.deepStrictEqual(defaultRes.aggIssueLinks, [
          { id: 'agg-1', type: { name: 'Blocks', inward: 'is blocked by', outward: 'blocks' } },
          { id: '42', type: { name: 'Relates' } },
        ]);

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
        assert.strictEqual(appRes.source, 'JIRA_AGG_AND_REST');
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
      requestGraph: async () => makeJsonResponse(500, {}),
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
      requestGraph: async () => makeJsonResponse(500, {}),
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
        requestGraph: async () => makeJsonResponse(500, {}),
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
      requestGraph: async () =>
        makeJsonResponse(200, {
          data: { jira: { issue: { id: 'ari:1', key: 'MN-1', summary: 'x', status: { name: 'Done' }, links: [] } } },
        }),
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
        assert.strictEqual(mn1Links[0].graphMetadata.aggTraversalStatus, 'LIVE (JIRA_AGG_AND_REST)');

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
      requestGraph: async () => makeJsonResponse(500, {}),
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
      requestGraph: async () => makeJsonResponse(500, {}),
    });

    await withForgeMocks({ kvsMock, asUserImpl: warnClient }, async () => {
      const res = await LiveIngestionService.syncFromAtlassian({ projectKey: 'WARN' }, 'acc-warn');
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
      requestGraph: async () => makeJsonResponse(500, {}),
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
              passwordConfirmed: true,
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
            passwordConfirmed: true,
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

  test.it('short-circuits /issue and AGG calls on untagged issues without Confluence links and preserves unreached/other-project LIVE links', async () => {
    const kvsMock = createFullMockForgeKvs();
    const issueDetailCalls = [];
    const graphCalls = [];

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
          // Untagged ALFA-2 has no Confluence links -> should short-circuit /issue and AGG calls
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
      requestGraph: async () => {
        graphCalls.push('called');
        return makeJsonResponse(200, { data: {} });
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

      // ALFA-2 short-circuited: neither /rest/api/3/issue/ALFA-2 nor AGG requestGraph was called
      assert.ok(
        !issueDetailCalls.some((u) => u.includes('ALFA-2')),
        `Untagged ALFA-2 should short-circuit /issue fetch, saw: ${JSON.stringify(issueDetailCalls)}`
      );
      assert.strictEqual(graphCalls.length, 1, 'Only ALFA-1 should hit AGG requestGraph');

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
      requestGraph: async () => makeJsonResponse(200, { data: {} }),
    });

    try {
      const mockClient = makeMockClient();
      await withForgeMocks({ kvsMock, asAppImpl: () => mockClient }, async () => {
        // Seed a hybrid ECDSA P-256 baseline for CUR-1 / SRS 91001 so live sync re-hydration can be verified too
        const kp = ComplianceEngine.generateEcdsaP256KeyPair();
        const specHash = sha256Hex('<p>srs body for 91001</p>');
        const meaning = 'Initial hybrid signoff';
        const challenge = ComplianceEngine.computePart11ClientChallenge({
          hazardKey: 'HAZ-CUR-1',
          specId: 'srs-91001',
          artifactSha256: specHash,
          meaning,
        });
        const clientSig = ComplianceEngine.signPart11ClientChallenge(challenge, kp.privateKeyPkcs8Base64);
        const signedAt = '2026-11-15T00:00:00.000Z';
        const seal = ComplianceEngine.computePart11Seal(
          {
            hazardKey: 'HAZ-CUR-1',
            specId: 'srs-91001',
            artifactSha256: specHash,
            signedByAccountId: 'acc-ecdsa-live',
            signedBy: 'Dr. Live ECDSA',
            role: 'Authorized Atlassian User',
            meaning,
            signedAt,
            authMethod: 'PART11_ATTESTATION',
            signatureAlgorithm: 'ECDSA-P256-SHA256+HMAC-SEAL-V1',
            clientPublicKeySpki: kp.publicKeySpkiBase64,
            clientSignatureBase64: clientSig,
          },
          'cursor-ecdsa-secret'
        );
        await SeederService.setSignedSpecBaseline({
          hazardKey: 'HAZ-CUR-1',
          specId: 'srs-91001',
          pageId: '91001',
          sha256Hash: specHash,
          signedBy: 'Dr. Live ECDSA',
          signedByAccountId: 'acc-ecdsa-live',
          signedAt,
          role: 'Authorized Atlassian User',
          meaning,
          authMethod: 'PART11_ATTESTATION',
          signatureAlgorithm: 'ECDSA-P256-SHA256+HMAC-SEAL-V1',
          signatureSeal: seal,
          sealKeyId: 'env:MEDTRACE_PART11_SECRET',
          clientPublicKeySpki: kp.publicKeySpkiBase64,
          clientSignatureBase64: clientSig,
          clientKeyFingerprint: kp.keyFingerprint,
        });

        // Invocation 1: exact page-size cap maxIssues: 2 -> truncates and persists cursor-tok-2
        const pass1 = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'CUR', maxIssues: 2, callerMode: 'APP' },
          'acc-cur'
        );
        assert.strictEqual(pass1.truncated, true);
        assert.strictEqual(pass1.nextPageToken, 'cursor-tok-2');
        assert.strictEqual(pass1.resumedFromCursor, undefined);
        const savedCursor = kvsMock.store.get('medtrace:ingestion:cursor:CUR');
        assert.strictEqual(savedCursor?.nextPageToken, 'cursor-tok-2');

        const cur1Link = pass1.summary.traceLinks.find((l) => l.work.key === 'CUR-1');
        assert.ok(cur1Link, 'Expected CUR-1 link in pass1');
        assert.strictEqual(cur1Link.signature.signatureAlgorithm, 'ECDSA-P256-SHA256+HMAC-SEAL-V1');
        assert.strictEqual(cur1Link.signature.clientKeyFingerprint, kp.keyFingerprint);
        assert.strictEqual(cur1Link.signature.isValid, true);
        assert.strictEqual(pass1.driftDetectedCount, 0);

        // Invocation 2: resumeFromCursor: true reads cursor-tok-2 from KVS, merges CUR-1/CUR-2 + CUR-3, and deletes cursor
        const pass2 = await LiveIngestionService.syncFromAtlassian(
          { projectKey: 'CUR', maxIssues: 2, resumeFromCursor: true, callerMode: 'APP' },
          'acc-cur'
        );
        assert.strictEqual(pass2.truncated, false);
        assert.strictEqual(pass2.nextPageToken, undefined);
        assert.strictEqual(pass2.resumedFromCursor, true);
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
});
