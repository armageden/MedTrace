const test = require('node:test');
const assert = require('node:assert/strict');
const forgeApi = require('@forge/api');
const { LiveProofScenarioService } = require('../dist/live-proof-scenario.js');
const { LiveIngestionService } = require('../dist/ingestion.js');
const { AuditLogService } = require('../dist/audit-log.js');
const { resolverHandler } = require('../dist/index.js');

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

function parseBody(opts) {
  return JSON.parse(String(opts?.body || '{}'));
}

function makeSummaryForWork(workKey) {
  return {
    datasetMode: 'LIVE',
    initialized: true,
    traceLinks: [{ work: { key: workKey } }],
    warnings: [],
  };
}

async function withLiveProofMocks(handlers, fn) {
  const apiDefault = forgeApi.default || forgeApi;
  const origDefaultAsUser = apiDefault.asUser;
  const origTopAsUser = forgeApi.asUser;
  const origSync = LiveIngestionService.syncFromAtlassian;
  const origAuditAppend = AuditLogService.append;
  const hadRuntime = Object.prototype.hasOwnProperty.call(globalThis, '__forge_runtime__');
  const oldRuntime = globalThis.__forge_runtime__;

  const calls = {
    jira: [],
    confluence: [],
    pageCreates: [],
    issueCreates: [],
    issueLinks: [],
    remoteLinks: [],
    syncOptions: null,
    auditEntries: [],
  };

  const requestJira =
    handlers.requestJira ||
    (async (url, opts) => {
      if (url.startsWith('/rest/api/3/mypermissions')) {
        return makeHttpResponse(200, {
          permissions: {
            CREATE_ISSUES: { havePermission: true },
            EDIT_ISSUES: { havePermission: true },
            LINK_ISSUES: { havePermission: true },
            ADMINISTER_PROJECTS: { havePermission: false },
          },
        });
      }
      if (url === '/rest/api/3/issue' && opts?.method === 'POST') {
        const sequence = ['MED-101', 'MED-102', 'MED-103'];
        const key = sequence[calls.issueCreates.length];
        calls.issueCreates.push(parseBody(opts));
        return makeHttpResponse(201, {
          id: String(1000 + calls.issueCreates.length),
          key,
          self: `https://medtrace.atlassian.net/rest/api/3/issue/${1000 + calls.issueCreates.length}`,
        });
      }
      if (url === '/rest/api/3/issueLink' && opts?.method === 'POST') {
        calls.issueLinks.push(parseBody(opts));
        return makeHttpResponse(204, {});
      }
      if (url === '/rest/api/3/issue/MED-103/remotelink' && opts?.method === 'POST') {
        calls.remoteLinks.push(parseBody(opts));
        return makeHttpResponse(201, { id: 44 });
      }
      return makeHttpResponse(404, { error: `Unmocked Jira route ${url}` });
    });

  const requestConfluence =
    handlers.requestConfluence ||
    (async (url, opts) => {
      if (/^\/wiki\/api\/v2\/spaces\/\d+\/operations/.test(url)) {
        return makeHttpResponse(200, { operations: [{ operation: 'create', targetType: 'page' }] });
      }
      if (url.includes('/wiki/api/v2/spaces')) {
        return makeHttpResponse(200, { results: [{ id: '555', key: 'MED' }] });
      }
      if (url === '/wiki/api/v2/pages' && opts?.method === 'POST') {
        calls.pageCreates.push(parseBody(opts));
        return makeHttpResponse(200, {
          id: '987',
          title: parseBody(opts).title,
          _links: {
            base: 'https://medtrace.atlassian.net/wiki',
            webui: '/spaces/MED/pages/987/SRS',
          },
        });
      }
      return makeHttpResponse(404, { error: `Unmocked Confluence route ${url}` });
    });

  const mockAsUser = () => ({
    requestJira: async (url, opts) => {
      const asString = routeToString(url);
      calls.jira.push({ url: asString, opts });
      return requestJira(asString, opts);
    },
    requestConfluence: async (url, opts) => {
      const asString = routeToString(url);
      calls.confluence.push({ url: asString, opts });
      return requestConfluence(asString, opts);
    },
  });

  globalThis.__forge_runtime__ = true;
  apiDefault.asUser = mockAsUser;
  forgeApi.asUser = mockAsUser;
  LiveIngestionService.syncFromAtlassian = async (options, actorAccountId) => {
    calls.syncOptions = { ...options, actorAccountId };
    return {
      success: true,
      datasetMode: 'LIVE',
      jiraIssuesScanned: 3,
      confluencePagesScanned: 1,
      linkedPairsFound: 1,
      driftDetectedCount: 0,
      warnings: [],
      summary: makeSummaryForWork('MED-103'),
    };
  };
  AuditLogService.append = async (entry) => {
    calls.auditEntries.push(entry);
    return { ...entry, seq: 1, entryHash: 'hash' };
  };

  try {
    return await fn(calls);
  } finally {
    apiDefault.asUser = origDefaultAsUser;
    forgeApi.asUser = origTopAsUser;
    LiveIngestionService.syncFromAtlassian = origSync;
    AuditLogService.append = origAuditAppend;
    if (hadRuntime) {
      globalThis.__forge_runtime__ = oldRuntime;
    } else {
      delete globalThis.__forge_runtime__;
    }
  }
}

test('live proof scenario creates and links real artifacts, syncs exact keys, and appends audit evidence', async () => {
  await withLiveProofMocks({}, async (calls) => {
    const result = await LiveProofScenarioService.createScenario({
      projectKey: 'med',
      actorAccountId: 'user-1',
    });

    assert.equal(result.success, true);
    assert.equal(result.projectKey, 'MED');
    assert.equal(result.spaceId, '555');
    assert.equal(result.pageId, '987');
    assert.equal(result.hazardIssueKey, 'MED-101');
    assert.equal(result.testIssueKey, 'MED-102');
    assert.equal(result.workIssueKey, 'MED-103');
    assert.equal(result.remoteLinkCreated, true);
    assert.deepEqual(result.issueLinksCreated, ['MED-101->MED-103', 'MED-102->MED-103']);

    assert.equal(calls.pageCreates.length, 1);
    assert.equal(calls.pageCreates[0].spaceId, '555');
    assert.match(calls.pageCreates[0].body.value, /5\.0 mL\/hr/);
    assert.match(calls.pageCreates[0].body.value, /Edit 5\.0 to 5\.5 mL\/hr/);

    assert.equal(calls.issueCreates.length, 3);
    assert.deepEqual(calls.issueCreates[0].fields.labels, ['medtrace-live-proof', 'medtrace-hazard', 'class-c']);
    assert.deepEqual(calls.issueCreates[1].fields.labels, ['medtrace-live-proof', 'medtrace-test', 'hil-test', 'class-c']);
    assert.deepEqual(calls.issueCreates[2].fields.labels, ['medtrace-live-proof', 'class-c']);
    assert.equal(calls.issueCreates[0].fields.project.key, 'MED');
    assert.equal(calls.issueCreates[0].fields.description.type, 'doc');

    assert.equal(calls.issueLinks.length, 2);
    assert.equal(calls.issueLinks[0].type.name, 'Relates');
    assert.equal(calls.issueLinks[0].inwardIssue.key, 'MED-101');
    assert.equal(calls.issueLinks[0].outwardIssue.key, 'MED-103');

    assert.equal(calls.remoteLinks.length, 1);
    assert.equal(calls.remoteLinks[0].globalId, 'pageId=987');
    assert.equal(
      calls.remoteLinks[0].object.url,
      'https://medtrace.atlassian.net/wiki/spaces/MED/pages/987/SRS'
    );
    assert.equal(calls.remoteLinks[0].object.title, result.pageTitle);

    assert.equal(calls.syncOptions.projectKey, 'MED');
    assert.equal(calls.syncOptions.spaceId, undefined);
    assert.equal(calls.syncOptions.jql, 'key in ("MED-101", "MED-102", "MED-103")');
    assert.equal(calls.syncOptions.callerMode, 'USER');
    assert.equal(calls.syncOptions.actorAccountId, 'user-1');

    assert.equal(calls.auditEntries.length, 1);
    assert.equal(calls.auditEntries[0].action, 'CREATE_LIVE_PROOF_SCENARIO');
    assert.equal(calls.auditEntries[0].targetKey, 'MED-103');
    assert.equal(calls.auditEntries[0].details.ingested, true);
  });
});

test('live proof falls back to the first readable global space when no project-key space exists', async () => {
  const spaceQueries = [];
  await withLiveProofMocks(
    {
      requestConfluence: async (url, opts) => {
        if (/^\/wiki\/api\/v2\/spaces\/\d+\/operations/.test(url)) {
          return makeHttpResponse(200, { operations: [{ operation: 'create', targetType: 'page' }] });
        }
        if (url.includes('/wiki/api/v2/spaces')) {
          spaceQueries.push(url);
          if (url.includes('keys=')) return makeHttpResponse(200, { results: [] });
          if (url === '/wiki/api/v2/spaces?type=global&limit=1') {
            return makeHttpResponse(200, { results: [{ id: '777', key: 'EVAL' }] });
          }
          return makeHttpResponse(400, { error: 'bad spaces query' });
        }
        if (url === '/wiki/api/v2/pages' && opts?.method === 'POST') {
          return makeHttpResponse(200, {
            id: '987',
            title: parseBody(opts).title,
            _links: {
              base: 'https://medtrace.atlassian.net/wiki',
              webui: '/spaces/EVAL/pages/987/SRS',
            },
          });
        }
        return makeHttpResponse(404, { error: `Unmocked Confluence route ${url}` });
      },
    },
    async () => {
      const result = await LiveProofScenarioService.createScenario({
        projectKey: 'MED',
        actorAccountId: 'user-1',
      });
      assert.equal(result.spaceId, '777');
      assert.ok(spaceQueries.includes('/wiki/api/v2/spaces?type=global&limit=1'));
      assert.ok(!spaceQueries.some((url) => url.includes('%26') || url.includes('%3D')));
    }
  );
});

test('createLiveProofScenario resolver enforces operator RBAC and forwards the Jira project context', async () => {
  await withLiveProofMocks(
    {
      requestJira: async (url) => {
        if (url === '/rest/api/3/myself') {
          return makeHttpResponse(200, { accountId: 'op-1', active: true });
        }
        if (url.startsWith('/rest/api/3/mypermissions')) {
          return makeHttpResponse(200, {
            permissions: {
              BROWSE_PROJECTS: { havePermission: true },
              EDIT_ISSUES: { havePermission: true },
              LINK_ISSUES: { havePermission: true },
              ADMINISTER_PROJECTS: { havePermission: false },
            },
          });
        }
        return makeHttpResponse(404, {});
      },
    },
    async () => {
      const origCreate = LiveProofScenarioService.createScenario;
      const captured = [];
      LiveProofScenarioService.createScenario = async (params) => {
        captured.push(params);
        return {
          success: true,
          projectKey: params.projectKey,
          spaceId: params.spaceId || '555',
          pageId: '987',
          pageTitle: 'SRS MedTrace Live Proof MED',
          hazardIssueKey: 'MED-101',
          workIssueKey: 'MED-103',
          testIssueKey: 'MED-102',
          issueLinksCreated: ['MED-101->MED-103', 'MED-102->MED-103'],
          remoteLinkCreated: true,
          warnings: [],
          summary: { datasetMode: 'LIVE', initialized: false, traceLinks: [] },
        };
      };

      try {
        const result = await resolverHandler(
          {
            call: {
              functionKey: 'createLiveProofScenario',
              payload: {},
            },
            context: { extension: { type: 'jira:projectPage', project: { key: 'MED' } } },
          },
          { principal: { accountId: 'op-1' } }
        );
        assert.equal(result.success, true);
        assert.equal(result.projectKey, 'MED');
        assert.equal(captured.length, 1);
        assert.equal(captured[0].projectKey, 'MED');
        assert.equal(captured[0].actorAccountId, 'op-1');
      } finally {
        LiveProofScenarioService.createScenario = origCreate;
      }
    }
  );
});

test('live proof scenario rejects missing Jira create/edit/link permission before creating artifacts', async () => {
  let haveCreate = false;
  let haveLink = true;
  await withLiveProofMocks(
    {
      requestJira: async (url) => {
        if (url.startsWith('/rest/api/3/mypermissions')) {
          return makeHttpResponse(200, {
            permissions: {
              CREATE_ISSUES: { havePermission: haveCreate },
              EDIT_ISSUES: { havePermission: true },
              LINK_ISSUES: { havePermission: haveLink },
              ADMINISTER_PROJECTS: { havePermission: false },
            },
          });
        }
        return makeHttpResponse(404, {});
      },
    },
    async (calls) => {
      await assert.rejects(
        () =>
          LiveProofScenarioService.createScenario({
            projectKey: 'MED',
            actorAccountId: 'viewer-1',
          }),
        /Forbidden: Requires Jira CREATE_ISSUES, EDIT_ISSUES, and LINK_ISSUES/
      );
      haveCreate = true;
      haveLink = false;
      await assert.rejects(
        () =>
          LiveProofScenarioService.createScenario({
            projectKey: 'MED',
            actorAccountId: 'viewer-1',
          }),
        /Forbidden: Requires Jira CREATE_ISSUES, EDIT_ISSUES, and LINK_ISSUES/
      );
      assert.equal(calls.pageCreates.length, 0);
      assert.equal(calls.issueCreates.length, 0);
      assert.equal(calls.syncOptions, null);
      assert.equal(calls.auditEntries.length, 0);
    }
  );
});

test('live proof scenario rejects missing Confluence page-create permission before creating artifacts', async () => {
  await withLiveProofMocks(
    {
      requestConfluence: async (url) => {
        if (/^\/wiki\/api\/v2\/spaces\/\d+\/operations/.test(url)) {
          return makeHttpResponse(200, { operations: [{ operation: 'read', targetType: 'page' }] });
        }
        if (url.includes('/wiki/api/v2/spaces')) {
          return makeHttpResponse(200, { results: [{ id: '555', key: 'MED' }] });
        }
        return makeHttpResponse(404, {});
      },
    },
    async (calls) => {
      await assert.rejects(
        () =>
          LiveProofScenarioService.createScenario({
            projectKey: 'MED',
            actorAccountId: 'viewer-1',
          }),
        /Forbidden: Requires Confluence page-create permission in space 555/
      );
      assert.equal(calls.pageCreates.length, 0);
      assert.equal(calls.issueCreates.length, 0);
      assert.equal(calls.syncOptions, null);
      assert.equal(calls.auditEntries.length, 0);
    }
  );
});

test('live proof scenario validates project key and actor before any remote writes', async () => {
  await withLiveProofMocks({}, async (calls) => {
    await assert.rejects(
      () =>
        LiveProofScenarioService.createScenario({
          projectKey: 'BAD KEY!',
          actorAccountId: 'user-1',
        }),
      /valid Jira projectKey/
    );
    await assert.rejects(
      () =>
        LiveProofScenarioService.createScenario({
          projectKey: 'MED',
          actorAccountId: ' ',
        }),
      /actorAccountId is required/
    );
    assert.equal(calls.jira.length, 0);
    assert.equal(calls.confluence.length, 0);
  });
});

test('live proof scenario discloses created artifact keys when post-create ingestion fails', async () => {
  await withLiveProofMocks({}, async () => {
    const mockedSync = LiveIngestionService.syncFromAtlassian;
    LiveIngestionService.syncFromAtlassian = async () => {
      throw new Error('KVS unavailable during ingestion');
    };
    try {
      await assert.rejects(
        () =>
          LiveProofScenarioService.createScenario({
            projectKey: 'MED',
            actorAccountId: 'user-1',
          }),
        /KVS unavailable during ingestion\. Created artifact\(s\) before failure: Confluence page 987, Jira hazard MED-101, Jira test MED-102, Jira work MED-103/
      );
    } finally {
      LiveIngestionService.syncFromAtlassian = mockedSync;
    }
  });
});

test('live proof scenario reports partial real artifacts when remote linking fails and does not audit as complete', async () => {
  let createdIssueCount = 0;
  await withLiveProofMocks(
    {
      requestJira: async (url, opts) => {
        if (url.startsWith('/rest/api/3/mypermissions')) {
          return makeHttpResponse(200, {
            permissions: {
              CREATE_ISSUES: { havePermission: true },
              EDIT_ISSUES: { havePermission: true },
              LINK_ISSUES: { havePermission: true },
              ADMINISTER_PROJECTS: { havePermission: false },
            },
          });
        }
        if (url === '/rest/api/3/issue' && opts?.method === 'POST') {
          const sequence = ['MED-101', 'MED-102', 'MED-103'];
          const key = sequence[createdIssueCount++] || `MED-${200 + createdIssueCount}`;
          return makeHttpResponse(201, {
            key,
            self: `https://medtrace.atlassian.net/rest/api/3/issue/${key}`,
          });
        }
        if (url === '/rest/api/3/issueLink') return makeHttpResponse(204, {});
        if (url.includes('/remotelink')) return makeHttpResponse(403, { message: 'Link issues denied' });
        return makeHttpResponse(404, {});
      },
    },
    async (calls) => {
      await assert.rejects(
        () =>
          LiveProofScenarioService.createScenario({
            projectKey: 'MED',
            actorAccountId: 'user-1',
          }),
        /Created artifact\(s\) before failure: Confluence page 987, Jira hazard MED-101, Jira test MED-102, Jira work MED-103/
      );
      assert.equal(calls.syncOptions, null);
      assert.equal(calls.auditEntries.length, 0);
    }
  );
});
