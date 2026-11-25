import api, { route } from '@forge/api';
import { AuditLogService } from './audit-log';
import { JIRA_PROJECT_KEY_RE } from './crypto-utils';
import { LiveIngestionService } from './ingestion';
import { isForgeRuntime } from './runtime';
import { CreateLiveProofScenarioResponse } from './types';

const CONFLUENCE_ID_RE = /^\d+$/;
const PROOF_LABEL = 'medtrace-live-proof';

type ForgeUserClient = ReturnType<typeof api.asUser>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function adfParagraphs(lines: string[]): Record<string, unknown> {
  return {
    type: 'doc',
    version: 1,
    content: lines.map((text) => ({
      type: 'paragraph',
      content: [{ type: 'text', text }],
    })),
  };
}

async function errorBody(res: { text(): Promise<string> }): Promise<string> {
  return (await res.text().catch(() => '')).slice(0, 240);
}

async function requireCreatedJson(
  res: { status: number; json(): Promise<unknown>; text(): Promise<string> },
  action: string
): Promise<Record<string, unknown>> {
  if (res.status !== 200 && res.status !== 201) {
    throw new Error(`${action} failed (HTTP ${res.status}): ${await errorBody(res)}`);
  }
  const json = await res.json().catch(() => null);
  if (!isRecord(json)) {
    throw new Error(`${action} returned malformed JSON.`);
  }
  return json;
}

function stringId(value: unknown): string {
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return '';
}

async function resolveSpaceId(
  client: ForgeUserClient,
  projectKey: string,
  options: { spaceId?: string }
): Promise<string> {
  if (options.spaceId) {
    if (!CONFLUENCE_ID_RE.test(options.spaceId)) {
      throw new Error('Bad Request: Invalid Confluence spaceId format.');
    }
    return options.spaceId;
  }

  const res = await client.requestConfluence(route`/wiki/api/v2/spaces?keys=${projectKey}&limit=1`);
  if (res.status === 200) {
    const json = (await res.json().catch(() => null)) as { results?: Array<{ id?: unknown }> } | null;
    const id = stringId(json?.results?.[0]?.id);
    if (id) return id;
  }

  for (const spaceRoute of [
    route`/wiki/api/v2/spaces?type=global&limit=1`,
    route`/wiki/api/v2/spaces?limit=1`,
  ]) {
    const res = await client.requestConfluence(spaceRoute);
    if (res.status !== 200) continue;
    const json = (await res.json().catch(() => null)) as { results?: Array<{ id?: unknown }> } | null;
    const id = stringId(json?.results?.[0]?.id);
    if (id) return id;
  }

  throw new Error(
    'No readable Confluence space found for the live proof scenario. Open the app from a Confluence space or supply spaceId.'
  );
}

async function assertJiraCreatePermissions(client: ForgeUserClient, projectKey: string): Promise<void> {
  const res = await client.requestJira(
    route`/rest/api/3/mypermissions?projectKey=${projectKey}&permissions=CREATE_ISSUES,EDIT_ISSUES,ADMINISTER_PROJECTS,LINK_ISSUES`
  );
  if (res.status !== 200) {
    throw new Error(`Unable to verify Jira create/edit permissions in project ${projectKey} (HTTP ${res.status}).`);
  }
  const json = (await res.json().catch(() => null)) as {
    permissions?: {
      CREATE_ISSUES?: { havePermission?: boolean };
      EDIT_ISSUES?: { havePermission?: boolean };
      ADMINISTER_PROJECTS?: { havePermission?: boolean };
      LINK_ISSUES?: { havePermission?: boolean };
    };
  } | null;
  if (
    json?.permissions?.CREATE_ISSUES?.havePermission !== true ||
    (json?.permissions?.EDIT_ISSUES?.havePermission !== true &&
      json?.permissions?.ADMINISTER_PROJECTS?.havePermission !== true) ||
    json?.permissions?.LINK_ISSUES?.havePermission !== true
  ) {
    throw new Error(`Forbidden: Requires Jira CREATE_ISSUES, EDIT_ISSUES, and LINK_ISSUES permissions in project ${projectKey}.`);
  }
}

async function assertConfluencePageCreatePermission(client: ForgeUserClient, spaceId: string): Promise<void> {
  const res = await client.requestConfluence(route`/wiki/api/v2/spaces/${spaceId}/operations`);
  if (res.status !== 200) {
    throw new Error(`Unable to verify Confluence page-create permission in space ${spaceId} (HTTP ${res.status}).`);
  }
  const json = (await res.json().catch(() => null)) as {
    operations?: Array<{ operation?: unknown; targetType?: unknown }>;
  } | null;
  const canCreatePage = (Array.isArray(json?.operations) ? json.operations : []).some((op) => {
    const operation = typeof op?.operation === 'string' ? op.operation.trim().toLowerCase() : '';
    const targetType = typeof op?.targetType === 'string' ? op.targetType.trim().toLowerCase() : '';
    return (
      (operation === 'create' && (targetType === 'page' || targetType === 'space' || targetType === '')) ||
      (operation === 'administer' && (targetType === 'page' || targetType === 'space' || targetType === ''))
    );
  });
  if (!canCreatePage) {
    throw new Error(`Forbidden: Requires Confluence page-create permission in space ${spaceId}.`);
  }
}

export class LiveProofScenarioService {
  /**
   * Creates a minimal real Jira/Confluence proof chain, links it, and ingests it.
   * It intentionally does not record test evidence or sign approvals; those remain explicit user attestations.
   */
  static async createScenario(params: {
    projectKey?: string;
    spaceId?: string;
    actorAccountId: string;
  }): Promise<CreateLiveProofScenarioResponse> {
    if (!isForgeRuntime()) {
      throw new Error('Live proof scenario creation requires an active Atlassian Forge runtime.');
    }
    const actorAccountId = (params.actorAccountId || '').trim();
    if (!actorAccountId) {
      throw new Error('Authenticated actorAccountId is required to create a live proof scenario.');
    }
    const projectKey = (params.projectKey || '').trim().toUpperCase();
    if (!JIRA_PROJECT_KEY_RE.test(projectKey)) {
      throw new Error('Bad Request: A valid Jira projectKey is required.');
    }

    const client = api.asUser();
    await assertJiraCreatePermissions(client, projectKey);
    const spaceId = await resolveSpaceId(client, projectKey, {
      ...(params.spaceId?.trim() ? { spaceId: params.spaceId.trim() } : {}),
    });
    await assertConfluencePageCreatePermission(client, spaceId);

    const createdArtifacts: string[] = [];
    let pageId = '';
    let pageTitle = '';
    let hazardIssueKey = '';
    let testIssueKey = '';
    let workIssueKey = '';
    let pageUrl: string | undefined;
    const issueLinksCreated: string[] = [];
    let remoteLinkCreated = false;

    try {
      const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+$/, '').replace('T', '-');
      pageTitle = `SRS MedTrace Live Proof ${projectKey} ${stamp}`;
      const pageBody = [
        '<h2>MedTrace live proof requirement</h2>',
        '<p><strong>Bolus delivery threshold:</strong> 5.0 mL/hr</p>',
        '<p>This page is a real Confluence requirement artifact created for judge evaluation. Edit 5.0 to 5.5 mL/hr to prove drift detection and approval invalidation.</p>',
      ].join('');
      const pageJson = await requireCreatedJson(
        await client.requestConfluence(route`/wiki/api/v2/pages`, {
          method: 'POST',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            spaceId,
            status: 'current',
            title: pageTitle,
            body: { representation: 'storage', value: pageBody },
          }),
        }),
        'Confluence proof page creation'
      );
      pageId = stringId(pageJson.id);
      if (!pageId) throw new Error('Confluence proof page creation succeeded without returning a page id.');
      createdArtifacts.push(`Confluence page ${pageId}`);

      const createIssue = async (
        summary: string,
        labels: string[],
        description: string[]
      ): Promise<{ key: string; self?: string }> => {
        const json = await requireCreatedJson(
          await client.requestJira(route`/rest/api/3/issue`, {
            method: 'POST',
            headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify({
              fields: {
                project: { key: projectKey },
                issuetype: { name: 'Task' },
                summary,
                labels,
                description: adfParagraphs(description),
              },
            }),
          }),
          `Jira issue creation for "${summary}"`
        );
        const key = typeof json.key === 'string' ? json.key.trim().toUpperCase() : '';
        if (!key) throw new Error(`Jira issue creation for "${summary}" did not return an issue key.`);
        return { key, ...(typeof json.self === 'string' ? { self: json.self } : {}) };
      };

      const hazard = await createIssue(
        '[MedTrace Proof] Over-infusion hazard',
        [PROOF_LABEL, 'medtrace-hazard', 'class-c'],
        [
          'ISO 14971 hazard: over-infusion caused by an incorrect bolus threshold.',
          'MedTrace live proof artifact; link and verification state are intentionally real.',
        ]
      );
      hazardIssueKey = hazard.key;
      createdArtifacts.push(`Jira hazard ${hazardIssueKey}`);

      const test = await createIssue(
        '[MedTrace Proof] Bolus threshold verification test',
        [PROOF_LABEL, 'medtrace-test', 'hil-test', 'class-c'],
        [
          'IEC 62304 verification test for the bolus threshold requirement.',
          'Record real HTTPS test evidence in MedTrace before approving release.',
        ]
      );
      testIssueKey = test.key;
      createdArtifacts.push(`Jira test ${testIssueKey}`);

      const work = await createIssue(
        '[MedTrace Proof] Implement bolus threshold control',
        [PROOF_LABEL, 'class-c'],
        [
          'Implementation work item for the bolus threshold control.',
          `Requirement page: ${pageTitle} (${pageId}).`,
        ]
      );
      workIssueKey = work.key;
      createdArtifacts.push(`Jira work ${workIssueKey}`);

      const links = isRecord(pageJson._links) ? pageJson._links : {};
      const base = typeof links.base === 'string' ? links.base.replace(/\/+$/, '') : '';
      const webui = typeof links.webui === 'string' ? links.webui : '';
      if (base) {
        pageUrl = webui
          ? `${base}${webui.startsWith('/') ? webui : `/${webui}`}`
          : `${base}/pages/viewpage.action?pageId=${pageId}`;
      } else if (work.self) {
        try {
          const siteOrigin = new URL(work.self).origin;
          pageUrl = `${siteOrigin}/wiki/pages/viewpage.action?pageId=${pageId}`;
        } catch {
          pageUrl = undefined;
        }
      }
      if (!pageUrl) {
        throw new Error('Unable to derive an absolute Confluence page URL for the Jira remote link.');
      }

      const linkIssues = async (inwardKey: string, outwardKey: string): Promise<void> => {
        const res = await client.requestJira(route`/rest/api/3/issueLink`, {
          method: 'POST',
          headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: { name: 'Relates' },
            inwardIssue: { key: inwardKey },
            outwardIssue: { key: outwardKey },
          }),
        });
        if (res.status !== 200 && res.status !== 201 && res.status !== 204) {
          throw new Error(`Jira issue link ${inwardKey} -> ${outwardKey} failed (HTTP ${res.status}): ${await errorBody(res)}`);
        }
        issueLinksCreated.push(`${inwardKey}->${outwardKey}`);
      };

      await linkIssues(hazardIssueKey, workIssueKey);
      await linkIssues(testIssueKey, workIssueKey);

      const remoteRes = await client.requestJira(route`/rest/api/3/issue/${workIssueKey}/remotelink`, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({
          globalId: `pageId=${pageId}`,
          application: { type: 'com.atlassian.confluence', name: 'Confluence' },
          relationship: 'Wiki Page',
          object: { url: pageUrl, title: pageTitle },
        }),
      });
      if (remoteRes.status !== 200 && remoteRes.status !== 201) {
        throw new Error(`Jira remote link to Confluence page ${pageId} failed (HTTP ${remoteRes.status}): ${await errorBody(remoteRes)}`);
      }
      remoteLinkCreated = true;

      const syncResult = await LiveIngestionService.syncFromAtlassian(
        {
          // Omit spaceId: the remote link fetches the exact page, while scanning a large space can truncate the proof sync.
          projectKey,
          jql: `key in ("${hazardIssueKey}", "${testIssueKey}", "${workIssueKey}")`,
          callerMode: 'USER',
        },
        actorAccountId
      );

      const warnings = [...syncResult.warnings];
      const ingested = syncResult.summary.traceLinks.some(
        (link) => (link.work?.key || '').trim().toUpperCase() === workIssueKey
      );
      if (!ingested) {
        warnings.push(
          `Proof artifacts were created, but ${workIssueKey} was not ingested yet; run Sync Live Atlassian once if Jira indexing is still settling.`
        );
      }

      await AuditLogService.append({
        actorAccountId,
        action: 'CREATE_LIVE_PROOF_SCENARIO',
        targetKey: workIssueKey,
        details: {
          projectKey,
          spaceId,
          pageId,
          hazardIssueKey,
          testIssueKey,
          workIssueKey,
          remoteLinkCreated,
          ingested,
        },
        authMethod: 'FORGE_USER_SESSION',
      });

      return {
        success: true,
        projectKey,
        spaceId,
        pageId,
        pageTitle,
        ...(pageUrl ? { pageUrl } : {}),
        hazardIssueKey,
        workIssueKey,
        testIssueKey,
        issueLinksCreated,
        remoteLinkCreated,
        warnings,
        summary: syncResult.summary,
      };
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      const partial =
        createdArtifacts.length > 0
          ? `${detail.trim().endsWith('.') ? '' : '.'} Created artifact(s) before failure: ${createdArtifacts.join(', ')}.`
          : '';
      throw new Error(`${detail}${partial}`);
    }
  }
}
