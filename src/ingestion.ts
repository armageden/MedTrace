import api, { route } from '@forge/api';
import crypto from 'node:crypto';
import { AuditLogService } from './audit-log';
import { ComplianceEngine } from './compliance-engine';
import { isForgeRuntime } from './runtime';
import { SeederService } from './seeder';
import { TeamworkGraphService } from './teamwork-graph';
import {
  ConfluenceSpec,
  IsoHazard,
  JiraWorkItem,
  LiveSyncResult,
  Part11Signature,
  RiskClass,
  TraceLink,
  VerificationTest,
} from './types';

function sha256Hex(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function stripStorageMarkup(storageHtml: string): string {
  return storageHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 220);
}

function inferRiskClass(labels: string[], priorityName?: string): {
  riskClass: RiskClass;
  severity: IsoHazard['severity'];
  probability: IsoHazard['probability'];
} {
  const lowerLabels = labels.map((l) => l.toLowerCase());
  const lowerPriority = (priorityName || '').toLowerCase();

  if (lowerLabels.some((l) => l.includes('class-c') || l.includes('class_c') || l.includes('critical-safety')) || lowerPriority === 'highest') {
    return { riskClass: 'CLASS_C', severity: 'CATASTROPHIC', probability: 'OCCASIONAL' };
  }
  if (lowerLabels.some((l) => l.includes('class-b') || l.includes('class_b')) || lowerPriority === 'high') {
    return { riskClass: 'CLASS_B', severity: 'CRITICAL', probability: 'REMOTE' };
  }
  return { riskClass: 'CLASS_A', severity: 'MINOR', probability: 'IMPROBABLE' };
}

function mapJiraStatusToWorkStatus(statusName?: string, categoryName?: string): JiraWorkItem['status'] {
  if (statusName === 'Done' || categoryName === 'Done') return 'Done';
  if (statusName === 'Under Review' || statusName === 'In Review') return 'Under Review';
  if (statusName === 'To Do' || categoryName === 'To Do') return 'To Do';
  return 'In Progress';
}

export class LiveIngestionService {
  /**
   * Synchronizes real Jira issues + Confluence SRS pages (with SHA-256 hashing over `body.storage.value`)
   * into an active LIVE compliance suite persisted in sharded Forge KVS.
   */
  public static async syncFromAtlassian(
    options: { projectKey?: string; spaceId?: string; jql?: string } = {},
    actorAccountId: string = 'system:live-sync'
  ): Promise<LiveSyncResult> {
    if (!isForgeRuntime()) {
      throw new Error('LiveIngestionService.syncFromAtlassian requires an active Atlassian Forge runtime.');
    }

    const warnings: string[] = [];
    const projectKey = options.projectKey?.trim().toUpperCase();
    const jql =
      options.jql?.trim() ||
      (projectKey ? `project = "${projectKey}" ORDER BY updated DESC` : 'ORDER BY updated DESC');

    // 1. Fetch Jira issues via Jira REST v3 search/jql
    const jiraResp = await api
      .asApp()
      .requestJira(
        route`/rest/api/3/search/jql?jql=${jql}&maxResults=50&fields=summary,status,assignee,labels,priority,issuetype,project`
      );

    if (jiraResp.status !== 200) {
      const errText = await jiraResp.text();
      throw new Error(`Jira search failed (HTTP ${jiraResp.status}): ${errText.slice(0, 200)}`);
    }
    const jiraJson = await jiraResp.json();
    const issues: any[] = Array.isArray(jiraJson?.issues) ? jiraJson.issues : [];

    // 2. Fetch Confluence pages with storage representation for real SHA-256 hashing
    const pageRoute = options.spaceId?.trim()
      ? route`/wiki/api/v2/spaces/${options.spaceId.trim()}/pages?body-format=storage&limit=50`
      : route`/wiki/api/v2/pages?body-format=storage&limit=50`;
    const confResp = await api.asApp().requestConfluence(pageRoute);
    let pages: any[] = [];
    if (confResp.status === 200) {
      const confJson = await confResp.json();
      pages = Array.isArray(confJson?.results) ? confJson.results : [];
    } else {
      warnings.push(`Confluence pages query returned HTTP ${confResp.status}; proceeding with Jira remote links only.`);
    }

    const pageById = new Map<string, any>();
    for (const p of pages) {
      if (p?.id) pageById.set(String(p.id), p);
    }

    const existingSuite = await SeederService.getActiveComplianceSuite();
    const existingByWorkKey = new Map<string, TraceLink>();
    for (const link of existingSuite.traceLinks) {
      existingByWorkKey.set(link.work.key.toUpperCase(), link);
    }

    const traceLinks: TraceLink[] = [];
    let linkedPairsFound = 0;
    let driftDetectedCount = 0;

    for (const issue of issues) {
      const issueKey: string = issue?.key || '';
      if (!issueKey) continue;

      const fields = issue.fields || {};
      const labels: string[] = Array.isArray(fields.labels) ? fields.labels : [];
      const { riskClass, severity, probability } = inferRiskClass(labels, fields.priority?.name);

      // Resolve Teamwork Graph + Jira remote links to Confluence pages
      const graphCtx = await TeamworkGraphService.queryIssueGraphContext(issueKey);
      const linkedConfluence = graphCtx?.confluenceLinks?.[0];
      let matchedPage: any | undefined = linkedConfluence?.pageId ? pageById.get(String(linkedConfluence.pageId)) : undefined;

      // Fallback match by title/SRS tag if remote link omitted pageId or page wasn't in initial batch
      if (!matchedPage && linkedConfluence?.pageId) {
        try {
          const singlePageResp = await api
            .asApp()
            .requestConfluence(route`/wiki/api/v2/pages/${linkedConfluence.pageId}?body-format=storage`);
          if (singlePageResp.status === 200) {
            matchedPage = await singlePageResp.json();
          }
        } catch {
          // Non-fatal: page may be restricted
        }
      }

      if (!matchedPage) {
        const srsMatch = String(fields.summary || '').match(/\bSRS-\d+\b/i)?.[0]?.toLowerCase();
        if (srsMatch) {
          matchedPage = pages.find((p) => String(p.title || '').toLowerCase().includes(srsMatch));
        }
      }

      const prevLink = existingByWorkKey.get(issueKey.toUpperCase());
      const hazardKey = prevLink?.hazard?.key || `HAZ-${issueKey}`;

      let spec: ConfluenceSpec;
      if (matchedPage) {
        linkedPairsFound++;
        const storageBody: string = matchedPage?.body?.storage?.value || '';
        const currentHash = sha256Hex(storageBody);
        const pageIdStr = String(matchedPage.id);
        const baseline =
          (await SeederService.getSignedSpecBaseline(pageIdStr)) ||
          (await SeederService.getSignedSpecBaseline(`srs-${pageIdStr}`));

        const isDrifted = baseline ? baseline.sha256Hash !== currentHash : false;
        if (isDrifted) driftDetectedCount++;

        spec = {
          id: `srs-${pageIdStr}`,
          pageId: pageIdStr,
          title: matchedPage.title || `Confluence Page ${pageIdStr}`,
          version: Number(matchedPage?.version?.number || 1),
          sha256Hash: currentHash,
          lastSignedHash: baseline?.sha256Hash || '',
          isSignatureInvalidated: isDrifted,
          contentSnippet: stripStorageMarkup(storageBody) || matchedPage.title || '',
          lastUpdated: matchedPage?.version?.createdAt || new Date().toISOString(),
        };
      } else {
        spec = {
          id: `unlinked-${issueKey.toLowerCase()}`,
          title: '',
          version: 0,
          sha256Hash: sha256Hex(''),
          lastSignedHash: '',
          isSignatureInvalidated: true,
          contentSnippet: 'No linked Confluence SRS specification found on Jira issue remote links.',
          lastUpdated: new Date().toISOString(),
        };
      }

      const hazard: IsoHazard = {
        id: hazardKey.toLowerCase(),
        key: hazardKey,
        title: fields.summary || `Hazard for ${issueKey}`,
        riskClass,
        severity,
        probability,
        mitigationRequirementId: spec.id,
        status: 'UNVERIFIED_RISK',
      };

      const work: JiraWorkItem = {
        id: String(issue.id || issueKey.toLowerCase()),
        key: issueKey,
        title: fields.summary || issueKey,
        status: mapJiraStatusToWorkStatus(fields.status?.name, fields.status?.statusCategory?.name),
        assignee: fields.assignee?.displayName || 'Unassigned',
      };

      const existingTest = prevLink?.test;
      const test: VerificationTest = existingTest
        ? { ...existingTest }
        : {
            id: `test-${issueKey.toLowerCase()}`,
            testKey: `TEST-${issueKey}`,
            title: `Verification Test for ${issueKey}`,
            testType: riskClass === 'CLASS_C' ? 'Automated HIL (Hardware-in-Loop)' : 'Integration Test',
            status: 'UNTESTED',
          };

      const baseline = matchedPage
        ? (await SeederService.getSignedSpecBaseline(String(matchedPage.id))) ||
          (await SeederService.getSignedSpecBaseline(spec.id))
        : undefined;

      const signature: Part11Signature = baseline
        ? {
            id: `sig-${spec.id}`,
            signedBy: baseline.signedBy,
            signedAt: baseline.signedAt,
            role: baseline.role,
            meaning: baseline.meaning,
            artifactSha256: baseline.sha256Hash,
            isValid: !spec.isSignatureInvalidated,
            authMethod: baseline.authMethod,
            ...(spec.isSignatureInvalidated
              ? { invalidationReason: 'Confluence SRS content hash changed since Part 11 sign-off.' }
              : {}),
          }
        : {
            id: `sig-${spec.id}`,
            signedBy: prevLink?.signature?.signedBy || '',
            signedAt: prevLink?.signature?.signedAt || '',
            role: prevLink?.signature?.role || 'Regulatory Authority',
            meaning: prevLink?.signature?.meaning || 'Pending 21 CFR Part 11 Sign-off',
            artifactSha256: prevLink?.signature?.artifactSha256 || '',
            isValid: false,
            invalidationReason: 'No 21 CFR Part 11 sign-off recorded for this Confluence SRS version.',
          };

      const evaluated = ComplianceEngine.evaluateTraceLink(hazard, spec, work, test, signature, {
        entityAri: graphCtx?.issueAri || `jira:issue:${issueKey}`,
        hazardAri: `ari:cloud:medtrace::iso14971-hazard/${hazard.key}`,
        linkedSpecAri: matchedPage ? `confluence:page:${matchedPage.id}` : 'unlinked',
        edgeType: graphCtx?.source === 'AGG' ? 'AGG:jira-issue-links-confluence' : 'REST:remotelink',
        aggTraversalStatus: graphCtx ? `LIVE (${graphCtx.source})` : 'LIVE (REST fallback)',
      });
      evaluated.hazard.status = evaluated.complianceState === 'VERIFIED' ? 'MITIGATED' : 'UNVERIFIED_RISK';
      traceLinks.push(evaluated);
    }

    if (traceLinks.length === 0) {
      warnings.push('No Jira issues matched the live sync query; keeping existing compliance suite unchanged.');
      return {
        success: false,
        datasetMode: existingSuite.datasetMode,
        jiraIssuesScanned: issues.length,
        confluencePagesScanned: pages.length,
        linkedPairsFound,
        driftDetectedCount,
        warnings,
        summary: existingSuite,
      };
    }

    const projectLabel =
      projectKey ||
      issues[0]?.fields?.project?.name ||
      'Atlassian Cloud Live Medical Project';

    await AuditLogService.append({
      actorAccountId,
      action: 'SYNC_LIVE',
      targetKey: projectLabel,
      details: {
        jiraIssuesScanned: issues.length,
        confluencePagesScanned: pages.length,
        linkedPairsFound,
        driftDetectedCount,
      },
      authMethod: 'FORGE_USER_SESSION',
    });

    const summary = ComplianceEngine.generateComplianceReport(traceLinks, 'LIVE', projectLabel);
    const saved = await SeederService.saveComplianceSuite(summary);

    return {
      success: true,
      datasetMode: 'LIVE',
      jiraIssuesScanned: issues.length,
      confluencePagesScanned: pages.length,
      linkedPairsFound,
      driftDetectedCount,
      warnings,
      summary: saved,
    };
  }

  /**
   * Forge product trigger handler for `avi:confluence:updated:page`.
   * Re-computes SHA-256 of updated Confluence SRS pages and invalidates drifted Part 11 signatures.
   */
  public static async handleConfluencePageUpdated(event: any): Promise<{
    processed: boolean;
    pageId?: string;
    affectedHazards: string[];
  }> {
    const pageId = String(event?.content?.id || event?.page?.id || '').trim();
    if (!pageId) {
      return { processed: false, affectedHazards: [] };
    }

    const suite = await SeederService.getActiveComplianceSuite();
    const matchingIndices: number[] = [];
    suite.traceLinks.forEach((link, idx) => {
      if (link.spec.pageId === pageId || link.spec.id === pageId || link.spec.id === `srs-${pageId}`) {
        matchingIndices.push(idx);
      }
    });

    if (matchingIndices.length === 0) {
      return { processed: false, pageId, affectedHazards: [] };
    }

    let newHash = '';
    let newVersion: number | undefined;
    let newTitle: string | undefined;
    let newSnippet: string | undefined;

    if (isForgeRuntime()) {
      const resp = await api
        .asApp()
        .requestConfluence(route`/wiki/api/v2/pages/${pageId}?body-format=storage`);
      if (resp.status !== 200) {
        throw new Error(`Confluence trigger failed to fetch page ${pageId} (HTTP ${resp.status}).`);
      }
      const pageData = await resp.json();
      const bodyValue: string = pageData?.body?.storage?.value || '';
      newHash = sha256Hex(bodyValue);
      newVersion = Number(pageData?.version?.number || 1);
      newTitle = pageData?.title;
      newSnippet = stripStorageMarkup(bodyValue);
    } else if (typeof event?.contentHash === 'string') {
      newHash = event.contentHash;
    } else if (typeof event?.storageBody === 'string') {
      newHash = sha256Hex(event.storageBody);
      newSnippet = stripStorageMarkup(event.storageBody);
    } else {
      return { processed: false, pageId, affectedHazards: [] };
    }

    const affectedHazards: string[] = [];
    for (const idx of matchingIndices) {
      const link = suite.traceLinks[idx];
      link.spec.sha256Hash = newHash;
      if (newVersion) link.spec.version = newVersion;
      if (newTitle) link.spec.title = newTitle;
      if (newSnippet) link.spec.contentSnippet = newSnippet;
      link.spec.lastUpdated = new Date().toISOString();

      const drifted = newHash !== link.signature.artifactSha256;
      link.spec.isSignatureInvalidated = drifted;
      if (drifted) {
        link.signature.isValid = false;
        link.signature.invalidationReason =
          `AUTOMATIC REVOCATION: Confluence page ${pageId} updated (SHA-256 ${newHash.slice(0, 12)}... != signed ${link.signature.artifactSha256.slice(0, 12)}...).`;
      }

      suite.traceLinks[idx] = ComplianceEngine.evaluateTraceLink(
        link.hazard,
        link.spec,
        link.work,
        link.test,
        link.signature,
        link.graphMetadata
      );
      affectedHazards.push(link.hazard.key);
    }

    await AuditLogService.append({
      actorAccountId: String(event?.atlassianId || event?.context?.accountId || 'confluence-event-trigger'),
      action: 'CONFLUENCE_PAGE_DRIFT',
      targetKey: `page:${pageId}`,
      details: {
        pageId,
        newSha256: newHash,
        affectedHazards,
      },
      authMethod: 'CONFLUENCE_EVENT_TRIGGER',
    });

    const updated = ComplianceEngine.generateComplianceReport(
      suite.traceLinks,
      suite.datasetMode,
      suite.projectName
    );
    await SeederService.saveComplianceSuite(updated);

    return { processed: true, pageId, affectedHazards };
  }
}
