import api, { route } from '@forge/api';
import { ComplianceEngine } from './compliance-engine';
import {
  cloneJsonValue,
  isKvsConflictError,
  isSignatureTimestampInvalidated,
  JIRA_ISSUE_KEY_RE,
  sha256Hex,
} from './crypto-utils';
import { isForgeRuntime } from './runtime';
import {
  BaselineMutationRecord,
  commitSuiteMutation,
  mapJiraStatusToWorkStatus,
  SeederService,
  SignedSpecBaseline,
} from './seeder';
import { ComplianceSummary, RiskClass, TraceLink } from './types';

export const MAX_CAS_RETRY_ATTEMPTS = 3;
const CONFLUENCE_RECONCILE_BATCH_SIZE = 5;
const CONFLUENCE_RECONCILE_BUDGET_MS = 8_000;

export const DEFAULT_HAZARD_ISSUE_TYPES = new Set<string>([
  'hazard',
  'risk',
  'safety hazard',
  'safety-hazard',
]);

export const DEFAULT_HAZARD_LABEL_PATTERNS = [
  'class-a',
  'class_a',
  'class-b',
  'class_b',
  'class-c',
  'class_c',
  'critical-safety',
  'iso-14971',
  'iec-62304',
  'medtrace-hazard',
];

const DEFAULT_TEST_ISSUE_TYPES = new Set<string>([
  'test',
  'verification',
  'verification test',
  'test case',
  'test execution',
  'qa test',
  'sub-test',
]);

export interface ConfluencePageUpdatedEvent {
  content?: { id?: string | number };
  page?: { id?: string | number };
  atlassianId?: string;
  context?: { accountId?: string };
  contentHash?: string;
  storageBody?: string;
  prefetchedPageContent?: {
    newHash: string;
    newVersion?: number;
    newTitle?: string;
    newSnippet?: string;
  };
  authMethod?: 'CONFLUENCE_EVENT_TRIGGER' | 'FORGE_USER_SESSION';
}

export interface ConfluencePageUpdatedResult {
  processed: boolean;
  pageId?: string;
  affectedHazards: string[];
}

export interface JiraIssueUpdatedEvent {
  eventType?: string;
  issue?: { id?: string | number; key?: string };
  issueLink?: {
    sourceIssueId?: string | number;
    destinationIssueId?: string | number;
  };
  atlassianId?: string;
  context?: { accountId?: string };
}

export interface JiraIssueUpdatedResult {
  processed: boolean;
  issueKey?: string;
  affectedHazards: string[];
}

export interface JiraIssueLinkEntry {
  id?: string;
  type?: { name?: string; inward?: string; outward?: string };
  inwardIssue?: JiraApiIssue;
  outwardIssue?: JiraApiIssue;
}

export interface JiraApiIssue {
  id?: string | number;
  key?: string;
  self?: string;
  fields?: {
    summary?: string;
    status?: {
      name?: string;
      statusCategory?: { key?: string; name?: string };
    };
    assignee?: { displayName?: string } | null;
    labels?: unknown[];
    priority?: { name?: string };
    issuetype?: { name?: string };
    project?: { name?: string; key?: string };
    issuelinks?: unknown[];
  };
}

export interface ConfluencePageData {
  id: string | number;
  title?: string;
  version?: { number?: number; createdAt?: string };
  body?: { storage?: { value?: string } };
}

export interface ResolvedJiraLinkedIssue {
  key: string;
  id: string;
  summary: string;
  statusName: string;
  statusObj?: NonNullable<JiraApiIssue['fields']>['status'];
  issueTypeName: string;
  labels: string[];
  linkTypeName: string;
  linkDirection: 'inward' | 'outward';
  relationshipLabel: string;
  self?: string;
}

export function stripStorageMarkup(storageHtml: string): string {
  return storageHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 220);
}

export function inferRiskClass(labels: string[]): {
  riskClass: RiskClass;
  safetyClassAssigned?: boolean;
} {
  const lowerLabels = labels.map((l) => l.toLowerCase());

  if (lowerLabels.some((l) => l.includes('class-c') || l.includes('class_c') || l.includes('critical-safety'))) {
    return { riskClass: 'CLASS_C' };
  }
  if (lowerLabels.some((l) => l.includes('class-b') || l.includes('class_b'))) {
    return { riskClass: 'CLASS_B' };
  }
  if (lowerLabels.some((l) => l.includes('class-a') || l.includes('class_a'))) {
    return { riskClass: 'CLASS_A' };
  }
  return {
    riskClass: 'CLASS_C',
    safetyClassAssigned: false,
  };
}

export function normalizeStringArray(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  const out: string[] = [];
  for (const item of values) {
    if (typeof item === 'string') {
      const trimmed = item.trim();
      if (trimmed) out.push(trimmed);
    }
  }
  return out;
}

export function isPureHazardIssue(issue: { issueTypeName?: string; labels?: string[] }): boolean {
  const typeLower = (issue.issueTypeName || '').trim().toLowerCase();
  if (typeLower && DEFAULT_HAZARD_ISSUE_TYPES.has(typeLower)) {
    return true;
  }
  const labelsLower = (issue.labels || []).map((l) => l.toLowerCase());
  return labelsLower.some(
    (l) => l === 'medtrace-hazard' || l === 'hazard' || l === 'iso-14971-hazard'
  );
}

export function isPureVerificationTestIssue(issue: { issueTypeName?: string; labels?: string[] }): boolean {
  const typeLower = (issue.issueTypeName || '').trim().toLowerCase();
  if (typeLower && DEFAULT_TEST_ISSUE_TYPES.has(typeLower)) {
    return true;
  }
  const labelsLower = (issue.labels || []).map((l) => l.toLowerCase());
  return labelsLower.some(
    (l) =>
      l === 'medtrace-test' ||
      l === 'verification-test' ||
      l === 'hil-test'
  );
}

export function extractLinkedIssueCandidates(
  rawLinks: unknown[],
  issueByKey: Map<string, JiraApiIssue>
): ResolvedJiraLinkedIssue[] {
  if (!Array.isArray(rawLinks) || rawLinks.length === 0) return [];
  const out: ResolvedJiraLinkedIssue[] = [];
  const seen = new Set<string>();

  for (const raw of rawLinks) {
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as JiraIssueLinkEntry;
    const linkTypeName = String(entry.type?.name || '').trim();
    const inwardLabel = String(entry.type?.inward || '').trim();
    const outwardLabel = String(entry.type?.outward || '').trim();

    const pairs: Array<{
      issue?: JiraApiIssue;
      direction: 'inward' | 'outward';
      relLabel: string;
    }> = [
      { issue: entry.inwardIssue, direction: 'inward', relLabel: inwardLabel || linkTypeName },
      { issue: entry.outwardIssue, direction: 'outward', relLabel: outwardLabel || linkTypeName },
    ];

    for (const pair of pairs) {
      const key = typeof pair.issue?.key === 'string' ? pair.issue.key.trim().toUpperCase() : '';
      if (!key || seen.has(`${key}:${pair.direction}`)) continue;
      seen.add(`${key}:${pair.direction}`);

      const enriched = issueByKey.get(key);
      const fields = pair.issue?.fields || {};
      const enrichedFields = enriched?.fields || {};
      const summary =
        (typeof enrichedFields.summary === 'string' && enrichedFields.summary) ||
        (typeof fields.summary === 'string' && fields.summary) ||
        key;
      const statusObj = enrichedFields.status || fields.status;
      const statusName = String(statusObj?.name || '').trim();
      const issueTypeName = String(
        enrichedFields.issuetype?.name || fields.issuetype?.name || ''
      ).trim();
      const labels = normalizeStringArray(enrichedFields.labels ?? fields.labels);
      const id = String(enriched?.id || pair.issue?.id || key.toLowerCase());
      const self = enriched?.self || pair.issue?.self;

      out.push({
        key,
        id,
        summary,
        statusName,
        statusObj,
        issueTypeName,
        labels,
        linkTypeName,
        linkDirection: pair.direction,
        relationshipLabel: pair.relLabel,
        ...(self ? { self } : {}),
      });
    }
  }

  return out;
}

export function resolveLinkedHazardAndTest(
  linkedIssues: ResolvedJiraLinkedIssue[]
): {
  linkedHazard?: ResolvedJiraLinkedIssue;
  linkedTest?: ResolvedJiraLinkedIssue;
  linkedReverification?: ResolvedJiraLinkedIssue;
} {
  let linkedHazard: ResolvedJiraLinkedIssue | undefined;
  let linkedTest: ResolvedJiraLinkedIssue | undefined;
  let linkedReverification: ResolvedJiraLinkedIssue | undefined;

  for (const item of linkedIssues) {
    const rel = `${item.linkTypeName} ${item.relationshipLabel}`.toLowerCase();
    const isRev = item.labels.some((l) => l.toLowerCase() === 'medtrace-reverification');
    if (isRev) {
      if (!linkedReverification) {
        linkedReverification = item;
      }
      continue;
    }

    const itemIsTest = isPureVerificationTestIssue(item);
    const itemIsHazard = isPureHazardIssue(item);

    if (
      !linkedHazard &&
      !itemIsTest &&
      (itemIsHazard || /\b(mitigat|hazard|risk)\b/i.test(rel))
    ) {
      linkedHazard = item;
      continue;
    }

    if (
      !linkedTest &&
      !itemIsHazard &&
      (itemIsTest || /\b(test(s|ed|ing)?|verif(y|ies|ied|ication))\b/i.test(rel))
    ) {
      linkedTest = item;
    }
  }

  return { linkedHazard, linkedTest, linkedReverification };
}

export function isBaselineInvalidated(baseline: SignedSpecBaseline | undefined): boolean {
  if (!baseline?.invalidatedAt) return false;
  const invMs = Date.parse(baseline.invalidatedAt);
  const signedMs = baseline.signedAt ? Date.parse(baseline.signedAt) : NaN;
  if (!Number.isFinite(invMs) || !Number.isFinite(signedMs)) return true;
  return signedMs <= invMs;
}

export function isConcurrencyError(err: unknown): boolean {
  if (isKvsConflictError(err)) return true;
  const msg = err instanceof Error ? err.message : String(err ?? '');
  return /Concurrent modification|version lock conflict/i.test(msg);
}

export function buildBaselineMutationForInvalidation(
  hazardKey: string,
  specId: string,
  pageId: string | undefined,
  newHash: string,
  invalidatedAt: string,
  reason: string
): BaselineMutationRecord {
  return {
    action: 'INVALIDATE',
    invalidation: {
      hazardKey,
      specId,
      ...(pageId ? { pageId } : {}),
      newHash,
      invalidatedAt,
      reason,
    },
  };
}

/**
 * Forge product trigger handler for `avi:confluence:updated:page`.
 * Re-computes SHA-256 of updated Confluence SRS pages, invalidates drifted Part 11 signatures
 * (without resurrecting previously invalidated signatures on page revert), and commits with 3-attempt CAS retry.
 */
export async function handleConfluencePageUpdatedTrigger(
  event: ConfluencePageUpdatedEvent
): Promise<ConfluencePageUpdatedResult> {
  const pageId = String(event?.content?.id || event?.page?.id || '').trim();
  if (!pageId) {
    return { processed: false, affectedHazards: [] };
  }

  let fetchedPageContent:
    | {
        newHash: string;
        newVersion?: number;
        newTitle?: string;
        newSnippet?: string;
      }
    | undefined;

  for (let attempt = 1; attempt <= MAX_CAS_RETRY_ATTEMPTS; attempt++) {
    const { summary: suite, version } = await SeederService.getSuiteWithVersion();
    const matchingIndices: number[] = [];
    suite.traceLinks.forEach((link, idx) => {
      if (link.spec.pageId === pageId || link.spec.id === pageId || link.spec.id === `srs-${pageId}`) {
        matchingIndices.push(idx);
      }
    });

    if (matchingIndices.length === 0) {
      if (isForgeRuntime()) {
        console.log(`[MedTrace ConfluenceTrigger] Page ${pageId} matched 0 links in current KVS partition.`);
      }
      return { processed: false, pageId, affectedHazards: [] };
    }

    if (!fetchedPageContent) {
      if (event.prefetchedPageContent) {
        fetchedPageContent = event.prefetchedPageContent;
      } else if (isForgeRuntime()) {
        const resp = await api
          .asApp()
          .requestConfluence(route`/wiki/api/v2/pages/${pageId}?body-format=storage`);
        if (resp.status !== 200) {
          throw new Error(`Confluence trigger failed to fetch page ${pageId} (HTTP ${resp.status}).`);
        }
        const pageData = (await resp.json()) as ConfluencePageData;
        const bodyValue = typeof pageData?.body?.storage?.value === 'string' ? pageData.body.storage.value : '';
        fetchedPageContent = {
          newHash: sha256Hex(bodyValue),
          newVersion: Number(pageData?.version?.number || 1),
          newTitle: pageData?.title,
          newSnippet: stripStorageMarkup(bodyValue),
        };
      } else if (typeof event?.contentHash === 'string') {
        fetchedPageContent = { newHash: event.contentHash };
      } else if (typeof event?.storageBody === 'string') {
        fetchedPageContent = {
          newHash: sha256Hex(event.storageBody),
          newSnippet: stripStorageMarkup(event.storageBody),
        };
      } else {
        return { processed: false, pageId, affectedHazards: [] };
      }
    }

    const { newHash, newVersion, newTitle, newSnippet } = fetchedPageContent;
    const updatedLinks = suite.traceLinks.map(cloneJsonValue);
    const affectedHazards: string[] = [];
    const baselineUpdates: BaselineMutationRecord[] = [];
    const part11Secret = (process.env.MEDTRACE_PART11_SECRET || '').trim();
    const eventNowIso = new Date().toISOString();

    for (const idx of matchingIndices) {
      const link = updatedLinks[idx];

      const compositeSpecBaseline = await SeederService.getSignedSpecBaseline(link.spec.id, link.hazard.key);
      const compositePageBaseline =
        !compositeSpecBaseline && link.spec.pageId
          ? await SeederService.getSignedSpecBaseline(link.spec.pageId, link.hazard.key)
          : undefined;
      const existingBaseline = compositeSpecBaseline || compositePageBaseline;

      const baselineInvalidated = isBaselineInvalidated(existingBaseline);
      const hasPriorSignature = Boolean(
        link.signature.artifactSha256 ||
          link.signature.signedAt ||
          link.signature.signedBy ||
          existingBaseline
      );
      const wasAlreadyInvalidated =
        Boolean(link.spec.isSignatureInvalidated) ||
        (hasPriorSignature && !link.signature.isValid) ||
        isSignatureTimestampInvalidated(link.signature) ||
        baselineInvalidated;

      const hashMismatch = hasPriorSignature && newHash !== link.signature.artifactSha256;
      const shouldInvalidate =
        (hasPriorSignature || Boolean(link.spec.isSignatureInvalidated)) &&
        (wasAlreadyInvalidated || hashMismatch);

      link.spec.sha256Hash = newHash;
      link.spec.isMissingSentinel = false;
      if (newVersion) link.spec.version = newVersion;
      if (newTitle) link.spec.title = newTitle;
      if (newSnippet !== undefined) link.spec.contentSnippet = newSnippet;
      link.spec.lastUpdated = eventNowIso;

      if (shouldInvalidate) {
        link.spec.isSignatureInvalidated = true;
        link.signature.isValid = false;

        const signedMs = link.signature.signedAt ? Date.parse(link.signature.signedAt) : NaN;
        let invalidatedAt =
          existingBaseline?.invalidatedAt || link.signature.invalidatedAt || eventNowIso;

        if (hashMismatch) {
          const safeMs =
            Number.isFinite(signedMs) && Date.now() <= signedMs ? signedMs + 1 : Date.now();
          invalidatedAt = new Date(safeMs).toISOString();
        }

        if (hasPriorSignature) {
          link.signature.invalidatedAt = invalidatedAt;
          if (hashMismatch) {
            link.signature.invalidationReason =
              `AUTOMATIC REVOCATION: Confluence page ${pageId} updated (SHA-256 ${newHash.slice(0, 12)}... != signed ${link.signature.artifactSha256.slice(0, 12)}...).`;
          } else {
            link.signature.invalidationReason =
              link.signature.invalidationReason ||
              existingBaseline?.invalidationReason ||
              `AUTOMATIC REVOCATION PERSISTED: Confluence page ${pageId} reverted to ${newHash.slice(0, 12)}... after prior invalidation; fresh Part 11 re-signature required.`;
          }

          if (hashMismatch || (existingBaseline && !baselineInvalidated)) {
            baselineUpdates.push(
              buildBaselineMutationForInvalidation(
                link.hazard.key,
                link.spec.id,
                pageId,
                newHash,
                invalidatedAt,
                link.signature.invalidationReason
              )
            );
          }
        }
      }

      const evaluated = ComplianceEngine.evaluateTraceLink(
        link.hazard,
        link.spec,
        link.work,
        link.test,
        link.signature,
        link.graphMetadata,
        {
          linkId: link.id,
          part11Secret,
          requireCryptographicSeal: true,
          requireTestEvidence: suite.datasetMode === 'LIVE',
          reverificationTaskKey: link.reverificationTaskKey,
        }
      );
      evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
      updatedLinks[idx] = evaluated;
      if (!affectedHazards.includes(evaluated.hazard.key)) {
        affectedHazards.push(evaluated.hazard.key);
      }
    }

    const affectedWorkKeys = Array.from(
      new Set(
        matchingIndices
          .map((i) => updatedLinks[i]?.work?.key?.trim().toUpperCase())
          .filter((k): k is string => Boolean(k))
      )
    );
    const affectedProjectKeys = Array.from(
      new Set(
        affectedWorkKeys
          .map((k) => k.split('-')[0])
          .filter(Boolean)
      )
    );

    const updated = ComplianceEngine.generateComplianceReport(
      updatedLinks,
      suite.datasetMode,
      suite.projectName,
      {
        initialized: suite.initialized ?? true,
        lastSyncedAt: suite.lastSyncedAt,
        syncIncomplete: suite.syncIncomplete,
        incompleteProjectKeys: suite.incompleteProjectKeys,
      }
    );

    try {
      await commitSuiteMutation({
        summary: updated,
        expectedVersion: version ?? 0,
        baselineUpdates,
        auditEntry: {
          actorAccountId: String(
            event?.atlassianId || event?.context?.accountId || 'confluence-event-trigger'
          ),
          action: 'CONFLUENCE_PAGE_DRIFT',
          targetKey: `page:${pageId}`,
          details: {
            pageId,
            newSha256: newHash,
            affectedHazards,
            affectedWorkKeys,
            projectKeys: affectedProjectKeys,
          },
          authMethod: event.authMethod || 'CONFLUENCE_EVENT_TRIGGER',
        },
      });
      return { processed: true, pageId, affectedHazards };
    } catch (err: unknown) {
      if (isConcurrencyError(err) && attempt < MAX_CAS_RETRY_ATTEMPTS) {
        continue;
      }
      throw err;
    }
  }

  throw new Error(`Failed to persist Confluence page drift for ${pageId} after ${MAX_CAS_RETRY_ATTEMPTS} attempts.`);
}

/**
 * Reconciles live Confluence SRS hashes in the current product's KVS partition on read/gate paths
 * so edits made in Confluence invalidate approvals inside Jira's separate Forge KVS partition
 * even when `avi:confluence:updated:page` fires on Confluence's isolated partition.
 */
export async function reconcileConfluenceSpecsTrigger(
  suite: ComplianceSummary,
  options?: {
    targetPageIds?: string[];
    actorAccountId?: string;
    projectKey?: string;
    issueKeyFilter?: string;
    allowAppFallback?: boolean;
    onDriftDetected?: (event: ConfluencePageUpdatedEvent) => Promise<ConfluencePageUpdatedResult>;
  }
): Promise<ComplianceSummary> {
  if (
    !isForgeRuntime() ||
    suite.datasetMode !== 'LIVE' ||
    suite.initialized === false ||
    suite.traceLinks.length === 0
  ) {
    return suite;
  }

  const filterSet = options?.targetPageIds
    ? new Set(options.targetPageIds.map((p) => p.trim()).filter(Boolean))
    : undefined;

  const linksByPageId = new Map<string, TraceLink[]>();
  for (const link of suite.traceLinks) {
    const pid = typeof link.spec?.pageId === 'string' ? link.spec.pageId.trim() : '';
    if (!pid || !/^\d+$/.test(pid) || link.spec?.isMissingSentinel || link.spec?.specRestricted) {
      continue;
    }
    if (filterSet && !filterSet.has(pid)) {
      continue;
    }
    const existing = linksByPageId.get(pid);
    if (existing) {
      existing.push(link);
    } else {
      linksByPageId.set(pid, [link]);
    }
  }

  if (linksByPageId.size === 0) {
    return suite;
  }

  const prioritizedEntries = Array.from(linksByPageId.entries()).sort(([, linksA], [, linksB]) => {
    const signedA = linksA.some(
      (l) => l.signature?.isValid === true && l.spec?.isSignatureInvalidated !== true
    );
    const signedB = linksB.some(
      (l) => l.signature?.isValid === true && l.spec?.isSignatureInvalidated !== true
    );
    return Number(signedB) - Number(signedA);
  });

  const fetchPage = async (pageId: string): Promise<ConfluencePageData | undefined> => {
    const pageRoute = route`/wiki/api/v2/pages/${pageId}?body-format=storage`;
    try {
      const userResp = await api.asUser().requestConfluence(pageRoute);
      if (userResp?.status === 200) {
        return (await userResp.json()) as ConfluencePageData;
      }
    } catch {
      // Fall through to app fallback when permitted
    }

    if (options?.allowAppFallback) {
      try {
        const appResp = await api.asApp().requestConfluence(pageRoute);
        if (appResp?.status === 200) {
          return (await appResp.json()) as ConfluencePageData;
        }
      } catch {
        return undefined;
      }
    }
    return undefined;
  };

  const driftedPages: Array<{
    pageId: string;
    newHash: string;
    newVersion: number;
    newTitle?: string;
    newSnippet?: string;
  }> = [];

  const reconcileStartedAt = Date.now();
  for (let i = 0; i < prioritizedEntries.length; i += CONFLUENCE_RECONCILE_BATCH_SIZE) {
    if (i > 0 && Date.now() - reconcileStartedAt >= CONFLUENCE_RECONCILE_BUDGET_MS) {
      console.warn(
        `[MedTrace] reconcileConfluenceSpecs paused after ${CONFLUENCE_RECONCILE_BUDGET_MS}ms budget; checked ${i}/${prioritizedEntries.length} unique Confluence page(s).`
      );
      break;
    }
    const batch = prioritizedEntries.slice(i, i + CONFLUENCE_RECONCILE_BATCH_SIZE);
    await Promise.all(
      batch.map(async ([pageId, links]) => {
        const pageData = await fetchPage(pageId);
        if (!pageData || typeof pageData?.body?.storage?.value !== 'string') {
          return;
        }
        const bodyValue = pageData.body.storage.value;
        const newHash = sha256Hex(bodyValue);
        const newVersion = Number(pageData?.version?.number || 1);
        const hasChange = links.some(
          (l) =>
            l.spec.sha256Hash !== newHash ||
            (Number.isFinite(newVersion) && newVersion > 0 && l.spec.version !== newVersion)
        );
        if (hasChange) {
          driftedPages.push({
            pageId,
            newHash,
            newVersion,
            newTitle: pageData.title,
            newSnippet: stripStorageMarkup(bodyValue),
          });
        }
      })
    );
  }

  if (driftedPages.length === 0) {
    return suite;
  }

  const dispatchDrift = options?.onDriftDetected || handleConfluencePageUpdatedTrigger;
  let updatedAny = false;
  for (const item of driftedPages) {
    try {
      const res = await dispatchDrift({
        content: { id: item.pageId },
        atlassianId: options?.actorAccountId || 'confluence-drift-reconcile',
        prefetchedPageContent: {
          newHash: item.newHash,
          newVersion: item.newVersion,
          newTitle: item.newTitle,
          newSnippet: item.newSnippet,
        },
        authMethod: 'FORGE_USER_SESSION',
      });
      if (res.processed) {
        updatedAny = true;
      }
    } catch {
      // Non-fatal per page; remaining pages still checked
    }
  }

  if (!updatedAny) {
    return suite;
  }

  return SeederService.getActiveComplianceSuite({
    ...(options?.projectKey ? { projectKey: options.projectKey } : {}),
    ...(options?.issueKeyFilter ? { issueKeyFilter: options.issueKeyFilter } : {}),
  });
}

/**
 * Forge product trigger handler for `avi:jira:updated:issue`, `avi:jira:created:issuelink`,
 * and `avi:jira:deleted:issuelink`. Refreshes tracked LIVE Jira issues automatically so status,
 * title, assignee, labels, and linked Hazard/Test `issuelinks` stay current without manual re-sync.
 */
export async function handleJiraIssueUpdatedTrigger(
  event: JiraIssueUpdatedEvent
): Promise<JiraIssueUpdatedResult> {
  if (!isForgeRuntime()) {
    return { processed: false, affectedHazards: [] };
  }

  const candidateIssueRefs: string[] = [];
  if (typeof event?.issue?.key === 'string' && event.issue.key.trim()) {
    candidateIssueRefs.push(event.issue.key.trim().toUpperCase());
  } else if (event?.issue?.id !== undefined && event?.issue?.id !== null) {
    candidateIssueRefs.push(String(event.issue.id).trim());
  }
  if (event?.issueLink?.sourceIssueId !== undefined && event?.issueLink?.sourceIssueId !== null) {
    candidateIssueRefs.push(String(event.issueLink.sourceIssueId).trim());
  }
  if (event?.issueLink?.destinationIssueId !== undefined && event?.issueLink?.destinationIssueId !== null) {
    candidateIssueRefs.push(String(event.issueLink.destinationIssueId).trim());
  }

  const uniqueRefs = Array.from(new Set(candidateIssueRefs.filter(Boolean)));
  if (uniqueRefs.length === 0) {
    return { processed: false, affectedHazards: [] };
  }

  const client = api.asApp();
  const fetchedByKey = new Map<string, JiraApiIssue>();
  const fetchedIds = new Set<string>();
  let primaryResolvedKey: string | undefined;

  const fetchJiraIssueIntoMap = async (ref: string): Promise<JiraApiIssue | undefined> => {
    try {
      const resp = await client.requestJira(
        route`/rest/api/3/issue/${ref}?fields=summary,status,assignee,labels,issuetype,project,issuelinks`
      );
      if (resp.status === 200) {
        const parsed = (await resp.json()) as JiraApiIssue;
        if (typeof parsed?.key === 'string' && parsed.key.trim()) {
          const upperKey = parsed.key.trim().toUpperCase();
          fetchedByKey.set(upperKey, parsed);
          fetchedIds.add(upperKey);
          if (parsed.id !== undefined && parsed.id !== null) {
            fetchedIds.add(String(parsed.id).trim());
          }
          if (!primaryResolvedKey) {
            primaryResolvedKey = upperKey;
          }
          return parsed;
        }
      }
    } catch {
      // Ignore transient or deleted-issue 404 refs and continue resolving siblings
    }
    return undefined;
  };

  for (const ref of uniqueRefs) {
    await fetchJiraIssueIntoMap(ref);
  }

  if (!primaryResolvedKey || fetchedByKey.size === 0) {
    return { processed: false, affectedHazards: [] };
  }

  const collectRawIssueLinkKeys = (issuelinks: unknown): Set<string> => {
    const keys = new Set<string>();
    if (!Array.isArray(issuelinks)) return keys;
    for (const raw of issuelinks) {
      if (!raw || typeof raw !== 'object') continue;
      const entry = raw as JiraIssueLinkEntry;
      for (const side of [entry.inwardIssue, entry.outwardIssue]) {
        if (typeof side?.key === 'string' && side.key.trim()) {
          keys.add(side.key.trim().toUpperCase());
        }
      }
    }
    return keys;
  };

  const isDeletedLinkEvent = event?.eventType === 'avi:jira:deleted:issuelink';

  for (let attempt = 1; attempt <= MAX_CAS_RETRY_ATTEMPTS; attempt++) {
    const { summary: suite, version } = await SeederService.getSuiteWithVersion();
    if (suite.datasetMode !== 'LIVE' || suite.initialized === false || suite.traceLinks.length === 0) {
      return { processed: false, issueKey: primaryResolvedKey, affectedHazards: [] };
    }

    const matchingIndices: number[] = [];
    suite.traceLinks.forEach((link, idx) => {
      const workKey = (link.work?.key || '').trim().toUpperCase();
      const hazKey = (link.hazard?.key || '').trim().toUpperCase();
      const testKey = (link.test?.testKey || '').trim().toUpperCase();
      const revKey = (link.reverificationTaskKey || '').trim().toUpperCase();
      if (
        (workKey && fetchedByKey.has(workKey)) ||
        (hazKey && fetchedByKey.has(hazKey)) ||
        (testKey && fetchedByKey.has(testKey)) ||
        (revKey && fetchedByKey.has(revKey)) ||
        (link.work?.id && fetchedIds.has(String(link.work.id).trim())) ||
        (link.hazard?.id && fetchedIds.has(String(link.hazard.id).trim())) ||
        (link.test?.id && fetchedIds.has(String(link.test.id).trim()))
      ) {
        matchingIndices.push(idx);
      }
    });

    if (matchingIndices.length === 0) {
      return { processed: false, issueKey: primaryResolvedKey, affectedHazards: [] };
    }

    // Ensure every affected link's anchoring Jira work item is fetched so issuelinks reconciliation has current truth.
    for (const idx of matchingIndices) {
      const wk = (suite.traceLinks[idx].work?.key || '').trim().toUpperCase();
      if (wk && JIRA_ISSUE_KEY_RE.test(wk) && !fetchedByKey.has(wk)) {
        await fetchJiraIssueIntoMap(wk);
      }
    }

    const updatedLinks = suite.traceLinks.map(cloneJsonValue);
    const affectedHazards: string[] = [];
    const part11Secret = (process.env.MEDTRACE_PART11_SECRET || '').trim();

    for (const idx of matchingIndices) {
      const link = updatedLinks[idx];
      const workKeyUpper = (link.work?.key || '').trim().toUpperCase();
      const hazKeyUpper = (link.hazard?.key || '').trim().toUpperCase();
      const testKeyUpper = (link.test?.testKey || '').trim().toUpperCase();

      const workIssue = workKeyUpper ? fetchedByKey.get(workKeyUpper) : undefined;
      let hazDowngraded = false;
      let testDowngraded = false;

      if (workIssue) {
        const workFields = workIssue.fields || {};
        const workLabels = normalizeStringArray(workFields.labels);
        link.work.title = workFields.summary || link.work.title;
        link.work.status = mapJiraStatusToWorkStatus(workFields.status);
        link.work.assignee = workFields.assignee?.displayName || 'Unassigned';

        const rawLinks = Array.isArray(workFields.issuelinks) ? workFields.issuelinks : [];
        const rawLinkedKeys = collectRawIssueLinkKeys(rawLinks);
        const linked = resolveLinkedHazardAndTest(
          extractLinkedIssueCandidates(rawLinks, fetchedByKey)
        );

        if (linked.linkedHazard) {
          link.hazard.id = linked.linkedHazard.id;
          link.hazard.key = linked.linkedHazard.key;
          link.hazard.title = linked.linkedHazard.summary || link.hazard.title;
          link.hazard.source = 'JIRA_ISSUE';
          if (link.graphMetadata) {
            link.graphMetadata.hazardAri = `ari:cloud:jira::issue/${linked.linkedHazard.key}`;
            link.graphMetadata.edgeType = linked.linkedHazard.relationshipLabel || link.graphMetadata.edgeType;
          }
        } else if (link.hazard.source === 'JIRA_ISSUE' && Array.isArray(workFields.issuelinks)) {
          const fallbackHazKey = `HAZ-${workKeyUpper}`;
          link.hazard.id = fallbackHazKey.toLowerCase();
          link.hazard.key = fallbackHazKey;
          link.hazard.title = workFields.summary || `Hazard for ${workKeyUpper}`;
          link.hazard.source = 'APP_MANAGED';
          hazDowngraded = true;
          if (link.graphMetadata) {
            link.graphMetadata.hazardAri = `ari:cloud:medtrace::iso14971-hazard/${fallbackHazKey}`;
          }
        }

        if (linked.linkedTest) {
          const changedTest =
            link.test.testKey.toUpperCase() !== linked.linkedTest.key.toUpperCase();
          link.test.id = linked.linkedTest.id;
          link.test.testKey = linked.linkedTest.key;
          link.test.title = linked.linkedTest.summary || link.test.title;
          link.test.source = 'JIRA_ISSUE';
          if (changedTest) {
            link.test.status = 'UNTESTED';
            delete link.test.evidenceUrl;
            delete link.test.executionDate;
            delete link.test.recordedBy;
            delete link.test.notes;
          }
        } else if (link.test.source === 'JIRA_ISSUE' && Array.isArray(workFields.issuelinks)) {
          const fallbackTestKey = `TEST-${workKeyUpper}`;
          link.test.id = fallbackTestKey.toLowerCase();
          link.test.testKey = fallbackTestKey;
          link.test.title = `Verification Test for ${workKeyUpper}`;
          link.test.source = 'APP_MANAGED';
          link.test.status = 'UNTESTED';
          delete link.test.evidenceUrl;
          delete link.test.executionDate;
          delete link.test.recordedBy;
          delete link.test.notes;
          testDowngraded = true;
        }

        if (linked.linkedReverification) {
          link.reverificationTaskKey = linked.linkedReverification.key;
        } else if (
          link.reverificationTaskKey &&
          Array.isArray(workFields.issuelinks) &&
          !rawLinkedKeys.has(link.reverificationTaskKey.trim().toUpperCase())
        ) {
          delete link.reverificationTaskKey;
        }

        if (workLabels.length > 0 && !linked.linkedHazard) {
          const inferred = inferRiskClass(workLabels);
          link.hazard.riskClass = inferred.riskClass;
          delete link.hazard.severity;
          delete link.hazard.probability;
          if (inferred.safetyClassAssigned === false) {
            link.hazard.safetyClassAssigned = false;
          } else {
            delete link.hazard.safetyClassAssigned;
          }
        }
      }

      const currentHazKey = (link.hazard?.key || '').trim().toUpperCase();
      const hazIssue = !hazDowngraded
        ? fetchedByKey.get(currentHazKey) || (hazKeyUpper ? fetchedByKey.get(hazKeyUpper) : undefined)
        : undefined;
      if (hazIssue && !hazDowngraded && (!link.hazard.source || link.hazard.source === 'JIRA_ISSUE' || hazIssue.key?.toUpperCase() === currentHazKey)) {
        const hazFields = hazIssue.fields || {};
        const hazLabels = normalizeStringArray(hazFields.labels);
        link.hazard.title = hazFields.summary || link.hazard.title;
        link.hazard.source = 'JIRA_ISSUE';
        if (hazLabels.length > 0) {
          const inferred = inferRiskClass(hazLabels);
          if (inferred.safetyClassAssigned !== false) {
            link.hazard.riskClass = inferred.riskClass;
            delete link.hazard.severity;
            delete link.hazard.probability;
            delete link.hazard.safetyClassAssigned;
          }
        }
      }

      const currentTestKey = (link.test?.testKey || '').trim().toUpperCase();
      const testIssue = !testDowngraded
        ? fetchedByKey.get(currentTestKey) || (testKeyUpper ? fetchedByKey.get(testKeyUpper) : undefined)
        : undefined;
      if (testIssue && !testDowngraded) {
        const testFields = testIssue.fields || {};
        link.test.title = testFields.summary || link.test.title;
        link.test.source = 'JIRA_ISSUE';
      }

      if (isDeletedLinkEvent && link.reverificationTaskKey) {
        const revUpper = link.reverificationTaskKey.trim().toUpperCase();
        const revIssue = fetchedByKey.get(revUpper);
        if (revIssue && Array.isArray(revIssue.fields?.issuelinks)) {
          const revLinkedKeys = collectRawIssueLinkKeys(revIssue.fields.issuelinks);
          if (workKeyUpper && !revLinkedKeys.has(workKeyUpper)) {
            delete link.reverificationTaskKey;
          }
        }
      }

      const evaluated = ComplianceEngine.evaluateTraceLink(
        link.hazard,
        link.spec,
        link.work,
        link.test,
        link.signature,
        link.graphMetadata,
        {
          linkId: link.id,
          part11Secret,
          requireCryptographicSeal: true,
          requireTestEvidence: true,
          reverificationTaskKey: link.reverificationTaskKey,
        }
      );
      evaluated.hazard.status = ComplianceEngine.deriveHazardStatus(evaluated.complianceState);
      updatedLinks[idx] = evaluated;
      if (!affectedHazards.includes(evaluated.hazard.key)) {
        affectedHazards.push(evaluated.hazard.key);
      }
    }

    const eventNowIso = new Date().toISOString();
    const updated = ComplianceEngine.generateComplianceReport(
      updatedLinks,
      suite.datasetMode,
      suite.projectName,
      {
        initialized: true,
        lastSyncedAt: eventNowIso,
        syncIncomplete: suite.syncIncomplete,
        incompleteProjectKeys: suite.incompleteProjectKeys,
      }
    );

    const affectedWorkProject = updatedLinks[matchingIndices[0]]?.work?.key?.split('-')[0];
    const projectKey = affectedWorkProject || primaryResolvedKey.split('-')[0];

    try {
      await commitSuiteMutation({
        summary: updated,
        expectedVersion: version ?? 0,
        auditEntry: {
          actorAccountId: String(
            event?.atlassianId || event?.context?.accountId || 'jira-event-trigger'
          ),
          action: 'SYNC_LIVE',
          targetKey: primaryResolvedKey,
          details: {
            projectKey,
            issueKey: primaryResolvedKey,
            eventType: event?.eventType || 'avi:jira:updated:issue',
            affectedHazards,
            lastSyncedAt: eventNowIso,
          },
          authMethod: 'JIRA_EVENT_TRIGGER',
        },
      });
      return { processed: true, issueKey: primaryResolvedKey, affectedHazards };
    } catch (err: unknown) {
      if (isConcurrencyError(err) && attempt < MAX_CAS_RETRY_ATTEMPTS) {
        continue;
      }
      throw err;
    }
  }

  throw new Error(
    `Failed to persist Jira issue trigger sync for ${primaryResolvedKey} after ${MAX_CAS_RETRY_ATTEMPTS} attempts.`
  );
}
