import api, { route } from '@forge/api';
import { AuditLogService } from './audit-log';
import { ComplianceEngine } from './compliance-engine';
import { JIRA_ISSUE_KEY_RE, JIRA_PROJECT_KEY_RE } from './crypto-utils';
import { isForgeRuntime } from './runtime';
import {
  AuthorizedUserIdentity,
  BlastRadiusReport,
  ComplianceSummary,
  ConfluenceSpec,
  JiraWorkItem,
  TraceLink,
} from './types';

type AuditAppendInput = Parameters<typeof AuditLogService.append>[0];
type AuditAuthMethod = NonNullable<AuditAppendInput['authMethod']>;

/**
 * Context supplied to a `UserIdentityResolver` when authenticating a Part 11 signatory.
 */
export interface UserIdentityResolverContext {
  actorAccountId: string;
  extensionType?: string;
  projectKey?: string;
  spaceKey?: string;
  authMethod?: AuditAuthMethod;
}

/**
 * Authoritative identity and role resolver used to bind Part 11 signatures on the server.
 */
export interface UserIdentityResolver {
  resolveSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity>;
}

let customUserIdentityResolver: UserIdentityResolver | null = null;

/**
 * Overrides the active `UserIdentityResolver` (pass `null` to restore runtime default).
 */
export function setUserIdentityResolver(resolver: UserIdentityResolver | null): void {
  customUserIdentityResolver = resolver;
}

const localFallbackIdentityResolver: UserIdentityResolver = {
  async resolveSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity> {
    return {
      accountId: ctx.actorAccountId,
      displayName: `accountId:${ctx.actorAccountId}`,
      role: 'Authorized Signatory',
      authSource: 'LOCAL_TEST',
    };
  },
};

function hasConfluenceEditorPermission(operations: Array<{ operation?: string; targetType?: string }>): {
  canEdit: boolean;
  isAdmin: boolean;
} {
  let canEdit = false;
  let isAdmin = false;
  for (const op of operations) {
    const operation = String(op?.operation || '').toLowerCase();
    const targetType = String(op?.targetType || '').toLowerCase();
    if (operation === 'administer') {
      canEdit = true;
      isAdmin = true;
    } else if (
      (operation === 'create' || operation === 'update' || operation === 'delete') &&
      (targetType === 'page' || targetType === 'space' || targetType === 'comment' || targetType === '')
    ) {
      canEdit = true;
    }
  }
  return { canEdit, isAdmin };
}

async function resolveJiraSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity> {
  const myselfResp = await api.asUser().requestJira(route`/rest/api/3/myself?expand=groups`);
  if (myselfResp.status !== 200) {
    throw new Error(`Forbidden: Failed to verify Jira signatory identity (HTTP ${myselfResp.status}).`);
  }
  const userData = (await myselfResp.json()) as {
    accountId?: string;
    displayName?: string;
    emailAddress?: string;
    active?: boolean;
  };
  if (!userData?.accountId || userData.active === false) {
    throw new Error('Forbidden: Authenticated Jira user account is inactive or missing accountId.');
  }
  if (ctx.actorAccountId && userData.accountId !== ctx.actorAccountId) {
    throw new Error('Forbidden: Signatory accountId does not match authenticated Jira session user.');
  }

  const permsRoute = ctx.projectKey?.trim()
    ? route`/rest/api/3/mypermissions?projectKey=${ctx.projectKey.trim()}&permissions=EDIT_ISSUES,ADMINISTER_PROJECTS`
    : route`/rest/api/3/mypermissions?permissions=EDIT_ISSUES,ADMINISTER_PROJECTS`;
  const permsResp = await api.asUser().requestJira(permsRoute);
  if (permsResp.status !== 200) {
    throw new Error(`Forbidden: Unable to verify Jira permissions for signatory (HTTP ${permsResp.status}).`);
  }
  const permsData = (await permsResp.json()) as {
    permissions?: Record<string, { havePermission?: boolean }>;
  };
  const canEdit = Boolean(permsData?.permissions?.EDIT_ISSUES?.havePermission);
  const isAdmin = Boolean(permsData?.permissions?.ADMINISTER_PROJECTS?.havePermission);
  if (!canEdit && !isAdmin) {
    throw new Error('Forbidden: Jira user lacks EDIT_ISSUES or ADMINISTER_PROJECTS permission for Part 11 sign-off.');
  }

  const displayName = (userData.displayName || userData.accountId).trim();
  const role = isAdmin
    ? 'Project Administrator / Compliance Approver'
    : 'Jira Engineering Approver';

  return {
    accountId: userData.accountId,
    displayName: `${displayName} (${userData.accountId})`,
    role,
    emailAddress: userData.emailAddress,
    authSource: 'JIRA_MYSELF',
  };
}

async function resolveConfluenceSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity> {
  const userResp = await api.asUser().requestConfluence(route`/wiki/rest/api/user/current`);
  if (userResp.status !== 200) {
    throw new Error(`Forbidden: Failed to verify Confluence signatory identity (HTTP ${userResp.status}).`);
  }
  const userData = (await userResp.json()) as {
    accountId?: string;
    displayName?: string;
    publicName?: string;
    email?: string;
  };
  if (!userData?.accountId) {
    throw new Error('Forbidden: Authenticated Confluence user response missing accountId.');
  }
  if (ctx.actorAccountId && userData.accountId !== ctx.actorAccountId) {
    throw new Error('Forbidden: Signatory accountId does not match authenticated Confluence session user.');
  }

  const spacesResp = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces?type=global&limit=25`);
  if (spacesResp.status !== 200) {
    throw new Error(`Forbidden: Unable to inspect Confluence global space permissions (HTTP ${spacesResp.status}).`);
  }
  const spacesJson = (await spacesResp.json()) as {
    results?: Array<{ id?: string; key?: string; type?: string }>;
  };
  const globalSpaces = (spacesJson?.results || []).filter(
    (s) => s?.id && (!s.type || s.type.toLowerCase() === 'global') && (!ctx.spaceKey || s.key === ctx.spaceKey)
  );

  let authorizedEditor = false;
  let authorizedAdmin = false;
  for (const space of globalSpaces) {
    const opsResp = await api
      .asUser()
      .requestConfluence(route`/wiki/api/v2/spaces/${space.id!}/operations`);
    if (opsResp.status !== 200) continue;
    const opsJson = (await opsResp.json()) as {
      operations?: Array<{ operation?: string; targetType?: string }>;
    };
    const perms = hasConfluenceEditorPermission(opsJson?.operations || []);
    if (perms.canEdit) {
      authorizedEditor = true;
      if (perms.isAdmin) authorizedAdmin = true;
      break;
    }
  }

  if (!authorizedEditor) {
    throw new Error(
      'Forbidden: Confluence user lacks edit permission in any global space and cannot perform Part 11 sign-off.'
    );
  }

  const displayName = (userData.displayName || userData.publicName || userData.accountId).trim();
  return {
    accountId: userData.accountId,
    displayName: `${displayName} (${userData.accountId})`,
    role: authorizedAdmin
      ? 'Confluence Space Administrator / Compliance Approver'
      : 'Confluence Compliance Approver',
    emailAddress: userData.email,
    authSource: 'CONFLUENCE_CURRENT_USER',
  };
}

/**
 * Production Forge identity resolver querying `/rest/api/3/myself` + `/mypermissions`
 * or Confluence `/wiki/rest/api/user/current` + global-space `/operations` as the calling user.
 */
export const forgeUserIdentityResolver: UserIdentityResolver = {
  async resolveSignerIdentity(ctx: UserIdentityResolverContext): Promise<AuthorizedUserIdentity> {
    if (ctx.actorAccountId.startsWith('service:')) {
      throw new Error('Forbidden: Automated service principals cannot execute human Part 11 signatures.');
    }
    const ext = (ctx.extensionType || '').toLowerCase();
    if (ext.startsWith('confluence:')) {
      return await resolveConfluenceSignerIdentity(ctx);
    }
    if (ext.startsWith('jira:')) {
      return await resolveJiraSignerIdentity(ctx);
    }

    try {
      return await resolveJiraSignerIdentity(ctx);
    } catch (jiraErr) {
      if (jiraErr instanceof Error && jiraErr.message.includes('lacks EDIT_ISSUES')) {
        throw jiraErr;
      }
      try {
        return await resolveConfluenceSignerIdentity(ctx);
      } catch (confErr) {
        if (confErr instanceof Error && confErr.message.startsWith('Forbidden:')) {
          throw confErr;
        }
        throw jiraErr;
      }
    }
  },
};

export function getActiveUserIdentityResolver(): UserIdentityResolver {
  if (customUserIdentityResolver) {
    return customUserIdentityResolver;
  }
  return isForgeRuntime() ? forgeUserIdentityResolver : localFallbackIdentityResolver;
}

/**
 * Retrieves `MEDTRACE_PART11_SECRET` for Part 11 HMAC-SHA256 signing and fails closed if missing.
 */
export function getPart11SigningSecret(): string {
  const secret = (process.env.MEDTRACE_PART11_SECRET || '').trim();
  if (!secret) {
    throw new Error(
      '21 CFR Part 11 configuration error: MEDTRACE_PART11_SECRET environment variable must be set before signing.'
    );
  }
  return secret;
}

/**
 * Maps Jira `fields.status` name and category onto MedTrace's canonical workflow statuses.
 */
export function mapJiraStatusToWorkStatus(statusField?: {
  name?: string;
  statusCategory?: { key?: string; name?: string };
}): JiraWorkItem['status'] {
  const rawName = String(statusField?.name || '').trim().toLowerCase();
  const categoryKey = String(statusField?.statusCategory?.key || '').trim().toLowerCase();
  const categoryName = String(statusField?.statusCategory?.name || '').trim().toLowerCase();

  if (
    categoryKey === 'done' ||
    categoryName === 'done' ||
    rawName === 'done' ||
    rawName === 'closed' ||
    rawName === 'resolved' ||
    rawName === 'verified' ||
    rawName === 'completed' ||
    rawName === 'complete'
  ) {
    return 'Done';
  }
  if (
    rawName === 'under review' ||
    rawName === 'in review' ||
    rawName === 'code review' ||
    rawName === 'qa review' ||
    rawName === 'peer review' ||
    rawName === 'review'
  ) {
    return 'Under Review';
  }
  if (
    categoryKey === 'indeterminate' ||
    categoryName === 'in progress' ||
    rawName === 'in progress' ||
    rawName === 'in development' ||
    rawName === 'active' ||
    rawName === 'doing'
  ) {
    return 'In Progress';
  }
  return 'To Do';
}

export { JIRA_PROJECT_KEY_RE, JIRA_ISSUE_KEY_RE };

interface JiraBrowsePermissionEntry {
  havePermission?: boolean;
}

interface JiraBrowsePermissionsPayload {
  active?: unknown;
  permissions?: Record<string, JiraBrowsePermissionEntry | undefined>;
}

function isIdentityHttpOk(res: { ok?: boolean; status: number }): boolean {
  return typeof res.ok === 'boolean' ? res.ok : res.status >= 200 && res.status < 300;
}

/**
 * Extracts a canonical Jira project key from an issue key or synthetic `HAZ-<PROJ>-<NUM>` /
 * `TEST-<PROJ>-<NUM>` identifier without treating synthetic `HAZ-<NUM>` or `TEST-<NUM>` keys as Jira projects.
 */
export function extractJiraProjectKeyFromRawKey(
  rawKey?: unknown,
  source?: 'JIRA_ISSUE' | 'APP_MANAGED'
): string | undefined {
  if (typeof rawKey !== 'string') return undefined;
  const upper = rawKey.trim().toUpperCase();
  if (!upper) return undefined;

  if (upper.startsWith('HAZ-') || upper.startsWith('TEST-')) {
    const stripped = upper.replace(/^(?:HAZ|TEST)-/i, '');
    if (JIRA_ISSUE_KEY_RE.test(stripped)) {
      return stripped.split('-')[0];
    }
    if (source === 'JIRA_ISSUE' && JIRA_ISSUE_KEY_RE.test(upper)) {
      return upper.split('-')[0];
    }
    return undefined;
  }

  if (JIRA_ISSUE_KEY_RE.test(upper)) {
    return upper.split('-')[0];
  }
  return undefined;
}

function normalizeJiraIssueCandidate(
  rawKey?: unknown,
  source?: 'JIRA_ISSUE' | 'APP_MANAGED'
): string | undefined {
  if (typeof rawKey !== 'string') return undefined;
  const upper = rawKey.trim().toUpperCase();
  if (!upper) return undefined;

  if (upper.startsWith('HAZ-') || upper.startsWith('TEST-')) {
    const stripped = upper.replace(/^(?:HAZ|TEST)-/i, '');
    if (JIRA_ISSUE_KEY_RE.test(stripped)) {
      return stripped;
    }
    if (source === 'JIRA_ISSUE' && JIRA_ISSUE_KEY_RE.test(upper)) {
      return upper;
    }
    return undefined;
  }

  return JIRA_ISSUE_KEY_RE.test(upper) ? upper : undefined;
}

/**
 * Collects every real Jira issue key referenced across work, hazard, verification test, and re-verification fields.
 */
export function extractAllJiraIssueKeysFromLink(link: TraceLink): string[] {
  const keys = new Set<string>();
  const candidates: Array<{ raw: unknown; source?: 'JIRA_ISSUE' | 'APP_MANAGED' }> = [
    { raw: link.work?.key, source: 'JIRA_ISSUE' },
    { raw: link.hazard?.key, source: link.hazard?.source },
    { raw: link.test?.testKey, source: link.test?.source },
    { raw: link.reverificationTaskKey, source: 'JIRA_ISSUE' },
  ];
  for (const c of candidates) {
    const issueKey = normalizeJiraIssueCandidate(c.raw, c.source);
    if (issueKey) keys.add(issueKey);
  }
  return Array.from(keys);
}

/**
 * Collects every distinct Jira project key referenced anywhere in a TraceLink (primary + secondary artifacts).
 */
export function extractAllJiraProjectKeysFromLink(link: TraceLink): string[] {
  const projs = new Set<string>();
  const candidates: Array<{ raw: unknown; source?: 'JIRA_ISSUE' | 'APP_MANAGED' }> = [
    { raw: link.work?.key, source: 'JIRA_ISSUE' },
    { raw: link.hazard?.key, source: link.hazard?.source },
    { raw: link.test?.testKey, source: link.test?.source },
    { raw: link.reverificationTaskKey, source: 'JIRA_ISSUE' },
  ];
  for (const c of candidates) {
    const proj = extractJiraProjectKeyFromRawKey(c.raw, c.source);
    if (proj) projs.add(proj);
  }
  return Array.from(projs);
}

/**
 * Resolves the primary Jira project key anchoring a TraceLink (prefers work item, then native hazard/test/task).
 */
export function extractPrimaryJiraProjectKeyFromLink(link: TraceLink): string | undefined {
  return (
    extractJiraProjectKeyFromRawKey(link.work?.key, 'JIRA_ISSUE') ||
    extractJiraProjectKeyFromRawKey(link.hazard?.key, link.hazard?.source) ||
    extractJiraProjectKeyFromRawKey(link.test?.testKey, link.test?.source) ||
    extractJiraProjectKeyFromRawKey(link.reverificationTaskKey, 'JIRA_ISSUE')
  );
}

export interface JiraBrowsePermissionResult {
  httpOk: boolean;
  status: number;
  inactive: boolean;
  allowed: boolean;
}

/**
 * Checks Jira `BROWSE_PROJECTS` permission for the calling user with HTTP/inactive metadata.
 */
export async function checkJiraBrowsePermissionDetailed(target?: {
  projectKey?: string;
  issueKey?: string;
}): Promise<JiraBrowsePermissionResult> {
  const permRoute = target?.issueKey
    ? route`/rest/api/3/mypermissions?issueKey=${target.issueKey}&permissions=BROWSE_PROJECTS`
    : target?.projectKey
    ? route`/rest/api/3/mypermissions?projectKey=${target.projectKey}&permissions=BROWSE_PROJECTS`
    : route`/rest/api/3/mypermissions?permissions=BROWSE_PROJECTS`;

  try {
    const res = await api.asUser().requestJira(permRoute);
    if (!isIdentityHttpOk(res)) {
      return { httpOk: false, status: res.status, inactive: false, allowed: false };
    }
    const data = (await res.json().catch(() => ({}))) as JiraBrowsePermissionsPayload;
    if (data.active === false) {
      return { httpOk: true, status: res.status, inactive: true, allowed: false };
    }
    const browsePerm = data.permissions?.BROWSE_PROJECTS;
    const allowed =
      browsePerm !== undefined
        ? browsePerm.havePermission === true
        : data.permissions?.EDIT_ISSUES?.havePermission === true ||
          data.permissions?.ADMINISTER_PROJECTS?.havePermission === true;
    return { httpOk: true, status: res.status, inactive: false, allowed };
  } catch {
    return { httpOk: false, status: 500, inactive: false, allowed: false };
  }
}

/**
 * Checks Jira `BROWSE_PROJECTS` permission for the calling user (failing closed on errors or inactive accounts).
 */
export async function hasJiraBrowsePermissionForCaller(target?: {
  projectKey?: string;
  issueKey?: string;
}): Promise<boolean> {
  const res = await checkJiraBrowsePermissionDetailed(target);
  return res.httpOk && !res.inactive && res.allowed;
}

/**
 * Checks whether the calling user can read a Confluence page via `/wiki/api/v2/pages/{pageId}` (fail-closed).
 */
export async function canReadConfluencePageForCaller(pageId: string): Promise<boolean> {
  const cleanId = pageId.trim();
  if (!cleanId) return false;
  try {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/pages/${cleanId}`);
    return isIdentityHttpOk(res);
  } catch {
    return false;
  }
}

function redactStringWithRestrictedLink(text: string, link: TraceLink): string {
  const placeholder = 'Restricted Confluence Specification';
  let out = text;
  const origTitle = (link.spec?.title || '').trim();
  if (origTitle && out.includes(origTitle)) {
    out = out.split(origTitle).join(placeholder);
    const shortCode = origTitle.split(':')[0].trim();
    if (/^[a-z]{2,10}-\d+$/i.test(shortCode) && out.includes(shortCode)) {
      out = out.split(shortCode).join(placeholder);
    }
  }
  for (const hash of [
    link.spec?.sha256Hash,
    link.spec?.lastSignedHash,
    link.signature?.artifactSha256,
  ]) {
    const cleanHash = (hash || '').trim();
    if (cleanHash.length >= 8) {
      if (out.includes(cleanHash)) {
        out = out.split(cleanHash).join('[redacted]');
      }
      const prefix = cleanHash.slice(0, 8);
      if (out.includes(prefix)) {
        out = out.split(prefix).join('[redacted]');
      }
    }
  }
  return out;
}

function redactTraceLinkConfluenceSpec(link: TraceLink): TraceLink {
  const placeholder = 'Restricted Confluence Specification';
  const redactedSpec: ConfluenceSpec = {
    ...link.spec,
    title: placeholder,
    version: 0,
    sha256Hash: '',
    lastSignedHash: '',
    specRestricted: true,
    contentSnippet: 'Confluence specification content hidden (caller lacks Confluence read access).',
  };

  return {
    ...link,
    spec: redactedSpec,
    violations: link.violations.map((v) => redactStringWithRestrictedLink(v, link)),
    signature: {
      ...link.signature,
      artifactSha256: '',
      ...(link.signature.invalidationReason
        ? { invalidationReason: redactStringWithRestrictedLink(link.signature.invalidationReason, link) }
        : {}),
    },
  };
}

/**
 * Redacts restricted Confluence specification metadata and hashes from an already-computed `BlastRadiusReport`
 * without altering the underlying deterministic graph verdicts.
 */
export function redactBlastRadiusReport(
  report: BlastRadiusReport,
  sourceLinks: TraceLink[],
  restrictedPageIds: ReadonlySet<string>
): BlastRadiusReport {
  if (restrictedPageIds.size === 0) {
    return report;
  }
  const restrictedLinks = sourceLinks.filter((l) => {
    const pid = typeof l.spec?.pageId === 'string' ? l.spec.pageId.trim() : '';
    return pid !== '' && restrictedPageIds.has(pid);
  });
  if (restrictedLinks.length === 0) {
    return report;
  }
  const scrub = (text: string): string => {
    let out = text;
    for (const link of restrictedLinks) {
      out = redactStringWithRestrictedLink(out, link);
    }
    return out;
  };

  return {
    ...report,
    triggerArtifact: {
      ...report.triggerArtifact,
      title: scrub(report.triggerArtifact.title),
      deltaReason: scrub(report.triggerArtifact.deltaReason),
    },
    traversalPath: report.traversalPath.map((edge) => ({
      ...edge,
      from: scrub(edge.from),
      to: scrub(edge.to),
      effect: scrub(edge.effect),
    })),
    transitiveActionPlan: report.transitiveActionPlan.map(scrub),
  };
}

export interface AuthorizeLiveSuiteOptions {
  extensionType?: string;
  projectKey?: string;
  checkConfluencePages?: boolean;
}

export interface AuthorizedLiveSuiteResult {
  unredactedSuite: ComplianceSummary;
  outboundSuite: ComplianceSummary;
  restrictedPageIds: Set<string>;
}

/**
 * Authorizes a LIVE compliance suite against Jira `BROWSE_PROJECTS` (for all associated artifacts) and
 * Confluence page read permissions. Computes verdicts on the unredacted server-side model FIRST, then
 * produces a clean outbound representation with restricted spec fields and `signature.artifactSha256` scrubbed.
 */
export async function authorizeAndFilterLiveSuiteDetailed(
  suite: ComplianceSummary,
  options?: AuthorizeLiveSuiteOptions
): Promise<AuthorizedLiveSuiteResult> {
  const emptyRestricted = new Set<string>();
  if (
    suite.datasetMode !== 'LIVE' ||
    suite.initialized === false ||
    suite.traceLinks.length === 0
  ) {
    return { unredactedSuite: suite, outboundSuite: suite, restrictedPageIds: emptyRestricted };
  }

  const runtimeActive = isForgeRuntime();
  const cleanScopeProject = options?.projectKey?.trim().toUpperCase() || undefined;
  if (!cleanScopeProject && !runtimeActive) {
    return { unredactedSuite: suite, outboundSuite: suite, restrictedPageIds: emptyRestricted };
  }

  const checkConfluence = runtimeActive && options?.checkConfluencePages !== false;
  const projectPermCache = new Map<string, boolean>();
  const confluencePagePermCache = new Map<string, boolean>();
  let globalBrowsePerm: boolean | undefined;

  const canBrowseProject = async (projectKey: string): Promise<boolean> => {
    const clean = projectKey.trim().toUpperCase();
    if (cleanScopeProject) {
      if (clean === cleanScopeProject) return true;
      if (!runtimeActive) return false;
    }
    if (!runtimeActive) return true;
    if (projectPermCache.has(clean)) {
      return projectPermCache.get(clean) === true;
    }
    const allowed = await hasJiraBrowsePermissionForCaller({ projectKey: clean });
    projectPermCache.set(clean, allowed);
    return allowed;
  };

  const canBrowseGlobal = async (): Promise<boolean> => {
    if (!runtimeActive) return !cleanScopeProject;
    if (globalBrowsePerm === undefined) {
      globalBrowsePerm = await hasJiraBrowsePermissionForCaller(undefined);
    }
    return globalBrowsePerm;
  };

  const canReadPage = async (pageId: string): Promise<boolean> => {
    const cleanId = pageId.trim();
    if (!cleanId) return false;
    if (confluencePagePermCache.has(cleanId)) {
      return confluencePagePermCache.get(cleanId) === true;
    }
    const allowed = await canReadConfluencePageForCaller(cleanId);
    confluencePagePermCache.set(cleanId, allowed);
    return allowed;
  };

  const jiraAuthorizedLinks: TraceLink[] = [];
  const restrictedPageIds = new Set<string>();

  for (const link of suite.traceLinks) {
    const primaryProj = extractPrimaryJiraProjectKeyFromLink(link);
    const allProjs = extractAllJiraProjectKeysFromLink(link);

    let jiraAllowed = false;
    if (cleanScopeProject) {
      if (primaryProj !== cleanScopeProject) {
        continue;
      }
      const secondaryProjs = allProjs.filter((p) => p !== cleanScopeProject);
      jiraAllowed = true;
      for (const sec of secondaryProjs) {
        if (!(await canBrowseProject(sec))) {
          jiraAllowed = false;
          break;
        }
      }
    } else if (allProjs.length > 0) {
      jiraAllowed = true;
      for (const projKey of allProjs) {
        if (!(await canBrowseProject(projKey))) {
          jiraAllowed = false;
          break;
        }
      }
    } else {
      jiraAllowed = await canBrowseGlobal();
    }

    if (!jiraAllowed) {
      continue;
    }

    jiraAuthorizedLinks.push(link);
  }

  if (checkConfluence && jiraAuthorizedLinks.length > 0) {
    const pageIdsToCheck = Array.from(
      new Set(
        jiraAuthorizedLinks
          .map((link) => (typeof link.spec?.pageId === 'string' && !link.spec?.isMissingSentinel ? link.spec.pageId.trim() : ''))
          .filter(Boolean)
      )
    );
    const CONFLUENCE_PERM_BATCH_SIZE = 5;
    for (let i = 0; i < pageIdsToCheck.length; i += CONFLUENCE_PERM_BATCH_SIZE) {
      const batch = pageIdsToCheck.slice(i, i + CONFLUENCE_PERM_BATCH_SIZE);
      const results = await Promise.all(batch.map((pageId) => canReadPage(pageId)));
      for (let j = 0; j < batch.length; j += 1) {
        if (!results[j]) {
          restrictedPageIds.add(batch[j]);
        }
      }
    }
  }

  const scopedName =
    cleanScopeProject && !suite.projectName.toUpperCase().startsWith(cleanScopeProject)
      ? `${cleanScopeProject} (${suite.projectName})`
      : suite.projectName;

  const hasProjectIncompleteList =
    Array.isArray(suite.incompleteProjectKeys) && suite.incompleteProjectKeys.length > 0;
  const scopedSyncIncomplete =
    cleanScopeProject && hasProjectIncompleteList
      ? suite.incompleteProjectKeys!.includes(cleanScopeProject)
      : suite.syncIncomplete;

  const unredactedSuite =
    jiraAuthorizedLinks.length === suite.traceLinks.length
      ? suite
      : ComplianceEngine.generateComplianceReport(
          jiraAuthorizedLinks,
          suite.datasetMode,
          scopedName,
          {
            storageFormat: suite.storageFormat,
            auditEntryCount: suite.auditEntryCount,
            auditHeadHash: suite.auditHeadHash,
            initialized: suite.initialized,
            lastAuditTimestamp: suite.lastAuditTimestamp,
            lastSyncedAt: suite.lastSyncedAt,
            syncIncomplete: scopedSyncIncomplete,
            ...(hasProjectIncompleteList && (!cleanScopeProject || suite.incompleteProjectKeys!.includes(cleanScopeProject))
              ? {
                  incompleteProjectKeys: cleanScopeProject ? [cleanScopeProject] : suite.incompleteProjectKeys,
                }
              : {}),
          }
        );

  if (restrictedPageIds.size === 0) {
    return {
      unredactedSuite,
      outboundSuite: unredactedSuite,
      restrictedPageIds,
    };
  }

  const restrictedLinks = unredactedSuite.traceLinks.filter((l) => {
    const pid = typeof l.spec?.pageId === 'string' ? l.spec.pageId.trim() : '';
    return pid !== '' && restrictedPageIds.has(pid);
  });

  const scrubBlockingReason = (reason: string): string => {
    let out = reason;
    for (const link of restrictedLinks) {
      out = redactStringWithRestrictedLink(out, link);
    }
    return out;
  };

  const outboundSuite: ComplianceSummary = {
    ...unredactedSuite,
    blockingReasons: unredactedSuite.blockingReasons.map(scrubBlockingReason),
    traceLinks: unredactedSuite.traceLinks.map((link) => {
      const pid = typeof link.spec?.pageId === 'string' ? link.spec.pageId.trim() : '';
      return pid && restrictedPageIds.has(pid) ? redactTraceLinkConfluenceSpec(link) : link;
    }),
  };

  return {
    unredactedSuite,
    outboundSuite,
    restrictedPageIds,
  };
}

/**
 * Shared fail-closed authorization filter returning the outbound ComplianceSummary directly.
 */
export async function authorizeAndFilterLiveSuite(
  suite: ComplianceSummary,
  options?: AuthorizeLiveSuiteOptions
): Promise<ComplianceSummary> {
  const { outboundSuite } = await authorizeAndFilterLiveSuiteDetailed(suite, options);
  return outboundSuite;
}

