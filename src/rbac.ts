import api, { route } from '@forge/api';
import { SeederService } from './seeder';
import {
  authorizeAndFilterLiveSuite,
  canReadConfluencePageForCaller,
  checkJiraBrowsePermissionDetailed,
  extractAllJiraIssueKeysFromLink,
  extractAllJiraProjectKeysFromLink,
  extractJiraProjectKeyFromRawKey,
  hasJiraBrowsePermissionForCaller,
} from './seeder-identity';
import { isForgeRuntime } from './runtime';
import { isHttpOk, JIRA_ISSUE_KEY_RE, JIRA_PROJECT_KEY_RE } from './crypto-utils';
import { AuditLogEntry, ComplianceSummary, TraceLink } from './types';

export interface ForgeExtensionPayload {
  type?: string;
  project?: {
    key?: string;
    id?: string;
  };
  issue?: {
    key?: string;
    id?: string;
  };
  space?: {
    key?: string;
    id?: string;
  };
  content?: {
    id?: string;
    type?: string;
  };
}

export interface ForgeResolverContext {
  accountId?: string;
  cloudId?: string;
  installContext?: string;
  principal?: {
    accountId?: string;
  };
  extension?: ForgeExtensionPayload;
  permissions?: string[];
}

export interface ForgeResolverRequest<TPayload = unknown> {
  payload?: TPayload;
  context?: ForgeResolverContext;
}

export interface AuthorizedCaller {
  accountId: string;
  extensionType: string;
  projectKey?: string;
  spaceKey?: string;
  spaceId?: string;
  contentId?: string;
}

export interface AuthorizationTarget {
  projectKey?: string;
  issueKey?: string;
  spaceId?: string;
  contentId?: string;
}

const CONFLUENCE_ID_RE = /^[a-zA-Z0-9_-]{1,64}$/;
const CONFLUENCE_GLOBAL_SPACES_PROBE_LIMIT = 10;

export function extractCallerAccountId(req?: ForgeResolverRequest<unknown>): string | undefined {
  const direct = req?.context?.accountId;
  if (typeof direct === 'string' && direct.trim().length > 0) {
    return direct.trim();
  }
  const principal = req?.context?.principal?.accountId;
  if (typeof principal === 'string' && principal.trim().length > 0) {
    return principal.trim();
  }
  return undefined;
}

interface NormalizedAuthScope {
  extensionType: string;
  isConfluence: boolean;
  effectiveProjectKey?: string;
  effectiveIssueKey?: string;
  effectiveSpaceId?: string;
  effectiveContentId?: string;
  extSpaceKey?: string;
  hasExplicitJiraTarget: boolean;
  hasExplicitConfluenceTarget: boolean;
}

function normalizeAndValidateScope(
  ext: ForgeExtensionPayload | undefined,
  target?: AuthorizationTarget
): NormalizedAuthScope {
  const extensionType = typeof ext?.type === 'string' ? ext.type.trim().toLowerCase() : '';
  const isConfluence = extensionType.startsWith('confluence');

  const extProjectKey =
    typeof ext?.project?.key === 'string' && ext.project.key.trim().length > 0
      ? ext.project.key.trim().toUpperCase()
      : undefined;
  const rawTargetProjectKey =
    typeof target?.projectKey === 'string' && target.projectKey.trim().length > 0
      ? target.projectKey.trim().toUpperCase()
      : undefined;

  if (rawTargetProjectKey && !JIRA_PROJECT_KEY_RE.test(rawTargetProjectKey)) {
    throw new Error('Bad Request: Invalid Jira projectKey format.');
  }

  const rawTargetIssueKey =
    typeof target?.issueKey === 'string' && target.issueKey.trim().length > 0
      ? target.issueKey.trim().toUpperCase()
      : undefined;

  if (rawTargetIssueKey && !JIRA_ISSUE_KEY_RE.test(rawTargetIssueKey)) {
    throw new Error('Bad Request: Invalid Jira issueKey format.');
  }

  if (extProjectKey && rawTargetProjectKey && rawTargetProjectKey !== extProjectKey) {
    throw new Error(
      `Forbidden: Cross-project override is not permitted (${rawTargetProjectKey} !== ${extProjectKey}).`
    );
  }

  if (extProjectKey && rawTargetIssueKey) {
    const issueProject = rawTargetIssueKey.split('-')[0];
    if (issueProject !== extProjectKey) {
      throw new Error(
        `Forbidden: Cross-project issue access is not permitted (${rawTargetIssueKey} outside project ${extProjectKey}).`
      );
    }
  }

  if (rawTargetProjectKey && rawTargetIssueKey) {
    const issueProject = rawTargetIssueKey.split('-')[0];
    if (issueProject !== rawTargetProjectKey) {
      throw new Error(
        `Forbidden: Target issue ${rawTargetIssueKey} does not belong to project ${rawTargetProjectKey}.`
      );
    }
  }

  const rawTargetSpaceId =
    typeof target?.spaceId === 'string' && target.spaceId.trim().length > 0
      ? target.spaceId.trim()
      : undefined;
  if (rawTargetSpaceId && !CONFLUENCE_ID_RE.test(rawTargetSpaceId)) {
    throw new Error('Bad Request: Invalid Confluence spaceId format.');
  }

  const rawTargetContentId =
    typeof target?.contentId === 'string' && target.contentId.trim().length > 0
      ? target.contentId.trim()
      : undefined;
  if (rawTargetContentId && !CONFLUENCE_ID_RE.test(rawTargetContentId)) {
    throw new Error('Bad Request: Invalid Confluence contentId format.');
  }

  const extSpaceId =
    typeof ext?.space?.id === 'string' && ext.space.id.trim().length > 0
      ? ext.space.id.trim()
      : undefined;
  const extContentId =
    typeof ext?.content?.id === 'string' && ext.content.id.trim().length > 0
      ? ext.content.id.trim()
      : undefined;
  const extSpaceKey =
    typeof ext?.space?.key === 'string' && ext.space.key.trim().length > 0
      ? ext.space.key.trim()
      : undefined;

  return {
    extensionType: ext?.type || 'jira:globalPage',
    isConfluence,
    effectiveProjectKey: rawTargetProjectKey || extProjectKey,
    effectiveIssueKey: rawTargetIssueKey,
    effectiveSpaceId: rawTargetSpaceId || extSpaceId,
    effectiveContentId: rawTargetContentId || extContentId,
    extSpaceKey,
    hasExplicitJiraTarget: Boolean(rawTargetProjectKey || rawTargetIssueKey),
    hasExplicitConfluenceTarget: Boolean(rawTargetSpaceId || rawTargetContentId),
  };
}

interface JiraPermissionEntry {
  havePermission?: boolean;
}

interface JiraPermissionsResponse {
  permissions?: Record<string, JiraPermissionEntry | undefined>;
}

export async function verifyJiraIdentity(expectedAccountId: string): Promise<void> {
  const res = await api.asUser().requestJira(route`/rest/api/3/myself`);
  if (!isHttpOk(res)) {
    throw new Error(`Forbidden: Jira user session validation failed (HTTP ${res.status}).`);
  }
  const myself = (await res.json().catch(() => ({}))) as {
    accountId?: unknown;
    active?: unknown;
  };
  if (myself.active === false) {
    throw new Error('Forbidden: Jira user account is inactive.');
  }
  if (
    typeof myself.accountId === 'string' &&
    myself.accountId.trim().length > 0 &&
    myself.accountId.trim() !== expectedAccountId
  ) {
    throw new Error('Forbidden: Authenticated Jira session account mismatch.');
  }
}

async function assertJiraReaderPermissions(projectKey?: string, issueKey?: string): Promise<void> {
  const perm = await checkJiraBrowsePermissionDetailed({ projectKey, issueKey });
  if (!perm.httpOk) {
    throw new Error(`Forbidden: Jira user lacks permission (${perm.status}).`);
  }
  if (perm.inactive || !perm.allowed) {
    throw new Error('Forbidden: Requires Jira BROWSE_PROJECTS permission.');
  }
}

export async function assertJiraOperatorPermissions(projectKey?: string, issueKey?: string): Promise<void> {
  const permRoute = issueKey
    ? route`/rest/api/3/mypermissions?issueKey=${issueKey}&permissions=BROWSE_PROJECTS,EDIT_ISSUES,ADMINISTER_PROJECTS`
    : projectKey
    ? route`/rest/api/3/mypermissions?projectKey=${projectKey}&permissions=BROWSE_PROJECTS,EDIT_ISSUES,ADMINISTER_PROJECTS`
    : route`/rest/api/3/mypermissions?permissions=BROWSE_PROJECTS,EDIT_ISSUES,ADMINISTER_PROJECTS`;

  const res = await api.asUser().requestJira(permRoute);
  if (!isHttpOk(res)) {
    throw new Error(`Forbidden: Jira user lacks permission (${res.status}).`);
  }
  const data = (await res.json().catch(() => ({}))) as JiraPermissionsResponse;
  const browsePerm = data.permissions?.BROWSE_PROJECTS;
  if (browsePerm !== undefined && browsePerm.havePermission === false) {
    throw new Error('Forbidden: Requires Jira BROWSE_PROJECTS permission.');
  }
  const canEdit = data.permissions?.EDIT_ISSUES?.havePermission === true;
  const canAdmin = data.permissions?.ADMINISTER_PROJECTS?.havePermission === true;
  if (!canEdit && !canAdmin) {
    throw new Error('Forbidden: Requires Jira EDIT_ISSUES or ADMINISTER_PROJECTS permission.');
  }
}

export async function assertJiraSiteAdminPermissions(expectedAccountId: string): Promise<void> {
  if (!isForgeRuntime()) {
    return;
  }
  await verifyJiraIdentity(expectedAccountId);
  const res = await api
    .asUser()
    .requestJira(route`/rest/api/3/mypermissions?permissions=ADMINISTER`);
  if (!isHttpOk(res)) {
    throw new Error(`Forbidden: Jira site administrator permission check failed (${res.status}).`);
  }
  const data = (await res.json().catch(() => ({}))) as JiraPermissionsResponse;
  if (data.permissions?.ADMINISTER?.havePermission !== true) {
    throw new Error(
      'Forbidden: Requires Jira site administrator (ADMINISTER) permission to overwrite an initialized LIVE compliance suite.'
    );
  }
}

interface ConfluenceOperation {
  operation?: unknown;
  targetType?: unknown;
}

interface ConfluenceSpaceSummary {
  id?: unknown;
  key?: unknown;
  type?: unknown;
}

export type ConfluenceOperationAction = 'create' | 'update' | 'delete' | 'administer';

/**
 * Normalizes a Confluence `/operations` payload into trimmed, lowercase `{ operation, targetType }` entries.
 * Single parsing point shared by every Confluence permission check in `rbac`, `seeder-identity`, and
 * `live-proof-scenario` so the `/operations` semantics never drift between call sites.
 */
export function normalizeConfluenceOperations(
  operations: ReadonlyArray<ConfluenceOperation> | undefined | null
): Array<{ operation: string; targetType: string }> {
  return (Array.isArray(operations) ? operations : [])
    .map((op) => ({
      operation: typeof op?.operation === 'string' ? op.operation.trim().toLowerCase() : '',
      targetType: typeof op?.targetType === 'string' ? op.targetType.trim().toLowerCase() : '',
    }))
    .filter((op) => op.operation !== '');
}

/**
 * Returns true when `operations` grants any of `actions` on any of `targetTypes`.
 * An empty `targetTypes` matches every target type.
 */
export function hasConfluenceWriteOperation(
  operations: ReadonlyArray<ConfluenceOperation> | undefined | null,
  actions: ReadonlyArray<ConfluenceOperationAction>,
  targetTypes: ReadonlyArray<string> = []
): boolean {
  const actionSet = new Set(actions);
  const targetSet = new Set(targetTypes.map((t) => t.trim().toLowerCase()));
  return normalizeConfluenceOperations(operations).some(
    (op) =>
      actionSet.has(op.operation as ConfluenceOperationAction) &&
      (targetSet.size === 0 || targetSet.has(op.targetType))
  );
}

/**
 * Resolves Confluence content-editing capability (`canEdit`) and space-administration capability (`isAdmin`)
 * from a `/operations` payload. Shared by Part 11 Confluence sign-off identity resolution.
 */
export function hasConfluenceEditorPermission(
  operations: ReadonlyArray<ConfluenceOperation> | undefined | null
): { canEdit: boolean; isAdmin: boolean } {
  const normalized = normalizeConfluenceOperations(operations);
  const isAdmin = normalized.some((op) => op.operation === 'administer');
  const canEdit =
    isAdmin ||
    normalized.some(
      (op) =>
        (op.operation === 'create' || op.operation === 'update' || op.operation === 'delete') &&
        (op.targetType === 'page' || op.targetType === 'space' || op.targetType === '')
    );
  return { canEdit, isAdmin };
}

/**
 * Returns true when a `/operations` payload permits creating Confluence pages in a space.
 */
export function hasConfluencePageCreatePermission(
  operations: ReadonlyArray<ConfluenceOperation> | undefined | null
): boolean {
  return normalizeConfluenceOperations(operations).some(
    (op) =>
      (op.operation === 'create' || op.operation === 'administer') &&
      (op.targetType === 'page' || op.targetType === 'space' || op.targetType === '')
  );
}

function hasConfluencePageWriteOps(operations: ConfluenceOperation[]): boolean {
  return hasConfluenceWriteOperation(operations, ['update', 'delete', 'administer'], ['page']);
}

function hasConfluenceSpaceWriteOps(operations: ConfluenceOperation[]): boolean {
  return (
    hasConfluenceWriteOperation(operations, ['administer'], ['space', 'page', '']) ||
    hasConfluenceWriteOperation(operations, ['create', 'update', 'delete'], ['page', 'space'])
  );
}

async function verifyConfluenceIdentity(expectedAccountId: string): Promise<void> {
  const userRes = await api.asUser().requestConfluence(route`/wiki/rest/api/user/current`);
  if (!isHttpOk(userRes)) {
    throw new Error('Forbidden: Confluence user session lacks access.');
  }
  const userData = (await userRes.json().catch(() => ({}))) as {
    accountId?: unknown;
    type?: unknown;
  };
  if (
    userData.type === 'anonymous' ||
    typeof userData.accountId !== 'string' ||
    userData.accountId.trim() !== expectedAccountId
  ) {
    throw new Error('Forbidden: Authenticated Confluence user identity mismatch.');
  }
}

async function assertConfluenceReaderPermissions(spaceId?: string, contentId?: string): Promise<void> {
  if (contentId) {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/pages/${contentId}`);
    if (!isHttpOk(res)) {
      throw new Error(`Forbidden: Confluence user lacks read access to page ${contentId}.`);
    }
    return;
  }
  if (spaceId) {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces/${spaceId}`);
    if (!isHttpOk(res)) {
      throw new Error(`Forbidden: Confluence user lacks read access to space ${spaceId}.`);
    }
    return;
  }
  const res = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces?limit=1`);
  if (!isHttpOk(res)) {
    throw new Error('Forbidden: Confluence user session lacks access.');
  }
}

async function assertConfluenceOperatorPermissions(spaceId?: string, contentId?: string): Promise<void> {
  if (contentId) {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/pages/${contentId}/operations`);
    if (!isHttpOk(res)) {
      throw new Error(`Forbidden: Confluence user lacks edit access to page ${contentId}.`);
    }
    const data = (await res.json().catch(() => ({}))) as { operations?: unknown };
    const ops = Array.isArray(data.operations) ? (data.operations as ConfluenceOperation[]) : [];
    if (!hasConfluencePageWriteOps(ops)) {
      throw new Error('Forbidden: Requires Confluence page update or administer permission.');
    }
    return;
  }

  if (spaceId) {
    const res = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces/${spaceId}/operations`);
    if (!isHttpOk(res)) {
      throw new Error(`Forbidden: Confluence user lacks operator access to space ${spaceId}.`);
    }
    const data = (await res.json().catch(() => ({}))) as { operations?: unknown };
    const ops = Array.isArray(data.operations) ? (data.operations as ConfluenceOperation[]) : [];
    if (!hasConfluenceSpaceWriteOps(ops)) {
      throw new Error('Forbidden: Requires Confluence space create/update/administer permission.');
    }
    return;
  }

  const spacesRes = await api
    .asUser()
    .requestConfluence(route`/wiki/api/v2/spaces?type=global&limit=25`);
  if (!isHttpOk(spacesRes)) {
    throw new Error('Forbidden: Confluence user session lacks access.');
  }
  const spacesData = (await spacesRes.json().catch(() => ({}))) as { results?: unknown };
  const globalSpaces = (Array.isArray(spacesData.results) ? (spacesData.results as ConfluenceSpaceSummary[]) : []).filter(
    (s) => {
      if (typeof s.id !== 'string' || s.id.trim().length === 0) return false;
      const spaceType = typeof s.type === 'string' ? s.type.trim().toLowerCase() : '';
      return spaceType === '' || spaceType === 'global';
    }
  );

  for (const space of globalSpaces.slice(0, CONFLUENCE_GLOBAL_SPACES_PROBE_LIMIT)) {
    const sid = String(space.id).trim();
    const opRes = await api.asUser().requestConfluence(route`/wiki/api/v2/spaces/${sid}/operations`);
    if (!isHttpOk(opRes)) continue;
    const opData = (await opRes.json().catch(() => ({}))) as { operations?: unknown };
    const ops = Array.isArray(opData.operations) ? (opData.operations as ConfluenceOperation[]) : [];
    if (hasConfluenceSpaceWriteOps(ops)) {
      return;
    }
  }

  throw new Error(
    'Forbidden: Confluence operator requires create, update, or administer permission in at least one global space.'
  );
}

/**
 * Verifies authenticated Atlassian caller identity and read permissions (`BROWSE_PROJECTS` / Confluence space/page read),
 * enforcing cross-project confused-deputy checks before executing any read resolver.
 */
export async function assertAuthorizedReader(
  req?: ForgeResolverRequest<unknown>,
  target?: AuthorizationTarget
): Promise<AuthorizedCaller> {
  const accountId = extractCallerAccountId(req);
  if (!accountId) {
    throw new Error('Unauthorized: Authenticated Atlassian accountId is required in resolver context.');
  }

  const scope = normalizeAndValidateScope(req?.context?.extension, target);

  if (isForgeRuntime()) {
    const checkConfluence = scope.isConfluence || scope.hasExplicitConfluenceTarget;
    const checkJira = !scope.isConfluence || scope.hasExplicitJiraTarget;

    if (checkConfluence) {
      await verifyConfluenceIdentity(accountId);
      await assertConfluenceReaderPermissions(scope.effectiveSpaceId, scope.effectiveContentId);
    }

    if (checkJira) {
      await verifyJiraIdentity(accountId);
      await assertJiraReaderPermissions(scope.effectiveProjectKey, scope.effectiveIssueKey);
    }
  }

  return {
    accountId,
    extensionType: scope.extensionType,
    projectKey: scope.effectiveProjectKey,
    spaceKey: scope.extSpaceKey,
    spaceId: scope.effectiveSpaceId,
    contentId: scope.effectiveContentId,
  };
}

/**
 * Verifies authenticated Atlassian caller identity and write/admin permissions (`EDIT_ISSUES` / `ADMINISTER_PROJECTS`,
 * or Confluence page/global-space write operations), blocking read-only viewers and cross-project overrides.
 */
export async function assertAuthorizedOperator(
  req?: ForgeResolverRequest<unknown>,
  target?: AuthorizationTarget
): Promise<AuthorizedCaller> {
  const accountId = extractCallerAccountId(req);
  if (!accountId) {
    throw new Error('Unauthorized: Authenticated Atlassian accountId is required in resolver context.');
  }

  const scope = normalizeAndValidateScope(req?.context?.extension, target);

  if (isForgeRuntime()) {
    const checkConfluence = scope.isConfluence || scope.hasExplicitConfluenceTarget;
    const checkJira = !scope.isConfluence || scope.hasExplicitJiraTarget;

    if (checkConfluence) {
      await verifyConfluenceIdentity(accountId);
      await assertConfluenceOperatorPermissions(scope.effectiveSpaceId, scope.effectiveContentId);
    }

    if (checkJira) {
      await verifyJiraIdentity(accountId);
      await assertJiraOperatorPermissions(scope.effectiveProjectKey, scope.effectiveIssueKey);
    }
  }

  return {
    accountId,
    extensionType: scope.extensionType,
    projectKey: scope.effectiveProjectKey,
    spaceKey: scope.extSpaceKey,
    spaceId: scope.effectiveSpaceId,
    contentId: scope.effectiveContentId,
  };
}

/**
 * Filters and redacts a LIVE compliance suite to only Jira projects and Confluence pages readable by the caller.
 */
export async function filterLiveSuiteForCaller(
  caller: AuthorizedCaller,
  suite: ComplianceSummary,
  options?: { precheckedConfluencePages?: ReadonlyMap<string, boolean> }
): Promise<ComplianceSummary> {
  if (
    suite.datasetMode !== 'LIVE' ||
    suite.initialized === false ||
    suite.traceLinks.length === 0
  ) {
    return suite;
  }

  const runtimeActive = isForgeRuntime();
  if (!caller.projectKey && !runtimeActive) {
    return suite;
  }

  if (runtimeActive && caller.extensionType.toLowerCase().startsWith('confluence:')) {
    await verifyJiraIdentity(caller.accountId);
  }

  return authorizeAndFilterLiveSuite(suite, {
    extensionType: caller.extensionType,
    projectKey: caller.projectKey,
    checkConfluencePages: true,
    ...(options?.precheckedConfluencePages
      ? { precheckedConfluencePages: options.precheckedConfluencePages }
      : {}),
  });
}

interface LinkProjectIndex {
  byKey: Map<string, Set<string>>;
  bySpecOrPage: Map<string, Set<string>>;
  pageIdsBySpecId: Map<string, string>;
}

function buildLinkProjectIndex(suite: ComplianceSummary): LinkProjectIndex {
  const byKey = new Map<string, Set<string>>();
  const bySpecOrPage = new Map<string, Set<string>>();
  const pageIdsBySpecId = new Map<string, string>();

  const addProjects = (map: Map<string, Set<string>>, rawKey: string | undefined, projs: string[]) => {
    const clean = rawKey?.trim().toLowerCase();
    if (!clean || projs.length === 0) return;
    let set = map.get(clean);
    if (!set) {
      set = new Set<string>();
      map.set(clean, set);
    }
    for (const p of projs) set.add(p);
  };

  for (const link of suite.traceLinks) {
    const rawPageId = typeof link.spec?.pageId === 'string' ? link.spec.pageId.trim() : '';
    const rawSpecId = typeof link.spec?.id === 'string' ? link.spec.id.trim().toLowerCase() : '';
    if (rawSpecId && /^\d+$/.test(rawPageId)) {
      pageIdsBySpecId.set(rawSpecId, rawPageId);
    }
    const projs = extractAllJiraProjectKeysFromLink(link);
    if (projs.length === 0) continue;
    addProjects(byKey, link.hazard?.key, projs);
    addProjects(byKey, link.work?.key, projs);
    addProjects(byKey, link.test?.testKey, projs);
    addProjects(byKey, link.reverificationTaskKey, projs);
    addProjects(bySpecOrPage, link.spec?.id, projs);
    addProjects(bySpecOrPage, link.spec?.pageId, projs);
    if (link.spec?.pageId) {
      addProjects(bySpecOrPage, `page:${link.spec.pageId}`, projs);
    }
  }

  return { byKey, bySpecOrPage, pageIdsBySpecId };
}

function extractAuditEntryConfluencePageIds(entry: AuditLogEntry, index: LinkProjectIndex): Set<string> {
  const pageIds = new Set<string>();
  const targetMatch =
    typeof entry.targetKey === 'string' ? entry.targetKey.trim().match(/^page:(\d+)$/i) : null;
  if (targetMatch?.[1]) {
    pageIds.add(targetMatch[1]);
  }
  const details =
    entry.details && typeof entry.details === 'object'
      ? (entry.details as Record<string, unknown>)
      : {};
  if (typeof details.pageId === 'string') {
    const cleanPageId = details.pageId.trim();
    if (/^\d+$/.test(cleanPageId)) {
      pageIds.add(cleanPageId);
    }
  }
  const exposesSpecDigest =
    (typeof details.newSha256 === 'string' && details.newSha256.trim().length > 0) ||
    (typeof details.artifactSha256 === 'string' && details.artifactSha256.trim().length > 0);
  if (exposesSpecDigest && typeof details.specId === 'string') {
    const mappedPageId = index.pageIdsBySpecId.get(details.specId.trim().toLowerCase());
    if (mappedPageId) {
      pageIds.add(mappedPageId);
    }
  }
  return pageIds;
}

function extractAuditEntryProjectKeys(entry: AuditLogEntry, index: LinkProjectIndex): Set<string> {
  const projects = new Set<string>();
  const details =
    entry.details && typeof entry.details === 'object' ? entry.details : {};

  const addIfProject = (val: unknown) => {
    if (typeof val !== 'string') return;
    const upper = val.trim().toUpperCase();
    if (JIRA_PROJECT_KEY_RE.test(upper)) {
      projects.add(upper);
    }
  };

  const addFromSpecOrPageKey = (val: unknown) => {
    if (typeof val !== 'string') return;
    const trimmed = val.trim();
    if (!trimmed) return;
    const mapped = index.bySpecOrPage.get(trimmed.toLowerCase());
    if (mapped) {
      for (const p of mapped) projects.add(p);
    }
  };

  const addFromArtifactKey = (val: unknown) => {
    if (typeof val !== 'string') return;
    const trimmed = val.trim();
    if (!trimmed) return;
    const lower = trimmed.toLowerCase();
    if (lower.startsWith('srs-') || lower.startsWith('page:') || lower.startsWith('unlinked-')) {
      addFromSpecOrPageKey(trimmed);
      return;
    }
    const directProj = extractJiraProjectKeyFromRawKey(trimmed);
    if (directProj) projects.add(directProj);
    const mapped = index.byKey.get(lower) || index.bySpecOrPage.get(lower);
    if (mapped) {
      for (const p of mapped) projects.add(p);
    }
  };

  addIfProject(details.projectKey);
  if (Array.isArray(details.projectKeys)) {
    for (const pk of details.projectKeys) addIfProject(pk);
  }
  if (entry.action === 'SYNC_LIVE') {
    addIfProject(entry.targetKey);
  }

  addFromArtifactKey(entry.targetKey);
  for (const field of [
    details.hazardKey,
    details.workKey,
    details.testKey,
    details.previousIssueKey,
    details.newIssueKey,
    details.createdIssueKey,
    details.issueKey,
  ]) {
    addFromArtifactKey(field);
  }
  for (const specField of [details.specId, details.pageId]) {
    addFromSpecOrPageKey(specField);
  }
  for (const arrField of [details.affectedHazards, details.affectedWorkKeys, details.linkedIssueKeys]) {
    if (Array.isArray(arrField)) {
      for (const item of arrField) addFromArtifactKey(item);
    }
  }

  return projects;
}

/**
 * Filters audit log entries to projects and Confluence pages readable by the caller, omitting unauthorized
 * multi-project or restricted-page entries without mutating remaining entries so hash chains remain verifiable.
 */
export async function filterAuditEntriesForCaller(
  caller: AuthorizedCaller,
  entries: AuditLogEntry[],
  rawSuite: ComplianceSummary
): Promise<AuditLogEntry[]> {
  if (entries.length === 0) return entries;

  const runtimeActive = isForgeRuntime();
  if (
    runtimeActive &&
    rawSuite.datasetMode === 'LIVE' &&
    caller.extensionType.toLowerCase().startsWith('confluence:')
  ) {
    await verifyJiraIdentity(caller.accountId);
  }

  const index = buildLinkProjectIndex(rawSuite);
  const projectPermCache = new Map<string, boolean>();
  const confluencePagePermCache = new Map<string, boolean>();
  let globalBrowsePerm: boolean | undefined;

  const isConfluenceAuthorizedForEntry = async (entry: AuditLogEntry): Promise<boolean> => {
    if (!runtimeActive || rawSuite.datasetMode !== 'LIVE') {
      return true;
    }
    const pageIds = extractAuditEntryConfluencePageIds(entry, index);
    for (const pid of pageIds) {
      let allowed = confluencePagePermCache.get(pid);
      if (allowed === undefined) {
        allowed = await canReadConfluencePageForCaller(pid);
        confluencePagePermCache.set(pid, allowed);
      }
      if (!allowed) {
        return false;
      }
    }
    return true;
  };

  const isProjectAuthorized = async (projectKey: string): Promise<boolean> => {
    const clean = projectKey.trim().toUpperCase();
    if (caller.projectKey) {
      if (clean === caller.projectKey) return true;
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
    if (!runtimeActive) return !caller.projectKey;
    if (globalBrowsePerm === undefined) {
      globalBrowsePerm = await hasJiraBrowsePermissionForCaller(undefined);
    }
    return globalBrowsePerm;
  };

  const out: AuditLogEntry[] = [];
  for (const entry of entries) {
    if (entry.action === 'SEED_DEMO' || entry.action === 'DEMO_SIMULATION') {
      if (rawSuite.datasetMode === 'DEMO' || (!caller.projectKey && !runtimeActive)) {
        out.push(entry);
      }
      continue;
    }

    const entryProjects = extractAuditEntryProjectKeys(entry, index);

    if (caller.projectKey) {
      if (!entryProjects.has(caller.projectKey)) {
        continue;
      }
      const foreignProjects = Array.from(entryProjects).filter((p) => p !== caller.projectKey);
      // Omit multi-project entries entirely if the caller cannot browse all referenced projects so entryHash remains verifiable.
      let allForeignAllowed = true;
      for (const fp of foreignProjects) {
        if (!(await isProjectAuthorized(fp))) {
          allForeignAllowed = false;
          break;
        }
      }
      if (allForeignAllowed && (await isConfluenceAuthorizedForEntry(entry))) {
        out.push(entry);
      }
      continue;
    }

    // Global / Confluence context without explicit projectKey
    if (!runtimeActive || rawSuite.datasetMode === 'DEMO') {
      out.push(entry);
      continue;
    }

    if (entryProjects.size === 0) {
      if ((await canBrowseGlobal()) && (await isConfluenceAuthorizedForEntry(entry))) {
        out.push(entry);
      }
      continue;
    }

    let allAuthorized = true;
    for (const p of entryProjects) {
      if (!(await isProjectAuthorized(p))) {
        allAuthorized = false;
        break;
      }
    }
    if (allAuthorized && (await isConfluenceAuthorizedForEntry(entry))) {
      out.push(entry);
    }
  }

  return out;
}

/**
 * Verifies operator authorization for a target hazard/spec/work/test/link, including shared `testKey`
 * siblings and fallback Jira operator checks when no suite link matches.
 */
export async function assertOperatorAuthorizedForTarget(
  req: ForgeResolverRequest<unknown> | undefined,
  target: {
    hazardKey?: string;
    specId?: string;
    workKey?: string;
    linkId?: string;
    testKey?: string;
    includeSharedSpecSiblings?: boolean;
  }
): Promise<void> {
  const suite = await SeederService.getActiveComplianceSuite();
  if (suite.datasetMode === 'DEMO') {
    return;
  }

  const accountId = extractCallerAccountId(req);
  const scope = normalizeAndValidateScope(req?.context?.extension, undefined);

  const assertFallbackJiraOperator = async (derivedIssueKey?: string): Promise<void> => {
    if (derivedIssueKey && JIRA_ISSUE_KEY_RE.test(derivedIssueKey)) {
      await assertAuthorizedOperator(req, { issueKey: derivedIssueKey });
      return;
    }
    if (!isForgeRuntime()) {
      return;
    }
    if (scope.effectiveProjectKey) {
      await assertAuthorizedOperator(req, { projectKey: scope.effectiveProjectKey });
      return;
    }
    if (!accountId) {
      throw new Error('Unauthorized: Authenticated Atlassian accountId is required in resolver context.');
    }
    await verifyJiraIdentity(accountId);
    await assertJiraOperatorPermissions();
  };

  const cleanLinkId = target.linkId?.trim();
  const cleanHazard = target.hazardKey?.trim().toLowerCase();
  const cleanSpec = target.specId?.trim().toLowerCase();
  const cleanTest = target.testKey?.trim().toLowerCase();
  const cleanWork = target.workKey?.trim().toLowerCase();
  const matchesWork = (l: TraceLink): boolean =>
    !cleanWork ||
    (l.work?.key || '').toLowerCase() === cleanWork ||
    (l.hazard?.key || '').toLowerCase() === cleanWork ||
    (l.test?.testKey || '').toLowerCase() === cleanWork;

  const idx = cleanLinkId
    ? suite.traceLinks.findIndex(
        (l) =>
          l.id === cleanLinkId &&
          (!cleanHazard || (l.hazard?.key || '').toLowerCase() === cleanHazard) &&
          (!cleanSpec || (l.spec?.id || '').toLowerCase() === cleanSpec) &&
          (!cleanTest || (l.test?.testKey || '').toLowerCase() === cleanTest) &&
          matchesWork(l)
      )
    : suite.traceLinks.findIndex(
        (l) =>
          (!cleanHazard || (l.hazard?.key || '').toLowerCase() === cleanHazard) &&
          (!cleanSpec || (l.spec?.id || '').toLowerCase() === cleanSpec) &&
          (!cleanTest || (l.test?.testKey || '').toLowerCase() === cleanTest) &&
          matchesWork(l) &&
          Boolean(cleanHazard || cleanTest || cleanWork)
      );

  if (idx < 0) {
    await assertFallbackJiraOperator(target.workKey);
    return;
  }

  const targetLink = suite.traceLinks[idx];
  const linksToAuthorize: TraceLink[] = [targetLink];
  if (target.testKey !== undefined) {
    const sharedTestLower = (targetLink.test?.testKey || target.testKey || '').trim().toLowerCase();
    if (sharedTestLower) {
      for (const candidate of suite.traceLinks) {
        if (
          candidate !== targetLink &&
          (candidate.test?.testKey || '').trim().toLowerCase() === sharedTestLower
        ) {
          linksToAuthorize.push(candidate);
        }
      }
    }
  }
  if (target.includeSharedSpecSiblings === true) {
    const hazLower = targetLink.hazard.key.trim().toLowerCase();
    const specLower = targetLink.spec.id.trim().toLowerCase();
    const pageLower = (targetLink.spec.pageId || '').trim().toLowerCase();
    const targetHash = targetLink.spec.sha256Hash;
    for (const candidate of suite.traceLinks) {
      if (candidate === targetLink) continue;
      const matchesSpec =
        candidate.spec.id.trim().toLowerCase() === specLower ||
        (pageLower !== '' && (candidate.spec.pageId || '').trim().toLowerCase() === pageLower);
      if (
        candidate.hazard.key.trim().toLowerCase() === hazLower &&
        matchesSpec &&
        candidate.spec.isMissingSentinel !== true &&
        candidate.spec.sha256Hash === targetHash
      ) {
        linksToAuthorize.push(candidate);
      }
    }
  }

  const verifiedIssueKeys = new Set<string>();
  const checkedConfluencePages = new Map<string, boolean>();
  for (const link of linksToAuthorize) {
    const linkIssueKeys = extractAllJiraIssueKeysFromLink(link);
    if (linkIssueKeys.length > 0) {
      for (const issueKey of linkIssueKeys) {
        if (verifiedIssueKeys.has(issueKey)) continue;
        await assertAuthorizedOperator(req, { issueKey });
        verifiedIssueKeys.add(issueKey);
      }
    } else {
      await assertFallbackJiraOperator();
    }

    const specPageId = typeof link.spec?.pageId === 'string' ? link.spec.pageId.trim() : '';
    if (
      isForgeRuntime() &&
      suite.datasetMode === 'LIVE' &&
      link.spec?.isMissingSentinel !== true &&
      /^\d+$/.test(specPageId)
    ) {
      let readable = checkedConfluencePages.get(specPageId);
      if (readable === undefined) {
        readable = await canReadConfluencePageForCaller(specPageId);
        checkedConfluencePages.set(specPageId, readable);
      }
      if (!readable) {
        throw new Error(
          `Forbidden: Caller lacks Confluence read permission for linked specification page ${specPageId}.`
        );
      }
    }
  }
}
