import api, { route } from '@forge/api';
import { AuditLogService } from './audit-log';
import { isForgeRuntime } from './runtime';
import { AuthorizedUserIdentity, JiraWorkItem } from './types';

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

