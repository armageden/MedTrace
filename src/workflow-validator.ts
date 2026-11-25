import api, { route } from '@forge/api';
import { ComplianceEngine } from './compliance-engine';
import { isSafetyTrackedIssue, LiveIngestionService } from './ingestion';
import { isForgeRuntime } from './runtime';
import { SeederService } from './seeder';
import { ComplianceSummary, TransitionResult } from './types';

/**
 * Typed payload delivered to the Jira `jira:workflowValidator` Forge function
 * or passed internally by `simulateTransition` / webtrigger handlers.
 */
export interface WorkflowValidatorPayload {
  issue?: {
    key?: string;
    fields?: {
      labels?: unknown[];
      issuetype?: { name?: string };
    };
  };
  issueKey?: string;
  key?: string;
  transition?: {
    id?: string | number;
    name?: string;
    from?: string | { id?: string | number; name?: string; statusCategory?: { key?: string; name?: string } };
    to?: string | { id?: string | number; name?: string; statusCategory?: { key?: string; name?: string } };
  };
  transitionId?: string | number;
}

const RELEASE_STATUS_NAME_RE = /^(done|closed|resolved|released|ready for release)$/i;
const RELEASE_TRANSITION_NAME_RE =
  /^(done|mark(ed)?( as)? done|move to done|release|ready for release|complete(d)?|close(d)?|resolve(d)?)$/i;
const statusDoneCache = new Map<string, boolean>();

function isDoneStatusLike(status?: { name?: string; statusCategory?: { key?: string } } | null): boolean | undefined {
  if (!status || typeof status !== 'object') return undefined;
  const cat = typeof status.statusCategory?.key === 'string' ? status.statusCategory.key.trim().toLowerCase() : '';
  if (cat) return cat === 'done';
  const name = typeof status.name === 'string' ? status.name.trim().toLowerCase() : '';
  if (name) return RELEASE_STATUS_NAME_RE.test(name);
  return undefined;
}

export function isReleaseTransitionPayload(payload?: WorkflowValidatorPayload | null): boolean {
  const t = payload?.transition;
  if (!t || typeof t !== 'object') {
    return false;
  }
  if (t.to && typeof t.to === 'object') {
    const resolved = isDoneStatusLike(t.to);
    if (resolved !== undefined) {
      return resolved;
    }
  }
  const transName = typeof t.name === 'string' ? t.name.trim().toLowerCase() : '';
  if (!transName) {
    return false;
  }
  return RELEASE_TRANSITION_NAME_RE.test(transName) || /(?:->|→|\bto)\s*done\b/i.test(transName);
}

async function resolveTransitionToDone(
  payload?: WorkflowValidatorPayload | null,
  issueKey?: string
): Promise<boolean> {
  if (isReleaseTransitionPayload(payload)) {
    return true;
  }
  const t = payload?.transition;
  if (!t || typeof t !== 'object') {
    return false;
  }
  if (t.to && typeof t.to === 'object' && isDoneStatusLike(t.to) === false) {
    return false;
  }
  if (!isForgeRuntime()) {
    return false;
  }

  const rawToId =
    typeof t.to === 'string'
      ? t.to.trim()
      : t.to && typeof t.to === 'object' && (typeof t.to.id === 'string' || typeof t.to.id === 'number')
        ? String(t.to.id).trim()
        : '';

  if (rawToId) {
    const cached = statusDoneCache.get(rawToId);
    if (cached !== undefined) {
      return cached;
    }
    try {
      const resp = await api.asApp().requestJira(route`/rest/api/3/status/${rawToId}`);
      if (resp.status === 200) {
        const statusData = (await resp.json().catch(() => null)) as {
          name?: string;
          statusCategory?: { key?: string };
        } | null;
        const isDone = isDoneStatusLike(statusData) === true;
        statusDoneCache.set(rawToId, isDone);
        return isDone;
      }
    } catch {
      return false;
    }
  }

  const rawTransId = t.id ?? payload?.transitionId;
  if (rawTransId !== undefined && rawTransId !== null && issueKey) {
    const transIdStr = String(rawTransId).trim();
    if (transIdStr) {
      try {
        const resp = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}/transitions`);
        if (resp.status === 200) {
          const data = (await resp.json().catch(() => null)) as {
            transitions?: Array<{
              id?: string | number;
              name?: string;
              to?: { id?: string | number; name?: string; statusCategory?: { key?: string } };
            }>;
          } | null;
          const matched = Array.isArray(data?.transitions)
            ? data.transitions.find((item) => String(item?.id ?? '') === transIdStr)
            : undefined;
          if (matched) {
            const byStatus = isDoneStatusLike(matched.to);
            if (byStatus !== undefined) return byStatus;
            const mName = typeof matched.name === 'string' ? matched.name.trim().toLowerCase() : '';
            if (mName) return RELEASE_TRANSITION_NAME_RE.test(mName);
          }
        }
      } catch {
        return false;
      }
    }
  }

  return false;
}

function normalizeIssueKey(payload?: WorkflowValidatorPayload | null): string | undefined {
  if (!payload || typeof payload !== 'object') {
    return undefined;
  }
  const candidates: unknown[] = [payload.issue?.key, payload.issueKey, payload.key];
  for (const candidate of candidates) {
    if (typeof candidate === 'string') {
      const trimmed = candidate.trim();
      if (trimmed !== '') {
        return trimmed;
      }
    }
  }
  return undefined;
}

function isMatchedInSuite(issueKey: string, suite: ComplianceSummary): boolean {
  const clean = issueKey.trim().toUpperCase();
  if (!clean || !Array.isArray(suite?.traceLinks)) return false;
  return suite.traceLinks.some(
    (l) =>
      (l.work?.key || '').toUpperCase() === clean ||
      (l.hazard?.key || '').toUpperCase() === clean ||
      (l.test?.testKey || '').toUpperCase() === clean
  );
}

/**
 * Probes whether an untracked Jira issue carries a safety label (`class-a/b/c`, `iec-62304`, `iso-14971`,
 * `critical-safety`, `medtrace-hazard`) or hazard issue type (`Hazard`, `Risk`, `Safety Hazard`).
 * Uses inline `payload.issue.fields` when supplied or queries Jira REST (`labels,issuetype`) in Forge runtime.
 * Fails closed (`isSafetyTaggedIssue: true`) if the Forge Jira metadata lookup fails.
 */
export async function probeUnsyncedSafetyIssue(
  issueKey: string,
  payload?: WorkflowValidatorPayload | null
): Promise<{ isSafetyTaggedIssue: boolean; unsyncedSafetyReason?: string }> {
  const cleanKey = issueKey.trim().toUpperCase();
  if (
    payload?.issue?.fields &&
    (Array.isArray(payload.issue.fields.labels) || payload.issue.fields.issuetype !== undefined)
  ) {
    const tagged = isSafetyTrackedIssue({
      key: cleanKey,
      fields: {
        labels: payload.issue.fields.labels,
        issuetype: payload.issue.fields.issuetype,
      },
    });
    return tagged
      ? {
          isSafetyTaggedIssue: true,
          unsyncedSafetyReason: `Safety-classified issue ${cleanKey} is not synced in the active compliance suite.`,
        }
      : { isSafetyTaggedIssue: false };
  }

  if (!isForgeRuntime()) {
    return { isSafetyTaggedIssue: false };
  }

  try {
    const resp = await api
      .asApp()
      .requestJira(route`/rest/api/3/issue/${cleanKey}?fields=labels,issuetype`);
    if (resp.status === 404) {
      return { isSafetyTaggedIssue: false };
    }
    if (resp.status !== 200) {
      return {
        isSafetyTaggedIssue: true,
        unsyncedSafetyReason: `Unable to verify safety labels for unsynced issue ${cleanKey} (Jira HTTP ${resp.status}); failing closed.`,
      };
    }
    const issueData = (await resp.json()) as {
      key?: string;
      fields?: { labels?: unknown[]; issuetype?: { name?: string } };
    };
    const tagged = isSafetyTrackedIssue({
      key: cleanKey,
      fields: issueData?.fields,
    });
    return tagged
      ? {
          isSafetyTaggedIssue: true,
          unsyncedSafetyReason: `Safety-classified issue ${cleanKey} is not synced in the active compliance suite.`,
        }
      : { isSafetyTaggedIssue: false };
  } catch {
    return {
      isSafetyTaggedIssue: true,
      unsyncedSafetyReason: `Unable to verify safety labels for unsynced issue ${cleanKey}; failing closed.`,
    };
  }
}

/**
 * Fast-path Jira Workflow Validator (`jira:workflowValidator`, < 80ms target execution).
 * Enforces regulatory gating on human-initiated Jira issue transitions via
 * `ComplianceEngine.evaluateIssueReleaseGate` (shared with the CI/CD `verify-release-gate` webtrigger):
 * - Fails closed when the suite is uninitialized (`suite.initialized === false` or 0 trace links).
 * - Evaluates the Global Release Gate (`issueKey = undefined`) when `issueKey` is omitted or empty/whitespace.
 * - Blocks tracked non-`VERIFIED` issues, blocks unsynced issues carrying safety labels or hazard issue types,
 *   and approves verified or everyday non-safety untracked issues on initialized suites.
 * - Fails closed (`result: false`) on any unexpected runtime or storage exception.
 *
 * Atlassian issue `ECO-624` reports a Jira Automation case but is marked Invalid and does not establish
 * direct REST API behavior. The repository's release-gate workflow is manual, reusable, or published-release
 * triggered; it is invoked by ci.yml on pull requests and pushes to main when release-gate secrets are configured.
 */
export async function workflowValidatorHandler(
  payload?: WorkflowValidatorPayload | null
): Promise<TransitionResult> {
  try {
    const issueKey = normalizeIssueKey(payload);
    console.log(
      '[MedTrace WorkflowValidator] Intercepting human transition attempt:',
      issueKey || 'global',
      JSON.stringify({
        keys: payload && typeof payload === 'object' ? Object.keys(payload) : [],
        transition: payload?.transition ?? null,
      })
    );

    let suite = await SeederService.getActiveComplianceSuite(
      issueKey ? { issueKeyFilter: issueKey } : undefined
    );

    const isInitialized =
      Boolean(suite) &&
      suite.initialized !== false &&
      Array.isArray(suite.traceLinks) &&
      !(suite.traceLinks.length === 0 && (!issueKey || (suite.totalHazards ?? 0) === 0));

    let safetyProbe: { isSafetyTaggedIssue: boolean; unsyncedSafetyReason?: string } | undefined;
    if (issueKey && isInitialized && !isMatchedInSuite(issueKey, suite)) {
      safetyProbe = await probeUnsyncedSafetyIssue(issueKey, payload);
    }

    if (isInitialized && isForgeRuntime() && suite.datasetMode === 'LIVE') {
      const cleanIssue = issueKey ? issueKey.trim().toUpperCase() : '';
      if (!cleanIssue) {
        suite = await LiveIngestionService.reconcileConfluenceSpecs(suite, {
          allowAppFallback: true,
        });
      } else if (isMatchedInSuite(cleanIssue, suite)) {
        const targetPageIds = suite.traceLinks
          .filter(
            (l) =>
              (l.work?.key || '').toUpperCase() === cleanIssue ||
              (l.hazard?.key || '').toUpperCase() === cleanIssue
          )
          .map((l) => l.spec?.pageId)
          .filter((p): p is string => typeof p === 'string' && p.trim().length > 0);
        if (targetPageIds.length > 0) {
          suite = await LiveIngestionService.reconcileConfluenceSpecs(suite, {
            targetPageIds,
            issueKeyFilter: cleanIssue,
            allowAppFallback: true,
          });
        }
      }
    }

    const transitionToDone = await resolveTransitionToDone(payload, issueKey);
    const outcome: TransitionResult = ComplianceEngine.evaluateIssueReleaseGate(
      issueKey,
      suite,
      safetyProbe || transitionToDone
        ? {
            ...(safetyProbe ?? {}),
            ...(transitionToDone ? { transitionToDone: true } : {}),
          }
        : undefined
    );

    if (!outcome.result) {
      console.warn(
        `[MedTrace WorkflowValidator] Transition BLOCKED (${issueKey || 'global'}):`,
        outcome.errorMessage
      );
    } else {
      console.log(`[MedTrace WorkflowValidator] Transition APPROVED (${issueKey || 'global'}).`);
    }

    return outcome;
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : String(err);
    console.error('[MedTrace WorkflowValidator] Error evaluating safety gate:', reason);
    // In medical software, fail-closed mode blocks by default on evaluation error
    return {
      result: false,
      errorMessage: 'MedTrace Safety Gate: Unable to verify IEC 62304 compliance integrity. Transition halted.',
    };
  }
}
