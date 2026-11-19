import api, { route } from '@forge/api';
import { ComplianceEngine } from './compliance-engine';
import { isSafetyTrackedIssue } from './ingestion';
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
  transition?: { name?: string };
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
      (l.hazard?.key || '').toUpperCase() === clean
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
      issueKey || 'global'
    );

    const suite = await SeederService.getActiveComplianceSuite(
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

    const outcome: TransitionResult = ComplianceEngine.evaluateIssueReleaseGate(
      issueKey,
      suite,
      safetyProbe
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
