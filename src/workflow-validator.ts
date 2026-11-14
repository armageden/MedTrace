import { ComplianceEngine } from './compliance-engine';
import { SeederService } from './seeder';
import { TransitionResult } from './types';

/**
 * Typed payload delivered to the Jira `jira:workflowValidator` Forge function
 * or passed internally by `simulateTransition` / webtrigger handlers.
 */
export interface WorkflowValidatorPayload {
  issue?: { key?: string };
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

/**
 * Fast-path Jira Workflow Validator (`jira:workflowValidator`, < 80ms target execution).
 * Enforces regulatory gating on human-initiated Jira issue transitions via
 * `ComplianceEngine.evaluateIssueReleaseGate` (shared with the CI/CD `verify-release-gate` webtrigger):
 * - Fails closed when the suite is uninitialized (`suite.initialized === false` or 0 trace links).
 * - Evaluates the Global Release Gate (`issueKey = undefined`) when `issueKey` is omitted or empty/whitespace.
 * - Blocks tracked non-`VERIFIED` issues and approves verified or untracked issues on initialized suites.
 * - Fails closed (`result: false`) on any unexpected runtime or storage exception.
 *
 * Platform Limitation (Atlassian `ECO-624`): Forge `jira:workflowValidator` does NOT intercept
 * Jira Automation rules or direct REST API status transitions, and cannot detect hazard tickets
 * that have not yet been synced or bound into MedTrace. Production releases MUST also enforce
 * `.github/workflows/medtrace-release-gate.yml` (`action: 'verify-release-gate'`, `requireLiveMode: true`).
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
    const outcome: TransitionResult = ComplianceEngine.evaluateIssueReleaseGate(issueKey, suite);

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
