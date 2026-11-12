import { ComplianceEngine } from './compliance-engine';
import { SeederService } from './seeder';

/**
 * Fast-path Jira Workflow Validator (< 80ms execution)
 * Enforces regulatory gating on human-initiated Jira issue transitions to "Done".
 * Uses the shared ComplianceEngine.evaluateIssueReleaseGate policy also used by CI/CD webtrigger.
 */
export async function workflowValidatorHandler(payload: any): Promise<{ result: boolean; errorMessage?: string }> {
  console.log('[MedTrace WorkflowValidator] Intercepting human transition attempt:', payload?.issue?.key || payload?.issueKey || 'global');

  try {
    const suite = await SeederService.getActiveComplianceSuite();
    const issueKey = (payload?.issue?.key || payload?.issueKey || payload?.key || '').trim();
    const outcome = ComplianceEngine.evaluateIssueReleaseGate(issueKey || undefined, suite);

    if (!outcome.result) {
      console.warn(`[MedTrace WorkflowValidator] Transition BLOCKED (${issueKey || 'global'}):`, outcome.errorMessage);
    } else {
      console.log(`[MedTrace WorkflowValidator] Transition APPROVED (${issueKey || 'global'}).`);
    }

    return outcome;
  } catch (err: any) {
    console.error('[MedTrace WorkflowValidator] Error evaluating safety gate:', err);
    // In medical software, fail-safe mode blocks by default on evaluation error
    return {
      result: false,
      errorMessage: 'MedTrace Safety Gate: Unable to verify IEC 62304 compliance integrity. Transition halted.',
    };
  }
}
