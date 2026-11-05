import { SeederService } from './seeder';

/**
 * Fast-path Jira Workflow Validator (< 80ms execution)
 * Physically blocks issue transitions in Jira when regulatory safety gates fail.
 */
export async function workflowValidatorHandler(payload: any): Promise<{ result: boolean; errorMessage?: string }> {
  console.log('[MedTrace WorkflowValidator] Intercepting Jira transition attempt:', payload);

  try {
    const suite = await SeederService.getActiveComplianceSuite();

    if (suite.releaseBlocked) {
      const topViolation = suite.blockingReasons[0] || 'Unresolved safety-critical compliance gaps.';
      const errorMessage = `❌ [MedTrace Safety Gate] Transition Blocked! Release contains unresolved IEC 62304 / 21 CFR Part 11 violations:\n• ${topViolation}\n\nResolve verification test runs or re-certify electronic signatures before releasing.`;

      console.warn('[MedTrace WorkflowValidator] Transition BLOCKED:', errorMessage);
      return {
        result: false,
        errorMessage,
      };
    }

    console.log('[MedTrace WorkflowValidator] All IEC 62304 Class C requirements verified. Transition APPROVED.');
    return {
      result: true,
    };
  } catch (err: any) {
    console.error('[MedTrace WorkflowValidator] Error evaluating safety gate:', err);
    // In medical software, fail-safe mode blocks by default on evaluation error
    return {
      result: false,
      errorMessage: 'MedTrace Safety Gate: Unable to verify IEC 62304 compliance integrity. Transition halted.',
    };
  }
}
