import { SeederService } from './seeder';

/**
 * Fast-path Jira Workflow Validator (< 80ms execution)
 * Enforces regulatory gating on human-initiated Jira issue transitions to "Done".
 * Note: Under Atlassian platform issue ECO-624, Jira Automation bypasses transition validators;
 * CI/CD pipelines enforce equivalent policy via authenticated HMAC webtrigger checks.
 */
export async function workflowValidatorHandler(payload: any): Promise<{ result: boolean; errorMessage?: string }> {
  console.log('[MedTrace WorkflowValidator] Intercepting human transition attempt:', payload);

  try {
    const suite = await SeederService.getActiveComplianceSuite();
    const issueKey = (payload?.issue?.key || payload?.issueKey || payload?.key || '').toUpperCase();

    // 1. If transition is for a specific Jira issue, validate its linked hazard lineage
    if (issueKey) {
      const matchedLink = suite.traceLinks.find(
        (l) => l.work.key.toUpperCase() === issueKey || l.hazard.key.toUpperCase() === issueKey
      );

      if (matchedLink && matchedLink.complianceState !== 'VERIFIED') {
        const violation = matchedLink.violations[0] || 'Unresolved safety-critical compliance gap.';
        const errorMessage = `❌ [MedTrace Safety Gate] Human-initiated transition blocked for ${issueKey}!\n• ${violation}\n\nResolve verification test runs or re-certify electronic signatures before releasing.`;
        console.warn(`[MedTrace WorkflowValidator] Transition BLOCKED for ${issueKey}:`, errorMessage);
        return { result: false, errorMessage };
      }

      console.log(`[MedTrace WorkflowValidator] Issue ${issueKey} has no blocking safety violations. Transition APPROVED.`);
      return { result: true };
    }

    // 2. Global release fallback (for release ticket or manual simulation)
    if (suite.releaseBlocked) {
      const topViolation = suite.blockingReasons[0] || 'Unresolved safety-critical compliance gaps.';
      const errorMessage = `❌ [MedTrace Safety Gate] Human-initiated transition blocked!\n• ${topViolation}\n\nResolve verification test runs or re-certify electronic signatures before releasing.`;

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
