import { SeederService } from './seeder';
import { ComplianceEngine } from './compliance-engine';

/**
 * MedTrace MCP Tools & Rovo Action Handlers
 * Serves both Atlassian Rovo agent invocations and external MCP coding assistants (Cursor, Claude Desktop).
 */
export class McpToolService {
  /**
   * Tool: get-hazard-lineage-action
   * Retrieves complete ISO 14971 hazard safety lineage for an issue or project
   */
  public static async getHazardLineage(inputs?: { issueKey?: string }): Promise<any> {
    const suite = await SeederService.getActiveComplianceSuite();

    if (inputs?.issueKey) {
      const match = suite.traceLinks.find(
        (l) =>
          l.hazard.key.toLowerCase() === inputs.issueKey?.toLowerCase() ||
          l.work.key.toLowerCase() === inputs.issueKey?.toLowerCase() ||
          l.test.testKey.toLowerCase() === inputs.issueKey?.toLowerCase()
      );
      if (match) {
        return {
          found: true,
          traceLink: match,
          regulatoryStatus: match.complianceState,
          riskClass: match.hazard.riskClass,
          safetyRequirement: match.spec.title,
          testStatus: match.test.status,
          part11Valid: match.signature.isValid,
        };
      }
    }

    return {
      projectName: suite.projectName,
      totalHazards: suite.totalHazards,
      traceLinks: suite.traceLinks.map((l) => ({
        hazardKey: l.hazard.key,
        riskClass: l.hazard.riskClass,
        severity: l.hazard.severity,
        requirementSpec: l.spec.title,
        workKey: l.work.key,
        testKey: l.test.testKey,
        testStatus: l.test.status,
        complianceState: l.complianceState,
        signatureValid: l.signature.isValid,
      })),
    };
  }

  /**
   * Tool: verify-iec-compliance-action
   * Audits active codebase/sprint against IEC 62304 and FDA 21 CFR Part 11 requirements
   */
  public static async verifyIecCompliance(inputs?: { prDiff?: string; componentName?: string }): Promise<any> {
    const suite = await SeederService.getActiveComplianceSuite();

    return {
      standards: suite.standards,
      canShipToClinicalProduction: !suite.releaseBlocked,
      verifiedCoveragePercentage: `${suite.verifiedPercentage}%`,
      classCSummary: {
        totalClassC: suite.classCCount,
        status: suite.releaseBlocked ? 'BLOCKED_BY_SAFETY_GATE' : 'CERTIFIED_READY',
      },
      signatureDriftDetected: suite.signatureDriftCount > 0,
      activeViolations: suite.blockingReasons,
      remediationGuidance: suite.releaseBlocked
        ? [
            'Execute automated Hardware-in-the-Loop test for TEST-88.',
            'Re-certify 21 CFR Part 11 electronic signature on Confluence SRS-104 (revision v3).',
          ]
        : ['All regulatory gates satisfied. Authorized for 510(k) release packaging.'],
    };
  }
}

/**
 * Handler for manifest module: action (used by rovo:agent and rovo:mcp)
 */
export async function rovoActionHandler(event: any): Promise<any> {
  console.log('[MedTrace RovoAction] Received event:', JSON.stringify(event));

  const actionKey = event?.actionKey || event?.key || '';
  const inputs = event?.inputs || {};

  if (actionKey.includes('get-hazard-lineage') || actionKey.includes('lineage')) {
    return await McpToolService.getHazardLineage(inputs);
  }

  if (actionKey.includes('verify-iec-compliance') || actionKey.includes('compliance')) {
    return await McpToolService.verifyIecCompliance(inputs);
  }

  return {
    error: `Unknown action: ${actionKey}`,
    availableTools: ['get-hazard-lineage-action', 'verify-iec-compliance-action'],
  };
}
