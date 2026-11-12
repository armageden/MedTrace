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
   * Performs real BFS graph traversal to calculate blast radius on referenced artifacts.
   */
  public static async verifyIecCompliance(inputs?: { prDiff?: string; componentName?: string; issueKey?: string }): Promise<any> {
    const suite = await SeederService.getActiveComplianceSuite();
    const fullText = `${inputs?.prDiff || ''} ${inputs?.componentName || ''} ${inputs?.issueKey || ''}`;

    // 1. Extract explicit issue, hazard, test, or spec keys (e.g. MED-42, HAZ-101, SRS-104, TEST-88)
    //    Keep only keys that actually exist in the active compliance suite, so stray tokens
    //    like "UTF-8" or "RFC-7231" cannot override the safety-critical keyword fallback.
    const rawKeyMatches = Array.from(new Set(fullText.match(/\b[A-Za-z]{2,5}-\d+\b/g) || [])).map((k) => k.toUpperCase());
    const suiteKeys = new Set(
      suite.traceLinks.flatMap((l) => [l.hazard.key, l.work.key, l.spec.id, l.test.testKey].map((k) => String(k).toUpperCase()))
    );
    const keyMatches = rawKeyMatches.filter((k) => suiteKeys.has(k));

    // 2. Resolve trigger key for BFS graph traversal
    let triggerKey = keyMatches[0];
    if (!triggerKey) {
      const lower = fullText.toLowerCase();
      if (lower.includes('bolus') || lower.includes('clamp') || lower.includes('motor') || lower.includes('flow') || lower.includes('pwm')) {
        triggerKey = 'srs-104';
      } else if (lower.includes('droplet') || lower.includes('sensor') || lower.includes('stall') || lower.includes('photodiode')) {
        triggerKey = 'srs-105';
      } else if (lower.includes('oled') || lower.includes('battery') || lower.includes('voltage') || lower.includes('spi')) {
        triggerKey = 'srs-106';
      }
    }

    // 3. Execute deterministic BFS blast-radius traversal on active compliance graph
    const blastRadius = triggerKey ? ComplianceEngine.computeBlastRadius(triggerKey, suite) : undefined;
    const affectedHazards = blastRadius && blastRadius.affectedHazardKeys.length > 0
      ? blastRadius.affectedHazardKeys.map((k) => {
          const l = suite.traceLinks.find((link) => link.hazard.key.toUpperCase() === k.toUpperCase());
          return l ? `${l.hazard.key} (${l.hazard.riskClass.replace('_', ' ')} - ${l.hazard.title.split(':')[0]})` : k;
        })
      : [];

    // Match any trace links touched by detected keys or trigger
    const matchedLinks = suite.traceLinks.filter((l) => {
      const linkKeys = [l.hazard.key, l.work.key, l.spec.id, l.test.testKey].map((k) => k.toUpperCase());
      return keyMatches.some((k) => linkKeys.includes(k)) || (triggerKey && linkKeys.includes(triggerKey.toUpperCase()));
    });

    const isTargeted = affectedHazards.length > 0 || matchedLinks.length > 0;

    // Release gate: only block if touched safety links have unverified compliance states (failing tests, signature drift)
    // Non-blocking Class A/B changes with passing verification tests and valid signatures are authorized to ship.
    const hasUnverifiedGaps = isTargeted
      ? matchedLinks.some((l) => l.complianceState !== 'VERIFIED')
      : suite.releaseBlocked;

    const canShip = !hasUnverifiedGaps;

    let guidance: string[];
    if (hasUnverifiedGaps && blastRadius && blastRadius.transitiveActionPlan.length > 0) {
      guidance = [
        `CRITICAL: Diff/Action impacts safety-critical graph rooted at ${blastRadius.triggerArtifact.title}.`,
        ...blastRadius.transitiveActionPlan,
      ];
    } else if (suite.releaseBlocked) {
      guidance = suite.blockingReasons.map((r) => `Open compliance gap: ${r}`);
    } else {
      guidance = ['All regulatory gates satisfied. Authorized for 510(k) release packaging.'];
    }

    return {
      standards: suite.standards,
      canShipToClinicalProduction: canShip,
      verifiedCoveragePercentage: `${suite.verifiedPercentage}%`,
      classCSummary: {
        totalClassC: suite.classCCount,
        status: suite.releaseBlocked ? 'BLOCKED_BY_SAFETY_GATE' : 'CERTIFIED_READY',
      },
      signatureDriftDetected: suite.signatureDriftCount > 0,
      touchesSafetyCriticalCode: !!isTargeted,
      affectedHazards: affectedHazards.length > 0 ? affectedHazards : ['None (General non-critical change)'],
      activeViolations: suite.blockingReasons,
      remediationGuidance: guidance,
      graphBlastRadius: blastRadius
        ? {
            trigger: blastRadius.triggerArtifact.title,
            severity: blastRadius.impactSeverity,
            traversalPath: blastRadius.traversalPath,
            blockedWorkItems: blastRadius.blockedWorkItemKeys,
            invalidatedTests: blastRadius.invalidatedTestKeys,
            executionTimeMs: blastRadius.executionTimeMs,
          }
        : undefined,
    };
  }
}

/**
 * Handler for manifest module: action (used by rovo:agent and rovo:mcp)
 *
 * Forge rovo:action contract: the function receives (payload, context) where declared inputs
 * are spread at the top of `payload` and the invoked action is identified by `context.moduleKey`
 * (also mirrored under `payload.context.moduleKey` on some invocation paths).
 */
export async function rovoActionHandler(payload: any, context?: any): Promise<any> {
  console.log('[MedTrace RovoAction] Received action invocation:', JSON.stringify(payload));

  const actionKey = context?.moduleKey || payload?.context?.moduleKey || payload?.actionKey || payload?.key || '';
  const inputs = payload?.inputs && typeof payload.inputs === 'object'
    ? { ...payload.inputs }
    : (() => {
        const { context: _ctx, actionKey: _ak, key: _k, ...rest } = payload || {};
        return rest;
      })();

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
