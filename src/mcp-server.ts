import { ComplianceEngine } from './compliance-engine';
import { SeederService } from './seeder';
import { TraceLink } from './types';

const STOP_WORDS = new Set([
  'with', 'from', 'that', 'this', 'must', 'every', 'during', 'within', 'clause',
  'test', 'tests', 'spec', 'specs', 'jira', 'confluence', 'hazard', 'issue',
  'firmware', 'software', 'system', 'systems', 'verification', 'safety', 'implement',
  'updated', 'modified', 'version', 'approved', 'pending', 'passed', 'failed',
]);

function extractMeaningfulTokens(text: string): string[] {
  const tokens = text.toLowerCase().match(/[a-z0-9_]{4,}/g) || [];
  return Array.from(new Set(tokens.filter((t) => !STOP_WORDS.has(t))));
}

function findLinksMatchingTextTokens(fullText: string, traceLinks: TraceLink[]): TraceLink[] {
  const lower = fullText.toLowerCase();
  if (!lower.trim()) return [];

  const matched: TraceLink[] = [];
  for (const link of traceLinks) {
    const corpus = `${link.spec?.title || ''} ${link.spec?.contentSnippet || ''} ${link.hazard?.title || ''} ${link.work?.title || ''}`;
    const tokens = extractMeaningfulTokens(corpus);
    if (tokens.some((tok) => lower.includes(tok))) {
      matched.push(link);
    }
  }
  return matched;
}

/**
 * MedTrace MCP Tools & Rovo Action Handlers.
 * Serves both Atlassian Rovo agent invocations and external MCP coding assistants.
 */
export class McpToolService {
  /**
   * Tool: get-hazard-lineage-action
   * Retrieves complete ISO 14971 hazard safety lineage for an issue/hazard/test key or full project.
   */
  public static async getHazardLineage(inputs?: { issueKey?: string; hazardKey?: string }): Promise<any> {
    const suite = await SeederService.getActiveComplianceSuite();
    const lookupKey = (inputs?.issueKey || inputs?.hazardKey || '').trim();

    if (lookupKey) {
      const lower = lookupKey.toLowerCase();
      const match = suite.traceLinks.find(
        (l) =>
          l.hazard.key.toLowerCase() === lower ||
          l.work.key.toLowerCase() === lower ||
          l.test.testKey.toLowerCase() === lower ||
          l.spec.id.toLowerCase() === lower ||
          (l.spec.pageId && l.spec.pageId.toLowerCase() === lower)
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

      return {
        found: false,
        queriedKey: lookupKey,
        message: `No trace link found for key "${lookupKey}" in project "${suite.projectName}".`,
        availableKeys: suite.traceLinks.map((l) => ({
          hazardKey: l.hazard.key,
          workKey: l.work.key,
          specId: l.spec.id,
          testKey: l.test.testKey,
        })),
      };
    }

    return {
      projectName: suite.projectName,
      datasetMode: suite.datasetMode,
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
   * Audits active codebase/sprint against IEC 62304 and FDA 21 CFR Part 11 requirements.
   * Matches explicit suite keys and dynamic tokens from active specs/hazards/work items,
   * then runs deterministic BFS blast-radius traversal.
   */
  public static async verifyIecCompliance(inputs?: {
    prDiff?: string;
    componentName?: string;
    issueKey?: string;
  }): Promise<any> {
    const suite = await SeederService.getActiveComplianceSuite();
    const fullText = `${inputs?.prDiff || ''} ${inputs?.componentName || ''} ${inputs?.issueKey || ''}`;

    // 1. Match explicit keys present in the active suite
    const rawKeyMatches = Array.from(new Set(fullText.match(/\b[A-Za-z]{2,8}-\d+\b/g) || [])).map((k) =>
      k.toUpperCase()
    );
    const suiteKeys = new Set(
      suite.traceLinks.flatMap((l) =>
        [l.hazard.key, l.work.key, l.spec.id, l.spec.pageId || '', l.test.testKey, l.signature.id]
          .filter(Boolean)
          .map((k) => String(k).toUpperCase())
      )
    );
    const keyMatches = rawKeyMatches.filter((k) => suiteKeys.has(k));

    // 2. Dynamic token matching across active suite specs/hazards/work items + safety fallback keywords
    let triggerKey = keyMatches[0];
    let tokenMatchedLinks: TraceLink[] = [];
    if (!triggerKey) {
      tokenMatchedLinks = findLinksMatchingTextTokens(fullText, suite.traceLinks);
      if (tokenMatchedLinks.length > 0) {
        triggerKey = tokenMatchedLinks[0].spec.id;
      } else {
        const lower = fullText.toLowerCase();
        if (
          lower.includes('bolus') ||
          lower.includes('clamp') ||
          lower.includes('motor') ||
          lower.includes('flow') ||
          lower.includes('pwm')
        ) {
          triggerKey = 'srs-104';
        } else if (
          lower.includes('droplet') ||
          lower.includes('sensor') ||
          lower.includes('stall') ||
          lower.includes('photodiode')
        ) {
          triggerKey = 'srs-105';
        } else if (
          lower.includes('oled') ||
          lower.includes('battery') ||
          lower.includes('voltage') ||
          lower.includes('spi')
        ) {
          triggerKey = 'srs-106';
        }
      }
    }

    // 3. Execute deterministic BFS blast-radius traversal on active compliance graph
    const blastRadius = triggerKey ? ComplianceEngine.computeBlastRadius(triggerKey, suite) : undefined;
    const affectedHazards =
      blastRadius && blastRadius.affectedHazardKeys.length > 0
        ? blastRadius.affectedHazardKeys.map((k) => {
            const l = suite.traceLinks.find((link) => link.hazard.key.toUpperCase() === k.toUpperCase());
            return l ? `${l.hazard.key} (${l.hazard.riskClass.replace('_', ' ')} - ${l.hazard.title.split(':')[0]})` : k;
          })
        : [];

    const matchedLinks = suite.traceLinks.filter((l) => {
      const linkKeys = [l.hazard.key, l.work.key, l.spec.id, l.spec.pageId || '', l.test.testKey]
        .filter(Boolean)
        .map((k) => k.toUpperCase());
      return (
        keyMatches.some((k) => linkKeys.includes(k)) ||
        (triggerKey && linkKeys.includes(triggerKey.toUpperCase())) ||
        tokenMatchedLinks.includes(l)
      );
    });

    const isTargeted = affectedHazards.length > 0 || matchedLinks.length > 0;
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
      datasetMode: suite.datasetMode,
      canShipToClinicalProduction: canShip,
      verifiedCoveragePercentage: `${suite.verifiedPercentage}%`,
      classCSummary: {
        totalClassC: suite.classCCount,
        status: suite.releaseBlocked ? 'BLOCKED_BY_SAFETY_GATE' : 'CERTIFIED_READY',
      },
      signatureDriftDetected: suite.signatureDriftCount > 0,
      touchesSafetyCriticalCode: Boolean(isTargeted),
      affectedHazards: affectedHazards.length > 0 ? affectedHazards : ['None (No matched safety-critical artifacts in change scope)'],
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
 * Handler for manifest module: action (used by rovo:agent and rovo:mcp).
 * Never logs raw PR diff payloads to prevent sensitive source exposure in platform logs.
 */
export async function rovoActionHandler(payload: any, context?: any): Promise<any> {
  const actionKey = String(context?.moduleKey || payload?.context?.moduleKey || payload?.actionKey || payload?.key || '').trim();
  const inputs =
    payload?.inputs && typeof payload.inputs === 'object'
      ? { ...payload.inputs }
      : (() => {
          const { context: _ctx, actionKey: _ak, key: _k, ...rest } = payload || {};
          return rest;
        })();

  console.log('[MedTrace RovoAction] Dispatching action:', {
    actionKey,
    issueKey: inputs?.issueKey || inputs?.hazardKey || null,
    componentName: inputs?.componentName || null,
    hasPrDiff: Boolean(inputs?.prDiff),
  });

  if (actionKey === 'get-hazard-lineage-action' || actionKey === 'get-hazard-lineage') {
    return await McpToolService.getHazardLineage(inputs);
  }

  if (actionKey === 'verify-iec-compliance-action' || actionKey === 'verify-iec-compliance') {
    return await McpToolService.verifyIecCompliance(inputs);
  }

  return {
    error: `Unknown action: ${actionKey}`,
    availableTools: ['get-hazard-lineage-action', 'verify-iec-compliance-action'],
  };
}
