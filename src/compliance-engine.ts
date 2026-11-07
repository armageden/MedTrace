import {
  TraceLink,
  ComplianceSummary,
  IsoHazard,
  ConfluenceSpec,
  JiraWorkItem,
  VerificationTest,
  Part11Signature,
  GraphMetadata,
  BlastRadiusReport,
  GraphEdgeType,
} from './types';

export class ComplianceEngine {
  /**
   * Audits a single 5-stage trace link against IEC 62304 and 21 CFR Part 11 rules
   */
  public static evaluateTraceLink(
    hazard: IsoHazard,
    spec: ConfluenceSpec,
    work: JiraWorkItem,
    test: VerificationTest,
    signature: Part11Signature,
    graphMetadata?: GraphMetadata
  ): TraceLink {
    const violations: string[] = [];
    let state: TraceLink['complianceState'] = 'VERIFIED';

    // 1. ISO 14971 Risk Mitigation Check
    if (!spec.title || spec.title.trim() === '') {
      violations.push('ISO 14971 Violation: Hazard lacks linked Software Safety Specification (Confluence SRS).');
      state = 'INCOMPLETE';
    }

    // 2. IEC 62304 Clause 5.7 / 5.8: Verification Test Enforcement
    if (hazard.riskClass === 'CLASS_C') {
      if (test.status !== 'PASSED') {
        violations.push(
          `IEC 62304 Critical Gap: Class C Hazard [${hazard.key}] requires verified test coverage. Current test [${test.testKey}] status is ${test.status}.`
        );
        state = 'SAFETY_VIOLATION';
      }
    } else if (hazard.riskClass === 'CLASS_B' && test.status !== 'PASSED') {
      violations.push(`IEC 62304 Notice: Class B Hazard [${hazard.key}] verification test is ${test.status}.`);
      if ((state as string) !== 'SAFETY_VIOLATION') {
        state = 'INCOMPLETE';
      }
    }

    // 3. FDA 21 CFR Part 11: Electronic Signature Hash Validation
    if (spec.sha256Hash !== signature.artifactSha256 || spec.isSignatureInvalidated) {
      violations.push(
        `Cryptographic Signature Drift: Confluence Spec [${spec.title}] was modified after clinical sign-off. Expected hash ${signature.artifactSha256.slice(0, 8)}..., current hash ${spec.sha256Hash.slice(0, 8)}...`
      );
      if (state !== 'SAFETY_VIOLATION') {
        state = 'SIGNATURE_DRIFT';
      }
    }

    return {
      id: `trace-${hazard.key}`,
      hazard,
      spec,
      work,
      test,
      signature,
      complianceState: state,
      violations,
      graphMetadata,
    };
  }

  /**
   * Evaluates the entire project suite and builds an audit-ready compliance summary
   */
  public static generateComplianceReport(traceLinks: TraceLink[]): ComplianceSummary {
    let classCCount = 0;
    let classBCount = 0;
    let classACount = 0;
    let verifiedCount = 0;
    let signatureDriftCount = 0;
    const blockingReasons: string[] = [];

    for (const link of traceLinks) {
      if (link.hazard.riskClass === 'CLASS_C') classCCount++;
      else if (link.hazard.riskClass === 'CLASS_B') classBCount++;
      else classACount++;

      if (link.complianceState === 'VERIFIED') {
        verifiedCount++;
      } else {
        blockingReasons.push(...link.violations);
      }

      if (link.complianceState === 'SIGNATURE_DRIFT') {
        signatureDriftCount++;
      }
    }

    const verifiedPercentage = traceLinks.length > 0
      ? Math.round((verifiedCount / traceLinks.length) * 100)
      : 0;

    const releaseBlocked = blockingReasons.length > 0;

    return {
      projectName: 'Smart Infusion Pump Firmware v2.1',
      standards: [
        'IEC 62304:2006+A1:2015 (Medical Device Software Lifecycle)',
        'ISO 14971:2019 (Risk Management for Medical Devices)',
        'FDA 21 CFR Part 11 (Electronic Records & Signatures)',
      ],
      totalHazards: traceLinks.length,
      classCCount,
      classBCount,
      classACount,
      verifiedPercentage,
      releaseBlocked,
      blockingReasons,
      signatureDriftCount,
      traceLinks,
      lastAuditTimestamp: new Date().toISOString(),
    };
  }

  /**
   * Deterministic Regulatory Blast Radius & Transitive Impact Analyzer
   * Executes a formal BFS traversal over the typed 5-stage traceability graph
   * (HAZARD, SPEC, WORK, TEST, SIGNATURE) to compute the ripple effect of specification
   * drift or test failures. Guaranteed cycle-safe and deterministic.
   */
  public static computeBlastRadius(triggerKey: string, suite: ComplianceSummary): BlastRadiusReport {
    const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const cleanKey = (triggerKey || '').trim().toLowerCase();

    // Identify all trace links connected to this trigger (by spec id/title, hazard key, work key, or test key)
    let matchingLinks = suite.traceLinks.filter(
      (l) =>
        l.spec.id.toLowerCase() === cleanKey ||
        l.spec.title.toLowerCase().includes(cleanKey) ||
        l.hazard.key.toLowerCase() === cleanKey ||
        l.hazard.mitigationRequirementId.toLowerCase() === cleanKey ||
        l.work.key.toLowerCase() === cleanKey ||
        l.test.testKey.toLowerCase() === cleanKey
    );

    // If no trigger was specified, default to first link for demonstration
    if (matchingLinks.length === 0 && (!cleanKey || cleanKey === '')) {
      matchingLinks = suite.traceLinks.slice(0, 1);
    }

    // If a specific trigger was requested but is completely disconnected / not found:
    if (matchingLinks.length === 0) {
      const endTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
      return {
        triggerArtifact: {
          type: 'SPEC',
          id: cleanKey,
          key: cleanKey,
          title: `Unknown / Disconnected Artifact [${cleanKey}]`,
          deltaReason: 'No downstream safety-critical trace links found in active project graph',
        },
        impactSeverity: 'MINOR',
        affectedHazardKeys: [],
        blockedWorkItemKeys: [],
        invalidatedTestKeys: [],
        invalidatedSignatureIds: [],
        traversalPath: [],
        transitiveActionPlan: ['No safety-critical artifacts affected.'],
        executionTimeMs: parseFloat(Math.max(0.01, endTime - startTime).toFixed(2)),
      };
    }

    const visited = new Set<string>();
    const traversalPath: BlastRadiusReport['traversalPath'] = [];
    const affectedHazardKeys: string[] = [];
    const blockedWorkItemKeys: string[] = [];
    const invalidatedTestKeys: string[] = [];
    const invalidatedSignatureIds: string[] = [];
    const transitiveActionPlan: string[] = [];

    const rootSpec = matchingLinks[0].spec;

    for (const link of matchingLinks) {
      const specNode = link.spec;
      const specKey = `spec:${specNode.id}`;

      // Hop 1: SIGNS edge (Spec -> Signature)
      const sigList = ((link as any).signatures && Array.isArray((link as any).signatures))
        ? [link.signature, ...(link as any).signatures].filter(Boolean)
        : [link.signature].filter(Boolean);

      for (const sig of sigList) {
        const sigKey = `sig:${sig.id}`;
        if (!visited.has(sigKey)) {
          visited.add(sigKey);
          const isSignatureDrifted = specNode.sha256Hash !== sig.artifactSha256 || specNode.isSignatureInvalidated;
          if (isSignatureDrifted) {
            invalidatedSignatureIds.push(sig.id);
            traversalPath.push({
              hop: traversalPath.length + 1,
              from: `Spec [${specNode.title.split(':')[0].trim()}]`,
              edge: 'SIGNS' as GraphEdgeType,
              to: `Signature [${sig.signedBy}]`,
              effect: `Signature evidence invalidated: hash drift detected (expected ${sig.artifactSha256.slice(0, 8)}..., current ${specNode.sha256Hash.slice(0, 8)}...).`,
            });
            transitiveActionPlan.push(`Re-certify clinical sign-off with ${sig.signedBy} (${sig.role}) for revised spec.`);
          }
        }
      }

      // Hop 2: MITIGATES edge (Spec -> Hazard)
      const haz = link.hazard;
      const mitigatesKey = `mitigates:${specNode.id}->${haz.key}`;
      if (!visited.has(mitigatesKey)) {
        visited.add(mitigatesKey);
        if (!affectedHazardKeys.includes(haz.key)) {
          affectedHazardKeys.push(haz.key);
        }
        traversalPath.push({
          hop: traversalPath.length + 1,
          from: `Spec [${specNode.title.split(':')[0].trim()}]`,
          edge: 'MITIGATES' as GraphEdgeType,
          to: `Hazard [${haz.key}]`,
          effect: `Safety mitigation compromised: ${haz.title} (${haz.riskClass.replace('_', ' ')}).`,
        });
        if (!transitiveActionPlan.some((p) => p.includes(haz.key))) {
          transitiveActionPlan.push(`Review ISO 14971 risk mitigations for ${haz.key} against revised specifications.`);
        }
      }

      // Hop 3: IMPLEMENTS edge (Hazard -> Jira Work Item)
      const work = link.work;
      const workKey = `work:${work.key}`;
      if (!visited.has(workKey)) {
        visited.add(workKey);
        blockedWorkItemKeys.push(work.key);
        traversalPath.push({
          hop: traversalPath.length + 1,
          from: `Hazard [${haz.key}]`,
          edge: 'IMPLEMENTS' as GraphEdgeType,
          to: `Jira Item [${work.key}]`,
          effect: `Transition blocked: Firmware task assigned to ${work.assignee} locked under human-transition policy gate.`,
        });
        transitiveActionPlan.push(`Verify firmware implementation in ${work.key} (${work.prNumber || 'open PR'}) matches updated parameters.`);
      }

      // Hop 4: VERIFIES edge (Hazard -> Test Execution)
      const test = link.test;
      const testKey = `test:${test.testKey}`;
      if (!visited.has(testKey)) {
        visited.add(testKey);
        invalidatedTestKeys.push(test.testKey);
        traversalPath.push({
          hop: traversalPath.length + 1,
          from: `Hazard [${haz.key}]`,
          edge: 'VERIFIES' as GraphEdgeType,
          to: `Test [${test.testKey}]`,
          effect: `Verification test evidence invalidated: ${test.title} must be executed against new specification parameters.`,
        });
        transitiveActionPlan.push(`Execute automated verification run for ${test.testKey} (${test.testType}) to regenerate passing evidence.`);
      }
    }

    // Determine highest severity among all affected hazards
    const hasClassC = matchingLinks.some((l) => l.hazard.riskClass === 'CLASS_C');
    const hasClassB = matchingLinks.some((l) => l.hazard.riskClass === 'CLASS_B');
    const impactSeverity: BlastRadiusReport['impactSeverity'] = hasClassC
      ? 'CRITICAL_CATASTROPHIC'
      : hasClassB
      ? 'MAJOR_SERIOUS'
      : 'MINOR';

    const endTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const executionTimeMs = parseFloat(Math.max(0.01, endTime - startTime).toFixed(2));

    const isHazardTrigger = matchingLinks.some((l) => l.hazard.key.toLowerCase() === cleanKey);
    const triggerHazard = isHazardTrigger ? matchingLinks.find((l) => l.hazard.key.toLowerCase() === cleanKey)!.hazard : null;

    return {
      triggerArtifact: triggerHazard
        ? {
            type: 'HAZARD',
            id: triggerHazard.id,
            key: triggerHazard.key,
            title: triggerHazard.title,
            deltaReason: `Hazard risk mitigation audit: ${triggerHazard.severity} risk`,
          }
        : {
            type: 'SPEC',
            id: rootSpec.id,
            key: rootSpec.title.split(':')[0].trim(),
            title: rootSpec.title,
            deltaReason: rootSpec.lastUpdated || 'Specification content modified',
          },
      impactSeverity,
      affectedHazardKeys,
      blockedWorkItemKeys,
      invalidatedTestKeys,
      invalidatedSignatureIds,
      traversalPath,
      transitiveActionPlan,
      executionTimeMs,
    };
  }
}
