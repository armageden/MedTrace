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
  GraphNodeType,
} from './types';

export interface ReleaseGateOutcome {
  result: boolean;
  errorMessage?: string;
}

export class ComplianceEngine {
  /**
   * Audits a single 5-stage trace link against ISO 14971, IEC 62304, and 21 CFR Part 11 rules.
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

    // 2. IEC 62304 Traceability: Linked Implementation Work Item Check
    if (!work || !work.key || work.key.trim() === '') {
      violations.push(`IEC 62304 Traceability Gap: Hazard [${hazard.key}] lacks a linked Jira implementation work item.`);
      state = 'INCOMPLETE';
    }

    // 3. IEC 62304 Clause 5.7 / 5.8: Verification Test Enforcement
    if (hazard.riskClass === 'CLASS_C') {
      if (test.status !== 'PASSED') {
        violations.push(
          `IEC 62304 Critical Gap: Class C Hazard [${hazard.key}] requires verified test coverage. Current test [${test.testKey}] status is ${test.status}.`
        );
        state = 'SAFETY_VIOLATION';
      }
    } else if (hazard.riskClass === 'CLASS_B' && test.status !== 'PASSED') {
      violations.push(`IEC 62304 Notice: Class B Hazard [${hazard.key}] verification test is ${test.status}.`);
      state = 'INCOMPLETE';
    } else if (hazard.riskClass === 'CLASS_A' && test.status === 'FAILED') {
      violations.push(`IEC 62304 Notice: Class A Hazard [${hazard.key}] verification test [${test.testKey}] FAILED.`);
      state = 'INCOMPLETE';
    }

    // 4. FDA 21 CFR Part 11: Electronic Signature Hash & Validity Enforcement
    const hasHashDrift = spec.sha256Hash !== signature.artifactSha256 || spec.isSignatureInvalidated;
    const hasInvalidSignature =
      !signature.isValid ||
      !signature.signedBy ||
      signature.signedBy.trim() === '' ||
      !signature.signedAt ||
      signature.signedAt.trim() === '';

    if (hasHashDrift) {
      violations.push(
        `Cryptographic Signature Drift: Confluence Spec [${spec.title}] was modified after clinical sign-off. Expected hash ${signature.artifactSha256.slice(0, 8)}..., current hash ${spec.sha256Hash.slice(0, 8)}...`
      );
      if (state !== 'SAFETY_VIOLATION') {
        state = 'SIGNATURE_DRIFT';
      }
    } else if (hasInvalidSignature) {
      violations.push(
        `FDA 21 CFR Part 11 Violation: Electronic signature [${signature.id}] is invalid or missing required signer attestation.`
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
   * Shared issue/global release gate policy used identically by Jira Workflow Validator
   * and the CI/CD HMAC Webtrigger (`verify-release-gate`).
   */
  public static evaluateIssueReleaseGate(issueKey: string | undefined, suite: ComplianceSummary): ReleaseGateOutcome {
    const cleanIssueKey = (issueKey || '').trim().toUpperCase();

    if (cleanIssueKey) {
      const matchedLinks = suite.traceLinks.filter(
        (l) =>
          (l.work?.key || '').toUpperCase() === cleanIssueKey ||
          (l.hazard?.key || '').toUpperCase() === cleanIssueKey
      );

      const blocking = matchedLinks.find((l) => l.complianceState !== 'VERIFIED');
      if (blocking) {
        const violation = blocking.violations[0] || 'Unresolved safety-critical compliance gap.';
        return {
          result: false,
          errorMessage: `❌ [MedTrace Safety Gate] Human-initiated transition blocked for ${cleanIssueKey}!\n• ${violation}\n\nResolve verification test runs or re-certify electronic signatures before releasing.`,
        };
      }

      // Unlinked everyday issues or fully verified safety issues pass without blocking
      return { result: true };
    }

    // Global release gate (no issueKey specified)
    if (suite.releaseBlocked) {
      const topViolation = suite.blockingReasons[0] || 'Unresolved safety-critical compliance gaps.';
      return {
        result: false,
        errorMessage: `❌ [MedTrace Safety Gate] Human-initiated transition blocked!\n• ${topViolation}\n\nResolve verification test runs or re-certify electronic signatures before releasing.`,
      };
    }

    return { result: true };
  }

  /**
   * Evaluates the entire project suite and builds an audit-ready compliance summary.
   */
  public static generateComplianceReport(
    traceLinks: TraceLink[],
    datasetMode: 'DEMO' | 'LIVE' = 'DEMO',
    projectName: string = 'Smart Infusion Pump Firmware v2.1',
    metadata?: {
      storageFormat?: 'SHARDED_V2' | 'SINGLE_KEY_V1';
      auditEntryCount?: number;
      auditHeadHash?: string;
    }
  ): ComplianceSummary {
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

      const hasDriftedOrInvalidSig =
        link.complianceState === 'SIGNATURE_DRIFT' ||
        Boolean(
          link.spec &&
            link.signature &&
            (link.spec.sha256Hash !== link.signature.artifactSha256 ||
              link.spec.isSignatureInvalidated ||
              !link.signature.isValid)
        );
      if (hasDriftedOrInvalidSig) {
        signatureDriftCount++;
      }
    }

    const verifiedPercentage =
      traceLinks.length > 0 ? Math.round((verifiedCount / traceLinks.length) * 100) : 0;

    const releaseBlocked = blockingReasons.length > 0;

    return {
      projectName,
      datasetMode,
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
      ...(metadata?.storageFormat ? { storageFormat: metadata.storageFormat } : {}),
      ...(typeof metadata?.auditEntryCount === 'number' ? { auditEntryCount: metadata.auditEntryCount } : {}),
      ...(metadata?.auditHeadHash ? { auditHeadHash: metadata.auditHeadHash } : {}),
    };
  }

  private static matchesLinkByKey(link: TraceLink, cleanKey: string): GraphNodeType | null {
    if (
      link.hazard?.key?.toLowerCase() === cleanKey ||
      link.hazard?.id?.toLowerCase() === cleanKey
    ) {
      return 'HAZARD';
    }
    const specShortKey = (link.spec?.title || '').split(':')[0].trim().toLowerCase();
    if (
      link.spec?.id?.toLowerCase() === cleanKey ||
      (link.spec?.pageId && link.spec.pageId.toLowerCase() === cleanKey) ||
      link.hazard?.mitigationRequirementId?.toLowerCase() === cleanKey ||
      (link.spec?.title && link.spec.title.toLowerCase() === cleanKey) ||
      (specShortKey !== '' && specShortKey === cleanKey)
    ) {
      return 'SPEC';
    }
    if (
      link.work?.key?.toLowerCase() === cleanKey ||
      link.work?.id?.toLowerCase() === cleanKey
    ) {
      return 'WORK';
    }
    if (
      link.test?.testKey?.toLowerCase() === cleanKey ||
      link.test?.id?.toLowerCase() === cleanKey
    ) {
      return 'TEST';
    }
    if (link.signature?.id?.toLowerCase() === cleanKey) {
      return 'SIGNATURE';
    }
    return null;
  }

  /**
   * Deterministic Regulatory Blast Radius & Transitive Impact Analyzer.
   * Executes a breadth-first traversal over the typed 5-stage traceability graph
   * (HAZARD, SPEC, WORK, TEST, SIGNATURE).
   */
  public static computeBlastRadius(triggerKey: string, suite: ComplianceSummary): BlastRadiusReport {
    const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const cleanKey = (triggerKey || '').trim().toLowerCase();

    let matchingLinks: TraceLink[];
    let matchedType: GraphNodeType = 'SPEC';
    if (!cleanKey) {
      matchingLinks = suite.traceLinks.slice(0, 1);
    } else {
      const matched: Array<{ link: TraceLink; nodeType: GraphNodeType }> = [];
      for (const l of suite.traceLinks) {
        const nodeType = this.matchesLinkByKey(l, cleanKey);
        if (nodeType) {
          matched.push({ link: l, nodeType });
        }
      }
      matchingLinks = matched.map((m) => m.link);
      if (matched.length > 0) {
        matchedType = matched[0].nodeType;
      }
    }

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

    const nodeKeysOf = (link: TraceLink): string[] => [
      `spec:${link.spec.id.toLowerCase()}`,
      `haz:${link.hazard.key.toLowerCase()}`,
      `work:${link.work.key.toLowerCase()}`,
      `test:${link.test.testKey.toLowerCase()}`,
      `sig:${link.signature.id.toLowerCase()}`,
    ];

    const linksByNode = new Map<string, TraceLink[]>();
    for (const link of suite.traceLinks) {
      for (const nodeKey of nodeKeysOf(link)) {
        const links = linksByNode.get(nodeKey);
        if (links) {
          if (!links.includes(link)) links.push(link);
        } else {
          linksByNode.set(nodeKey, [link]);
        }
      }
    }

    // Pre-collect the reachable connected component so we know whether any upstream spec drifted.
    const reachableSet = new Set<TraceLink>();
    const exploreQueue: TraceLink[] = [];
    for (const link of matchingLinks) {
      if (!reachableSet.has(link)) {
        reachableSet.add(link);
        exploreQueue.push(link);
      }
    }
    let exploreIdx = 0;
    while (exploreIdx < exploreQueue.length) {
      const link = exploreQueue[exploreIdx++];
      for (const nodeKey of nodeKeysOf(link)) {
        for (const sibling of linksByNode.get(nodeKey) || []) {
          if (!reachableSet.has(sibling)) {
            reachableSet.add(sibling);
            exploreQueue.push(sibling);
          }
        }
      }
    }
    const componentHasSignatureDrift = Array.from(reachableSet).some(
      (l) => l.spec.sha256Hash !== l.signature.artifactSha256 || l.spec.isSignatureInvalidated || !l.signature.isValid
    );

    const visitedNodes = new Set<string>();
    const visitedRels = new Set<string>();
    const enqueued = new Set<TraceLink>();
    const plannedHazardKeys = new Set<string>();
    const traversalPath: BlastRadiusReport['traversalPath'] = [];
    const affectedHazardKeys: string[] = [];
    const blockedWorkItemKeys: string[] = [];
    const invalidatedTestKeys: string[] = [];
    const invalidatedSignatureIds: string[] = [];
    const transitiveActionPlan: string[] = [];
    const affectedLinks: TraceLink[] = [];

    const queue: TraceLink[] = [];
    const enqueue = (link: TraceLink) => {
      if (!enqueued.has(link)) {
        enqueued.add(link);
        queue.push(link);
      }
    };
    for (const link of matchingLinks) enqueue(link);

    const rootLink = matchingLinks[0];
    let cursor = 0;
    while (cursor < queue.length) {
      const link = queue[cursor++];
      affectedLinks.push(link);
      const specNode = link.spec;
      const haz = link.hazard;

      // SIGNS edge (Spec -> Signature)
      const sig = link.signature;
      const sigKey = `sig:${sig.id.toLowerCase()}`;
      const isSignatureDrifted = specNode.sha256Hash !== sig.artifactSha256 || specNode.isSignatureInvalidated || !sig.isValid;
      if (!visitedNodes.has(sigKey)) {
        visitedNodes.add(sigKey);
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

      // MITIGATES edge (Spec -> Hazard)
      const mitigatesKey = `mitigates:${specNode.id.toLowerCase()}->${haz.key.toLowerCase()}`;
      if (!visitedRels.has(mitigatesKey)) {
        visitedRels.add(mitigatesKey);
        if (!affectedHazardKeys.includes(haz.key)) {
          affectedHazardKeys.push(haz.key);
        }
        const isCompromised = componentHasSignatureDrift || link.complianceState !== 'VERIFIED';
        traversalPath.push({
          hop: traversalPath.length + 1,
          from: `Spec [${specNode.title.split(':')[0].trim()}]`,
          edge: 'MITIGATES' as GraphEdgeType,
          to: `Hazard [${haz.key}]`,
          effect: isCompromised
            ? `Safety mitigation compromised: ${haz.title} (${haz.riskClass.replace('_', ' ')}).`
            : `Safety mitigation verified: ${haz.title} (${haz.riskClass.replace('_', ' ')}).`,
        });
        if (isCompromised && !plannedHazardKeys.has(haz.key)) {
          plannedHazardKeys.add(haz.key);
          transitiveActionPlan.push(`Review ISO 14971 risk mitigations for ${haz.key} against revised specifications.`);
        }
      }

      // IMPLEMENTS edge (Hazard -> Jira Work Item)
      const work = link.work;
      const workKey = `work:${work.key.toLowerCase()}`;
      const isWorkAffected =
        componentHasSignatureDrift || link.complianceState !== 'VERIFIED' || work.status !== 'Done';
      if (!visitedNodes.has(workKey)) {
        visitedNodes.add(workKey);
        if (isWorkAffected) {
          blockedWorkItemKeys.push(work.key);
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Hazard [${haz.key}]`,
            edge: 'IMPLEMENTS' as GraphEdgeType,
            to: `Jira Item [${work.key}]`,
            effect: `Transition blocked: Firmware task assigned to ${work.assignee} locked under human-transition policy gate.`,
          });
          transitiveActionPlan.push(`Verify firmware implementation in ${work.key} (${work.prNumber || 'open PR'}) matches updated parameters.`);
        } else {
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Hazard [${haz.key}]`,
            edge: 'IMPLEMENTS' as GraphEdgeType,
            to: `Jira Item [${work.key}]`,
            effect: `Implementation verified (${work.status}) with no active signature drift.`,
          });
        }
      }

      // VERIFIES edge (Hazard -> Test Execution)
      const test = link.test;
      const testKey = `test:${test.testKey.toLowerCase()}`;
      const isTestAffected =
        componentHasSignatureDrift || link.complianceState !== 'VERIFIED' || test.status !== 'PASSED';
      if (!visitedNodes.has(testKey)) {
        visitedNodes.add(testKey);
        if (isTestAffected) {
          invalidatedTestKeys.push(test.testKey);
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Hazard [${haz.key}]`,
            edge: 'VERIFIES' as GraphEdgeType,
            to: `Test [${test.testKey}]`,
            effect: `Verification test evidence invalidated: ${test.title} must be executed against new specification parameters.`,
          });
          transitiveActionPlan.push(`Execute automated verification run for ${test.testKey} (${test.testType}) to regenerate passing evidence.`);
        } else {
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Hazard [${haz.key}]`,
            edge: 'VERIFIES' as GraphEdgeType,
            to: `Test [${test.testKey}]`,
            effect: `Verification test ${test.testKey} remains PASSED under valid Part 11 signature.`,
          });
        }
      }

      for (const nodeKey of nodeKeysOf(link)) {
        for (const sibling of linksByNode.get(nodeKey) || []) {
          enqueue(sibling);
        }
      }
    }

    if (transitiveActionPlan.length === 0) {
      transitiveActionPlan.push('All traversed artifacts are verified and signed; no remediation required.');
    }

    const hasClassC = affectedLinks.some((l) => l.hazard.riskClass === 'CLASS_C');
    const hasClassB = affectedLinks.some((l) => l.hazard.riskClass === 'CLASS_B');
    const impactSeverity: BlastRadiusReport['impactSeverity'] = hasClassC
      ? 'CRITICAL_CATASTROPHIC'
      : hasClassB
      ? 'MAJOR_SERIOUS'
      : 'MINOR';

    const endTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const executionTimeMs = parseFloat(Math.max(0.01, endTime - startTime).toFixed(2));

    let triggerArtifact: BlastRadiusReport['triggerArtifact'];
    if (matchedType === 'HAZARD') {
      triggerArtifact = {
        type: 'HAZARD',
        id: rootLink.hazard.id,
        key: rootLink.hazard.key,
        title: rootLink.hazard.title,
        deltaReason: `Hazard risk mitigation audit: ${rootLink.hazard.severity} risk`,
      };
    } else if (matchedType === 'WORK') {
      triggerArtifact = {
        type: 'WORK',
        id: rootLink.work.id,
        key: rootLink.work.key,
        title: rootLink.work.title,
        deltaReason: `Jira work item state: ${rootLink.work.status}`,
      };
    } else if (matchedType === 'TEST') {
      triggerArtifact = {
        type: 'TEST',
        id: rootLink.test.id,
        key: rootLink.test.testKey,
        title: rootLink.test.title,
        deltaReason: `Verification test status: ${rootLink.test.status}`,
      };
    } else if (matchedType === 'SIGNATURE') {
      triggerArtifact = {
        type: 'SIGNATURE',
        id: rootLink.signature.id,
        key: rootLink.signature.id,
        title: `${rootLink.signature.signedBy} — ${rootLink.signature.meaning}`,
        deltaReason: rootLink.signature.invalidationReason || (rootLink.signature.isValid ? 'Valid Part 11 signature' : 'Invalidated Part 11 signature'),
      };
    } else {
      triggerArtifact = {
        type: 'SPEC',
        id: rootLink.spec.id,
        key: rootLink.spec.title.split(':')[0].trim(),
        title: rootLink.spec.title,
        deltaReason: rootLink.spec.lastUpdated || 'Specification content modified',
      };
    }

    return {
      triggerArtifact,
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
