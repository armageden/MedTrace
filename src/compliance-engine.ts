import { TraceLink, ComplianceSummary, IsoHazard, ConfluenceSpec, JiraWorkItem, VerificationTest, Part11Signature } from './types';

export class ComplianceEngine {
  /**
   * Audits a single 5-stage trace link against IEC 62304 and 21 CFR Part 11 rules
   */
  public static evaluateTraceLink(
    hazard: IsoHazard,
    spec: ConfluenceSpec,
    work: JiraWorkItem,
    test: VerificationTest,
    signature: Part11Signature
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
    } else if (hazard.riskClass === 'CLASS_B' && test.status === 'UNTESTED') {
      violations.push(`IEC 62304 Notice: Class B Hazard [${hazard.key}] has no verification execution record.`);
      if ((state as string) !== 'SAFETY_VIOLATION') {
        state = 'INCOMPLETE';
      }
    }

    // 3. FDA 21 CFR Part 11: Electronic Signature Hash Validation
    if (spec.sha256Hash !== signature.artifactSha256 || spec.isSignatureInvalidated) {
      violations.push(
        `21 CFR Part 11 Signature Drift: Confluence Spec [${spec.title}] was modified after clinical sign-off. Expected hash ${signature.artifactSha256.slice(0, 8)}..., current hash ${spec.sha256Hash.slice(0, 8)}...`
      );
      state = 'SIGNATURE_DRIFT';
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
}
