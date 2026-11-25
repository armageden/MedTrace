import crypto from 'node:crypto';
import {
  canonicalJsonStringify,
  isSignatureTimestampInvalidated,
  sanitizeKvsKeySegment,
  sha256Hex,
  validateHttpsUrl,
} from './crypto-utils';
import {
  BlastRadiusReport,
  ComplianceSummary,
  ConfluenceSpec,
  GraphEdgeType,
  GraphMetadata,
  GraphNodeType,
  IsoHazard,
  JiraWorkItem,
  Part11Signature,
  RiskClass,
  TraceLink,
  VerificationTest,
} from './types';

export interface ReleaseGateOutcome {
  result: boolean;
  errorMessage?: string;
}

export interface EvaluateTraceOptions {
  linkId?: string;
  part11Secret?: string;
  requireCryptographicSeal?: boolean;
  requireTestEvidence?: boolean;
  reverificationTaskKey?: string;
}

export interface CanonicalPart11Payload {
  hazardKey: string;
  specId: string;
  artifactSha256: string;
  signedByAccountId: string;
  signedBy: string;
  role: string;
  meaning: string;
  signedAt: string;
  authMethod: string;
}

type ComplianceState = TraceLink['complianceState'];

const STATE_PRECEDENCE: Record<ComplianceState, number> = {
  VERIFIED: 0,
  INCOMPLETE: 1,
  SIGNATURE_DRIFT: 2,
  SAFETY_VIOLATION: 3,
};

function escalateComplianceState(current: ComplianceState, candidate: ComplianceState): ComplianceState {
  return STATE_PRECEDENCE[candidate] > STATE_PRECEDENCE[current] ? candidate : current;
}

function severityForRiskClass(riskClass: RiskClass): ComplianceState {
  return riskClass === 'CLASS_C' ? 'SAFETY_VIOLATION' : 'INCOMPLETE';
}

function hasPriorElectronicSignOff(signature: Part11Signature | undefined): boolean {
  if (!signature) {
    return false;
  }
  return Boolean(
    (signature.artifactSha256 && signature.artifactSha256.trim() !== '') ||
      (signature.signedBy && signature.signedBy.trim() !== '') ||
      (signature.signedAt && signature.signedAt.trim() !== '') ||
      (signature.invalidatedAt && signature.invalidatedAt.trim() !== '')
  );
}

function isLinkSignatureDrifted(link: TraceLink): boolean {
  if (!link.spec || !link.signature) {
    return false;
  }
  if (link.spec.isSignatureInvalidated === true) {
    return true;
  }
  if (!hasPriorElectronicSignOff(link.signature)) {
    return false;
  }
  if (link.spec.isMissingSentinel === true || link.spec.specRestricted === true) {
    return !link.signature.isValid || isSignatureTimestampInvalidated(link.signature);
  }
  return (
    (Boolean(link.spec.sha256Hash) && link.spec.sha256Hash !== link.signature.artifactSha256) ||
    !link.signature.isValid ||
    isSignatureTimestampInvalidated(link.signature)
  );
}

function buildNodeKeys(link: TraceLink): string[] {
  const keys: string[] = [];
  if (link.spec?.id?.trim()) keys.push(`spec:${link.spec.id.trim().toLowerCase()}`);
  if (link.hazard?.key?.trim()) keys.push(`haz:${link.hazard.key.trim().toLowerCase()}`);
  if (link.work?.key?.trim()) keys.push(`work:${link.work.key.trim().toLowerCase()}`);
  if (link.test?.testKey?.trim()) keys.push(`test:${link.test.testKey.trim().toLowerCase()}`);
  if (link.signature?.id?.trim()) keys.push(`sig:${link.signature.id.trim().toLowerCase()}`);
  return keys;
}

function formatSpecLabel(spec: ConfluenceSpec | undefined): string {
  const title = (spec?.title || '').trim();
  if (title) {
    return title.split(':')[0].trim() || title;
  }
  return (spec?.id || '').trim() || 'UNLINKED';
}

function buildSingleTriggerArtifact(
  rootLink: TraceLink,
  matchedType: GraphNodeType
): BlastRadiusReport['triggerArtifact'] {
  if (matchedType === 'HAZARD') {
    return {
      type: 'HAZARD',
      id: rootLink.hazard.id,
      key: rootLink.hazard.key,
      title: rootLink.hazard.title,
      deltaReason: rootLink.hazard.severity
        ? `Hazard risk mitigation audit: ${rootLink.hazard.severity} risk`
        : `IEC 62304 safety class audit: ${rootLink.hazard.riskClass.replace('_', ' ')}`,
    };
  }
  if (matchedType === 'WORK') {
    return {
      type: 'WORK',
      id: rootLink.work.id,
      key: rootLink.work.key,
      title: rootLink.work.title,
      deltaReason: `Jira work item state: ${rootLink.work.status}`,
    };
  }
  if (matchedType === 'TEST') {
    return {
      type: 'TEST',
      id: rootLink.test.id,
      key: rootLink.test.testKey,
      title: rootLink.test.title,
      deltaReason: `Verification test status: ${rootLink.test.status}`,
    };
  }
  if (matchedType === 'SIGNATURE') {
    return {
      type: 'SIGNATURE',
      id: rootLink.signature.id,
      key: rootLink.signature.id,
      title: `${rootLink.signature.signedBy} — ${rootLink.signature.meaning}`,
      deltaReason:
        rootLink.signature.invalidationReason ||
        (rootLink.signature.isValid ? 'Valid Part 11 signature' : 'Invalidated Part 11 signature'),
    };
  }
  return {
    type: 'SPEC',
    id: rootLink.spec.id,
    key: formatSpecLabel(rootLink.spec),
    title: rootLink.spec.title || rootLink.spec.id,
    deltaReason: rootLink.spec.lastUpdated || 'Specification content modified',
  };
}

export class ComplianceEngine {
  /**
   * Constructs a collision-resistant composite TraceLink ID supporting M:N hazard-spec-work mappings.
   */
  public static buildTraceLinkId(hazardKey: string, specId: string, workKey?: string): string {
    const hazSeg = sanitizeKvsKeySegment(hazardKey || 'unknown-hazard');
    const specSeg = sanitizeKvsKeySegment(specId || 'no-spec');
    const workSeg = sanitizeKvsKeySegment(workKey || 'unbound');
    return `trace-${hazSeg}--${specSeg}--${workSeg}`;
  }

  /**
   * Maps a TraceLink's evaluated compliance state onto the hazard's workflow status.
   */
  public static deriveHazardStatus(complianceState: TraceLink['complianceState']): IsoHazard['status'] {
    switch (complianceState) {
      case 'VERIFIED':
        return 'MITIGATED';
      case 'SAFETY_VIOLATION':
      case 'SIGNATURE_DRIFT':
        return 'ACTION_REQUIRED';
      case 'INCOMPLETE':
      default:
        return 'UNVERIFIED_RISK';
    }
  }

  /**
   * Re-evaluates an existing TraceLink and synchronizes `hazard.status` from `complianceState`.
   */
  public static reEvaluateLink(
    link: TraceLink,
    datasetMode: 'DEMO' | 'LIVE' = 'LIVE',
    overrides?: Partial<EvaluateTraceOptions>
  ): TraceLink {
    const isLive = datasetMode === 'LIVE';
    const evaluated = this.evaluateTraceLink(
      link.hazard,
      link.spec,
      link.work,
      link.test,
      link.signature,
      link.graphMetadata,
      {
        linkId: link.id,
        part11Secret: process.env.MEDTRACE_PART11_SECRET,
        requireCryptographicSeal: isLive,
        requireTestEvidence: isLive,
        reverificationTaskKey: link.reverificationTaskKey,
        ...overrides,
      }
    );
    evaluated.hazard.status = this.deriveHazardStatus(evaluated.complianceState);
    return evaluated;
  }

  /**
   * Computes an HMAC-SHA256 tamper-evident seal over canonicalized 21 CFR Part 11 signature metadata.
   */
  public static computePart11Seal(payload: CanonicalPart11Payload, secret: string): string {
    if (typeof secret !== 'string' || secret.trim() === '') {
      throw new Error('MEDTRACE_PART11_SECRET must be non-empty to compute a Part 11 cryptographic seal.');
    }
    const normalized: CanonicalPart11Payload = {
      hazardKey: String(payload.hazardKey || '').trim(),
      specId: String(payload.specId || '').trim(),
      artifactSha256: String(payload.artifactSha256 || '').trim(),
      signedByAccountId: String(payload.signedByAccountId || '').trim(),
      signedBy: String(payload.signedBy || '').trim(),
      role: String(payload.role || '').trim(),
      meaning: String(payload.meaning || '').trim(),
      signedAt: String(payload.signedAt || '').trim(),
      authMethod: String(payload.authMethod || '').trim(),
    };
    const canonical = canonicalJsonStringify(normalized);
    return crypto.createHmac('sha256', secret).update(canonical, 'utf8').digest('hex');
  }

  /**
   * Computes a non-secret 12-hex-character key fingerprint for identifying active or retired Part 11 HMAC keys.
   */
  public static computePart11KeyFingerprint(secret: string): string {
    if (typeof secret !== 'string' || secret.trim() === '') {
      throw new Error('MEDTRACE_PART11_SECRET must be non-empty to compute a Part 11 key fingerprint.');
    }
    return `sha256:${sha256Hex(secret.trim()).slice(0, 12)}`;
  }

  /**
   * Resolves the ordered, deduplicated Part 11 verification key ring (active secret followed by retired secrets).
   * Only reads `MEDTRACE_PART11_PREVIOUS_SECRETS` when `previousSecretsCsv` is supplied, `primarySecret` is omitted,
   * or `primarySecret` matches the active `MEDTRACE_PART11_SECRET` so explicit wrong-secret checks fail closed.
   */
  public static resolvePart11VerificationSecrets(
    primarySecret?: string,
    previousSecretsCsv?: string
  ): string[] {
    const activeEnvSecret = (process.env.MEDTRACE_PART11_SECRET || '').trim();
    const resolvedPrimary =
      primarySecret === undefined
        ? activeEnvSecret
        : typeof primarySecret === 'string'
          ? primarySecret.trim()
          : '';

    const secrets: string[] = [];
    const seen = new Set<string>();
    const addUnique = (candidate: string) => {
      const trimmed = candidate.trim();
      if (trimmed && !seen.has(trimmed)) {
        seen.add(trimmed);
        secrets.push(trimmed);
      }
    };

    if (resolvedPrimary) {
      addUnique(resolvedPrimary);
    }

    const shouldReadEnvPrevious =
      previousSecretsCsv !== undefined ||
      primarySecret === undefined ||
      (activeEnvSecret !== '' && resolvedPrimary === activeEnvSecret);

    const rawPreviousCsv =
      previousSecretsCsv !== undefined
        ? previousSecretsCsv
        : shouldReadEnvPrevious
          ? process.env.MEDTRACE_PART11_PREVIOUS_SECRETS || ''
          : '';

    for (const entry of String(rawPreviousCsv).split(',')) {
      addUnique(entry);
    }

    return secrets;
  }

  /**
   * Verifies a Part 11 signature's HMAC-SHA256 seal in constant time against an active key or key ring.
   * Fails closed on missing/mismatched data or invalid key candidates.
   */
  public static verifyPart11Seal(
    hazardKey: string,
    specId: string,
    signature: Part11Signature,
    secret: string | string[],
    previousSecretsCsv?: string
  ): boolean {
    const candidateSecrets = Array.isArray(secret)
      ? Array.from(
          new Set(secret.map((s) => (typeof s === 'string' ? s.trim() : '')).filter(Boolean))
        )
      : this.resolvePart11VerificationSecrets(secret, previousSecretsCsv);

    if (candidateSecrets.length === 0) {
      return false;
    }
    if (!signature || typeof signature.signatureSeal !== 'string') {
      return false;
    }
    const cleanSeal = signature.signatureSeal.trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(cleanSeal)) {
      return false;
    }
    if (signature.signatureAlgorithm && signature.signatureAlgorithm !== 'HMAC-SHA256-SEAL-V1') {
      return false;
    }
    if (!signature.signedByAccountId || signature.signedByAccountId.trim() === '') {
      return false;
    }

    try {
      const actualBuf = Buffer.from(cleanSeal, 'hex');
      const payload: CanonicalPart11Payload = {
        hazardKey,
        specId,
        artifactSha256: signature.artifactSha256,
        signedByAccountId: signature.signedByAccountId,
        signedBy: signature.signedBy,
        role: signature.role,
        meaning: signature.meaning,
        signedAt: signature.signedAt,
        authMethod: signature.authMethod || '',
      };
      for (const candidate of candidateSecrets) {
        const expectedHex = this.computePart11Seal(payload, candidate);
        const expectedBuf = Buffer.from(expectedHex, 'hex');
        if (actualBuf.length === expectedBuf.length && crypto.timingSafeEqual(actualBuf, expectedBuf)) {
          return true;
        }
      }
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Audits a single 5-stage trace link against ISO 14971, IEC 62304, and 21 CFR Part 11 rules.
   */
  public static evaluateTraceLink(
    hazard: IsoHazard,
    spec: ConfluenceSpec,
    work: JiraWorkItem,
    test: VerificationTest,
    signature: Part11Signature,
    graphMetadata?: GraphMetadata,
    options?: EvaluateTraceOptions
  ): TraceLink {
    const violations: string[] = [];
    let state: ComplianceState = 'VERIFIED';

    // 1. ISO 14971 Risk Mitigation Check
    if (!spec || !spec.title || spec.title.trim() === '' || spec.isMissingSentinel === true) {
      violations.push('ISO 14971 Violation: Hazard lacks linked Software Safety Specification (Confluence SRS).');
      state = escalateComplianceState(state, severityForRiskClass(hazard.riskClass));
    }

    // 2. IEC 62304 Traceability: Linked Implementation Work Item Check
    if (!work || !work.key || work.key.trim() === '') {
      violations.push(
        `IEC 62304 Traceability Gap: Hazard [${hazard.key}] lacks a linked Jira implementation work item.`
      );
      state = escalateComplianceState(state, severityForRiskClass(hazard.riskClass));
    } else if (work.status !== 'Done') {
      violations.push(
        `IEC 62304 Traceability Gap: Implementation work item [${work.key}] for Hazard [${hazard.key}] is "${work.status || 'Unknown'}" (must be "Done" for release).`
      );
      state = escalateComplianceState(state, severityForRiskClass(hazard.riskClass));
    }

    // 3. IEC 62304 Clause 5.7 / 5.8: Verification Test Enforcement
    if (hazard.riskClass === 'CLASS_C') {
      if (!test || test.status !== 'PASSED') {
        violations.push(
          `IEC 62304 Critical Gap: Hazard [${hazard.key}] (Software Safety Class C) requires verified test coverage. Current test [${test?.testKey || 'UNLINKED'}] status is ${test?.status || 'MISSING'}.`
        );
        state = escalateComplianceState(state, 'SAFETY_VIOLATION');
      }
    } else if (hazard.riskClass === 'CLASS_B') {
      if (!test || test.status !== 'PASSED') {
        violations.push(
          `IEC 62304 Notice: Hazard [${hazard.key}] (Software Safety Class B) verification test is ${test?.status || 'MISSING'}.`
        );
        state = escalateComplianceState(state, 'INCOMPLETE');
      }
    } else if (!test || test.status !== 'PASSED') {
      if (test?.status === 'FAILED') {
        violations.push(
          `IEC 62304 Notice: Hazard [${hazard.key}] (Software Safety Class A) verification test [${test.testKey}] FAILED.`
        );
      } else {
        violations.push(
          `IEC 62304 Notice: Hazard [${hazard.key}] (Software Safety Class A) verification test [${test?.testKey || 'UNLINKED'}] is ${test?.status || 'MISSING'} (requires PASSED).`
        );
      }
      state = escalateComplianceState(state, 'INCOMPLETE');
    }

    // 3b. Verification Evidence URL & Completeness Checks
    const evidenceIssue = this.validateTestEvidence(
      test,
      hazard.key,
      options?.requireTestEvidence
    );
    if (evidenceIssue) {
      violations.push(evidenceIssue);
      state = escalateComplianceState(state, severityForRiskClass(hazard.riskClass));
    }

    // 4. FDA 21 CFR Part 11: Electronic Signature Hash, Validity & Seal Enforcement
    const hasPriorSignOff = hasPriorElectronicSignOff(signature);
    const hasHashDrift = Boolean(
      hasPriorSignOff &&
        spec?.sha256Hash &&
        signature?.artifactSha256 &&
        spec.sha256Hash !== signature.artifactSha256
    );
    const hasInvalidSignature =
      !signature ||
      !signature.isValid ||
      !signature.signedBy ||
      signature.signedBy.trim() === '' ||
      !signature.signedAt ||
      signature.signedAt.trim() === '' ||
      isSignatureTimestampInvalidated(signature) ||
      (hasPriorSignOff && !hasHashDrift && isLinkSignatureDrifted({ spec, signature } as TraceLink));

    const part11Secret =
      typeof options?.part11Secret === 'string'
        ? options.part11Secret.trim()
        : process.env.MEDTRACE_PART11_SECRET?.trim() || '';
    const shouldVerifySeal = Boolean(
      options?.requireCryptographicSeal || signature?.signatureSeal
    );
    const hasSealFailure = shouldVerifySeal
      ? !this.verifyPart11Seal(hazard.key, spec?.id || '', signature, part11Secret)
      : false;

    if (hasHashDrift) {
      violations.push(
        `Cryptographic Signature Drift: Confluence Spec [${spec?.title || spec?.id || 'Unlinked'}] was modified after clinical sign-off. Expected hash ${(signature?.artifactSha256 || '').slice(0, 8)}..., current hash ${(spec?.sha256Hash || '').slice(0, 8)}...`
      );
      state = escalateComplianceState(state, 'SIGNATURE_DRIFT');
    } else if (hasInvalidSignature) {
      violations.push(
        `FDA 21 CFR Part 11 Violation: Electronic signature [${signature?.id || 'missing'}] is invalid or missing required signer attestation.`
      );
      state = escalateComplianceState(state, 'SIGNATURE_DRIFT');
    }
    if (hasSealFailure && !(!hasHashDrift && hasInvalidSignature)) {
      violations.push(
        `FDA 21 CFR Part 11 Cryptographic Seal Violation: Electronic signature [${signature?.id || 'missing'}] failed HMAC-SHA256 integrity verification.`
      );
      state = escalateComplianceState(state, 'SIGNATURE_DRIFT');
    }

    // 5. IEC 62304 Software Safety Class Assignment (fail-closed when no class label)
    if (hazard.safetyClassAssigned === false) {
      violations.push(
        `IEC 62304 Classification Gap: Hazard [${hazard.key}] has no software safety class label (class-a, class-b, or class-c); treated as Class C until classified.`
      );
      state = escalateComplianceState(state, severityForRiskClass('CLASS_C'));
    }

    const linkId = options?.linkId?.trim() || this.buildTraceLinkId(hazard.key, spec?.id || '', work?.key);

    return {
      id: linkId,
      hazard,
      spec,
      work,
      test,
      signature,
      complianceState: state,
      violations,
      graphMetadata,
      ...(options?.reverificationTaskKey ? { reverificationTaskKey: options.reverificationTaskKey } : {}),
    };
  }

  private static validateTestEvidence(
    test: TraceLink['test'] | undefined,
    hazardKey: string,
    requireTestEvidence?: boolean
  ): string | null {
    if (test?.evidenceUrl && test.evidenceUrl.trim() !== '') {
      try {
        validateHttpsUrl(test.evidenceUrl);
      } catch (err: unknown) {
        const reason = err instanceof Error ? err.message : 'Invalid URL';
        return `IEC 62304 Verification Evidence Violation: Test [${test.testKey}] has unsafe or invalid evidenceUrl (${reason}).`;
      }
    }
    if (requireTestEvidence && test?.status === 'PASSED') {
      const missingParts: string[] = [];
      if (!test.evidenceUrl || test.evidenceUrl.trim() === '') missingParts.push('evidenceUrl');
      if (!test.executionDate || test.executionDate.trim() === '') missingParts.push('executionDate');
      if (missingParts.length > 0) {
        return `IEC 62304 Verification Evidence Gap: Passed test [${test.testKey}] for Hazard [${hazardKey}] is missing required ${missingParts.join(' and ')}.`;
      }
    }
    return null;
  }

  private static evaluateTestIssueVerificationGap(
    link: TraceLink,
    requireTestEvidence: boolean
  ): string | null {
    const test = link.test;
    const hazardKey = link.hazard?.key || 'UNKNOWN';
    if (!test || test.status !== 'PASSED') {
      const testKey = test?.testKey || 'UNLINKED';
      const status = test?.status || 'MISSING';
      return `IEC 62304 Verification Test Gap: Test [${testKey}] for Hazard [${hazardKey}] is ${status} (requires PASSED).`;
    }
    return this.validateTestEvidence(test, hazardKey, requireTestEvidence);
  }

  /**
   * Returns true if `link` references `cleanUpperKey` as its Jira work, hazard, or verification test key.
   */
  public static linkMatchesIssueKey(link: TraceLink, cleanUpperKey: string): boolean {
    if (!cleanUpperKey) return false;
    return (
      (link.work?.key || '').trim().toUpperCase() === cleanUpperKey ||
      (link.hazard?.key || '').trim().toUpperCase() === cleanUpperKey ||
      (link.test?.testKey || '').trim().toUpperCase() === cleanUpperKey
    );
  }

  /**
   * Shared issue/global release gate policy used identically by Jira Workflow Validator
   * and the CI/CD HMAC Webtrigger (`verify-release-gate`). Fails closed on uninitialized suites
   * and on unsynced issues carrying a safety label or hazard issue type.
   */
  public static evaluateIssueReleaseGate(
    issueKey: string | undefined,
    suite: ComplianceSummary,
    options?: {
      isSafetyTaggedIssue?: boolean;
      unsyncedSafetyReason?: string;
      transitionToDone?: boolean;
    }
  ): ReleaseGateOutcome {
    const cleanIssueKey = (issueKey || '').trim().toUpperCase();
    const isEmptyOrUninitialized =
      !suite ||
      suite.initialized === false ||
      !Array.isArray(suite.traceLinks) ||
      (suite.traceLinks.length === 0 && (!cleanIssueKey || (suite.totalHazards ?? 0) === 0));
    if (isEmptyOrUninitialized) {
      return {
        result: false,
        errorMessage:
          '❌ [MedTrace Safety Gate] Compliance suite is uninitialized (0 hazards synced). Run Live Sync before releasing.',
      };
    }

    if (cleanIssueKey) {
      const matchedLinks = suite.traceLinks.filter((l) => this.linkMatchesIssueKey(l, cleanIssueKey));

      if (matchedLinks.length === 0 && options?.isSafetyTaggedIssue === true) {
        const detail =
          options.unsyncedSafetyReason ||
          `Safety-classified issue ${cleanIssueKey} is not synced in the active compliance suite.`;
        return {
          result: false,
          errorMessage: `❌ [MedTrace Safety Gate] Human-initiated transition blocked for ${cleanIssueKey}!\n• ${detail}\n\nRun Live Sync and complete verification evidence + attestation before releasing.`,
        };
      }

      for (const link of matchedLinks) {
        if (link.complianceState === 'VERIFIED') {
          continue;
        }
        const matchesWork = (link.work?.key || '').trim().toUpperCase() === cleanIssueKey;
        const matchesHazard = (link.hazard?.key || '').trim().toUpperCase() === cleanIssueKey;
        const matchesTestOnly =
          !matchesWork &&
          !matchesHazard &&
          (link.test?.testKey || '').trim().toUpperCase() === cleanIssueKey;

        if (matchesTestOnly) {
          const testGap = this.evaluateTestIssueVerificationGap(link, suite.datasetMode === 'LIVE');
          if (!testGap) {
            continue;
          }
          return {
            result: false,
            errorMessage: `❌ [MedTrace Safety Gate] Human-initiated transition blocked for ${cleanIssueKey}!\n• ${testGap}\n\nComplete verification test execution and attach valid HTTPS evidence before releasing.`,
          };
        }

        // Transition-aware check: when moving the linked work item INTO Done, evaluate with status 'Done'
        // so compliant issues in Under Review / In Progress can transition without already being Done.
        if (
          options?.transitionToDone === true &&
          matchesWork &&
          link.hazard &&
          link.spec &&
          link.work &&
          link.test &&
          link.signature
        ) {
          const reEvaluated = this.evaluateTraceLink(
            link.hazard,
            link.spec,
            { ...link.work, status: 'Done' },
            link.test,
            link.signature,
            link.graphMetadata,
            {
              linkId: link.id,
              part11Secret: process.env.MEDTRACE_PART11_SECRET,
              requireCryptographicSeal: suite.datasetMode === 'LIVE',
              requireTestEvidence: suite.datasetMode === 'LIVE',
              reverificationTaskKey: link.reverificationTaskKey,
            }
          );
          if (reEvaluated.complianceState === 'VERIFIED') {
            continue;
          }
          const violation =
            reEvaluated.violations[0] ||
            link.violations[0] ||
            'Unresolved safety-critical compliance gap.';
          return {
            result: false,
            errorMessage: `❌ [MedTrace Safety Gate] Human-initiated transition blocked for ${cleanIssueKey}!\n• ${violation}\n\nResolve verification test runs or re-certify electronic signatures before releasing.`,
          };
        }

        const violation = link.violations[0] || 'Unresolved safety-critical compliance gap.';
        return {
          result: false,
          errorMessage: `❌ [MedTrace Safety Gate] Human-initiated transition blocked for ${cleanIssueKey}!\n• ${violation}\n\nResolve verification test runs or re-certify electronic signatures before releasing.`,
        };
      }

      // Unlinked everyday issues or fully verified safety issues pass without blocking
      return { result: true };
    }

    // Global release gate (no issueKey specified)
    if (suite.syncIncomplete === true) {
      return {
        result: false,
        errorMessage:
          '❌ [MedTrace Safety Gate] Live Atlassian synchronization is incomplete (truncated).\n• Run Resume Sync to finish syncing all safety artifacts before releasing.',
      };
    }

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
   * Deduplicates `totalHazards` and `class*Count` by distinct hazard key so M:N trace links
   * do not inflate hazard totals.
   */
  public static generateComplianceReport(
    traceLinks: TraceLink[],
    datasetMode: 'DEMO' | 'LIVE' = 'DEMO',
    projectName?: string,
    metadata?: {
      storageFormat?: 'SHARDED_V2';
      auditEntryCount?: number;
      auditHeadHash?: string;
      initialized?: boolean;
      lastAuditTimestamp?: string;
      lastSyncedAt?: string;
      syncIncomplete?: boolean;
      incompleteProjectKeys?: string[];
    }
  ): ComplianceSummary {
    const resolvedProjectName =
      projectName && projectName.trim() !== ''
        ? projectName
        : datasetMode === 'DEMO'
          ? 'Smart Infusion Pump Firmware v2.1'
          : 'Atlassian Cloud Medical Project';

    const initialized = metadata?.initialized ?? (traceLinks.length > 0 || datasetMode === 'DEMO');

    const RISK_PRECEDENCE: Record<RiskClass, number> = {
      CLASS_A: 0,
      CLASS_B: 1,
      CLASS_C: 2,
    };
    const distinctHazards = new Map<string, { riskClass: RiskClass; allVerified: boolean }>();

    let signatureDriftCount = 0;
    const blockingReasons: string[] = [];

    for (const link of traceLinks) {
      const hazId = (link.hazard?.key || link.hazard?.id || link.id || '').trim().toUpperCase();
      const existingHaz = distinctHazards.get(hazId);
      const linkVerified = link.complianceState === 'VERIFIED';
      if (!existingHaz) {
        distinctHazards.set(hazId, {
          riskClass: link.hazard.riskClass,
          allVerified: linkVerified,
        });
      } else {
        if (RISK_PRECEDENCE[link.hazard.riskClass] > RISK_PRECEDENCE[existingHaz.riskClass]) {
          existingHaz.riskClass = link.hazard.riskClass;
        }
        if (!linkVerified) {
          existingHaz.allVerified = false;
        }
      }

      if (!linkVerified) {
        blockingReasons.push(...link.violations);
      }

      const hasDriftedOrInvalidSig =
        isLinkSignatureDrifted(link) ||
        link.violations.some(
          (v) => v.includes('Signature Drift') || v.includes('Cryptographic Seal Violation')
        );
      if (hasDriftedOrInvalidSig) {
        signatureDriftCount++;
      }
    }

    let classCCount = 0;
    let classBCount = 0;
    let classACount = 0;
    let verifiedHazardCount = 0;
    for (const haz of distinctHazards.values()) {
      if (haz.riskClass === 'CLASS_C') classCCount++;
      else if (haz.riskClass === 'CLASS_B') classBCount++;
      else classACount++;
      if (haz.allVerified) {
        verifiedHazardCount++;
      }
    }

    const totalHazards = distinctHazards.size;

    if (traceLinks.length === 0) {
      blockingReasons.push(
        'Compliance suite is uninitialized or contains 0 hazard trace links. Sync Live Atlassian artifacts (or seed demo data in non-production) before release.'
      );
    }

    if (metadata?.syncIncomplete === true) {
      blockingReasons.push(
        'Live Atlassian synchronization is incomplete (truncated). Run Resume Sync to finish syncing all safety artifacts before releasing.'
      );
    }

    const verifiedPercentage =
      totalHazards > 0 ? Math.round((verifiedHazardCount / totalHazards) * 100) : 0;

    const releaseBlocked = blockingReasons.length > 0;

    return {
      projectName: resolvedProjectName,
      datasetMode,
      initialized,
      standards: [
        'IEC 62304:2006+A1:2015 (Medical Device Software Lifecycle)',
        'ISO 14971:2019 (Risk Management for Medical Devices)',
        'FDA 21 CFR Part 11 (Electronic Records & Signatures)',
      ],
      totalHazards,
      classCCount,
      classBCount,
      classACount,
      verifiedPercentage,
      releaseBlocked,
      blockingReasons,
      signatureDriftCount,
      traceLinks,
      lastAuditTimestamp: metadata?.lastAuditTimestamp || new Date().toISOString(),
      ...(metadata?.lastSyncedAt ? { lastSyncedAt: metadata.lastSyncedAt } : {}),
      ...(metadata?.syncIncomplete === true ? { syncIncomplete: true } : {}),
      ...(metadata?.incompleteProjectKeys && metadata.incompleteProjectKeys.length > 0
        ? { incompleteProjectKeys: metadata.incompleteProjectKeys }
        : {}),
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
    const rawPrefix = (link.spec?.title || '').split(':')[0].trim();
    const specShortKey = /^[a-z]{2,10}-\d+$/i.test(rawPrefix) ? rawPrefix.toLowerCase() : '';
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

  private static runBlastRadiusBfs(
    matched: Array<{ link: TraceLink; nodeType: GraphNodeType }>,
    suite: ComplianceSummary,
    startTime: number,
    distinctKeys: string[]
  ): BlastRadiusReport {
    const linksByNode = new Map<string, TraceLink[]>();
    for (const link of suite.traceLinks) {
      for (const nodeKey of buildNodeKeys(link)) {
        const links = linksByNode.get(nodeKey);
        if (links) {
          if (!links.includes(link)) links.push(link);
        } else {
          linksByNode.set(nodeKey, [link]);
        }
      }
    }

    // Pre-collect the reachable connected component and track drift/compromise per hazard & spec
    const reachableSet = new Set<TraceLink>();
    const exploreQueue: TraceLink[] = [];
    for (const entry of matched) {
      if (!reachableSet.has(entry.link)) {
        reachableSet.add(entry.link);
        exploreQueue.push(entry.link);
      }
    }
    let exploreIdx = 0;
    while (exploreIdx < exploreQueue.length) {
      const link = exploreQueue[exploreIdx++];
      for (const nodeKey of buildNodeKeys(link)) {
        for (const sibling of linksByNode.get(nodeKey) || []) {
          if (!reachableSet.has(sibling)) {
            reachableSet.add(sibling);
            exploreQueue.push(sibling);
          }
        }
      }
    }

    const compromisedHazards = new Set<string>();
    const driftedSpecIds = new Set<string>();
    for (const link of reachableSet) {
      const hazKey = link.hazard?.key?.trim().toLowerCase();
      const specId = link.spec?.id?.trim().toLowerCase();
      const specDrifted = isLinkSignatureDrifted(link);
      if (specDrifted && specId) {
        driftedSpecIds.add(specId);
      }
      if (hazKey && (specDrifted || link.complianceState !== 'VERIFIED')) {
        compromisedHazards.add(hazKey);
      }
    }

    const visitedRels = new Set<string>();
    const enqueued = new Set<TraceLink>();
    const plannedHazardKeys = new Set<string>();
    const plannedWorkKeys = new Set<string>();
    const plannedTestKeys = new Set<string>();
    const affectedHazardSet = new Set<string>();
    const blockedWorkSet = new Set<string>();
    const invalidatedTestSet = new Set<string>();
    const invalidatedSigSet = new Set<string>();

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
    for (const entry of matched) enqueue(entry.link);

    let cursor = 0;
    while (cursor < queue.length) {
      const link = queue[cursor++];
      affectedLinks.push(link);
      const specNode = link.spec;
      const haz = link.hazard;
      const specIdLower = (specNode?.id || 'no-spec').trim().toLowerCase();
      const hazKeyLower = (haz?.key || 'no-hazard').trim().toLowerCase();
      const specLabel = formatSpecLabel(specNode);
      const specDrifted = isLinkSignatureDrifted(link);

      // SIGNS edge (Spec -> Signature): always emit hop for symmetric 4-stage graph traversal
      const sig = link.signature;
      const sigIdLower = (sig?.id || link.id).trim().toLowerCase();
      const signsRelKey = `signs:${specIdLower}->${sigIdLower}`;
      if (!visitedRels.has(signsRelKey)) {
        visitedRels.add(signsRelKey);
        if (specDrifted) {
          if (sig?.id?.trim() && !invalidatedSigSet.has(sig.id)) {
            invalidatedSigSet.add(sig.id);
            invalidatedSignatureIds.push(sig.id);
          }
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Spec [${specLabel}]`,
            edge: 'SIGNS' as GraphEdgeType,
            to: `Signature [${sig?.signedBy || sig?.id || 'Missing'}]`,
            effect: `Signature evidence invalidated: hash drift detected (expected ${(sig?.artifactSha256 || '').slice(0, 8)}..., current ${(specNode?.sha256Hash || '').slice(0, 8)}...).`,
          });
          transitiveActionPlan.push(
            `Re-certify clinical sign-off with ${sig?.signedBy || 'authorized signatory'} (${sig?.role || 'Safety Authority'}) for revised spec.`
          );
        } else if (!hasPriorElectronicSignOff(sig) || !sig?.isValid) {
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Spec [${specLabel}]`,
            edge: 'SIGNS' as GraphEdgeType,
            to: 'Signature [Unsigned]',
            effect: 'No 21 CFR Part 11 sign-off recorded yet for this specification revision.',
          });
        } else {
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Spec [${specLabel}]`,
            edge: 'SIGNS' as GraphEdgeType,
            to: `Signature [${sig.signedBy}]`,
            effect: `Part 11 signature valid for current spec hash (${(sig.artifactSha256 || '').slice(0, 8)}...).`,
          });
        }
      }

      // MITIGATES edge (Spec -> Hazard): compromised only if this spec drifted or this hazard is compromised
      const mitigatesRelKey = `mitigates:${specIdLower}->${hazKeyLower}`;
      if (!visitedRels.has(mitigatesRelKey)) {
        visitedRels.add(mitigatesRelKey);
        if (haz?.key?.trim() && !affectedHazardSet.has(haz.key)) {
          affectedHazardSet.add(haz.key);
          affectedHazardKeys.push(haz.key);
        }
        const isMitigationCompromised =
          specDrifted || driftedSpecIds.has(specIdLower) || compromisedHazards.has(hazKeyLower);
        traversalPath.push({
          hop: traversalPath.length + 1,
          from: `Spec [${specLabel}]`,
          edge: 'MITIGATES' as GraphEdgeType,
          to: `Hazard [${haz.key}]`,
          effect: isMitigationCompromised
            ? `Safety mitigation compromised: ${haz.title} (${haz.riskClass.replace('_', ' ')}).`
            : `Safety mitigation verified: ${haz.title} (${haz.riskClass.replace('_', ' ')}).`,
        });
        if (isMitigationCompromised && !plannedHazardKeys.has(haz.key)) {
          plannedHazardKeys.add(haz.key);
          transitiveActionPlan.push(
            `Review ISO 14971 risk mitigations for ${haz.key} against revised specifications.`
          );
        }
      }

      // IMPLEMENTS edge (Hazard -> Jira Work Item)
      const work = link.work;
      const workKeyClean = (work?.key || '').trim();
      const workIdLower = (workKeyClean || link.id).toLowerCase();
      const implementsRelKey = `implements:${hazKeyLower}->${workIdLower}`;
      if (!visitedRels.has(implementsRelKey)) {
        visitedRels.add(implementsRelKey);
        const isWorkAffected =
          compromisedHazards.has(hazKeyLower) ||
          link.complianceState !== 'VERIFIED' ||
          work?.status !== 'Done';
        if (isWorkAffected) {
          if (workKeyClean && !blockedWorkSet.has(workKeyClean)) {
            blockedWorkSet.add(workKeyClean);
            blockedWorkItemKeys.push(workKeyClean);
          }
          const workTitleSnippet = work?.title?.trim() ? ` "${work.title.trim()}"` : '';
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Hazard [${haz.key}]`,
            edge: 'IMPLEMENTS' as GraphEdgeType,
            to: `Jira Item [${workKeyClean || 'UNBOUND'}]`,
            effect: `Transition blocked: Work item${workTitleSnippet} assigned to ${work?.assignee || 'Unassigned'} locked under human-transition policy gate.`,
          });
          if (!plannedWorkKeys.has(workIdLower)) {
            plannedWorkKeys.add(workIdLower);
            const prSuffix = work?.prNumber ? ` (${work.prNumber})` : '';
            transitiveActionPlan.push(
              `Verify implementation in ${workKeyClean || haz.key}${prSuffix} matches updated specification parameters.`
            );
          }
        } else {
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Hazard [${haz.key}]`,
            edge: 'IMPLEMENTS' as GraphEdgeType,
            to: `Jira Item [${workKeyClean}]`,
            effect: `Implementation verified (${work.status}) with no active signature drift.`,
          });
        }
      }

      // VERIFIES edge (Hazard -> Test Execution)
      const test = link.test;
      const testKeyClean = (test?.testKey || '').trim();
      const testIdLower = (testKeyClean || link.id).toLowerCase();
      const verifiesRelKey = `verifies:${hazKeyLower}->${testIdLower}`;
      if (!visitedRels.has(verifiesRelKey)) {
        visitedRels.add(verifiesRelKey);
        const isTestAffected =
          compromisedHazards.has(hazKeyLower) ||
          link.complianceState !== 'VERIFIED' ||
          test?.status !== 'PASSED';
        if (isTestAffected) {
          if (testKeyClean && !invalidatedTestSet.has(testKeyClean)) {
            invalidatedTestSet.add(testKeyClean);
            invalidatedTestKeys.push(testKeyClean);
          }
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Hazard [${haz.key}]`,
            edge: 'VERIFIES' as GraphEdgeType,
            to: `Test [${testKeyClean || 'UNLINKED'}]`,
            effect: `Verification test evidence invalidated: ${test?.title || 'Verification test'} must be executed against new specification parameters.`,
          });
          if (!plannedTestKeys.has(testIdLower)) {
            plannedTestKeys.add(testIdLower);
            transitiveActionPlan.push(
              `Execute automated verification run for ${testKeyClean || haz.key} (${test?.testType || 'Verification Test'}) to regenerate passing evidence.`
            );
          }
        } else {
          traversalPath.push({
            hop: traversalPath.length + 1,
            from: `Hazard [${haz.key}]`,
            edge: 'VERIFIES' as GraphEdgeType,
            to: `Test [${testKeyClean}]`,
            effect: `Verification test ${testKeyClean} remains PASSED under valid Part 11 signature.`,
          });
        }
      }

      for (const nodeKey of buildNodeKeys(link)) {
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

    const firstTrigger = buildSingleTriggerArtifact(matched[0].link, matched[0].nodeType);
    const triggerArtifact: BlastRadiusReport['triggerArtifact'] =
      distinctKeys.length > 1 && matched.length > 1
        ? {
            ...firstTrigger,
            title: `${firstTrigger.title} (+${distinctKeys.length - 1} related: ${distinctKeys.slice(1).map((k) => k.toUpperCase()).join(', ')})`,
          }
        : firstTrigger;

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

  /**
   * Deterministic Regulatory Blast Radius & Transitive Impact Analyzer across one or more trigger keys.
   * Executes a breadth-first traversal over the typed 5-stage traceability graph.
   */
  public static computeMultiBlastRadius(triggerKeys: string[], suite: ComplianceSummary): BlastRadiusReport {
    const startTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const cleanKeys = Array.from(
      new Set((triggerKeys || []).map((k) => (k || '').trim().toLowerCase()).filter(Boolean))
    );

    if (cleanKeys.length === 0) {
      const endTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
      return {
        triggerArtifact: {
          type: 'SPEC',
          id: '',
          key: '',
          title: 'No Trigger Artifact Specified',
          deltaReason: 'No trigger key provided; skipping blast-radius traversal',
        },
        impactSeverity: 'MINOR',
        affectedHazardKeys: [],
        blockedWorkItemKeys: [],
        invalidatedTestKeys: [],
        invalidatedSignatureIds: [],
        traversalPath: [],
        transitiveActionPlan: ['No trigger artifact specified.'],
        executionTimeMs: parseFloat(Math.max(0.01, endTime - startTime).toFixed(2)),
      };
    }

    const matched: Array<{ link: TraceLink; nodeType: GraphNodeType }> = [];
    const seenLinks = new Set<TraceLink>();
    for (const cleanKey of cleanKeys) {
      for (const link of suite?.traceLinks || []) {
        if (seenLinks.has(link)) continue;
        const nodeType = this.matchesLinkByKey(link, cleanKey);
        if (nodeType) {
          seenLinks.add(link);
          matched.push({ link, nodeType });
        }
      }
    }

    if (matched.length === 0) {
      const endTime = typeof performance !== 'undefined' ? performance.now() : Date.now();
      const joined = cleanKeys.join(', ');
      return {
        triggerArtifact: {
          type: 'SPEC',
          id: joined,
          key: joined,
          title: `Unknown / Disconnected Artifact [${joined}]`,
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

    return this.runBlastRadiusBfs(matched, suite, startTime, cleanKeys);
  }

  /**
   * Deterministic Regulatory Blast Radius & Transitive Impact Analyzer for a single trigger key.
   */
  public static computeBlastRadius(triggerKey: string, suite: ComplianceSummary): BlastRadiusReport {
    return this.computeMultiBlastRadius([triggerKey], suite);
  }
}
