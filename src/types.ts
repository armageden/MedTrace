export const PART11_ATTESTATION_PHRASE = 'I CERTIFY THIS ELECTRONIC SIGNATURE' as const;

export type RiskClass = 'CLASS_A' | 'CLASS_B' | 'CLASS_C';

export interface IsoHazard {
  id: string;
  key: string;
  title: string;
  riskClass: RiskClass;
  severity: 'CATASTROPHIC' | 'CRITICAL' | 'SERIOUS' | 'MINOR';
  probability: 'FREQUENT' | 'PROBABLE' | 'OCCASIONAL' | 'REMOTE' | 'IMPROBABLE';
  mitigationRequirementId: string;
  status: 'MITIGATED' | 'UNVERIFIED_RISK' | 'ACTION_REQUIRED';
}

export interface ConfluenceSpec {
  id: string;
  pageId?: string;
  title: string;
  version: number;
  sha256Hash: string;
  lastSignedHash: string;
  isSignatureInvalidated: boolean;
  isMissingSentinel?: boolean;
  contentSnippet: string;
  lastUpdated: string;
}

export interface JiraWorkItem {
  id: string;
  key: string;
  title: string;
  status: 'In Progress' | 'Done' | 'Under Review' | 'To Do';
  assignee: string;
  prNumber?: string;
  commitSha?: string;
}

export interface VerificationTest {
  id: string;
  testKey: string;
  title: string;
  testType: 'Automated HIL (Hardware-in-Loop)' | 'Integration Test' | 'Unit Test' | 'Clinical Validation';
  status: 'PASSED' | 'FAILED' | 'UNTESTED' | 'IN_PROGRESS';
  executionDate?: string;
  evidenceUrl?: string;
  recordedBy?: string;
  notes?: string;
}

export interface Part11Signature {
  id: string;
  signedBy: string;
  signedByAccountId?: string;
  signedAt: string;
  invalidatedAt?: string;
  role: string;
  meaning: string;
  artifactSha256: string;
  isValid: boolean;
  invalidationReason?: string;
  authMethod?: string;
  signatureAlgorithm?: 'HMAC-SHA256-SEAL-V1' | 'ECDSA-P256-SHA256+HMAC-SEAL-V1';
  signatureSeal?: string;
  sealKeyId?: string;
  clientPublicKeySpki?: string;
  clientSignatureBase64?: string;
  clientKeyFingerprint?: string;
}

export interface GraphMetadata {
  entityAri: string;
  hazardAri: string;
  linkedSpecAri: string;
  edgeType: string;
  aggTraversalStatus: string;
}

export interface TraceLink {
  id: string;
  hazard: IsoHazard;
  spec: ConfluenceSpec;
  work: JiraWorkItem;
  test: VerificationTest;
  signature: Part11Signature;
  complianceState: 'VERIFIED' | 'SAFETY_VIOLATION' | 'SIGNATURE_DRIFT' | 'INCOMPLETE';
  violations: string[];
  graphMetadata?: GraphMetadata;
}

export interface ComplianceSummary {
  projectName: string;
  datasetMode: 'DEMO' | 'LIVE';
  initialized?: boolean;
  standards: string[]; // ["IEC 62304:2006+A1:2015", "ISO 14971:2019", "FDA 21 CFR Part 11"]
  totalHazards: number;
  classCCount: number;
  classBCount: number;
  classACount: number;
  verifiedPercentage: number;
  releaseBlocked: boolean;
  blockingReasons: string[];
  signatureDriftCount: number;
  traceLinks: TraceLink[];
  lastAuditTimestamp: string;
  storageFormat?: 'SHARDED_V2' | 'SINGLE_KEY_V1';
  auditEntryCount?: number;
  auditHeadHash?: string;
}

export type GraphNodeType = 'HAZARD' | 'SPEC' | 'WORK' | 'TEST' | 'SIGNATURE';
export type GraphEdgeType = 'MITIGATES' | 'IMPLEMENTS' | 'VERIFIES' | 'SIGNS';

export interface BlastRadiusReport {
  triggerArtifact: {
    type: GraphNodeType;
    id: string;
    key: string;
    title: string;
    deltaReason: string;
  };
  impactSeverity: 'CRITICAL_CATASTROPHIC' | 'MAJOR_SERIOUS' | 'MINOR';
  affectedHazardKeys: string[];
  blockedWorkItemKeys: string[];
  invalidatedTestKeys: string[];
  invalidatedSignatureIds: string[];
  traversalPath: {
    hop: number;
    from: string;
    edge: GraphEdgeType;
    to: string;
    effect: string;
  }[];
  transitiveActionPlan: string[];
  executionTimeMs: number;
}

export type AuditActionType =
  | 'SEED_DEMO'
  | 'SYNC_LIVE'
  | 'BIND_ISSUE'
  | 'RECORD_TEST_RESULT'
  | 'PART11_SIGNOFF'
  | 'DEMO_SIMULATION'
  | 'CONFLUENCE_PAGE_DRIFT';

export type AuditAuthMethod =
  | 'FORGE_USER_SESSION'
  | 'PART11_ATTESTATION'
  | 'HMAC_WEBTRIGGER'
  | 'CONFLUENCE_EVENT_TRIGGER'
  | 'SYSTEM_INIT';

export interface AuditLogEntry {
  seq: number;
  timestamp: string;
  actorAccountId: string;
  action: AuditActionType | string;
  targetKey: string;
  details: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
  authMethod: AuditAuthMethod | string;
}

export interface VerifyAuditChainOptions {
  fromSeq?: number;
  maxEntries?: number;
  expectedPrevHash?: string;
}

export interface AuditChainVerification {
  valid: boolean;
  totalEntries: number;
  headHash: string;
  brokenAtSeq?: number;
  reason?: string;
  verifiedFromSeq?: number;
  verifiedToSeq?: number;
  nextFromSeq?: number;
  truncated?: boolean;
  windowEntryCount?: number;
}

export type AuditChainVerificationResult = AuditChainVerification;

export interface AuthorizedUserIdentity {
  accountId: string;
  displayName: string;
  role: string;
  emailAddress?: string;
  authSource?: 'JIRA_MYSELF' | 'CONFLUENCE_CURRENT_USER' | 'LOCAL_TEST' | 'FALLBACK';
}

// Temporary backward-compatible attestation fields until Phase 1B/2 removes client spoofing.
export interface Part11Attestation {
  meaning: string;
  attestationConfirmed: boolean;
  attestationPhrase?: string;
  passwordConfirmed?: boolean;
  signedBy?: string;
  signedAt?: string;
  role?: string;
  clientPublicKeySpki?: string;
  clientSignatureBase64?: string;
}

export interface ConfluenceRemoteLinkRef {
  pageId?: string;
  title: string;
  url: string;
  relationship?: string;
}

export interface AggIssueLinkRef {
  id: string;
  type?: {
    name?: string;
    inward?: string;
    outward?: string;
  };
}

export interface IssueGraphContextResult {
  source: 'JIRA_AGG_AND_REST' | 'JIRA_REST';
  confluenceSource?: 'JIRA_REMOTELINK_REST';
  issueKey: string;
  issueId?: string;
  issueAri?: string;
  summary?: string;
  status?: { name?: string; category?: string };
  issuelinks: unknown[];
  aggIssueLinks?: AggIssueLinkRef[];
  confluenceLinks: ConfluenceRemoteLinkRef[];
  aggRaw?: unknown;
}

export interface LiveSyncOptions {
  projectKey?: string;
  spaceId?: string;
  jql?: string;
  includeUntaggedIssues?: boolean;
  callerMode?: 'USER' | 'APP';
  resumeFromCursor?: boolean;
  pageToken?: string;
}

export interface LiveSyncResult {
  success: boolean;
  datasetMode: 'LIVE' | 'DEMO';
  jiraIssuesScanned: number;
  confluencePagesScanned: number;
  linkedPairsFound: number;
  driftDetectedCount: number;
  truncated?: boolean;
  nextPageToken?: string;
  resumedFromCursor?: boolean;
  skippedUntaggedCount?: number;
  warnings: string[];
  summary: ComplianceSummary;
}

export interface SeedDemoResponse {
  success: boolean;
  confluenceEnabled: boolean;
  summary: ComplianceSummary;
  message: string;
}

export interface BindIssueResponse {
  success: boolean;
  summary?: ComplianceSummary;
  error?: string;
}

export interface TransitionResult {
  result: boolean;
  errorMessage?: string;
  evaluatedIssueKey?: string;
  evalError?: string;
}

export interface MedTraceResolverMap {
  getComplianceSuite: {
    payload: Record<string, never> | undefined;
    response: ComplianceSummary;
  };
  seedDemoSuite: {
    payload: { confirmOverwriteLive?: boolean } | undefined;
    response: SeedDemoResponse;
  };
  syncLiveSuite: {
    payload: Omit<LiveSyncOptions, 'callerMode'> | undefined;
    response: LiveSyncResult;
  };
  remediateGap: {
    payload: {
      hazardKey: string;
      simulate: boolean;
      attestationConfirmed: boolean;
      meaning?: string;
    };
    response: ComplianceSummary;
  };
  recordTestResult: {
    payload: {
      hazardKey?: string;
      testKey?: string;
      linkId?: string;
      status: VerificationTest['status'];
      evidenceUrl?: string;
      executionDate?: string;
      notes?: string;
    };
    response: ComplianceSummary;
  };
  signOffPart11: {
    payload: {
      hazardKey: string;
      linkId?: string;
      specId?: string;
      meaning: string;
      attestationConfirmed: boolean;
      passwordConfirmed: boolean;
      attestationPhrase: string;
      clientPublicKeySpki?: string;
      clientSignatureBase64?: string;
    };
    response: ComplianceSummary;
  };
  queryGraphContext: {
    payload: { issueKey?: string } | undefined;
    response: IssueGraphContextResult | null;
  };
  bindIssueToHazard: {
    payload: {
      hazardKey: string;
      issueKey?: string;
      linkId?: string;
    };
    response: BindIssueResponse;
  };
  simulateTransition: {
    payload: {
      issueKey?: string;
      scope?: 'global' | 'issue';
    } | undefined;
    response: TransitionResult;
  };
  analyzeBlastRadius: {
    payload: { triggerKey?: string } | undefined;
    response: BlastRadiusReport;
  };
  getAuditLog: {
    payload: { limit?: number; beforeSeq?: number } | undefined;
    response: AuditLogEntry[];
  };
  verifyAuditChain: {
    payload: VerifyAuditChainOptions | undefined;
    response: AuditChainVerification;
  };
}
