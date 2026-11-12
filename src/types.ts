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
  signedAt: string;
  role: string;
  meaning: string;
  artifactSha256: string;
  isValid: boolean;
  invalidationReason?: string;
  authMethod?: string;
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

export interface GraphNodeRef {
  id: string;
  type: GraphNodeType;
  key: string;
  title: string;
}

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
  | 'CONFLUENCE_PAGE_DRIFT'
  | 'WORKFLOW_GATE_BLOCKED'
  | 'WORKFLOW_GATE_APPROVED';

export type AuditAuthMethod =
  | 'FORGE_USER_SESSION'
  | 'PART11_ATTESTATION'
  | 'HMAC_WEBTRIGGER'
  | 'CONFLUENCE_EVENT_TRIGGER'
  | 'ROVO_AGENT'
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

export interface AuditChainVerification {
  valid: boolean;
  totalEntries: number;
  headHash: string;
  brokenAtSeq?: number;
  reason?: string;
}

export interface Part11Attestation {
  meaning: string;
  attestationConfirmed: boolean;
  attestationPhrase?: string;
  passwordConfirmed?: boolean;
  signedBy?: string;
  signedAt?: string;
  role?: string;
}

export interface LiveSyncResult {
  success: boolean;
  datasetMode: 'LIVE' | 'DEMO';
  jiraIssuesScanned: number;
  confluencePagesScanned: number;
  linkedPairsFound: number;
  driftDetectedCount: number;
  warnings: string[];
  summary: ComplianceSummary;
}
