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
}

export interface GraphMetadata {
  entityAri: string;
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
  standards: string[];
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
}

export interface BlastRadiusReport {
  triggerArtifact: {
    type: 'HAZARD' | 'SPEC' | 'WORK' | 'TEST' | 'SIGNATURE';
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
    edge: 'MITIGATES' | 'IMPLEMENTS' | 'VERIFIES' | 'SIGNS';
    to: string;
    effect: string;
  }[];
  transitiveActionPlan: string[];
  executionTimeMs: number;
}
