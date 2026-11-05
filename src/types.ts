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

export interface TraceLink {
  id: string;
  hazard: IsoHazard;
  spec: ConfluenceSpec;
  work: JiraWorkItem;
  test: VerificationTest;
  signature: Part11Signature;
  complianceState: 'VERIFIED' | 'SAFETY_VIOLATION' | 'SIGNATURE_DRIFT' | 'INCOMPLETE';
  violations: string[];
}

export interface ComplianceSummary {
  projectName: string;
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
}
