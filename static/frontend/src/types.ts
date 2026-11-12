export * from '../../../src/types';

import type { ComplianceSummary } from '../../../src/types';

export interface ConfluenceRemoteLinkRef {
  pageId?: string;
  title: string;
  url: string;
  relationship?: string;
}

export interface IssueGraphContextResult {
  source: 'AGG' | 'JIRA_REST';
  issueKey: string;
  issueId?: string;
  issueAri?: string;
  summary?: string;
  status?: { name?: string; category?: string };
  issuelinks: unknown[];
  confluenceLinks: ConfluenceRemoteLinkRef[];
  aggRaw?: unknown;
}

export interface ForgePanelContext {
  extensionType: string;
  isCompactPanel: boolean;
  isConfluence: boolean;
  issueKey?: string;
  projectKey?: string;
  contentId?: string;
  spaceKey?: string;
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
  evalError?: string;
  evaluatedIssueKey?: string;
}
