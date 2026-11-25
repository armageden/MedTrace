export * from '../../../src/types';

export interface ForgePanelContext {
  extensionType: string;
  isCompactPanel: boolean;
  isConfluence: boolean;
  issueKey?: string;
  projectKey?: string;
  spaceId?: string;
  contentId?: string;
}

export interface UiNotice {
  kind: 'error' | 'warning' | 'info' | 'success';
  source?: 'load' | 'mutation' | 'sync' | 'info' | (string & {});
  message: string;
  retryable?: boolean;
}
