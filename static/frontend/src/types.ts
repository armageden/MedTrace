export * from '../../../src/types';

import type { TransitionResult } from '../../../src/types';

export interface ForgePanelContext {
  extensionType: string;
  isCompactPanel: boolean;
  isConfluence: boolean;
  issueKey?: string;
  projectKey?: string;
  contentId?: string;
}

export interface UiNotice {
  kind: 'error' | 'warning' | 'info' | 'success';
  source?: 'load' | 'mutation' | 'sync' | 'info' | (string & {});
  message: string;
  retryable?: boolean;
}

export interface ClientTransitionResult extends TransitionResult {
  evalError?: string;
}
