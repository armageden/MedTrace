import Resolver from '@forge/resolver';
import { SeederService } from './seeder';
import { TeamworkGraphService } from './teamwork-graph';
import { workflowValidatorHandler } from './workflow-validator';
import { rovoActionHandler } from './mcp-server';

const resolver = new Resolver();

// 1. Fetch current compliance state
resolver.define('getComplianceSuite', async () => {
  return await SeederService.getActiveComplianceSuite();
});

// 2. 1-Click Bulletproof Enterprise Seeder
resolver.define('seedDemoSuite', async () => {
  return await SeederService.seedEnterpriseDemoSuite();
});

// 3. Remediate Class C Gap (1-Click fix simulation)
resolver.define('remediateGap', async () => {
  return await SeederService.remediateClassCGap();
});

// 4. Teamwork Graph GraphQL Context Query
resolver.define('queryGraphContext', async (req) => {
  const issueKey = req.payload?.issueKey || 'HAZ-101';
  return await TeamworkGraphService.queryIssueGraphContext(issueKey);
});

// Export handlers matching manifest.yml functions
export const resolverHandler = resolver.getDefinitions();
export { workflowValidatorHandler, rovoActionHandler };
