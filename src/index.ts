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

// 3. Remediate Class C Gap (Hero demo fix simulation)
resolver.define('remediateGap', async () => {
  return await SeederService.remediateClassCGap();
});

// 4. Teamwork Graph GraphQL Context Query
resolver.define('queryGraphContext', async (req) => {
  const issueKey = req.payload?.issueKey || 'HAZ-101';
  return await TeamworkGraphService.queryIssueGraphContext(issueKey);
});

// 5. Simulate Jira Release Transition / Safety Gate Check
resolver.define('simulateTransition', async () => {
  return await workflowValidatorHandler({ transition: 'Done' });
});

/**
 * Webtrigger for real-time 2-way sync with local MCP Server (Cursor / Claude Desktop)
 * Allows local AI IDE agents to fetch live compliance state directly from deployed Forge KVS!
 */
export async function mcpWebtriggerHandler(request: any): Promise<any> {
  console.log('[MedTrace MCP Webtrigger] Handling external MCP sync request:', request?.method);

  try {
    // If request contains action payload to remediate
    if (request?.method === 'POST') {
      let body: any = {};
      try {
        body = JSON.parse(request.body || '{}');
      } catch {}

      if (body.action === 'remediate') {
        const updated = await SeederService.remediateClassCGap();
        return {
          body: JSON.stringify({ success: true, summary: updated }),
          headers: {
            'Content-Type': ['application/json'],
            'Access-Control-Allow-Origin': ['*'],
          },
          statusCode: 200,
        };
      }
    }

    // Default GET: return live compliance suite
    const suite = await SeederService.getActiveComplianceSuite();
    return {
      body: JSON.stringify(suite),
      headers: {
        'Content-Type': ['application/json'],
        'Access-Control-Allow-Origin': ['*'],
      },
      statusCode: 200,
    };
  } catch (err: any) {
    return {
      body: JSON.stringify({ error: err?.message || 'Failed to fetch MCP state' }),
      headers: {
        'Content-Type': ['application/json'],
        'Access-Control-Allow-Origin': ['*'],
      },
      statusCode: 500,
    };
  }
}

// Export handlers matching manifest.yml functions
export const resolverHandler = resolver.getDefinitions();
export { workflowValidatorHandler, rovoActionHandler };
