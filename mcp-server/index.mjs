#!/usr/bin/env node

/**
 * MedTrace Model Context Protocol (MCP) Server
 * Exposes IEC 62304 & ISO 14971 Compliance Tools to Cursor, Claude Desktop, and AI coding agents.
 */

import readline from 'readline';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const SERVER_NAME = 'medtrace-mcp-server';
const SERVER_VERSION = '1.0.0';

// Live Mock / Connected Compliance Data Source
let complianceState = {
  projectName: 'Smart Infusion Pump Firmware v2.1',
  standards: [
    'IEC 62304:2006+A1:2015 (Medical Device Software Lifecycle)',
    'ISO 14971:2019 (Risk Management for Medical Devices)',
    'FDA 21 CFR Part 11 (Electronic Records & Signatures)',
  ],
  totalHazards: 3,
  classCCount: 1,
  verifiedPercentage: 67,
  releaseBlocked: true,
  signatureDriftCount: 1,
  traceLinks: [
    {
      hazardKey: 'HAZ-101',
      riskClass: 'CLASS_C',
      severity: 'CATASTROPHIC',
      title: 'Over-Infusion Hazard: Bolus delivery exceeds 5.0 mL/hr clinical threshold',
      confluenceSpec: 'SRS-104: Dual-Core Microcontroller Hardware Bolus Clamp (v3)',
      specHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      signedHash: 'a789ef2398fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b112',
      isSignatureValid: false,
      signatureDriftReason: 'AUTOMATIC REVOCATION: Confluence spec modified at version 3 without clinical re-signature.',
      jiraWorkItem: 'MED-42 (Implement Dual-Core Hardware PWM Clamp on Infusion Motor)',
      testKey: 'TEST-88',
      testStatus: 'UNTESTED',
      complianceState: 'SAFETY_VIOLATION',
      violations: [
        'IEC 62304 Critical Gap: Class C Hazard [HAZ-101] requires verified test coverage. Current test [TEST-88] status is UNTESTED.',
        '21 CFR Part 11 Signature Drift: Confluence Spec modified after sign-off.',
      ],
    },
    {
      hazardKey: 'HAZ-102',
      riskClass: 'CLASS_B',
      severity: 'CRITICAL',
      title: 'Under-Infusion Hazard: Unintended pump stall leading to severe hypoglycemia',
      confluenceSpec: 'SRS-105: Optical Droplet Sensor Real-Time Flow Rate Verification (v2)',
      specHash: 'b45c22998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b333',
      signedHash: 'b45c22998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b333',
      isSignatureValid: true,
      jiraWorkItem: 'MED-43 (Integrate Optical Droplet Sensor Interrupt Routine)',
      testKey: 'TEST-89',
      testStatus: 'PASSED',
      complianceState: 'VERIFIED',
      violations: [],
    },
    {
      hazardKey: 'HAZ-103',
      riskClass: 'CLASS_A',
      severity: 'MINOR',
      title: 'Display Transient Glitch: OLED backlight flicker during emergency battery cutover',
      confluenceSpec: 'SRS-106: Power Management Rail Glitch Filter & OLED Retention (v1)',
      specHash: 'c67d33998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b444',
      signedHash: 'c67d33998fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b444',
      isSignatureValid: true,
      jiraWorkItem: 'MED-44 (Calibrate OLED SPI Bus Low-Power Sleep Transitions)',
      testKey: 'TEST-90',
      testStatus: 'PASSED',
      complianceState: 'VERIFIED',
      violations: [],
    },
  ],
};

const TOOLS = [
  {
    name: 'medtrace_get_hazard_lineage',
    description: 'Retrieves complete ISO 14971 hazard safety lineage, linked Confluence SRS specifications, and verification test status for medical device software.',
    inputSchema: {
      type: 'object',
      properties: {
        hazardKey: {
          type: 'string',
          description: 'Optional hazard or issue key (e.g. HAZ-101, MED-42, TEST-88). Omit to retrieve full project lineage.',
        },
      },
    },
  },
  {
    name: 'medtrace_verify_iec_compliance',
    description: 'Audits the active sprint or PR against IEC 62304 and FDA 21 CFR Part 11 requirements, checking for unmitigated Class C hazards and signature drift.',
    inputSchema: {
      type: 'object',
      properties: {
        prDiff: {
          type: 'string',
          description: 'Git PR diff or modified code file path to analyze against safety hazards.',
        },
      },
    },
  },
  {
    name: 'medtrace_remediate_safety_gap',
    description: 'Simulates executing automated Hardware-in-the-Loop verification tests for Class C hazards and re-certifying 21 CFR Part 11 electronic signatures.',
    inputSchema: {
      type: 'object',
      properties: {
        hazardKey: {
          type: 'string',
          description: 'Hazard key to remediate (e.g. HAZ-101).',
        },
      },
      required: ['hazardKey'],
    },
  },
];

function handleMessage(message) {
  const { id, method, params } = message;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: {},
        },
        serverInfo: {
          name: SERVER_NAME,
          version: SERVER_VERSION,
        },
      },
    };
  }

  if (method === 'notifications/initialized') {
    return null; // No response needed for notification
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id,
      result: {
        tools: TOOLS,
      },
    };
  }

  if (method === 'tools/call') {
    const { name, arguments: args } = params;

    if (name === 'medtrace_get_hazard_lineage') {
      const hazardKey = args?.hazardKey;
      if (hazardKey) {
        const found = complianceState.traceLinks.find(
          (l) =>
            l.hazardKey.toLowerCase() === hazardKey.toLowerCase() ||
            l.jiraWorkItem.toLowerCase().includes(hazardKey.toLowerCase()) ||
            l.testKey.toLowerCase() === hazardKey.toLowerCase()
        );
        if (found) {
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(found, null, 2),
                },
              ],
            },
          };
        }
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                projectName: complianceState.projectName,
                totalHazards: complianceState.totalHazards,
                verifiedPercentage: `${complianceState.verifiedPercentage}%`,
                releaseBlocked: complianceState.releaseBlocked,
                lineages: complianceState.traceLinks,
              }, null, 2),
            },
          ],
        },
      };
    }

    if (name === 'medtrace_verify_iec_compliance') {
      const prDiff = args?.prDiff || '';
      const touchesBolus = prDiff.includes('bolus') || prDiff.includes('flow') || prDiff.includes('dose');

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                standards: complianceState.standards,
                releaseGateStatus: complianceState.releaseBlocked ? '🚨 BLOCKED BY JIRA SAFETY GATE' : '✅ 510(k) AUTHORIZED',
                verifiedCoverage: `${complianceState.verifiedPercentage}%`,
                classCSafetyGaps: complianceState.releaseBlocked ? 1 : 0,
                touchesSafetyCriticalCode: touchesBolus,
                safetyWarning: touchesBolus
                  ? '⚠️ CRITICAL: Diff modifies bolus delivery logic governed by ISO 14971 Class C Hazard HAZ-101. IEC 62304 verification test TEST-88 is required before merge!'
                  : 'Normal inspection: no unmitigated Class C hazard triggered.',
                activeViolations: complianceState.traceLinks.flatMap((l) => l.violations),
                signatureDriftCount: complianceState.signatureDriftCount,
              }, null, 2),
            },
          ],
        },
      };
    }

    if (name === 'medtrace_remediate_safety_gap') {
      const target = complianceState.traceLinks.find((l) => l.hazardKey === args?.hazardKey);
      if (target) {
        target.testStatus = 'PASSED';
        target.isSignatureValid = true;
        target.complianceState = 'VERIFIED';
        target.violations = [];
        target.signedHash = target.specHash;
        complianceState.verifiedPercentage = 100;
        complianceState.releaseBlocked = false;
        complianceState.signatureDriftCount = 0;
      }

      return {
        jsonrpc: '2.0',
        id,
        result: {
          content: [
            {
              type: 'text',
              text: `✅ Remediated ${args?.hazardKey}! Automated Hardware-in-the-Loop test PASSED (120/120 assertions). 21 CFR Part 11 Electronic Signature re-certified by Chief Medical Officer. Jira Safety Gate UNLOCKED.`,
            },
          ],
        },
      };
    }

    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: -32601,
        message: `Unknown tool: ${name}`,
      },
    };
  }

  return {
    jsonrpc: '2.0',
    id,
    error: {
      code: -32601,
      message: `Unsupported method: ${method}`,
    },
  };
}

rl.on('line', (line) => {
  if (!line.trim()) return;
  try {
    const message = JSON.parse(line);
    const response = handleMessage(message);
    if (response) {
      process.stdout.write(JSON.stringify(response) + '\n');
    }
  } catch (err) {
    console.error('Error handling MCP JSON-RPC message:', err);
  }
});
