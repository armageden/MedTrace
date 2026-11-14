**Back:** [00-overview](./00-overview.md)

# How-To: Add an ISO 14971 Clinical Hazard

## Goal
Add a new clinical hazard record to the MedTrace `DEMO` dataset and link it through the 5-stage regulatory chain (`HAZARD <-> SPEC <-> WORK <-> TEST <-> SIGNATURE`).

> **Note:** On cold start in production, MedTrace initializes as an empty `LIVE` suite (`initialized: false`, `totalHazards: 0`) rather than auto-seeding demo records. Production hazards come from Jira and Confluence via `LiveIngestionService.syncFromAtlassian()` ([src/ingestion.ts](../../src/ingestion.ts)).

## Steps

1. **Define the Hazard Data Contract:**
   Open [src/types.ts](../../src/types.ts) and ensure your risk classification matches `RiskClass` (`'CLASS_A' | 'CLASS_B' | 'CLASS_C'`). Note that `ComplianceEngine.evaluateTraceLink()` ([src/compliance-engine.ts](../../src/compliance-engine.ts)) requires a non-sentinel Confluence `spec.title`, `work.status === 'Done'`, `test.status === 'PASSED'`, and a valid Part 11 signature (`isValid === true`, matching `sha256Hash`) across all three risk classes before a link reaches `VERIFIED`.

2. **Add Entry to the Demo Seeder:**
   Open [src/seeder.ts](../../src/seeder.ts) and append a new hazard object to `hazards` inside `SeederService.seedEnterpriseDemoSuite()`:
   ```ts
   {
     id: 'haz-104',
     key: 'HAZ-104',
     title: 'Thermal Overheat Hazard: Battery charging thermal runaway during high-speed delivery',
     riskClass: 'CLASS_B',
     severity: 'SERIOUS',
     probability: 'REMOTE',
     mitigationRequirementId: 'srs-107',
     status: 'MITIGATED',
   }
   ```

3. **Provide Corresponding Spec, Work Item, Test, Signature & Graph Metadata:**
   In [src/seeder.ts](../../src/seeder.ts), append index-aligned entries in `specs`, `workItems`, `tests`, `signatures`, and `graphMetadatas`. `ComplianceEngine.buildTraceLinkId(hazard.key, spec.id, work.key)` generates deterministic composite M:N IDs (`trace-<haz>--<spec>--<work>`).

4. **Verify Implementation:**
   Run:
   ```bash
   npm run typecheck
   npm run build:all
   npm run test:all
   npm run lint:manifest
   npm run docs:check
   ```
   When Forge credentials are configured, also run `forge lint`.

## Key Files

| Path | Role |
|---|---|
| `src/types.ts` | Shared TypeScript contracts for `IsoHazard`, `RiskClass`, and `TraceLink`. |
| `src/seeder.ts` | Data provisioning service (`seedEnterpriseDemoSuite`, sharded KVS persistence). |
| `src/compliance-engine.ts` | Regulatory rules engine evaluating hazard link validity and composite IDs. |
| `src/ingestion.ts` | Live Jira and Confluence synchronization (`syncFromAtlassian`) for `LIVE` mode. |

## Related

- [Regulatory Evaluation Rules](../02-compliance-engine/evaluation-rules.md)
- [How-To: Add an MCP Tool](./02-add-mcp-tool.md)
- [How-To: Deploy to Production](./03-deploy-production.md)
