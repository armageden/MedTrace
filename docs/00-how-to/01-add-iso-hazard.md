**Back:** [00-overview](./00-overview.md)

# How-To: Add an ISO 14971 Clinical Hazard

## Goal
Add a new clinical hazard record to the MedTrace demo dataset and link it through the 5-stage regulatory chain.

## Steps

1. **Define the Hazard Data Contract:**
   Open `src/types.ts` and ensure your risk classification matches `'CLASS_A' | 'CLASS_B' | 'CLASS_C'`.

2. **Add Entry to the Seeder:**
   Open `src/seeder.ts` and append a new hazard object to `hazards` inside `SeederService.seedEnterpriseDemoSuite()`:
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

3. **Provide Corresponding SRS Spec & Test:**
   In `src/seeder.ts`, append matching entries in `specs`, `workItems`, `tests`, and `signatures`.

4. **Verify Implementation:**
   Run:
   ```bash
   npx tsc --noEmit
   forge lint
   ```

## Key Files

| Path | Role |
|---|---|
| `src/types.ts` | Type definitions for `IsoHazard` and risk classifications. |
| `src/seeder.ts` | Data provisioning service creating hazard records. |
| `src/compliance-engine.ts` | Regulatory rules engine evaluating hazard link validity. |

## Related

- [Regulatory Evaluation Rules](../02-compliance-engine/evaluation-rules.md)
- [How-To: Add an MCP Tool](./02-add-mcp-tool.md)
