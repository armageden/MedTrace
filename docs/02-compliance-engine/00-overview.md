**Back:** [Repository Root](../../README.md)

# Compliance Engine Overview

**Covers:** `src/compliance-engine.ts`, `src/seeder.ts`, `src/types.ts`  
**Read this when:** reviewing IEC 62304 software safety classification, ISO 14971 hazard mapping, FDA 21 CFR Part 11 cryptographic signature validation, or demo seeding.

The compliance engine provides pure in-memory regulatory evaluation functions (`src/compliance-engine.ts`) operating over the 5-stage `TraceLink` data model (`src/types.ts`). Evaluated summaries are persisted in `@forge/kvs` and seeded by `SeederService` (`src/seeder.ts`), enabling fast-path Jira workflow gating (<80ms) without runtime GraphQL dependencies.

## Contents

| File | Description |
|---|---|
| [evaluation-rules.md](./evaluation-rules.md) | Evaluation logic, safety classification rules, signature verification, and SeederService contracts. |
