**Back:** [Repository Root](../../README.md)

# Architecture Overview

**Covers:** `manifest.yml`, `src/index.ts`, `src/types.ts`, `static/frontend/src/App.tsx`  
**Read this when:** understanding how the Atlassian Forge backend, Custom UI frontend, and external Model Context Protocol services connect.

MedTrace turns Atlassian Cloud into a continuous regulatory compliance platform for medical device software (IEC 62304 & FDA 21 CFR Part 11). It maintains unbroken bidirectional traceability between:
$$\text{ISO 14971 Clinical Hazard} \longleftrightarrow \text{Safety Requirement (Confluence)} \longleftrightarrow \text{Firmware Task (Jira)} \longleftrightarrow \text{Verification Test} \longleftrightarrow \text{Part 11 Signature}$$

## Contents

| File | Description |
|---|---|
| [forge-modules.md](./forge-modules.md) | Declared Forge manifest modules, extension points, resolver RPCs, and permissions. |
