**Back:** [00-overview](./00-overview.md)

# How-To: Deploy and Upgrade MedTrace in Production

## Goal
Deploy backend updates and Custom UI frontend builds to Atlassian Cloud production environments for Devpost judging.

## Steps

1. **Build Custom UI Frontend:**
   ```bash
   cd static/frontend && npm run build && cd ../..
   ```

2. **Verify Types and Manifest:**
   ```bash
   npx tsc --noEmit
   forge lint
   ```

3. **Deploy to Production Environment:**
   ```bash
   forge deploy -e production
   ```

4. **Upgrade Cloud Installations:**
   ```bash
   forge install -s one-atlas-feur.atlassian.net -p jira -e production --confirm-scopes --non-interactive
   forge install -s one-atlas-feur.atlassian.net -p confluence -e production --confirm-scopes --non-interactive
   ```

## Key Files

| Path | Role |
|---|---|
| `manifest.yml` | App manifest defining scopes, modules, and runtime settings. |
| `static/frontend/dist` | Compiled Custom UI web application assets. |
| `package.json` | Project configuration and build scripts. |

## Related

- [Forge Modules & Manifest Extensions](../01-architecture/forge-modules.md)
- [Docs Sync Runbook](./sync-docs-runbook.md)
