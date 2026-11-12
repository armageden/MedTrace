/**
 * Detects whether code is executing inside an active Atlassian Forge runtime.
 * Outside Forge (e.g., unit tests in local Node.js), `global.__forge_runtime__` is undefined.
 */
export function isForgeRuntime(): boolean {
  return Boolean((globalThis as { __forge_runtime__?: unknown }).__forge_runtime__);
}
