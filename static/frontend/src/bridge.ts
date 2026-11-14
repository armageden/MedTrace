import type { FullContext } from '@forge/bridge';
import type { MedTraceResolverMap } from './types';

type ForgeInvokePayload = Parameters<typeof import('@forge/bridge').invoke>[1];

export class BridgeUnavailableError extends Error {
  constructor(
    message = 'Forge Custom UI bridge is unavailable outside an Atlassian Forge iframe.'
  ) {
    super(message);
    this.name = 'BridgeUnavailableError';
    Object.setPrototypeOf(this, BridgeUnavailableError.prototype);
  }
}

let bridgeModulePromise: Promise<typeof import('@forge/bridge')> | null = null;

/**
 * Checks whether the Atlassian Forge Custom UI runtime bridge is attached to `globalThis`.
 * Safe to invoke outside Forge and during module initialization without throwing.
 */
export function isForgeBridgeAvailable(): boolean {
  return (
    typeof (globalThis as { __bridge?: { callBridge?: unknown } }).__bridge?.callBridge ===
    'function'
  );
}

/**
 * Clears the cached `@forge/bridge` dynamic import promise for isolated Vitest runs.
 */
export function _resetBridgeCacheForTests(): void {
  bridgeModulePromise = null;
}

/**
 * Lazily loads `@forge/bridge` only when `globalThis.__bridge.callBridge` is present,
 * preventing module-evaluation `BridgeAPIError` crashes outside the Forge runtime.
 */
export async function loadForgeBridge(): Promise<typeof import('@forge/bridge')> {
  if (!isForgeBridgeAvailable()) {
    throw new BridgeUnavailableError();
  }
  if (!bridgeModulePromise) {
    bridgeModulePromise = import('@forge/bridge').catch((err) => {
      bridgeModulePromise = null;
      throw err;
    });
  }
  return bridgeModulePromise;
}

/**
 * Fetches Forge Custom UI extension context safely, returning `null` outside Forge or on failure.
 */
export async function getForgeContext(): Promise<FullContext | null> {
  if (!isForgeBridgeAvailable()) {
    return null;
  }
  try {
    const bridge = await loadForgeBridge();
    return await bridge.view.getContext();
  } catch {
    return null;
  }
}

/**
 * Enables Atlassian Forge design-system theming safely, returning `false` outside Forge or on failure.
 */
export async function enableForgeTheme(): Promise<boolean> {
  if (!isForgeBridgeAvailable()) {
    return false;
  }
  try {
    const bridge = await loadForgeBridge();
    await bridge.view.theme.enable();
    return true;
  } catch {
    return false;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Unwraps Forge `{ body, metadata }` response envelopes strictly: only unwraps when
 * `response` is a plain object whose own keys are a non-empty subset of `['body', 'metadata']`
 * and `'body'` is present, preventing domain objects that happen to define `body` alongside
 * other properties from being stripped.
 */
export function unwrapInvokeResponse<T>(response: unknown): T {
  if (!isPlainObject(response)) {
    return response as T;
  }
  const keys = Object.keys(response);
  if (
    keys.length > 0 &&
    Object.prototype.hasOwnProperty.call(response, 'body') &&
    keys.every((key) => key === 'body' || key === 'metadata')
  ) {
    return response.body as T;
  }
  return response as T;
}

/**
 * Strongly-typed wrapper around `@forge/bridge` `invoke()` keyed by `MedTraceResolverMap`.
 */
export async function invokeResolver<K extends keyof MedTraceResolverMap>(
  functionKey: K,
  ...args: MedTraceResolverMap[K]['payload'] extends undefined
    ? [payload?: undefined]
    : undefined extends MedTraceResolverMap[K]['payload']
    ? [payload?: MedTraceResolverMap[K]['payload']]
    : [payload: MedTraceResolverMap[K]['payload']]
): Promise<MedTraceResolverMap[K]['response']> {
  const bridge = await loadForgeBridge();
  const payload = args[0];
  const response: unknown = await bridge.invoke(
    functionKey,
    payload as ForgeInvokePayload
  );
  return unwrapInvokeResponse<MedTraceResolverMap[K]['response']>(response);
}
