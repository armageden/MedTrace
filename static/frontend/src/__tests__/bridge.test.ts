import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FullContext } from '@forge/bridge';
import type { ComplianceSummary } from '../types';

type BridgeCallHandler = (...args: [type: string, payload?: unknown]) => Promise<unknown>;

let activeBridgeHandler: BridgeCallHandler = async () => null;

const sharedBridgeDispatcher: BridgeCallHandler = (...args) =>
  activeBridgeHandler(...args);

function installMockBridge(handler: BridgeCallHandler): void {
  activeBridgeHandler = handler;
  (globalThis as { __bridge?: { callBridge: BridgeCallHandler } }).__bridge = {
    callBridge: sharedBridgeDispatcher,
  };
}

function makeMinimalSummary(): ComplianceSummary {
  return {
    projectName: 'PumpGuard Live',
    datasetMode: 'LIVE',
    initialized: true,
    standards: ['IEC 62304:2006+A1:2015', 'ISO 14971:2019', 'FDA 21 CFR Part 11'],
    totalHazards: 0,
    classCCount: 0,
    classBCount: 0,
    classACount: 0,
    verifiedPercentage: 0,
    releaseBlocked: true,
    blockingReasons: ['No trace links'],
    signatureDriftCount: 0,
    traceLinks: [],
    lastAuditTimestamp: '2026-01-01T00:00:00.000Z',
  };
}

describe('FE-01: Runtime-safe lazy Forge bridge and typed resolver client', () => {
  afterEach(() => {
    delete (globalThis as { __bridge?: unknown }).__bridge;
    vi.resetModules();
  });

  it('imports bridge.ts and App.tsx safely outside Forge without throwing BridgeAPIError', async () => {
    delete (globalThis as { __bridge?: unknown }).__bridge;
    vi.resetModules();

    const bridgeMod = await import('../bridge');
    const appMod = await import('../App');

    expect(bridgeMod.isForgeBridgeAvailable()).toBe(false);
    expect(typeof appMod.App).toBe('function');
  });

  it('reports bridge availability accurately and falls back safely outside Forge', async () => {
    delete (globalThis as { __bridge?: unknown }).__bridge;
    vi.resetModules();

    const {
      isForgeBridgeAvailable,
      getForgeContext,
      enableForgeTheme,
      loadForgeBridge,
      invokeResolver,
      BridgeUnavailableError,
      _resetBridgeCacheForTests,
    } = await import('../bridge');

    _resetBridgeCacheForTests();
    expect(isForgeBridgeAvailable()).toBe(false);
    await expect(getForgeContext()).resolves.toBeNull();
    await expect(enableForgeTheme()).resolves.toBe(false);
    await expect(loadForgeBridge()).rejects.toBeInstanceOf(BridgeUnavailableError);
    await expect(invokeResolver('getComplianceSuite')).rejects.toBeInstanceOf(
      BridgeUnavailableError
    );

    (globalThis as { __bridge?: { callBridge: string } }).__bridge = {
      callBridge: 'not-a-function',
    };
    expect(isForgeBridgeAvailable()).toBe(false);

    installMockBridge(async () => null);
    expect(isForgeBridgeAvailable()).toBe(true);
  });

  it('unwraps Forge { body, metadata } envelopes strictly without stripping domain objects', async () => {
    vi.resetModules();
    const { unwrapInvokeResponse } = await import('../bridge');

    expect(unwrapInvokeResponse({ body: { ok: true } })).toEqual({ ok: true });
    expect(
      unwrapInvokeResponse({
        body: { count: 2 },
        metadata: { rateLimitProperties: { rateLimitRemaining: 499 } },
      })
    ).toEqual({ count: 2 });

    const domainObj = {
      body: 'SRS content',
      metadata: { source: 'confluence' },
      id: 'spec-1',
    };
    expect(unwrapInvokeResponse(domainObj)).toBe(domainObj);

    const emptyObj = {};
    expect(unwrapInvokeResponse(emptyObj)).toBe(emptyObj);
    expect(unwrapInvokeResponse(null)).toBeNull();
    expect(unwrapInvokeResponse(['a', 'b'])).toEqual(['a', 'b']);
  });

  it('loads @forge/bridge lazily inside Forge for theme, context, and typed invokeResolver', async () => {
    vi.resetModules();
    const summary = makeMinimalSummary();
    const mockContext: FullContext = {
      accountId: 'acc-1',
      cloudId: 'cloud-1',
      extension: {
        type: 'jira:issuePanel',
        issue: { key: 'MED-10' },
        project: { key: 'MED' },
      },
      environmentId: 'env-1',
      environmentType: 'DEVELOPMENT',
      localId: 'local-1',
      locale: 'en-US',
      moduleKey: 'medtrace-panel',
      siteUrl: 'https://example.atlassian.net',
      timezone: 'UTC',
    };

    const callBridge = vi.fn<BridgeCallHandler>(async (type, payload) => {
      if (type === 'enableTheming') return undefined;
      if (type === 'getContext') return mockContext;
      if (type === 'invoke') {
        const inv = payload as { functionKey?: string };
        if (inv.functionKey === 'getComplianceSuite') {
          return { body: summary, metadata: { rateLimitProperties: {} } };
        }
        if (inv.functionKey === 'simulateTransition') {
          return { result: false, errorMessage: 'Blocked globally' };
        }
      }
      return null;
    });

    installMockBridge(callBridge);
    const {
      _resetBridgeCacheForTests,
      enableForgeTheme,
      getForgeContext,
      invokeResolver,
    } = await import('../bridge');
    _resetBridgeCacheForTests();

    await expect(enableForgeTheme()).resolves.toBe(true);
    await expect(getForgeContext()).resolves.toMatchObject({
      extension: { type: 'jira:issuePanel', issue: { key: 'MED-10' } },
    });

    const suite = await invokeResolver('getComplianceSuite');
    expect(suite.projectName).toBe('PumpGuard Live');

    const gate = await invokeResolver('simulateTransition', { scope: 'global' });
    expect(gate).toEqual({ result: false, errorMessage: 'Blocked globally' });

    expect(callBridge).toHaveBeenCalledWith('enableTheming');
    expect(callBridge).toHaveBeenCalledWith('getContext');
    expect(callBridge).toHaveBeenCalledWith('invoke', {
      functionKey: 'simulateTransition',
      payload: { scope: 'global' },
      metadata: undefined,
    });
  });

  it('catches bridge call failures in getForgeContext and enableForgeTheme without throwing', async () => {
    vi.resetModules();
    const failingCallBridge = vi.fn<BridgeCallHandler>(async () => {
      throw new Error('Bridge RPC failed');
    });
    installMockBridge(failingCallBridge);

    const { _resetBridgeCacheForTests, getForgeContext, enableForgeTheme } = await import(
      '../bridge'
    );
    _resetBridgeCacheForTests();

    await expect(enableForgeTheme()).resolves.toBe(false);
    await expect(getForgeContext()).resolves.toBeNull();
  });
});
