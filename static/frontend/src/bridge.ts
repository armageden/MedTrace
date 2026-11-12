import { invoke } from '@forge/bridge';

interface ResponseEnvelope<T> {
  body: T;
  metadata: unknown;
}

function isResponseEnvelope<T>(value: unknown): value is ResponseEnvelope<T> {
  return (
    typeof value === 'object' &&
    value !== null &&
    'body' in value &&
    'metadata' in value
  );
}

/**
 * Strongly-typed wrapper around `@forge/bridge` `invoke()` that unwraps optional
 * `{ body, metadata }` response envelopes without `any` casts.
 */
export async function invokeResolver<T>(
  functionKey: string,
  payload?: Parameters<typeof invoke>[1]
): Promise<T> {
  const response: unknown = await invoke<T>(functionKey, payload);
  if (isResponseEnvelope<T>(response)) {
    return response.body;
  }
  return response as T;
}
