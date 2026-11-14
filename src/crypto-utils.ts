import crypto from 'node:crypto';
import { ForgeKvsAPIError } from '@forge/kvs';

const SAFE_KVS_SEGMENT_RE = /^[a-zA-Z0-9:._#-]+$/;
// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;

/**
 * Computes lowercase hexadecimal SHA-256 digest of a UTF-8 string.
 */
export function sha256Hex(content: string): string {
  return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
}

/**
 * Recursively sorts plain-object keys lexicographically for deterministic hashing/serialization.
 */
export function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value instanceof Date) {
    return value;
  }
  if (value && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Produces deterministic canonical JSON with lexicographically sorted object keys.
 */
export function canonicalJsonStringify(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value)) ?? 'null';
}

/**
 * Detects Forge KVS optimistic/conditional-write conflicts (409 / KEY_ALREADY_EXISTS).
 */
export function isKvsConflictError(err: unknown): boolean {
  if (err instanceof ForgeKvsAPIError) {
    if (err.responseDetails?.status === 409) return true;
    if (/EXISTS|CONFLICT/i.test(err.code || '')) return true;
    if (/already exists|conflict/i.test(err.message || '')) return true;
  }
  if (!err || typeof err !== 'object') {
    return false;
  }
  const candidate = err as {
    status?: unknown;
    statusCode?: unknown;
    code?: unknown;
    message?: unknown;
    responseDetails?: { status?: unknown };
  };
  if (candidate.responseDetails?.status === 409) return true;
  if (candidate.status === 409 || candidate.statusCode === 409) return true;
  if (typeof candidate.code === 'string' && /EXISTS|CONFLICT/i.test(candidate.code)) return true;
  if (
    typeof candidate.message === 'string' &&
    /already exists|key already exists|conflict/i.test(candidate.message)
  ) {
    return true;
  }
  return false;
}

/**
 * Normalizes a key segment to satisfy Forge KVS key regex rules (`/^(?!\s+$)[a-zA-Z0-9:._\s-#]+$/`)
 * and bounded segment length while preserving collision resistance via a SHA-256 suffix when modified.
 */
export function sanitizeKvsKeySegment(raw: string, maxLen: number = 120): string {
  const safeMax = Number.isFinite(maxLen) && maxLen > 0 ? Math.floor(maxLen) : 120;
  const effectiveMax = Math.min(240, safeMax);
  const input = String(raw ?? '');
  const trimmed = input.trim();

  if (trimmed.length > 0 && trimmed.length <= effectiveMax && SAFE_KVS_SEGMENT_RE.test(trimmed)) {
    return trimmed;
  }

  const hashLen = effectiveMax >= 20 ? 16 : Math.max(4, Math.min(16, effectiveMax));
  const hashSuffix = sha256Hex(input).slice(0, hashLen);
  if (effectiveMax <= hashLen + 2) {
    return hashSuffix.slice(0, effectiveMax);
  }

  const cleaned = trimmed
    .replace(/[^a-zA-Z0-9:._#-]+/g, '_')
    .replace(/^_+|_+$/g, '');
  if (!cleaned) {
    return `k_${hashSuffix}`.slice(0, effectiveMax);
  }

  const prefixMax = effectiveMax - hashLen - 1;
  return `${cleaned.slice(0, prefixMax)}_${hashSuffix}`;
}

/**
 * Measures the UTF-8 byte length of a value when serialized as JSON.
 */
export function measureJsonBytes(value: unknown): number {
  const json = JSON.stringify(value);
  return json === undefined ? 0 : Buffer.byteLength(json, 'utf8');
}

/**
 * Validates that a URL is a well-formed `https://` URL without embedded credentials or control characters.
 */
export function validateHttpsUrl(rawUrl: string): string {
  if (typeof rawUrl !== 'string') {
    throw new Error('Invalid URL: expected a non-empty https:// URL string.');
  }
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    throw new Error('Invalid URL: URL must not be empty.');
  }
  if (CONTROL_CHAR_RE.test(trimmed)) {
    throw new Error('Invalid URL: control characters are not permitted.');
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`Invalid URL: "${trimmed}" is not a valid URL.`);
  }

  if (parsed.protocol !== 'https:') {
    throw new Error(`Unsafe URL scheme "${parsed.protocol}": only https:// URLs are permitted.`);
  }
  if (parsed.username !== '' || parsed.password !== '') {
    throw new Error('Invalid URL: embedded username/password credentials are not permitted.');
  }
  if (!parsed.hostname) {
    throw new Error('Invalid URL: missing hostname.');
  }

  return parsed.toString();
}
