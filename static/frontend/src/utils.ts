// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;

/**
 * Checks whether an unknown value is a plain JSON-style key-value record (non-null, non-array, plain prototype).
 */
export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Validates an optional HTTPS evidence URL, rejecting non-HTTPS schemes, embedded credentials, and control characters.
 * Returns `null` when valid or blank, or a human-readable validation error when invalid.
 */
export function validateHttpsUrlError(rawUrl: string): string | null {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return null;
  }
  if (CONTROL_CHAR_RE.test(trimmed)) {
    return 'Evidence URL must not contain control characters.';
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return 'Evidence URL must be a valid https:// URL.';
  }
  if (parsed.protocol !== 'https:') {
    return 'Evidence URL must start with https:// (http:// and javascript: URLs are not permitted).';
  }
  if (parsed.username !== '' || parsed.password !== '' || !parsed.hostname) {
    return 'Evidence URL must be a valid https:// URL without embedded credentials.';
  }
  return null;
}

/**
 * Returns the trimmed HTTPS URL when non-empty and safe, or `null` otherwise.
 */
export function getSafeHttpsUrl(rawUrl?: string): string | null {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return null;
  }
  const trimmed = rawUrl.trim();
  if (!trimmed || validateHttpsUrlError(trimmed) !== null) {
    return null;
  }
  return trimmed;
}

/**
 * Extracts a human-readable message from an unknown rejection (`Error` or plain Forge bridge `{ message }`).
 */
export function getErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message.trim()) {
    return err.message;
  }
  if (typeof err === 'string' && err.trim()) {
    return err.trim();
  }
  if (
    typeof err === 'object' &&
    err !== null &&
    'message' in err &&
    typeof (err as { message?: unknown }).message === 'string'
  ) {
    const msg = (err as { message: string }).message.trim();
    if (msg) return msg;
  }
  return fallback;
}

/**
 * Returns true when an attestation signature holds prior signing/invalidation metadata (distinguishing REVOKED vs UNSIGNED).
 */
export function hasPriorSignature(sig?: {
  artifactSha256?: string;
  signedBy?: string;
  signedAt?: string;
  invalidatedAt?: string;
}): boolean {
  return Boolean(sig && (sig.artifactSha256 || sig.signedBy || sig.signedAt || sig.invalidatedAt));
}
