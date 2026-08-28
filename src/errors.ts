/**
 * Typed errors plus the redaction helpers that keep secrets out of logs.
 *
 * Everything user-facing goes through `redact()`. Entra access tokens and the
 * profile's serversecret must never reach a terminal, a log file, or a crash
 * report, and the cheapest way to guarantee that is to scrub at the point of
 * formatting rather than trusting every call site to remember.
 */

/**
 * Options accepted by every OpenP2S error.
 *
 * `hint` is explicitly `string | undefined` rather than just optional so that
 * call sites can pass a value that may be undefined without contorting
 * themselves around exactOptionalPropertyTypes.
 */
export interface ErrorOptions {
  readonly exitCode?: number | undefined;
  readonly hint?: string | undefined;
  readonly cause?: unknown;
}

/** Base class for errors OpenP2S raises deliberately, with a clean message. */
export class OpenP2SError extends Error {
  /** Suggested process exit code. */
  readonly exitCode: number;
  /** Optional remediation hint printed under the error. */
  readonly hint: string | undefined;

  constructor(message: string, options: ErrorOptions = {}) {
    super(redact(message), options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    this.exitCode = options.exitCode ?? 1;
    this.hint = options.hint;
  }
}

/** The Azure XML profile could not be parsed or failed validation. */
export class ProfileError extends OpenP2SError {
  constructor(message: string, options: Omit<ErrorOptions, 'exitCode'> = {}) {
    super(message, { ...options, exitCode: 2 });
  }
}

/** Entra authentication failed, was declined, or timed out. */
export class AuthError extends OpenP2SError {
  constructor(message: string, options: Omit<ErrorOptions, 'exitCode'> = {}) {
    super(message, { ...options, exitCode: 3 });
  }
}

/** The OpenVPN subprocess failed to start, or exited before connecting. */
export class TunnelError extends OpenP2SError {
  constructor(message: string, options: Omit<ErrorOptions, 'exitCode'> = {}) {
    super(message, { ...options, exitCode: 4 });
  }
}

/** Configuring or reverting network state (DNS, routes) failed. */
export class NetworkError extends OpenP2SError {
  constructor(message: string, options: Omit<ErrorOptions, 'exitCode'> = {}) {
    super(message, { ...options, exitCode: 5 });
  }
}

const REDACTED = '[redacted]';

/**
 * Patterns for material that must never be printed.
 *
 * These are a backstop, not the primary defence: the code paths that handle
 * tokens are written not to pass them to a formatter in the first place. But
 * tokens have a way of ending up inside third-party error strings and HTTP
 * response bodies, so anything on its way to a human gets scrubbed too.
 */
type Replacement = string | ((match: string) => string);

/**
 * Known digest lengths, in hex characters: SHA-1, SHA-256, SHA-512.
 *
 * A run of exactly this many hex characters is a checksum, not a credential.
 * OpenP2S prints these constantly - patch hashes, binary hashes, certificate
 * thumbprints - and redacting them would make the provenance output useless.
 */
const DIGEST_HEX_LENGTHS: ReadonlySet<number> = new Set([40, 64, 128]);

/**
 * Shortest opaque run treated as credential material.
 *
 * Above every standard base64 wrapping width - PEM wraps at 64 columns, MIME
 * at 76 - so that an embedded certificate survives redaction intact. A
 * certificate is not a secret, and mangling one in the middle produces
 * something that looks like a copyable PEM but is not.
 *
 * A token fragment is far longer than this: what OpenVPN echoes back is a
 * slice of a ~2.3 KB access token, so nothing that matters is let through.
 */
const MIN_OPAQUE_RUN = 80;

/** Keep checksums; redact anything else that reaches a digest-shaped rule. */
function keepDigest(match: string, label: string): string {
  // A token is base64url and essentially never all-hex, so a hex run of a
  // length we publish digests at is a hash we printed on purpose.
  if (/^[0-9a-fA-F]+$/.test(match) && DIGEST_HEX_LENGTHS.has(match.length)) {
    return match;
  }
  return label;
}

const SECRET_PATTERNS: ReadonlyArray<readonly [RegExp, Replacement]> = [
  // JWTs: three base64url segments. Entra access and ID tokens.
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, `${REDACTED}-jwt`],
  // OpenVPN management commands, which carry credentials by design.
  [/(MANAGEMENT: CMD '(?:password|username)\s+"[^"]*"\s+)"[^']*"/g, `$1"${REDACTED}"`],
  [/((?:password|username)\s+"Auth"\s+)"[^"]*"/gi, `$1"${REDACTED}"`],
  // Entra refresh tokens ("0.AXoA..."-style long opaque blobs).
  [/\b0\.[A-Za-z0-9_-]{40,}/g, `${REDACTED}-refresh-token`],
  // The 512-hex-character serversecret, and any long hex run near its size.
  // A SHA-512 digest is exactly 128 hex characters and lands here, so this
  // rule has to exempt checksums just as the opaque-run rule below does.
  [/\b[0-9a-fA-F]{128,}\b/g, (match: string): string => keepDigest(match, `${REDACTED}-secret`)],
  // A *fragment* of a token, with no recognisable prefix or segment
  // structure. This is not hypothetical: OpenVPN's management interface
  // echoes back an over-long parameter, and what it echoes is the middle of
  // the access token - which the JWT pattern above does not match, because
  // there is no leading "eyJ" and no dots. A base64url run this long in a
  // VPN client's output is a credential.
  [
    new RegExp(`[A-Za-z0-9_-]{${MIN_OPAQUE_RUN},}`, 'g'),
    (match: string): string => keepDigest(match, `${REDACTED}-token-fragment`),
  ],
  // JSON/­query fields that name a secret, whatever the value looks like.
  [
    /("(?:access_token|refresh_token|id_token|client_secret|password|serversecret)"\s*:\s*")[^"]*"/gi,
    `$1${REDACTED}"`,
  ],
  [/\b((?:access_token|refresh_token|id_token|client_secret|password)=)[^&\s]+/gi, `$1${REDACTED}`],
];

/**
 * Remove anything that looks like a credential from a string.
 *
 * Deliberately aggressive: a redacted diagnostic is a nuisance, a leaked
 * token is an incident.
 */
export function redact(text: string): string {
  let out = text;
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    // Identical branches on purpose: `replace` has separate overloads for a
    // string and for a replacer function, and neither accepts the union.
    // Collapsing this is a build error, not a cleanup.
    out =
      typeof replacement === 'function'
        ? out.replace(pattern, replacement)
        : out.replace(pattern, replacement);
  }
  return out;
}

/** Redacted, human-readable message, following `cause` chains. */
export function describeError(error: unknown): string {
  if (error instanceof Error) {
    const parts = [error.message];
    let cause: unknown = error.cause;
    let depth = 0;
    while (cause instanceof Error && depth < 3) {
      const message: string = cause.message;
      // Wrappers often embed the cause's text already; skip the repeat.
      if (message && !parts.some((part) => part.includes(message))) {
        parts.push(message);
      }
      cause = cause.cause;
      depth += 1;
    }
    return redact(parts.join(': '));
  }
  if (typeof error === 'string') {
    return redact(error);
  }
  return redact(String(error));
}
