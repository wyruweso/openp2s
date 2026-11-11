/**
 * Synthetic JWTs, built at runtime.
 *
 * Assembled rather than written as literals so no `eyJ`-prefixed string
 * appears in the source for a secret scanner to flag.
 */

function segment(payload: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

/**
 * A short, well-formed synthetic JWT.
 *
 * `alg: none` and an audience that says what it is, so anyone who decodes it
 * sees immediately that it is a fixture.
 */
export function syntheticJwt(): string {
  return [
    segment({ alg: 'none', typ: 'JWT' }),
    segment({ aud: 'synthetic-openp2s-test-token', sub: 'fixture' }),
    'not-a-real-signature',
  ].join('.');
}

/**
 * A synthetic JWT of roughly the size of a real Entra access token (~2.3 KB).
 *
 * Used where the size matters: the management interface must split it across
 * base64 lines, and the length check must accept it.
 */
export function syntheticLongJwt(payloadBytes = 2200): string {
  return [
    segment({ alg: 'none', typ: 'JWT' }),
    segment({ aud: 'synthetic-openp2s-test-token', padding: 'x'.repeat(payloadBytes) }),
    'not-a-real-signature',
  ].join('.');
}

/**
 * A synthetic opaque Entra-style credential: a version digit, a dot, then
 * dot-separated base64url segments, as refresh tokens and authorization codes
 * are written.
 *
 * Every segment is kept under the redactor's opaque-run threshold, so a test
 * using this exercises the rules that recognise the credential itself rather
 * than passing because some long run happened to be caught.
 */
export function syntheticOpaqueCredential(version = 1, segmentLengths = [60, 70, 50]): string {
  const segments = segmentLengths.map((length, index) =>
    Buffer.from(`synthetic-openp2s-opaque-${index}-`.padEnd(length, 'x'), 'utf8')
      .toString('base64url')
      .slice(0, length),
  );
  return `${version}.${segments.join('.')}`;
}

/**
 * A synthetic 512-hex serversecret.
 *
 * A repeating nibble sequence: structurally valid, obviously not entropy.
 */
export function syntheticServerSecret(): string {
  return '0123456789abcdef'.repeat(32);
}
