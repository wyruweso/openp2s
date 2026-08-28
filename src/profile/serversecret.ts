/**
 * Conversion between Azure's <serversecret> and OpenVPN's static key format.
 *
 * Azure ships the tls-auth key as 512 hexadecimal characters (256 bytes).
 * OpenVPN wants the same bytes wrapped in its "Static key V1" envelope, laid
 * out as 16 lines of 32 hex characters.
 */

import { ProfileError } from '../errors.ts';

export const SERVER_SECRET_HEX_LENGTH = 512;
export const SERVER_SECRET_BYTES = SERVER_SECRET_HEX_LENGTH / 2;
const LINE_LENGTH = 32;
export const STATIC_KEY_LINES = SERVER_SECRET_HEX_LENGTH / LINE_LENGTH;

const BEGIN = '-----BEGIN OpenVPN Static key V1-----';
const END = '-----END OpenVPN Static key V1-----';

/**
 * Validate a raw <serversecret> value.
 *
 * Exactly 512 hex characters, nothing else. Whitespace is tolerated on the
 * outside (XML pretty-printing adds it) but not on the inside. The value is
 * lowercased so that comparisons and cache keys are stable.
 *
 * Note the error messages: they describe the shape of the problem and never
 * quote the value, because doing so would put key material into a log.
 */
export function validateServerSecret(value: string, field = 'serversecret'): string {
  const secret = value.trim();

  if (secret.length === 0) {
    throw new ProfileError(`<${field}> is empty`);
  }
  if (!/^[0-9a-fA-F]+$/.test(secret)) {
    throw new ProfileError(`<${field}> contains non-hexadecimal characters`, {
      hint: `Expected exactly ${SERVER_SECRET_HEX_LENGTH} hex characters.`,
    });
  }
  if (secret.length !== SERVER_SECRET_HEX_LENGTH) {
    throw new ProfileError(
      `<${field}> is ${secret.length} characters, expected exactly ${SERVER_SECRET_HEX_LENGTH}`,
      { hint: 'The Azure tls-auth key is 256 bytes, written as 512 hex characters.' },
    );
  }

  return secret.toLowerCase();
}

/**
 * Render the OpenVPN static key envelope.
 *
 * Returns the full block including BEGIN/END markers and a trailing newline,
 * ready to drop between <tls-auth> tags.
 */
export function toOpenVpnStaticKey(serverSecret: string): string {
  const secret = validateServerSecret(serverSecret);

  const lines: string[] = [];
  for (let offset = 0; offset < secret.length; offset += LINE_LENGTH) {
    lines.push(secret.slice(offset, offset + LINE_LENGTH));
  }

  return [BEGIN, ...lines, END, ''].join('\n');
}

/**
 * Recover the hex secret from a static key block.
 *
 * Exists so the round trip can be asserted in tests: a conversion bug here
 * would produce a key that fails authentication in a way that looks like a
 * server problem, so it is worth being able to prove the transform is exact.
 */
export function fromOpenVpnStaticKey(staticKey: string): string {
  const lines = staticKey
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const begin = lines.indexOf(BEGIN);
  const end = lines.indexOf(END);
  if (begin === -1 || end === -1 || end < begin) {
    throw new ProfileError('not a valid OpenVPN static key block');
  }

  const body = lines.slice(begin + 1, end);
  if (body.length !== STATIC_KEY_LINES) {
    throw new ProfileError(`static key has ${body.length} lines, expected ${STATIC_KEY_LINES}`);
  }

  return validateServerSecret(body.join(''));
}
