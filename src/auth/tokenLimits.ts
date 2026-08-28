/**
 * Credential size limits.
 *
 * The patched OpenVPN raises USER_PASS_LEN from 128 to 4096, which is enough
 * for every Entra access token seen so far. "Enough so far" is not a
 * guarantee: tokens grow with group claims, and a user in many groups can get
 * a much larger one.
 *
 * OpenVPN's behaviour at the limit is to truncate silently. The gateway then
 * rejects a credential that looks valid to us, and the failure surfaces as a
 * generic AUTH_FAILED with nothing pointing at the real cause. So OpenP2S
 * measures the token itself and refuses, with a message that says exactly
 * what happened.
 */

import { AuthError } from '../errors.ts';

/**
 * USER_PASS_LEN in the patched binary.
 *
 * The buffer holds a NUL terminator, so the usable credential length is one
 * byte less. Overridable because the build records the real value in
 * BUILDINFO - if the patch ever changes this, the check follows it rather
 * than staying pinned to a stale constant.
 */
export const DEFAULT_USER_PASS_LEN = 4096;

export interface CredentialLimits {
  /** Total buffer size, including the NUL terminator. */
  readonly userPassLen: number;
}

export function usableCredentialBytes(limits: CredentialLimits): number {
  return limits.userPassLen - 1;
}

/**
 * Reject a token that OpenVPN would truncate.
 *
 * Measured in *bytes*, not characters: a JWT is base64url and therefore
 * ASCII, but measuring the UTF-8 length is the correct thing to compare
 * against a C char buffer and costs nothing.
 */
export function assertTokenFits(
  accessToken: string,
  limits: CredentialLimits = { userPassLen: DEFAULT_USER_PASS_LEN },
): void {
  const bytes = Buffer.byteLength(accessToken, 'utf8');
  const maximum = usableCredentialBytes(limits);

  if (bytes > maximum) {
    throw new AuthError(
      `Entra access token is ${bytes} bytes, but this OpenVPN build supports a maximum of ${maximum} bytes.`,
      {
        hint:
          'OpenVPN would silently truncate the token and the gateway would reject it.\n' +
          'Rebuild with a larger USER_PASS_LEN (patches/<version>/long-credentials.patch),\n' +
          'or reduce the group claims in the token. Large tokens usually mean the\n' +
          'account is a member of a great many groups.',
      },
    );
  }
}

/**
 * Warn when a token is close enough to the limit to be worth knowing about.
 *
 * Group membership changes over time, so a token at 90% today is a connection
 * that breaks confusingly in a few months.
 */
export function tokenPressureWarning(
  accessToken: string,
  limits: CredentialLimits = { userPassLen: DEFAULT_USER_PASS_LEN },
): string | undefined {
  const bytes = Buffer.byteLength(accessToken, 'utf8');
  const maximum = usableCredentialBytes(limits);

  if (bytes > maximum * 0.9) {
    const percent = Math.round((bytes / maximum) * 100);
    return `the Entra access token is ${bytes} bytes, ${percent}% of this build's ${maximum}-byte limit`;
  }
  return undefined;
}
