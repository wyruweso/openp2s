/**
 * Certificate authority resolution: the system trust store, and nothing else.
 *
 * No CA is read from the profile - one that could nominate its own root would
 * be a trivial machine-in-the-middle - and none is bundled, which would go
 * stale and bypass distribution trust updates.
 *
 * The observed chain is DigiCert Global Root G2 -> Microsoft TLS RSA Root G2
 * -> Microsoft TLS G2 RSA CA -> *.vpn.azure.com.
 */

import { existsSync } from 'node:fs';
import { OpenP2SError } from '../errors.ts';

/**
 * Debian and Ubuntu explode the trust store into individual files, which lets
 * us pin the one relevant root. Elsewhere only a merged bundle exists, so this
 * is a preference rather than a requirement.
 */
const CANDIDATE_CA_PATHS: readonly string[] = [
  // Debian, Ubuntu
  '/etc/ssl/certs/DigiCert_Global_Root_G2.pem',
  '/usr/share/ca-certificates/mozilla/DigiCert_Global_Root_G2.crt',
  // Fedora, RHEL, CentOS: locally added anchors
  '/etc/pki/ca-trust/source/anchors/DigiCert_Global_Root_G2.pem',
];

/**
 * Whole-store fallbacks, in distribution order.
 *
 * Used when the individual anchor is not available. Chain validation still
 * happens; the connection is simply validated against the full system trust
 * store rather than one pinned root.
 */
const CANDIDATE_BUNDLE_PATHS: readonly string[] = [
  // Debian, Ubuntu, Alpine, Arch
  '/etc/ssl/certs/ca-certificates.crt',
  // Fedora, RHEL, CentOS
  '/etc/pki/tls/certs/ca-bundle.crt',
  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
  // openSUSE, SLES
  '/etc/ssl/ca-bundle.pem',
  // Arch, when ca-certificates-utils has run
  '/etc/ca-certificates/extracted/tls-ca-bundle.pem',
  // Void, Gentoo
  '/etc/ssl/certs/ca-bundle.crt',
];

export interface ResolvedCa {
  readonly path: string;
  /** True when this is the single DigiCert root rather than a whole bundle. */
  readonly pinned: boolean;
}

/**
 * Find the CA file to hand to OpenVPN.
 *
 * An explicit override is honoured but must exist; it is never silently
 * ignored, because a caller who thinks they pinned a root and did not is
 * worse off than one who gets an error.
 */
export function resolveCaPath(override?: string): ResolvedCa {
  if (override) {
    if (!existsSync(override)) {
      throw new OpenP2SError(`CA file not found: ${override}`);
    }
    return { path: override, pinned: true };
  }

  for (const candidate of CANDIDATE_CA_PATHS) {
    if (existsSync(candidate)) {
      return { path: candidate, pinned: true };
    }
  }

  for (const candidate of CANDIDATE_BUNDLE_PATHS) {
    if (existsSync(candidate)) {
      return { path: candidate, pinned: false };
    }
  }

  throw new OpenP2SError('no system CA certificate store found', {
    hint:
      "Install your distribution's CA bundle (on Debian/Ubuntu: " +
      'sudo apt install ca-certificates), or pass --ca with the path to ' +
      'DigiCert Global Root G2.',
  });
}

/**
 * `<usepinnedroot>` asks for validation against one specific root. OpenP2S
 * uses the system store, which is weaker, so this reports "unsupported" and
 * callers refuse rather than silently substituting the weaker policy.
 *
 * Shared by `connect` and `doctor` so they cannot disagree.
 */
export function pinnedRootSupport(
  profile: { readonly usePinnedRoot: boolean },
  options: { readonly allowSystemTrustStore?: boolean } = {},
): 'not-requested' | 'overridden' | 'unsupported' {
  if (!profile.usePinnedRoot) return 'not-requested';
  return options.allowSystemTrustStore ? 'overridden' : 'unsupported';
}

/** Why a pinned-root profile is refused. Shared by the error and the doctor. */
export const PINNED_ROOT_MESSAGE =
  'this profile requires pinned-root validation, which OpenP2S does not implement';

export const PINNED_ROOT_HINT =
  'The profile sets <usepinnedroot>true</usepinnedroot>, meaning the gateway\n' +
  'certificate should be validated against one specific root rather than the\n' +
  'system trust store. OpenP2S validates against the system store, which is\n' +
  'weaker than what the profile asks for.\n\n' +
  'Pass a specific root with --ca <file> and\n' +
  '--allow-system-trust-store to accept the weaker policy deliberately.';
