/**
 * Locating the OpenP2S OpenVPN binary.
 *
 * OpenP2S will not fall back to the system openvpn. Stock OpenVPN cannot
 * complete an Entra handshake - it truncates the access token at 128 bytes
 * and sends the wrong OCC string and peer-info - so silently using it would
 * produce a connection that fails in a way that looks like a server fault.
 * Better to say plainly that the binary has not been built yet.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { OpenP2SError } from '../errors.ts';

export interface OpenVpnBinary {
  readonly path: string;
  readonly upstreamVersion: string | undefined;
  readonly upstreamCommit: string | undefined;
  readonly patchSha256: string | undefined;
  readonly binarySha256: string | undefined;
  /** True when the binary understands --experimental-azure-compat. */
  readonly azureCompatAvailable: boolean;
  /** USER_PASS_LEN in this build; the credential size ceiling. */
  readonly userPassLen: number;
  readonly patchStack: string | undefined;
  /**
   * True when BUILDINFO described this exact binary.
   *
   * False for a binary supplied with --openvpn-binary that has no BUILDINFO
   * beside it: its capabilities are then unknown, and must not be assumed.
   */
  readonly provenanceKnown: boolean;
}

function sha256Of(path: string): string | undefined {
  try {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  } catch {
    return undefined;
  }
}

function parseBuildInfo(path: string): Record<string, string> {
  const info: Record<string, string> = {};
  try {
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      if (line.startsWith('#') || !line.includes('=')) continue;
      const index = line.indexOf('=');
      info[line.slice(0, index).trim()] = line.slice(index + 1).trim();
    }
  } catch {
    // A missing or unreadable BUILDINFO is not fatal; it only costs us the
    // provenance detail in `openp2s status`.
  }
  return info;
}

export interface LocateOptions {
  /** Explicit path from --openvpn-binary. */
  readonly override?: string | undefined;
  /**
   * Repository root, used to find build/openvpn in a source checkout.
   *
   * Undefined in a packaged build, where there is no checkout to look in and
   * only the installed locations apply.
   */
  readonly repoRoot?: string | undefined;
  readonly env?: NodeJS.ProcessEnv;
  /** Overrides process.execPath, so sibling discovery is testable. */
  readonly execPath?: string;
  /**
   * Overrides the well-known absolute install locations.
   *
   * The same reason execPath is overridable, and the last input that was not:
   * with these fixed, what discovery returns depends on whether the machine
   * running the tests happens to have the package installed, and the
   * not-found path cannot be reached deliberately at all.
   */
  readonly installedPaths?: readonly string[];
}

/**
 * Where an installed package puts the patched binary.
 *
 * Deliberately *not* /usr/sbin/openvpn: OpenP2S must never pick up the
 * distribution's OpenVPN, which cannot authenticate to an Azure gateway. The
 * private path makes that impossible by accident.
 */
export const INSTALLED_BINARY_PATHS: readonly string[] = [
  '/usr/lib/openp2s/openvpn',
  '/usr/libexec/openp2s/openvpn',
  '/usr/local/lib/openp2s/openvpn',
  '/opt/openp2s/sbin/openvpn',
];

/**
 * Every path discovery will consider, in precedence order.
 *
 * Exported so the ordering, and the absence of any distribution location from
 * it, can be asserted directly rather than inferred from whichever candidate
 * happens to exist on the machine running the tests.
 */
export function openVpnCandidates(options: LocateOptions): string[] {
  const env = options.env ?? process.env;
  const buildRoot = options.repoRoot ? join(options.repoRoot, 'build', 'openvpn') : undefined;

  const execDir = dirname(options.execPath ?? process.execPath);

  return [
    options.override,
    env['OPENP2S_OPENVPN_BINARY'],
    // A source checkout, if we are running from one.
    buildRoot ? join(buildRoot, 'sbin', 'openvpn') : undefined,
    // Beside the executable: what makes the portable tarball work in place.
    // Under a plain `node` this does not exist, so it costs nothing.
    join(execDir, 'openvpn-openp2s'),
    // The executable's own prefix, so /usr, /usr/local and a relocated tree
    // all work without enumerating them.
    join(execDir, '..', 'lib', 'openp2s', 'openvpn'),
    join(execDir, '..', 'libexec', 'openp2s', 'openvpn'),
    // Well-known absolute locations, for the case where the CLI is reached
    // through a symlink from somewhere else on PATH.
    ...(options.installedPaths ?? INSTALLED_BINARY_PATHS),
  ].filter((candidate): candidate is string => Boolean(candidate));
}

export function locateOpenVpnBinary(options: LocateOptions): OpenVpnBinary {
  const buildRoot = options.repoRoot ? join(options.repoRoot, 'build', 'openvpn') : undefined;
  const candidates = openVpnCandidates(options);

  const found = candidates.find((candidate) => existsSync(candidate));

  if (!found) {
    throw new OpenP2SError('the OpenP2S OpenVPN binary was not found', {
      hint:
        'Looked in:\n' +
        candidates.map((candidate) => `  ${candidate}`).join('\n') +
        '\n\nBuild it with scripts/build-openvpn.sh, install the openp2s ' +
        'package, or set OPENP2S_OPENVPN_BINARY.\n' +
        'OpenP2S will not fall back to the system openvpn: stock builds ' +
        'truncate the Entra access token and cannot authenticate to an Azure ' +
        'gateway.',
    });
  }

  // BUILDINFO sits next to the binary in a package, or under build/ in a
  // checkout. Prefer the one beside the binary: it describes *that* file.
  const beside = parseBuildInfo(join(dirname(found), 'BUILDINFO'));
  const fromCheckout = buildRoot ? parseBuildInfo(join(buildRoot, 'BUILDINFO')) : {};
  const info = Object.keys(beside).length > 0 ? beside : fromCheckout;

  // A BUILDINFO that names a different binary describes something else.
  const declaredSha = info['binary_sha256'];
  const provenanceKnown =
    Object.keys(info).length > 0 && (declaredSha === undefined || declaredSha === sha256Of(found));

  // Once provenance is unknown, nothing in that BUILDINFO may be believed -
  // user_pass_len least of all.
  const trusted = provenanceKnown ? info : {};

  return {
    path: found,
    upstreamVersion: trusted['openvpn_version'],
    upstreamCommit: trusted['openvpn_commit'],
    patchSha256: trusted['long_credentials_sha256'] ?? trusted['openp2s_patch_compat_sha256'],
    // Reported even when it mismatches: that is what a caller wants to see.
    binarySha256: info['binary_sha256'],
    azureCompatAvailable: trusted['azure_compat_available'] === '1',
    provenanceKnown,
    // Never guess this. An unpatched OpenVPN has 128, and assuming 4096 for
    // an unknown binary would let a token through that it silently truncates.
    userPassLen: Number(trusted['user_pass_len'] ?? (provenanceKnown ? 4096 : 128)),
    patchStack: trusted['patch_stack'],
  };
}
