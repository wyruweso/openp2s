/**
 * `openp2s inspect <profile.xml>`
 *
 * Shows what OpenP2S understood from a profile, without connecting or
 * authenticating. This is the first thing to run when a connection misbehaves:
 * it separates "the profile says something unexpected" from "the gateway is
 * refusing us".
 *
 * The output is split into what came out of the XML and what OpenP2S resolved
 * on *this machine*, because those are different kinds of fact and mixing them
 * makes the CA path look like something the profile chose.
 *
 * The serversecret is never printed, and there is no flag to print it.
 * Confirming that it is present and well-formed is all a troubleshooting
 * session needs. The tenant, audience and client id are *not* secrets and are
 * printed in full: telling one application id from another is exactly the
 * diagnosis this command exists for.
 */

import { describeAzureCompat } from '../../openvpn/azureCompat.ts';
import { locateOpenVpnBinary } from '../../openvpn/binary.ts';
import { PINNED_ROOT_MESSAGE, pinnedRootSupport, resolveCaPath } from '../../openvpn/ca.ts';
import { summariseProfile } from '../../profile/types.ts';
import { createContext, loadProfile, type GlobalOptions } from '../context.ts';

export interface InspectOptions extends GlobalOptions {
  readonly ca?: string;
  /** Also show optional Azure compatibility support and OpenVPN build provenance. */
  readonly showCompat?: boolean;
  /**
   * Inspect this binary instead of the one that would be located by default.
   *
   * Mirrors `connect --openvpn-binary`, so that `inspect --show-compat` can
   * describe the binary a connection will actually use.
   */
  readonly openvpnBinary?: string;
}

export async function inspectCommand(
  profilePath: string,
  options: InspectOptions = {},
): Promise<number> {
  const context = createContext(options);
  const { ui } = context;

  const profile = await loadProfile(profilePath);
  const summary = summariseProfile(profile);

  // ---- what the profile says --------------------------------------------
  ui.heading(`Profile: ${summary.name}`);
  ui.line();

  ui.fields([
    ['Gateway', `${summary.gateway}:${summary.port}`],
    ['Authentication', 'Microsoft Entra ID'],
    ['Tenant', summary.tenantId],
    ['Authority', summary.authority],
    ['Audience', summary.audience],
    ['Client ID', summary.clientId],
    ['Scope', profile.auth.scope],
    ['Server secret', summary.serverSecret],
    ['DNS servers', summary.dnsServers],
    ['DNS domains', summary.dnsSuffixes],
    ['Include routes', summary.includeRoutes],
  ]);

  if (pinnedRootSupport(profile) === 'unsupported') {
    ui.line();
    ui.warn(PINNED_ROOT_MESSAGE);
    ui.hint('`openp2s connect` refuses this profile unless --allow-system-trust-store is given.');
  }

  // ---- what connect would do with the DNS settings ------------------------
  //
  // Deliberately phrased as intent, not outcome: inspect cannot see the
  // options a later connect will be given, and --no-dns or an absent
  // systemd-resolved both change the answer.
  ui.line();
  if (profile.dnsServers.length > 0) {
    const domains = profile.dnsSuffixes.map((suffix) => `~${suffix}`);
    ui.line('DNS settings in this profile:');
    ui.fields([
      ['  servers', profile.dnsServers],
      ['  routing domains', domains.length > 0 ? domains : ['(none)']],
      ['  default route', 'no (the link is not used as the fallback DNS route)'],
    ]);
    ui.line();
    ui.line('`openp2s connect` applies these through systemd-resolved unless --no-dns is used.');

    if (domains.length === 0) {
      // The Private Link trap, and the reason `doctor` treats it as a finding:
      // resolvectl only sends a query to a link's servers when a routing
      // domain matches it, so servers with no domains receive nothing.
      ui.line();
      ui.warn('this profile sets DNS servers but no routing domains');
      ui.hint('Those servers will receive no queries unless --dns-domain or --dns-all is given.');
    }
  } else {
    ui.line('This profile specifies no DNS servers; system resolution is left unchanged.');
  }

  // ---- what this machine resolved ----------------------------------------
  ui.line();
  ui.heading('Local environment');
  ui.line();

  // CA resolution can fail, but inspect should still be useful when it does.
  try {
    const ca = resolveCaPath(options.ca);
    ui.fields([
      ['CA certificate', ca.path],
      [
        'CA scope',
        ca.pinned
          ? 'pinned to a single root certificate'
          : // Not a claim about the trust store's contents: OpenP2S only looked
            // for a standalone PEM at known paths. The root is very likely
            // inside the bundle.
            'system trust bundle',
      ],
    ]);
  } catch (error) {
    ui.warn(error instanceof Error ? error.message : String(error));
  }

  if (options.showCompat) {
    const binary = locateBinary(context, options, ui);

    ui.line();
    ui.heading('Azure compatibility');
    ui.line();
    ui.fields(describeAzureCompat(binary).map(([label, value]) => [`  ${label}`, value]));

    ui.line();
    ui.heading(options.openvpnBinary ? 'OpenVPN binary' : 'Default OpenVPN binary');
    ui.line();
    if (binary) {
      ui.fields([
        ['  Path', binary.path],
        ['  Upstream', binary.upstreamVersion ?? 'unknown'],
        ['  Commit', binary.upstreamCommit ?? 'unknown'],
        // Not build trivia: a USER_PASS_LEN of 128 truncates the Entra token,
        // which is the single failure this whole project exists to fix. It is
        // the first thing to ask for in a bug report.
        ['  USER_PASS_LEN', String(binary.userPassLen)],
        ['  Patch stack', binary.patchStack ?? 'unknown'],
        ['  Patch sha256', binary.patchSha256 ?? 'unknown'],
        ['  Binary sha256', binary.binarySha256 ?? 'unknown'],
      ]);
    }
  }

  return 0;
}

/** Locate the binary without making a missing one fatal to `inspect`. */
function locateBinary(
  context: ReturnType<typeof createContext>,
  options: InspectOptions,
  ui: ReturnType<typeof createContext>['ui'],
): ReturnType<typeof locateOpenVpnBinary> | undefined {
  try {
    return locateOpenVpnBinary({
      repoRoot: context.repoRoot,
      ...(options.openvpnBinary ? { override: options.openvpnBinary } : {}),
    });
  } catch (error) {
    ui.warn(error instanceof Error ? error.message : String(error));
    return undefined;
  }
}
