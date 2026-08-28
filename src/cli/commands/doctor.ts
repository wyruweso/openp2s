/**
 * `openp2s doctor [profile.xml]`
 *
 * Checks the things that break an Azure P2S connection, in the order they
 * break, and says what to do about each.
 *
 * The DNS checks earn their place. A tunnel can be completely healthy -
 * authenticated, routed, pingable - while Azure Virtual Desktop still fails
 * with "Access is forbidden from this network", because the name resolved
 * through public DNS to a public endpoint. That failure looks like a VPN
 * problem and is not one, and it is exactly what this command is for.
 *
 * Read-only. Nothing here changes system state.
 */

import { existsSync } from 'node:fs';
import { PINNED_ROOT_MESSAGE, pinnedRootSupport, resolveCaPath } from '../../openvpn/ca.ts';
import { locateOpenVpnBinary } from '../../openvpn/binary.ts';
import { isSystemdResolvedActive } from '../../network/systemdResolved.ts';
import { toRoutingDomain } from '../../network/dns.ts';
import { isProcessAlive } from '../../platform/session.ts';
import type { AzureVpnProfile } from '../../profile/types.ts';
import { createContext, loadProfile, type CommandContext, type GlobalOptions } from '../context.ts';

export interface DoctorOptions extends GlobalOptions {
  readonly ca?: string;
  /**
   * A hostname the caller expects to resolve privately through the VPN.
   *
   * There is no way to derive a real hostname from a DNS suffix, and
   * hardcoding one from a particular Azure Virtual Desktop deployment would
   * be wrong for a general Azure P2S client. So the check exists, and the
   * caller supplies the name.
   */
  readonly dnsProbe?: string;
}

export type Status = 'ok' | 'warn' | 'fail' | 'skip';

export interface Check {
  readonly status: Status;
  readonly label: string;
  readonly detail?: string | undefined;
  readonly fix?: string | undefined;
}

const MARK: Record<Status, string> = { ok: '✓', warn: '!', fail: '✗', skip: '-' };

function render(context: CommandContext, checks: readonly Check[]): void {
  const { ui } = context;
  for (const check of checks) {
    const line = `${MARK[check.status]} ${check.label}${check.detail ? ` (${check.detail})` : ''}`;
    if (check.status === 'ok') ui.ok(line.slice(2));
    else if (check.status === 'warn') ui.warn(line.slice(2));
    else if (check.status === 'fail') ui.error(line.slice(2));
    else ui.line(`${MARK.skip} ${check.label}${check.detail ? ` (${check.detail})` : ''}`);

    if (check.fix) ui.hint(`    ${check.fix}`);
  }
}

/**
 * Ask systemd-resolved what it currently has on a link.
 *
 * LC_ALL=C so the field labels this parses are not translated. Reading a
 * human-readable CLI is fragile enough without a locale changing the words.
 */
async function resolvectlStatus(
  context: CommandContext,
  interfaceName: string,
): Promise<string | undefined> {
  try {
    const result = await context.runner.run('resolvectl', ['status', interfaceName], {
      timeoutMs: 5_000,
      env: { LC_ALL: 'C', LANG: 'C' },
    });
    return result.code === 0 ? result.stdout : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Pull a multi-line field out of `resolvectl status` output.
 *
 * Values wrap onto continuation lines indented under the label, which is how
 * several DNS servers or domains are shown, so a single-line regex would see
 * only the first one.
 */
export function parseResolvectlField(status: string, label: string): string[] {
  const lines = status.split('\n');
  const start = lines.findIndex((line) => new RegExp(`^\\s*${label}\\s*:`, 'i').test(line));
  if (start === -1) return [];

  const first = lines[start]?.split(':').slice(1).join(':') ?? '';
  const values = first.trim().split(/\s+/).filter(Boolean);

  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    // A continuation line is indented and carries no "Label:" of its own.
    if (!/^\s+\S/.test(line) || /^\s*[A-Z][A-Za-z ]*:/.test(line)) break;
    values.push(...line.trim().split(/\s+/).filter(Boolean));
  }
  return values;
}

/** Is this interface present on the system? */
async function interfaceExists(
  context: CommandContext,
  interfaceName: string,
): Promise<boolean | undefined> {
  try {
    const result = await context.runner.run('ip', ['link', 'show', 'dev', interfaceName], {
      timeoutMs: 5_000,
      env: { LC_ALL: 'C' },
    });
    return result.code === 0;
  } catch {
    // `ip` missing: we cannot tell, which is not the same as "absent".
    return undefined;
  }
}

async function environmentChecks(
  context: CommandContext,
  options: DoctorOptions,
  /** True when a profile was given and it actually needs split DNS. */
  dnsRequired: boolean | undefined,
): Promise<Check[]> {
  const checks: Check[] = [];

  if (await isSystemdResolvedActive(context.runner)) {
    checks.push({ status: 'ok', label: 'systemd-resolved is active' });
  } else {
    // Only a failure when something actually needs it: a profile with no DNS
    // servers, or --no-dns, connects perfectly well without it.
    checks.push({
      status: dnsRequired === true ? 'fail' : 'warn',
      label: 'systemd-resolved is not active',
      detail:
        dnsRequired === true ? 'this profile requires split DNS' : 'DNS integration unavailable',
      fix:
        dnsRequired === true
          ? 'Enable it, or connect with --no-dns and accept that private names\n' +
            '    may resolve through your public resolver:\n' +
            '    sudo systemctl enable --now systemd-resolved'
          : 'Needed only for profiles that supply DNS servers.',
    });
  }

  checks.push(
    existsSync('/dev/net/tun')
      ? { status: 'ok', label: '/dev/net/tun is available' }
      : {
          status: 'fail',
          label: '/dev/net/tun is missing',
          fix: 'Load the tun module: sudo modprobe tun',
        },
  );

  try {
    const ca = resolveCaPath(options.ca);
    checks.push(
      ca.pinned
        ? { status: 'ok', label: 'DigiCert Global Root G2 is available', detail: ca.path }
        : {
            status: 'warn',
            label: 'using the whole system CA bundle',
            detail: ca.path,
            fix: "Install or update your distribution's CA certificates package.",
          },
    );
  } catch (error) {
    checks.push({
      status: 'fail',
      label: 'no system CA store found',
      detail: error instanceof Error ? error.message : undefined,
      fix: "Install your distribution's CA certificates package.",
    });
  }

  try {
    const binary = locateOpenVpnBinary({ repoRoot: context.repoRoot });
    checks.push({
      status: 'ok',
      label: 'OpenP2S OpenVPN binary is built',
      detail: `${binary.upstreamVersion ?? '?'} + ${binary.patchStack ?? 'patch'}`,
    });
  } catch (error) {
    checks.push({
      status: 'fail',
      label: 'OpenP2S OpenVPN binary is not built',
      detail: error instanceof Error ? error.message.split('\n')[0] : undefined,
      fix: 'scripts/build-openvpn.sh',
    });
  }

  return checks;
}

async function profileChecks(context: CommandContext, profile: AzureVpnProfile): Promise<Check[]> {
  const checks: Check[] = [];

  // This proves only that the gateway hostname currently resolves. It says
  // nothing about whether the tenant, audience or serversecret are still valid.
  try {
    const { lookup } = await import('node:dns/promises');
    await lookup(profile.gateway);
    checks.push({ status: 'ok', label: 'gateway hostname resolves', detail: profile.gateway });
  } catch {
    checks.push({
      status: 'fail',
      label: 'gateway hostname does not resolve',
      detail: profile.gateway,
      fix: 'Check your internet connection, or re-export the profile.',
    });
  }

  if (pinnedRootSupport(profile) === 'unsupported') {
    // The profile asks for a stricter trust policy than OpenP2S implements.
    // Silently applying a weaker one, and calling it a warning, would be the
    // wrong side of a security boundary to be relaxed on. `connect` refuses
    // the same profile, through the same predicate.
    checks.push({
      status: 'fail',
      label: PINNED_ROOT_MESSAGE,
      fix:
        'OpenP2S validates against the system trust store, which is weaker than\n' +
        '    what the profile asks for. Pass --allow-system-trust-store to connect\n' +
        '    anyway, accepting that policy.',
    });
  }

  if (profile.dnsServers.length === 0) {
    checks.push({
      status: 'warn',
      label: 'profile specifies no DNS servers',
      fix: 'Private names will resolve through your normal resolver.',
    });
  } else if (profile.dnsSuffixes.length === 0) {
    // The Private Link trap.
    checks.push({
      status: 'warn',
      label: 'profile has DNS servers but no DNS suffixes',
      detail: 'nothing would be routed to them',
      fix:
        'Private Link names may resolve to public addresses through your public DNS.\n' +
        '    Use --dns-domain <suffix>, or --dns-all to route every query over the VPN.',
    });
  } else {
    checks.push({
      status: 'ok',
      label: 'profile has DNS servers and suffixes',
      detail: profile.dnsSuffixes.map(toRoutingDomain).join(' '),
    });
  }

  return checks;
}

/**
 * Checks that only make sense while connected.
 *
 * The important one is the last: corporate DNS attached to the link with no
 * routing domains is the silent Private Link failure.
 */
export async function liveChecks(
  context: CommandContext,
  profile: AzureVpnProfile | undefined,
  dnsProbe: string | undefined,
): Promise<Check[]> {
  const checks: Check[] = [];
  const record = await context.session.read();

  if (!record) {
    checks.push({ status: 'skip', label: 'not connected' });
    return checks;
  }

  if (!isProcessAlive(record.openvpnPid, record.openvpnStartTime)) {
    // Worth distinguishing from "not connected": there is state to clean up.
    checks.push({
      status: 'warn',
      label: 'a session record remains but its OpenVPN is gone',
      detail: record.gateway,
      fix: 'openp2s disconnect   (removes the record and any leftover artifacts)',
    });
    return checks;
  }

  const interfaceName = record.interfaceName;
  if (!interfaceName) {
    checks.push({ status: 'warn', label: 'connected but no interface was recorded' });
    return checks;
  }

  // Actually look for the interface. A live OpenVPN process is not proof that
  // its tun device exists: it may be restarting, or the device may have been
  // torn down underneath it.
  const present = await interfaceExists(context, interfaceName);
  if (present === true) {
    checks.push({
      status: 'ok',
      label: 'VPN interface exists',
      detail: `${interfaceName} ${record.assignedAddress ?? ''}`.trim(),
    });
  } else if (present === false) {
    checks.push({
      status: 'fail',
      label: `${interfaceName} does not exist, although OpenVPN is running`,
      fix: 'The tunnel is not usable. Reconnect: openp2s disconnect && openp2s connect <profile>',
    });
    return checks;
  } else {
    checks.push({
      status: 'warn',
      label: `could not check whether ${interfaceName} exists`,
      detail: 'the `ip` command is unavailable',
    });
  }

  if (record.dnsServers.length === 0) {
    checks.push({ status: 'skip', label: 'no DNS was configured for this connection' });
    return checks;
  }

  const status = await resolvectlStatus(context, interfaceName);
  if (!status) {
    checks.push({
      status: 'warn',
      label: `could not read resolvectl status for ${interfaceName}`,
    });
    return checks;
  }

  // ---- servers: compare against what we asked for ------------------------
  const actualServers = parseResolvectlField(status, 'DNS Servers');
  const missingServers = record.dnsServers.filter((server) => !actualServers.includes(server));

  if (actualServers.length === 0) {
    checks.push({
      status: 'fail',
      label: 'no DNS servers on the VPN interface',
      fix: `sudo resolvectl dns ${interfaceName} ${record.dnsServers.join(' ')}`,
    });
  } else if (missingServers.length > 0) {
    // Something is attached, but not what the profile asked for. A green tick
    // on "some DNS exists" would hide exactly this.
    checks.push({
      status: 'fail',
      label: 'the VPN interface has different DNS servers than the profile requires',
      detail: `expected ${record.dnsServers.join(' ')}, found ${actualServers.join(' ')}`,
      fix: `sudo resolvectl dns ${interfaceName} ${record.dnsServers.join(' ')}`,
    });
  } else {
    checks.push({
      status: 'ok',
      label: "the profile's DNS servers are attached to the VPN interface",
      detail: actualServers.join(' '),
    });
  }

  // ---- domains: compare against what we asked for ------------------------
  const actualDomains = parseResolvectlField(status, 'DNS Domain');
  const routesEverything = actualDomains.includes('~.');
  const expectedDomains = record.dnsDomains.map((domain) =>
    domain === '.' ? '~.' : `~${domain.replace(/^~/, '')}`,
  );
  const missingDomains = expectedDomains.filter((domain) => !actualDomains.includes(domain));

  if (actualDomains.length === 0) {
    checks.push({
      status: 'fail',
      label: 'DNS routing domains are not installed',
      fix:
        `Corporate DNS is configured on ${interfaceName}, but nothing is routed to\n` +
        '    it, so private names still resolve through your public resolver.\n' +
        `    Fix: sudo resolvectl domain ${interfaceName} ${expectedDomains.join(' ')}`,
    });
  } else if (missingDomains.length > 0 && !routesEverything) {
    checks.push({
      status: 'fail',
      label: 'the expected DNS routing domains are not installed',
      detail: `expected ${expectedDomains.join(' ')}, found ${actualDomains.join(' ')}`,
      fix: `sudo resolvectl domain ${interfaceName} ${expectedDomains.join(' ')}`,
    });
  } else {
    checks.push({
      status: 'ok',
      label: 'the expected DNS routing domains are installed',
      detail: actualDomains.join(' '),
    });
  }

  // ---- scope: ~. and DefaultRoute are different things -------------------
  const defaultRoute = parseResolvectlField(status, 'Default Route')[0]?.toLowerCase();

  if (routesEverything) {
    // `~.` makes this link preferred for every name not claimed by a more
    // specific routing domain — regardless of DefaultRoute.
    checks.push({
      status: record.dnsDomains.includes('.') ? 'ok' : 'warn',
      label: 'every DNS name is routed to the VPN resolvers (~.)',
      detail: record.dnsDomains.includes('.') ? 'requested with --dns-all' : 'not requested',
      ...(record.dnsDomains.includes('.')
        ? {}
        : { fix: 'Reconnect without --dns-all to restrict the VPN to the profile suffixes.' }),
    });
  } else if (defaultRoute === 'no') {
    checks.push({
      status: 'ok',
      label: 'the VPN is not eligible as the default DNS route',
    });
  } else {
    checks.push({
      status: 'warn',
      label: 'the VPN interface is eligible as the default DNS route',
      detail: `Default Route: ${defaultRoute ?? 'unknown'}`,
      fix:
        'Names matching no other routing domain may go to the VPN resolvers.\n' +
        `    Fix: sudo resolvectl default-route ${interfaceName} no`,
    });
  }

  // ---- can the interface resolve at all? --------------------------------
  if (profile) {
    try {
      const result = await context.runner.run(
        'resolvectl',
        ['query', '--interface', interfaceName, profile.gateway],
        { timeoutMs: 8_000, env: { LC_ALL: 'C' } },
      );
      checks.push(
        result.code === 0
          ? {
              status: 'ok',
              // Deliberately modest: the gateway is a public name that any
              // resolver can answer. This shows the link resolves, not that
              // Private Link names resolve privately.
              label: 'DNS resolution through the VPN interface works',
            }
          : {
              status: 'warn',
              label: 'a DNS query through the VPN interface failed',
              detail: result.stderr.trim().split('\n')[0],
            },
      );
    } catch {
      checks.push({ status: 'warn', label: 'could not query DNS through the VPN interface' });
    }
  }

  // ---- the check that actually proves Private Link works -----------------
  if (dnsProbe) {
    try {
      const result = await context.runner.run(
        'resolvectl',
        ['query', '--interface', interfaceName, dnsProbe],
        { timeoutMs: 8_000, env: { LC_ALL: 'C' } },
      );
      const answer = result.stdout.trim().split('\n')[0] ?? '';
      const isPrivate = /\b(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(answer);
      checks.push({
        status: result.code === 0 && isPrivate ? 'ok' : 'warn',
        label: `${dnsProbe} resolves through the VPN`,
        detail: answer.slice(0, 120),
        ...(result.code === 0 && isPrivate
          ? {}
          : {
              fix:
                'It did not resolve to a private address. For Azure Private Link\n' +
                '    that usually means the query is being answered publicly.',
            }),
      });
    } catch {
      checks.push({ status: 'warn', label: `could not resolve ${dnsProbe}` });
    }
  }

  return checks;
}

export async function doctorCommand(
  profilePath: string | undefined,
  options: DoctorOptions = {},
): Promise<number> {
  const context = createContext(options);
  const { ui } = context;
  const all: Check[] = [];

  ui.heading('OpenP2S doctor');

  // ---- environment -----------------------------------------------------
  ui.line();
  ui.heading('Environment');
  // Whether DNS matters depends on the profile, so load it first.
  let profile: AzureVpnProfile | undefined;
  let profileError: unknown;
  if (profilePath) {
    try {
      profile = await loadProfile(profilePath);
    } catch (error) {
      profileError = error;
    }
  }
  const dnsRequired = profile ? profile.dnsServers.length > 0 : undefined;

  const environment = await environmentChecks(context, options, dnsRequired);
  render(context, environment);
  all.push(...environment);

  // ---- profile ----------------------------------------------------------
  if (profilePath) {
    const results: Check[] = profile
      ? await profileChecks(context, profile)
      : [
          {
            status: 'fail',
            label: 'profile could not be parsed',
            detail: profileError instanceof Error ? profileError.message : undefined,
          },
        ];
    ui.line();
    ui.heading(profile ? `Profile: ${profile.name}` : 'Profile');
    render(context, results);
    all.push(...results);
  }

  // ---- live connection --------------------------------------------------
  ui.line();
  ui.heading('Connection');
  const live = await liveChecks(context, profile, options.dnsProbe);
  render(context, live);
  all.push(...live);

  const failures = all.filter((check) => check.status === 'fail').length;
  const warnings = all.filter((check) => check.status === 'warn').length;

  ui.line();
  if (failures > 0) {
    ui.error(`${failures} problem${failures === 1 ? '' : 's'} found.`);
    return 1;
  }
  if (warnings > 0) {
    ui.warn(`${warnings} warning${warnings === 1 ? '' : 's'}.`);
    return 0;
  }
  ui.ok('Everything checks out.');
  return 0;
}
