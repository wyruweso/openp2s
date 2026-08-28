/**
 * `openp2s connect <profile.xml>`
 *
 * Runs in the foreground and owns the tunnel: Ctrl+C disconnects cleanly.
 * A second terminal can query it with `openp2s status` or shut it down with
 * `openp2s disconnect`, via the session record in the runtime directory.
 */

import { OpenP2SError } from '../../errors.ts';
import {
  PINNED_ROOT_HINT,
  PINNED_ROOT_MESSAGE,
  pinnedRootSupport,
  resolveCaPath,
} from '../../openvpn/ca.ts';
import { locateOpenVpnBinary } from '../../openvpn/binary.ts';
import { isSystemdResolvedActive } from '../../network/systemdResolved.ts';
import { ConnectionLock } from '../../platform/lock.ts';
import { ensurePrivateDir } from '../../platform/paths.ts';
import { Connection } from '../connection.ts';
import {
  createAuthenticator,
  createContext,
  createDnsConfigurator,
  loadProfile,
  type GlobalOptions,
} from '../context.ts';
import type { Ui } from '../ui.ts';

/**
 * What `openp2s disconnect` returns for the same state; the two must agree.
 *
 * Wins over the "tunnel died" code below: that the connection is gone is
 * visible anyway, that something is still running is not.
 */
const TEARDOWN_INCOMPLETE_EXIT = 5;

/** The individual problems are already reported through `onWarning`. */
function reportResidue(ui: Ui): void {
  ui.line();
  ui.warn(
    'the disconnect did not finish; the session record is kept so the cleanup can be retried',
  );
  ui.hint('Run `openp2s disconnect` again, or `openp2s status` to see what remains.');
}

export interface ConnectOptions extends GlobalOptions {
  readonly ca?: string;
  readonly clientId?: string;
  readonly scope?: string;
  readonly openvpnBinary?: string;
  /**
   * Proceed with an OpenVPN whose capabilities cannot be established.
   *
   * Without BUILDINFO beside it, OpenP2S cannot know its USER_PASS_LEN, and a
   * stock build truncates the Entra token silently.
   */
  readonly allowUnsupportedOpenvpn?: boolean;
  /**
   * Accept the system trust store for a profile that asked for a pinned root.
   *
   * A deliberate downgrade of the profile's trust policy, so it must be asked
   * for; it is never inferred.
   */
  readonly allowSystemTrustStore?: boolean;
  readonly timeout?: number;
  readonly noDns?: boolean;
  /**
   * Send the Azure OCC string and peer-info.
   *
   * Off by default: measurement against a live gateway showed only the patch's
   * buffer sizes are required. See README.md.
   */
  readonly azureCompat?: boolean;
  /** Route every DNS query over the VPN. Explicit request only. */
  readonly dnsAll?: boolean;
  readonly dnsDomains?: readonly string[];
  readonly verifyName?: string;
}

export async function connectCommand(
  profilePath: string,
  options: ConnectOptions = {},
): Promise<number> {
  const context = createContext(options);
  const { paths } = context;

  // Refuse to stack a second tunnel on top of a live one. Two openvpn
  // processes fighting over tun0 and the DNS link is not a state worth
  // supporting.
  //
  // Taken atomically, before anything else: reading the session record and
  // then deciding is a race, and two simultaneous connects would both see
  // "nothing running" and both proceed.
  ensurePrivateDir(paths.runtimeDir);
  const lock = new ConnectionLock(paths.lockFile);
  const acquisition = await lock.acquire();

  if (!acquisition.acquired) {
    const existing = await context.session.read();
    const where = existing ? ` to ${existing.gateway}` : '';
    const since = acquisition.heldBy ? ` since ${acquisition.heldBy.acquiredAt}` : '';
    throw new OpenP2SError(`already connected${where}${since}`, {
      hint: 'Run: openp2s disconnect',
    });
  }

  // The lock is ours from here on, so every exit path must release it.
  const releaseLock = (): void => lock.release();
  process.once('exit', releaseLock);

  try {
    return await runConnect(context, profilePath, options, lock);
  } catch (error) {
    lock.release();
    throw error;
  }
}

async function runConnect(
  context: ReturnType<typeof createContext>,
  profilePath: string,
  options: ConnectOptions,
  lock: ConnectionLock,
): Promise<number> {
  const { ui, paths } = context;

  // A record left by a crashed run; the lock proved nothing is running.
  if (await context.session.read()) {
    ui.debug('clearing a stale session record');
    await context.session.clear();
  }

  const profile = await loadProfile(profilePath);
  const binary = locateOpenVpnBinary({
    repoRoot: context.repoRoot,
    ...(options.openvpnBinary ? { override: options.openvpnBinary } : {}),
  });
  const ca = resolveCaPath(options.ca);

  // A binary with no BUILDINFO beside it could be anything, including the
  // distribution's own OpenVPN. Its USER_PASS_LEN would then be 128, the
  // token would be truncated, and the gateway would reject a credential that
  // looked fine on this side. Refuse rather than guess.
  if (!binary.provenanceKnown && !options.allowUnsupportedOpenvpn) {
    throw new OpenP2SError(`cannot establish what ${binary.path} is`, {
      hint:
        'No BUILDINFO was found beside it, so its USER_PASS_LEN and patch\n' +
        'stack are unknown. A stock OpenVPN truncates the Entra access token\n' +
        'and the gateway rejects it, which looks like a server fault.\n\n' +
        'Use the binary from scripts/build-openvpn.sh or the openp2s package,\n' +
        'or pass --allow-unsupported-openvpn to try anyway.',
    });
  }

  ui.heading(`Profile: ${profile.name}`);
  ui.fields([
    ['Gateway', profile.gateway],
    ['Authentication', 'Microsoft Entra ID'],
  ]);
  ui.line();

  // The profile asks for a stricter trust policy than this client implements.
  // Connecting anyway would silently substitute a weaker one and report
  // success. `doctor` reports the same profile as a failure; both go through
  // pinnedRootSupport() so they cannot disagree.
  if (pinnedRootSupport(profile, options) === 'unsupported') {
    throw new OpenP2SError(PINNED_ROOT_MESSAGE, { hint: PINNED_ROOT_HINT });
  }
  if (pinnedRootSupport(profile, options) === 'overridden') {
    ui.warn(
      'this profile asks for pinned-root validation; --allow-system-trust-store ' +
        'was given, so the system trust store is used instead',
    );
  }

  if (!ca.pinned) {
    // Not a problem, just less specific: the chain is still verified, against
    // the whole store rather than one pinned root.
    ui.debug(
      `validating against the system CA trust store (${ca.path}) rather than a ` +
        'single pinned root; ensure the system CA certificates are installed and current',
    );
  }

  // Should not happen with the shipped binary, which carries the patch. See
  // the hint below.
  if (options.azureCompat && !binary.azureCompatAvailable) {
    // The shipped binary always carries the patch, so this should be
    // unreachable in a normal install. It stays because --openvpn-binary can
    // point at anything, and "unknown option" from OpenVPN is a worse message.
    throw new OpenP2SError('--experimental-azure-compat needs an OpenVPN built with that support', {
      hint:
        'The OpenVPN shipped with OpenP2S carries it. This binary does not,\n' +
        'so it was built elsewhere or is an older OpenP2S build.\n\n' +
        'Rebuild with: scripts/build-openvpn.sh',
    });
  }

  // Conflicting or pointless DNS options are a mistake, not a preference.
  if (options.noDns && (options.dnsAll || options.dnsDomains?.length)) {
    throw new OpenP2SError('--no-dns cannot be combined with --dns-all or --dns-domain');
  }
  if ((options.dnsAll || options.dnsDomains?.length) && profile.dnsServers.length === 0) {
    throw new OpenP2SError(
      'this profile specifies no DNS servers, so there is nothing to route queries to',
      {
        hint:
          '--dns-all and --dns-domain choose *which* names go to the VPN resolvers;\n' +
          'they cannot supply the resolvers themselves.',
      },
    );
  }

  const wantsDns = !options.noDns && profile.dnsServers.length > 0;

  // Fail before authenticating rather than after the tunnel is up. DNS
  // configuration is fatal to a connect (the teardown stops OpenVPN), so
  // warning that "the tunnel will still come up" would be untrue - and for
  // an Azure Private Link profile a tunnel without its DNS is the exact
  // failure mode this client exists to avoid.
  if (wantsDns && !(await isSystemdResolvedActive(context.runner))) {
    throw new OpenP2SError('systemd-resolved is not active, but this profile requires split DNS', {
      hint:
        'The profile supplies DNS servers, and without systemd-resolved they\n' +
        'cannot be applied. Private names would resolve through your public\n' +
        'resolver, which is what breaks Azure Private Link.\n\n' +
        'Start it:      sudo systemctl enable --now systemd-resolved\n' +
        'Or connect without DNS configuration:  openp2s connect <profile> --no-dns',
    });
  }

  if (!context.elevator.isRoot) {
    ui.debug(context.elevator.describe());
  }

  const authenticator = createAuthenticator(context, profile, {
    ...(options.clientId ? { clientId: options.clientId } : {}),
    ...(options.scope ? { scope: options.scope } : {}),
  });

  const connection = new Connection({
    profile,
    paths,
    binary,
    caPath: ca.path,
    authenticator,
    dns: createDnsConfigurator(context),
    elevator: context.elevator,
    connectTimeoutMs: (options.timeout ?? 90) * 1000,
    verb: ui.isVerbose ? 4 : 3,
    ...(options.verifyName ? { verifyName: options.verifyName } : {}),
    ...(options.azureCompat ? { azureCompat: true } : {}),
    ...(options.noDns ? { skipDns: true } : {}),
    ...(options.dnsAll ? { dnsAllDomains: true } : {}),
    ...(options.dnsDomains ? { extraDnsDomains: options.dnsDomains } : {}),
    credentialLimits: { userPassLen: binary.userPassLen },
    events: {
      onAuthenticated: (outcome) => {
        ui.ok(
          outcome.fromCache
            ? `Authenticated using cached Entra session${outcome.account ? ` (${outcome.account})` : ''}`
            : `Authenticated${outcome.account ? ` as ${outcome.account}` : ''}`,
        );
      },
      onTunnelUp: (details) => {
        ui.ok('Azure VPN gateway certificate verified');
        ui.ok('VPN connected');
        if (details.assignedAddress) {
          ui.ok(`Assigned ${details.assignedAddress}`);
        }
        if (details.pushedRoutes.length > 0) {
          ui.ok(
            `Installed ${details.pushedRoutes.length} Azure route${details.pushedRoutes.length === 1 ? '' : 's'}`,
          );
        }
      },
      onDnsConfigured: () =>
        ui.ok(options.dnsAll ? 'Configured VPN-wide DNS (~.)' : 'Configured split DNS'),
      onWarning: (message) => ui.warn(message),
      onLogLine: (line) => ui.debug(line),
    },
  });

  // Signal handling is installed before connect() so that Ctrl+C during the
  // device-code wait tears down just as cleanly as Ctrl+C once connected.
  let shuttingDown = false;
  const shutdown = (signal: NodeJS.Signals): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    ui.line();
    ui.line(`Received ${signal}, disconnecting...`);
    void connection
      .disconnect()
      .then(() => {
        lock.release();
        if (connection.hasResidue) {
          reportResidue(ui);
          process.exit(TEARDOWN_INCOMPLETE_EXIT);
        }
        ui.ok('Disconnected');
        process.exit(0);
      })
      .catch(() => {
        lock.release();
        process.exit(1);
      });
  };

  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  process.once('SIGHUP', shutdown);

  const record = await connection.connect();

  ui.line();
  ui.heading('Connected');
  ui.fields([
    ['Interface', record.interfaceName ?? 'unknown'],
    ['Address', record.assignedAddress ?? 'unknown'],
    ['DNS servers', record.dnsServers.length > 0 ? [...record.dnsServers] : undefined],
    [
      'DNS domains',
      record.dnsDomains.length > 0 ? record.dnsDomains.map((d) => `~${d}`) : undefined,
    ],
  ]);
  ui.line();
  ui.line('Press Ctrl+C to disconnect.');

  // Hold the foreground until openvpn exits, whether that is because the user
  // pressed Ctrl+C, another terminal ran `openp2s disconnect`, or the gateway
  // dropped us.
  const exit = await connection.waitForExit();
  if (shuttingDown) {
    return 0;
  }

  // `openp2s disconnect` stamps the session record before it signals OpenVPN,
  // so a requested shutdown can be told apart from the tunnel dying. Without
  // that, a perfectly normal disconnect from another terminal would be
  // reported here as a failure.
  const finalRecord = await context.session.read();
  const requested = Boolean(finalRecord?.disconnectRequestedAt);

  await connection.cleanup();
  lock.release();

  if (requested) {
    if (connection.hasResidue) {
      reportResidue(ui);
      return TEARDOWN_INCOMPLETE_EXIT;
    }
    ui.line();
    ui.ok('Disconnected');
    return 0;
  }

  ui.line();
  ui.warn(
    exit.signal
      ? `openvpn terminated unexpectedly on ${exit.signal}`
      : `openvpn exited unexpectedly with code ${exit.code ?? 'unknown'}`,
  );
  if (connection.hasResidue) {
    reportResidue(ui);
    return TEARDOWN_INCOMPLETE_EXIT;
  }
  ui.ok('Cleaned up');
  // An unrequested loss of the tunnel is a failure even if OpenVPN happened
  // to exit cleanly: the connection the user asked for is gone.
  return 4;
}
