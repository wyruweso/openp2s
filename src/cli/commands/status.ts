/**
 * `openp2s status`
 *
 * Reports on the tunnel from any terminal, by reading the session record.
 *
 * ## The session record is not the output
 *
 * `SessionRecord` is internal recovery state: it holds the paths teardown has
 * to remove, the owner pid, and whatever else a future version needs. Spreading
 * it into `--json` would make every field a public API by accident - a new
 * internal field would appear in users' scripts, and could not be removed
 * again. So the JSON is an explicit projection, `StatusResult`, and that is
 * the stable contract.
 *
 * ## "Connected" is a claim that has to be earned
 *
 * A live pid alone does not mean a working tunnel: OpenVPN survives a dropped
 * gateway connection and sits in a reconnect loop. So the state is derived
 * from three observations - is the process the one we started, does its
 * interface still exist, and has a disconnect been requested - rather than
 * from the first of them alone.
 *
 * Exit codes: 0 connected, 1 anything else. That makes
 * `if openp2s status >/dev/null; then ...` mean what it looks like.
 */

import { existsSync } from 'node:fs';
import { isProcessAlive } from '../../platform/session.ts';
import type { SessionRecord } from '../../platform/session.ts';
import { createContext, type GlobalOptions } from '../context.ts';

export interface StatusOptions extends GlobalOptions {
  readonly json?: boolean;
}

/**
 * What the tunnel is doing.
 *
 * - `connected`      process alive, interface present, no disconnect pending
 * - `disconnecting`  a disconnect was requested; the process has not exited yet
 * - `reconnecting`   process alive but its interface is gone
 * - `stale`          a record remains for a process that is no longer running
 * - `disconnected`   no record at all
 */
type ConnectionState = 'connected' | 'disconnecting' | 'reconnecting' | 'stale' | 'disconnected';

/** The stable shape of `openp2s status --json`. */
interface StatusResult {
  readonly connected: boolean;
  readonly state: ConnectionState;
  readonly profile: string | null;
  readonly gateway: string | null;
  readonly interface: string | null;
  readonly address: string | null;
  readonly account: string | null;
  readonly connectedAt: string | null;
  /** A number, so scripts do not have to parse "1h 2m". */
  readonly uptimeSeconds: number | null;
  readonly dnsServers: readonly string[];
  readonly dnsDomains: readonly string[];
  readonly pushedRoutes: readonly string[];
  readonly includeRoutes: readonly string[];
  /** The build that started this tunnel; null for a session written before it was recorded. */
  readonly openvpn: {
    readonly version: string | null;
    readonly commit: string | null;
    readonly patchStack: string | null;
    readonly binarySha256: string | null;
    readonly userPassLen: number | null;
    readonly azureCompatAvailable: boolean | null;
  } | null;
}

function uptimeSeconds(fromIso: string): number | null {
  const started = Date.parse(fromIso);
  if (Number.isNaN(started)) return null;
  return Math.max(0, Math.floor((Date.now() - started) / 1000));
}

function humaniseDuration(seconds: number | null): string {
  if (seconds === null) return 'unknown';

  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

/**
 * Does this interface still exist?
 *
 * Read from sysfs rather than by running `ip`: no subprocess, no root, and no
 * dependence on iproute2 being installed.
 */
function interfaceExists(name: string | undefined): boolean {
  if (!name || !/^[A-Za-z0-9_.-]{1,15}$/.test(name)) return false;
  return existsSync(`/sys/class/net/${name}`);
}

function deriveState(record: SessionRecord): ConnectionState {
  if (!isProcessAlive(record.openvpnPid, record.openvpnStartTime)) return 'stale';
  if (record.disconnectRequestedAt) return 'disconnecting';
  // A tunnel with no interface is a tunnel that is not carrying traffic, even
  // though the process is healthy and will probably recover.
  if (!interfaceExists(record.interfaceName)) return 'reconnecting';
  return 'connected';
}

function project(record: SessionRecord, state: ConnectionState): StatusResult {
  const seconds = uptimeSeconds(record.connectedAt);
  return {
    connected: state === 'connected',
    state,
    profile: record.profileName,
    gateway: record.gateway,
    interface: record.interfaceName ?? null,
    address: record.assignedAddress ?? null,
    account: record.account ?? null,
    connectedAt: record.connectedAt,
    uptimeSeconds: seconds,
    dnsServers: record.dnsServers,
    dnsDomains: record.dnsDomains,
    pushedRoutes: record.pushedRoutes,
    includeRoutes: record.includeRoutes,
    openvpn: record.openvpn
      ? {
          version: record.openvpn.version ?? null,
          commit: record.openvpn.commit ?? null,
          patchStack: record.openvpn.patchStack ?? null,
          binarySha256: record.openvpn.binarySha256 ?? null,
          userPassLen: record.openvpn.userPassLen,
          azureCompatAvailable: record.openvpn.azureCompatAvailable,
        }
      : null,
  };
}

const DISCONNECTED: StatusResult = {
  connected: false,
  state: 'disconnected',
  profile: null,
  gateway: null,
  interface: null,
  address: null,
  account: null,
  connectedAt: null,
  uptimeSeconds: null,
  dnsServers: [],
  dnsDomains: [],
  pushedRoutes: [],
  includeRoutes: [],
  openvpn: null,
};

export async function statusCommand(options: StatusOptions = {}): Promise<number> {
  const context = createContext(options);
  const { ui } = context;

  const record = await context.session.read();
  const result = record ? project(record, deriveState(record)) : DISCONNECTED;

  if (options.json) {
    // stdout carries exactly one JSON document; everything else is stderr.
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result.connected ? 0 : 1;
  }

  switch (result.state) {
    case 'disconnected':
      ui.line('Not connected.');
      return 1;

    case 'stale':
      // The owning process is gone but left a record behind. Do not clear it
      // here: it is the only description of the DNS, credentials and socket
      // that may still need cleaning up.
      ui.line('Not connected.');
      ui.warn(
        `a stale session record for ${result.gateway ?? 'unknown'} remains; ` +
          'run `openp2s disconnect` to clean it up',
      );
      return 1;

    case 'disconnecting':
      ui.heading('Disconnecting');
      ui.line();
      ui.line('A disconnect was requested; OpenVPN has not exited yet.');
      ui.hint('Run `openp2s status` again in a moment, or `openp2s disconnect` to retry.');
      return 1;

    case 'reconnecting':
      ui.heading('Reconnecting');
      ui.line();
      ui.warn(
        `OpenVPN is running, but the interface ${result.interface ?? 'it created'} is gone; ` +
          'the tunnel is not carrying traffic',
      );
      break;

    case 'connected':
      ui.heading('Connected');
      break;
  }

  ui.line();
  ui.fields([
    ['Profile', result.profile ?? 'unknown'],
    ['Gateway', result.gateway ?? 'unknown'],
    ['Interface', result.interface ?? 'unknown'],
    ['Address', result.address ?? 'unknown'],
    ['Account', result.account ?? 'unknown'],
    ['Uptime', humaniseDuration(result.uptimeSeconds)],
    ['DNS servers', [...result.dnsServers]],
    ['DNS domains', result.dnsDomains.map((domain) => `~${domain}`)],
    ['Pushed routes', [...result.pushedRoutes]],
    ['Include routes', [...result.includeRoutes]],
  ]);

  if (ui.isVerbose) {
    ui.line();
    if (result.openvpn) {
      // From the session record, so this is the build that is actually
      // running - not whatever locateOpenVpnBinary() would find now.
      ui.fields([
        ['OpenVPN', result.openvpn.version ?? 'unknown'],
        ['Commit', result.openvpn.commit ?? 'unknown'],
        ['Patch stack', result.openvpn.patchStack ?? 'unknown'],
        [
          'USER_PASS_LEN',
          result.openvpn.userPassLen === null ? 'unknown' : String(result.openvpn.userPassLen),
        ],
        [
          'Azure compat',
          result.openvpn.azureCompatAvailable === null
            ? 'unknown'
            : result.openvpn.azureCompatAvailable
              ? 'available in this build'
              : 'not available in this build',
        ],
        ['Binary sha256', result.openvpn.binarySha256 ?? 'unknown'],
      ]);
    } else {
      ui.debug('this session predates OpenVPN provenance recording');
    }
  }

  return result.connected ? 0 : 1;
}
