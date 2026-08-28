/**
 * The one teardown policy.
 *
 * Both paths that take a connection down - Ctrl+C in a foreground `connect`,
 * and `openp2s disconnect` from another terminal - go through this. Two
 * implementations would drift, and the one that drifted would be the one
 * nobody exercised.
 *
 * The order matters:
 *
 *   1. stop OpenVPN
 *   2. only once it is confirmed gone, revert DNS
 *   3. only once it is confirmed gone, remove runtime artifacts
 *
 * Nothing a live OpenVPN might still need is taken from it. Reverting DNS
 * early sends private names to the public resolver over a live link; removing
 * the socket or credentials leaves a running process unreachable, and destroys
 * what a retry needs. That state is reported as `complete: false` so the
 * caller keeps the session record.
 *
 * Nothing here throws. Teardown runs from signal handlers and from failure
 * paths, where an exception would abandon the remaining steps. Problems are
 * reported in the result instead, and the caller decides what to do - in
 * particular whether it is safe to forget the session record.
 */

import { unlink } from 'node:fs/promises';
import { describeError } from '../errors.ts';
import type { DnsConfigurator } from '../network/dns.ts';
import { isProcessAlive } from '../platform/lock.ts';

/** Everything a teardown may need to undo. */
export interface TeardownTargets {
  readonly openvpnPid?: number | undefined;
  /** Carried through every liveness check, so a recycled pid is not signalled. */
  readonly openvpnStartTime?: number | undefined;
  readonly interfaceName?: string | undefined;
  /** Whether DNS was actually configured, and so needs reverting. */
  readonly dnsConfigured?: boolean;
  /** Files and sockets to remove. Missing ones are not a problem. */
  readonly artifacts?: ReadonlyArray<{ readonly label: string; readonly path: string }>;
}

export interface TeardownOptions {
  readonly dns: DnsConfigurator;
  /** How long OpenVPN gets to exit on SIGTERM before SIGKILL. */
  readonly graceMs?: number;
  /**
   * Stop the tunnel, returning whether it is confirmed gone. For a caller that
   * owns the child and learns of its exit directly; wins over `signal`.
   */
  readonly stopTunnel?: () => Promise<boolean>;
  /** For a process we did not spawn - `openp2s disconnect` from elsewhere. */
  readonly signal?: (pid: number, signal: 'SIGTERM' | 'SIGKILL') => Promise<void>;
  readonly onProgress?: (message: string) => void;
  readonly onWarning?: (message: string) => void;
}

export interface TeardownResult {
  /** True when no OpenVPN was running, or it is now confirmed gone. */
  readonly tunnelStopped: boolean;
  readonly dnsReverted: boolean;
  /** Artifacts that could not be removed and are still on disk. */
  readonly residue: string[];
  readonly problems: string[];
  /** False whenever anything is unresolved: the record must then be kept. */
  readonly complete: boolean;
}

const DEFAULT_GRACE_MS = 5_000;
const POLL_MS = 100;

/** Stop a process, escalating to SIGKILL, without ever signalling a stranger. */
async function stopProcess(
  pid: number,
  startTime: number | undefined,
  graceMs: number,
  signal: TeardownOptions['signal'],
): Promise<boolean> {
  // A process that is already gone is stopped, whether or not we were given a
  // way to signal it.
  if (!isProcessAlive(pid, startTime)) return true;
  if (!signal) return false;

  try {
    await signal(pid, 'SIGTERM');
  } catch {
    // The send failed; the liveness check below decides the outcome.
  }

  const deadline = Date.now() + graceMs;
  while (Date.now() < deadline) {
    if (!isProcessAlive(pid, startTime)) return true;
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }

  // Re-check immediately before escalating: this is the exact window in which
  // the pid can have been released and handed to something else.
  if (!isProcessAlive(pid, startTime)) return true;

  // Without a start time we cannot tell our process from one that inherited
  // its pid. SIGTERM to a stranger is survivable; SIGKILL is not.
  if (startTime === undefined) return false;

  try {
    await signal(pid, 'SIGKILL');
  } catch {
    // Nothing further to try.
  }

  await new Promise((resolve) => setTimeout(resolve, 2 * POLL_MS));
  return !isProcessAlive(pid, startTime);
}

/** Take a connection down. Never throws. */
export async function teardownConnection(
  targets: TeardownTargets,
  options: TeardownOptions,
): Promise<TeardownResult> {
  const problems: string[] = [];
  const residue: string[] = [];
  const note = (message: string): void => {
    problems.push(message);
    options.onWarning?.(message);
  };

  // ---- 1. stop OpenVPN --------------------------------------------------
  let tunnelStopped = true;
  const stoppable = options.stopTunnel !== undefined || targets.openvpnPid !== undefined;

  if (stoppable) {
    try {
      tunnelStopped = options.stopTunnel
        ? await options.stopTunnel()
        : await stopProcess(
            targets.openvpnPid as number,
            targets.openvpnStartTime,
            options.graceMs ?? DEFAULT_GRACE_MS,
            options.signal,
          );
    } catch (error) {
      tunnelStopped = false;
      note(`could not stop openvpn: ${describeError(error)}`);
    }

    if (tunnelStopped) {
      options.onProgress?.('Stopped OpenVPN');
    } else {
      note(
        `could not stop openvpn${targets.openvpnPid !== undefined ? ` (pid ${targets.openvpnPid})` : ''};` +
          ' it may still be running',
      );
    }
  }

  // ---- 2. revert DNS, only once the tunnel is confirmed gone -------------
  let dnsReverted = false;
  if (targets.dnsConfigured && !targets.interfaceName) {
    // Reported rather than ignored: DNS was applied to a link whose name we no
    // longer have, so it cannot be reverted here and the operator has to.
    note(
      'DNS was configured but the session records no interface name, so it cannot be reverted; ' +
        'check `resolvectl status` for a link still carrying the VPN resolvers',
    );
  }

  if (targets.dnsConfigured && targets.interfaceName) {
    if (!tunnelStopped) {
      note(
        `leaving DNS configured on ${targets.interfaceName}: openvpn may still be running, ` +
          'and reverting now would send private names to the public resolver over a live tunnel',
      );
    } else {
      try {
        await options.dns.revert(targets.interfaceName);
        dnsReverted = true;
        options.onProgress?.(`Reverted DNS on ${targets.interfaceName}`);
      } catch (error) {
        note(`could not revert DNS on ${targets.interfaceName}: ${describeError(error)}`);
      }
    }
  }

  // ---- 3. remove runtime artifacts, on the same condition ---------------
  // unlink() does not follow symlinks, so a planted link is removed rather
  // than its target.
  const artifacts = targets.artifacts ?? [];
  if (tunnelStopped) {
    for (const artifact of artifacts) {
      try {
        await unlink(artifact.path);
        options.onProgress?.(`Removed ${artifact.label}`);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
        residue.push(artifact.path);
        note(`could not remove ${artifact.label} at ${artifact.path}: ${describeError(error)}`);
      }
    }
  } else if (artifacts.length > 0) {
    for (const artifact of artifacts) residue.push(artifact.path);
    note(
      'leaving the runtime files in place: openvpn may still be running and may still ' +
        'need them, and they are how a retry finds what to clean up',
    );
  }

  // Anything configured and not reverted is outstanding, interface known or
  // not - otherwise DNS stays installed under a "complete" teardown.
  const dnsOutstanding = Boolean(targets.dnsConfigured) && !dnsReverted;

  return {
    tunnelStopped,
    dnsReverted,
    residue,
    problems,
    complete: tunnelStopped && !dnsOutstanding && residue.length === 0,
  };
}
