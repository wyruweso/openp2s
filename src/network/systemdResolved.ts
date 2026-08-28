/**
 * systemd-resolved implementation of DnsConfigurator.
 *
 * Three resolvectl calls, in a specific order and with a specific meaning:
 *
 *   resolvectl dns <if> <servers...>       which resolvers this link uses
 *   resolvectl domain <if> ~suffix ...     which names it is consulted for
 *   resolvectl default-route <if> no       never consulted for anything else
 *
 * The third call is the one that keeps this split DNS rather than a takeover
 * of the machine's name resolution, and it is issued unconditionally.
 */

import { NetworkError } from '../errors.ts';
import type { CommandRunner } from '../platform/exec.ts';
import type { Elevator } from '../platform/privilege.ts';
import {
  ALL_DOMAINS,
  isValidInterfaceName,
  toRoutingDomains,
  type DnsConfigureOptions,
  type DnsConfigurator,
} from './dns.ts';

export interface SystemdResolvedOptions {
  readonly runner: CommandRunner;
  readonly elevator: Elevator;
  readonly resolvectlPath?: string;
}

export class SystemdResolvedConfigurator implements DnsConfigurator {
  private readonly runner: CommandRunner;
  private readonly elevator: Elevator;
  private readonly resolvectl: string;

  constructor(options: SystemdResolvedOptions) {
    this.runner = options.runner;
    this.elevator = options.elevator;
    this.resolvectl = options.resolvectlPath ?? 'resolvectl';
  }

  private async resolvectlRun(args: readonly string[]): Promise<void> {
    const plan = this.elevator.plan(this.resolvectl, args);
    await this.runner.run(plan.command, plan.args, { check: true, timeoutMs: 15_000 });
  }

  async configure(
    interfaceName: string,
    dnsServers: readonly string[],
    domains: readonly string[],
    options: DnsConfigureOptions = {},
  ): Promise<void> {
    // The name comes from our own openvpn process, but it is about to become
    // an argument to a privileged command, so check rather than trust. This
    // also means OpenP2S can only ever touch the interface it was given -
    // it never enumerates tun* and reconfigures whatever it finds, which
    // would trample a second, unrelated VPN on the same machine.
    if (!isValidInterfaceName(interfaceName)) {
      throw new NetworkError(`refusing to configure DNS on an implausible interface name`);
    }

    if (dnsServers.length === 0) {
      // Nothing to do, and issuing `resolvectl dns <if>` with no servers
      // would clear the link rather than leave it alone.
      return;
    }

    // `~.` routes everything through the VPN. Only ever used on an explicit
    // request; never inferred from the presence of a DNS server.
    const routingDomains = options.allDomains ? [ALL_DOMAINS] : toRoutingDomains(domains);

    try {
      await this.resolvectlRun(['dns', interfaceName, ...dnsServers]);

      if (routingDomains.length > 0) {
        await this.resolvectlRun(['domain', interfaceName, ...routingDomains]);
      }

      // Unconditional, and last: even with no suffixes to route, this link
      // must never become the machine's default resolver. Issuing it after
      // the others means a failure part-way through still leaves the link
      // narrower than the system default rather than wider.
      await this.resolvectlRun(['default-route', interfaceName, 'no']);
    } catch (error) {
      throw new NetworkError(`failed to configure DNS on ${interfaceName}`, {
        cause: error,
        hint:
          'Check that systemd-resolved is running (systemctl status systemd-resolved). ' +
          'OpenP2S needs it to apply the split DNS settings from the Azure profile.',
      });
    }
  }

  /**
   * Revert the link to its default state.
   *
   * Never throws. This runs on the disconnect and failure paths, where an
   * exception would abandon the rest of the cleanup; the caller is told about
   * problems through the returned promise resolving normally, and the CLI
   * prints a warning of its own if the interface is still configured.
   */
  async revert(interfaceName: string): Promise<void> {
    if (!isValidInterfaceName(interfaceName)) {
      return;
    }
    try {
      await this.resolvectlRun(['revert', interfaceName]);
    } catch {
      // The link is usually gone already - openvpn tears down tun0 on exit,
      // and systemd-resolved drops its configuration with it.
    }
  }
}

/** True when systemd-resolved is available and running. */
export async function isSystemdResolvedActive(runner: CommandRunner): Promise<boolean> {
  try {
    const result = await runner.run('systemctl', ['is-active', 'systemd-resolved'], {
      timeoutMs: 5_000,
    });
    return result.stdout.trim() === 'active';
  } catch {
    return false;
  }
}
