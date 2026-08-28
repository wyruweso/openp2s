/**
 * Connection orchestration.
 *
 * Owns the ordering and, more importantly, the teardown. The sequence is:
 *
 *   authenticate -> write credentials -> write config -> start openvpn
 *     -> wait for the tunnel -> configure split DNS -> hold
 *
 * Every step records what it brought up in `EstablishedState`, and `cleanup()`
 * hands that to the shared `teardownConnection()`. That is what makes the
 * failure paths uniform: it does not matter whether we fell over during DNS
 * setup, or the user pressed Ctrl+C while waiting for a device code, or openvpn
 * died - the same teardown runs, and the token file is always removed.
 *
 * Deliberately not a stack of undo closures unwound in reverse: teardown order
 * is not setup order reversed - DNS is configured after OpenVPN starts and must
 * be reverted only once OpenVPN is confirmed gone. That policy lives in
 * teardown.ts, shared with `openp2s disconnect`.
 *
 * Cleanup is idempotent and never throws, because it also runs from signal
 * handlers where there is nobody left to catch anything.
 */

import type { AuthOutcome, TokenSource } from '../auth/entra.ts';
import { RuntimeCredentials, writePrivateFile } from '../auth/runtimeCredentials.ts';
import { describeError, TunnelError } from '../errors.ts';
import { AZURE_USERNAME } from '../openvpn/azureCompat.ts';
import { ManagementServer, supportsMultilinePassword } from '../openvpn/management.ts';
import {
  assertTokenFits,
  tokenPressureWarning,
  type CredentialLimits,
} from '../auth/tokenLimits.ts';
import type { OpenVpnBinary } from '../openvpn/binary.ts';
import { renderOpenVpnConfig, type CredentialDelivery } from '../openvpn/config.ts';
import {
  OpenVpnProcess,
  type ConnectionStage,
  type ProcessSpawner,
  type TunnelDetails,
} from '../openvpn/process.ts';
import { privateLinkWarning, type DnsConfigurator } from '../network/dns.ts';
import type { AzureVpnProfile } from '../profile/types.ts';
import { ensurePrivateDir, type OpenP2SPaths } from '../platform/paths.ts';
import type { Elevator } from '../platform/privilege.ts';
import { processStartTime } from '../platform/lock.ts';
import { SessionStore, type SessionRecord } from '../platform/session.ts';
import { teardownConnection, type TeardownResult } from './teardown.ts';

export interface ConnectionEvents {
  onAuthenticated?: (outcome: AuthOutcome) => void;
  onTunnelUp?: (details: TunnelDetails) => void;
  onDnsConfigured?: (servers: readonly string[], domains: readonly string[]) => void;
  onLogLine?: (line: string) => void;
  onWarning?: (message: string) => void;
}

export interface ConnectionOptions {
  readonly profile: AzureVpnProfile;
  readonly paths: OpenP2SPaths;
  readonly binary: OpenVpnBinary;
  readonly caPath: string;
  readonly authenticator: TokenSource;
  readonly dns: DnsConfigurator;
  readonly elevator: Elevator;
  readonly events?: ConnectionEvents;
  readonly spawner?: ProcessSpawner;
  readonly connectTimeoutMs?: number;
  readonly verb?: number;
  readonly verifyName?: string | undefined;
  /** Skip applying DNS settings, for users who manage resolution themselves. */
  readonly skipDns?: boolean;
  /** Route every DNS query over the VPN (`~.`). Explicit request only. */
  readonly dnsAllDomains?: boolean;
  /** Extra routing domains beyond those in the profile. */
  readonly extraDnsDomains?: readonly string[];
  /** How long openvpn gets to exit on SIGTERM before SIGKILL. */
  readonly stopGracePeriodMs?: number;
  /** Send the Azure OCC string and peer-info. Off by default. */
  readonly azureCompat?: boolean;
  /**
   * Force the 0600 credentials file instead of the management socket.
   *
   * The management socket is preferred and chosen automatically when the
   * binary supports it; this is an escape hatch.
   */
  readonly useCredentialsFile?: boolean;
  /** Credential size limits reported by the build. */
  readonly credentialLimits?: CredentialLimits;
  /**
   * Probe mode: run unprivileged, stop once the protocol exchange has gone as
   * far as it can without root, and report the stage reached.
   *
   * Never configures DNS, never writes a session record, never touches the
   * host's network state.
   */
  readonly probe?: boolean;
}

/** What the connection actually brought up, for teardown to undo. */
interface EstablishedState {
  credentialsPath?: string;
  managementSocketPath?: string;
  configPath?: string;
  interfaceName?: string;
  dnsConfigured: boolean;
}

export class Connection {
  private readonly options: ConnectionOptions;
  private readonly credentials: RuntimeCredentials;
  private readonly session: SessionStore;
  private tunnel: OpenVpnProcess | undefined;
  private management: ManagementServer | undefined;
  private cleanedUp = false;
  private readonly established: EstablishedState = { dnsConfigured: false };
  /** Set when a teardown could not finish; the caller must not forget us. */
  private teardownIncomplete = false;

  constructor(options: ConnectionOptions) {
    this.options = options;
    this.credentials = new RuntimeCredentials({
      directory: options.paths.runtimeDir,
      credentialsPath: options.paths.credentialsFile,
      user: options.paths.user,
    });
    this.session = new SessionStore(options.paths.sessionFile);
  }

  get details(): TunnelDetails | undefined {
    return this.tunnel?.details;
  }

  /**
   * Bring the connection up. Throws on any failure, after cleaning up.
   *
   * Note the try/catch: a caller that gets an exception from connect() can
   * assume teardown already happened, so it only has to report.
   */
  async connect(): Promise<SessionRecord> {
    try {
      return await this.run();
    } catch (error) {
      await this.cleanup();
      throw error;
    }
  }

  private async run(): Promise<SessionRecord> {
    const { profile, paths, binary, events } = this.options;

    ensurePrivateDir(paths.runtimeDir);

    // ---- 1. Entra -------------------------------------------------------
    const outcome = await this.options.authenticator.acquireToken();
    events?.onAuthenticated?.(outcome);

    // Measure the token before handing it anywhere. OpenVPN would truncate a
    // token past USER_PASS_LEN silently, and the resulting AUTH_FAILED gives
    // no hint at the real cause.
    const limits = this.options.credentialLimits;
    if (limits) {
      assertTokenFits(outcome.accessToken, limits);
      const pressure = tokenPressureWarning(outcome.accessToken, limits);
      if (pressure) events?.onWarning?.(pressure);
    } else {
      assertTokenFits(outcome.accessToken);
      const pressure = tokenPressureWarning(outcome.accessToken);
      if (pressure) events?.onWarning?.(pressure);
    }

    // ---- 2. credential delivery -----------------------------------------
    // Preferred: a private management socket, so the token stays in process
    // memory and no file is ever created. Requires OpenVPN >= 2.7.2, whose
    // management interface accepts a multi-line base64 password; older
    // builds cap a parameter at 256 bytes and cannot carry a token.
    const canUseManagement =
      !this.options.useCredentialsFile && supportsMultilinePassword(binary.upstreamVersion);

    let credentials: CredentialDelivery;
    let credentialsPath: string | undefined;
    let managementSocket: string | undefined;

    if (canUseManagement) {
      const server = new ManagementServer({
        socketPath: paths.managementSocket,
        credentials: { username: AZURE_USERNAME, password: outcome.accessToken },
        ...(events?.onLogLine ? { onDebug: events.onLogLine } : {}),
      });
      await server.start();
      this.management = server;
      managementSocket = server.path;
      credentials = { kind: 'management', socketPath: server.path };
      this.established.managementSocketPath = server.path;
    } else {
      events?.onWarning?.(
        `OpenVPN ${binary.upstreamVersion ?? 'build'} predates the multi-line management ` +
          'password (2.7.2); falling back to a 0600 credentials file',
      );
      await this.credentials.write(outcome.accessToken);
      credentialsPath = this.credentials.path;
      credentials = { kind: 'file', path: this.credentials.path };
      this.established.credentialsPath = this.credentials.path;
    }

    // ---- 3. config (embeds the tls-auth key, so also 0600) --------------
    const config = renderOpenVpnConfig({
      profile,
      credentials,
      caPath: this.options.caPath,
      verb: this.options.verb ?? 3,
      verifyName: this.options.verifyName,
      ...(this.options.azureCompat !== undefined ? { azureCompat: this.options.azureCompat } : {}),
      // Probe mode is enforced in the config, not by the privilege level:
      // `dev null` + route-noexec + ifconfig-noexec, so the run cannot alter
      // the host even under sudo. See RenderOptions.probe.
      ...(this.options.probe ? { probe: true } : {}),
    });
    await writePrivateFile(paths.configFile, config);
    this.established.configPath = paths.configFile;

    // ---- 4. openvpn -----------------------------------------------------
    // No environment is passed at all any more: every Azure-specific setting
    // is a directive inside the config file, which sidesteps sudo's
    // env_reset policy entirely.
    const plan = this.options.elevator.plan(binary.path, ['--config', paths.configFile]);

    const tunnel = new OpenVpnProcess({
      command: plan.command,
      args: plan.args,
      connectTimeoutMs: this.options.connectTimeoutMs ?? 90_000,
      ...(this.options.spawner ? { spawner: this.options.spawner } : {}),
      ...(events?.onLogLine ? { onLogLine: events.onLogLine } : {}),
    });

    this.tunnel = tunnel;
    tunnel.start();

    if (this.options.probe) {
      // Unprivileged: openvpn cannot open the tun device, so wait for the
      // furthest stage that does not need root and then stop.
      await tunnel.waitForStage('push', this.options.connectTimeoutMs ?? 60_000);
      return this.probeRecord(outcome.account);
    }

    const details = await tunnel.waitForConnection();
    events?.onTunnelUp?.(details);

    // ---- 5. split DNS, only once the interface actually exists ----------
    let dnsApplied = false;
    if (!this.options.skipDns && profile.dnsServers.length > 0) {
      if (!details.interfaceName) {
        // Should not happen: openvpn logs the device before completing
        // initialisation. Warn rather than fail, since the tunnel itself is up.
        events?.onWarning?.(
          'the tunnel is up but OpenVPN did not report an interface name; ' +
            'skipping DNS configuration',
        );
      } else {
        const interfaceName = details.interfaceName;
        const domains = [...profile.dnsSuffixes, ...(this.options.extraDnsDomains ?? [])];

        const warning = privateLinkWarning(
          profile.dnsServers,
          domains,
          this.options.dnsAllDomains ?? false,
        );
        if (warning) events?.onWarning?.(warning);

        await this.options.dns.configure(interfaceName, profile.dnsServers, domains, {
          allDomains: this.options.dnsAllDomains ?? false,
        });
        dnsApplied = true;
        this.established.dnsConfigured = true;
        this.established.interfaceName = interfaceName;
        events?.onDnsConfigured?.(profile.dnsServers, profile.dnsSuffixes);
      }
    }

    // ---- 6. session record ----------------------------------------------
    const record: SessionRecord = {
      version: 1,
      profileName: profile.name,
      gateway: profile.gateway,
      openvpnPid: tunnel.pid,
      openvpnStartTime: tunnel.pid === undefined ? undefined : processStartTime(tunnel.pid),
      ownerPid: process.pid,
      interfaceName: details.interfaceName,
      assignedAddress: details.assignedAddress,
      dnsServers: dnsApplied ? profile.dnsServers : [],
      dnsDomains: dnsApplied
        ? this.options.dnsAllDomains
          ? ['.']
          : [...profile.dnsSuffixes, ...(this.options.extraDnsDomains ?? [])]
        : [],
      pushedRoutes: details.pushedRoutes,
      includeRoutes: profile.includeRoutes.map((route) => route.cidr),
      account: outcome.account,
      connectedAt: new Date().toISOString(),
      openvpn: {
        path: this.options.binary.path,
        version: this.options.binary.upstreamVersion,
        commit: this.options.binary.upstreamCommit,
        patchStack: this.options.binary.patchStack,
        binarySha256: this.options.binary.binarySha256,
        userPassLen: this.options.binary.userPassLen,
        azureCompatAvailable: this.options.binary.azureCompatAvailable,
      },
      credentialsPath: credentialsPath ?? '',
      managementSocket: managementSocket ?? '',
      configPath: paths.configFile,
    };

    await this.session.write(record);

    return record;
  }

  /**
   * Leave behind enough for `openp2s disconnect` to finish the job.
   *
   * The session record is normally written only once the tunnel is up and DNS
   * is configured. But a connect can fail *after* OpenVPN has started - the
   * tunnel never comes up, or DNS setup fails - and then fail again trying to
   * stop it. Without this, the foreground process exits reporting an error
   * while an OpenVPN it spawned is still running, and the next
   * `openp2s disconnect` says "Not connected" because no record was ever
   * written.
   *
   * So an incomplete teardown always leaves a record, whether or not one
   * existed before. It describes what is actually outstanding rather than a
   * healthy connection: `status` reports it as stale or disconnecting, and
   * `disconnect` has the pid, the interface and the paths it needs.
   */
  private async writeRecoveryRecord(result: TeardownResult): Promise<void> {
    const tunnel = this.tunnel;
    const profile = this.options.profile;

    try {
      const existing = await this.session.read();
      const record: SessionRecord = {
        version: 1,
        profileName: existing?.profileName ?? profile.name,
        gateway: existing?.gateway ?? profile.gateway,
        openvpnPid: result.tunnelStopped ? undefined : tunnel?.pid,
        openvpnStartTime:
          result.tunnelStopped || tunnel?.pid === undefined
            ? undefined
            : processStartTime(tunnel.pid),
        ownerPid: process.pid,
        interfaceName: this.established.interfaceName,
        assignedAddress: existing?.assignedAddress,
        // Only what is still installed. Reverted DNS must not be described as
        // outstanding, or a retry would try to revert it again.
        dnsServers: result.dnsReverted ? [] : (existing?.dnsServers ?? profile.dnsServers),
        dnsDomains: result.dnsReverted ? [] : (existing?.dnsDomains ?? profile.dnsSuffixes),
        pushedRoutes: existing?.pushedRoutes ?? [],
        includeRoutes: existing?.includeRoutes ?? [],
        account: existing?.account,
        connectedAt: existing?.connectedAt ?? new Date().toISOString(),
        credentialsPath: result.tunnelStopped ? '' : (this.established.credentialsPath ?? ''),
        managementSocket: result.tunnelStopped ? '' : (this.established.managementSocketPath ?? ''),
        configPath: result.tunnelStopped ? '' : (this.established.configPath ?? ''),
      };

      await this.session.write(record);
      this.options.events?.onWarning?.(
        'a session record was kept so `openp2s disconnect` can finish the cleanup',
      );
    } catch (error) {
      // Nothing else to try, and cleanup must not fail. Say so, because the
      // user is now the only one who can finish this.
      this.options.events?.onWarning?.(
        `could not record what is still running: ${describeError(error)}. ` +
          'Check `ps` for openvpn and `resolvectl status` for leftover DNS.',
      );
    }
  }

  /** Summarise a probe run without writing any session state. */
  private probeRecord(account: string | undefined): SessionRecord {
    const details = this.tunnel?.details;
    return {
      version: 1,
      profileName: this.options.profile.name,
      gateway: this.options.profile.gateway,
      openvpnPid: undefined,
      ownerPid: process.pid,
      interfaceName: details?.interfaceName,
      assignedAddress: details?.assignedAddress,
      dnsServers: [],
      dnsDomains: [],
      pushedRoutes: details?.pushedRoutes ?? [],
      includeRoutes: [],
      account,
      connectedAt: new Date().toISOString(),
      credentialsPath: '',
      managementSocket: '',
      configPath: '',
    };
  }

  /** Stage reached, for probe reporting. */
  get stage(): ConnectionStage {
    return this.tunnel?.details.stage ?? 'start';
  }

  get failureReason(): string | undefined {
    return this.tunnel?.details.failureReason;
  }

  get tlsCipher(): string | undefined {
    return this.tunnel?.details.tlsCipher;
  }

  /** Resolve when openvpn exits, so the CLI can hold the foreground. */
  async waitForExit(): Promise<{ code: number | null; signal: string | null }> {
    const tunnel = this.tunnel;
    if (!tunnel || tunnel.hasExited) {
      return { code: null, signal: null };
    }
    return await new Promise((resolve) => {
      tunnel.once('exit', resolve);
    });
  }

  /**
   * Undo everything. Idempotent, and never throws.
   *
   * Delegates to the shared `teardownConnection()` so that Ctrl+C here and
   * `openp2s disconnect` from another terminal follow exactly the same
   * policy - in particular, DNS is reverted only once the tunnel is confirmed
   * gone. An LIFO unwind of the setup steps would get that backwards, because
   * DNS is configured after OpenVPN starts and would therefore be undone
   * first.
   */
  async cleanup(): Promise<void> {
    if (this.cleanedUp) return;
    this.cleanedUp = true;

    const tunnel = this.tunnel;
    const events = this.options.events;

    const result = await teardownConnection(
      {
        openvpnPid: tunnel?.pid,
        openvpnStartTime: tunnel?.pid === undefined ? undefined : processStartTime(tunnel.pid),
        interfaceName: this.established.interfaceName,
        dnsConfigured: this.established.dnsConfigured,
        artifacts: [
          this.established.credentialsPath
            ? { label: 'credentials', path: this.established.credentialsPath }
            : undefined,
          this.established.configPath
            ? { label: 'generated config', path: this.established.configPath }
            : undefined,
        ].filter((artifact): artifact is { label: string; path: string } => artifact !== undefined),
      },
      {
        dns: this.options.dns,
        ...(this.options.stopGracePeriodMs !== undefined
          ? { graceMs: this.options.stopGracePeriodMs }
          : {}),
        // We own the child, so we learn of its exit from the process handle
        // rather than by polling a pid. That is both accurate and immune to
        // pid reuse.
        stopTunnel: async () => {
          if (!tunnel || tunnel.hasExited) return true;
          await tunnel.stop(this.options.stopGracePeriodMs);
          return tunnel.hasExited;
        },
        ...(events?.onWarning ? { onWarning: events.onWarning } : {}),
      },
    );

    this.teardownIncomplete = !result.complete;

    // Everything below follows the teardown's verdict rather than overriding
    // it. Doing this unconditionally undid the policy the teardown had just
    // applied: it would close the management socket and delete the credentials
    // of an OpenVPN that is still running, and clear the session record that
    // is the only description of what is still up.
    if (result.tunnelStopped) {
      // The management socket is ours to close, not merely to unlink - and
      // only once nothing is left to talk to.
      if (this.management) {
        await this.management.stop();
        this.management = undefined;
      }

      // Belt and braces: make certain the token file is gone. Worth checking
      // twice, but only now that nothing can still be reading it.
      try {
        await this.credentials.remove();
        if (await this.credentials.exists()) {
          events?.onWarning?.(
            `the credentials file at ${this.credentials.path} could not be removed; ` +
              'delete it manually',
          );
        }
      } catch {
        // remove() does not throw, but never let cleanup fail.
      }
    } else if (this.management) {
      events?.onWarning?.(
        'leaving the management socket open: openvpn may still be running and it is ' +
          'the way to reach it',
      );
      // Open, but no longer a reason to stay alive. Nothing calls
      // process.exit(), so a listening handle would keep the CLI running
      // indefinitely after it had already reported the failure.
      this.management.unref();
    }

    // The session record is how `openp2s disconnect` finds what is still
    // running. It goes only when there is nothing left to find.
    if (result.complete) {
      await this.session.clear();
    } else {
      await this.writeRecoveryRecord(result);
    }
  }

  /** True when teardown left something behind. */
  get hasResidue(): boolean {
    return this.teardownIncomplete;
  }

  /** Stop the tunnel and tear everything down. */
  async disconnect(): Promise<void> {
    await this.cleanup();
  }
}

export { TunnelError };
