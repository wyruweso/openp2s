/**
 * A scripted stand-in for the openvpn process.
 *
 * Lets the lifecycle tests drive every interesting outcome - connects,
 * dies early, hangs, is killed - without spawning anything or touching the
 * network. It also records the argv and environment it was handed, which is
 * how the tests assert that the Azure compatibility flags and the token
 * handling are correct.
 */

import { EventEmitter } from 'node:events';
import type { ProcessSpawner, SpawnedProcess } from '../../src/openvpn/process.ts';

/** Log lines a real Azure P2S connection emits, in order. */
export const SUCCESSFUL_CONNECT_LOG = [
  'TCP/UDP: Preserving recently used remote address: [AF_INET]203.0.113.10:443',
  'Attempting to establish TCP connection with [AF_INET]203.0.113.10:443',
  'TCP connection established with [AF_INET]203.0.113.10:443',
  'TLS: Initial packet from [AF_INET]203.0.113.10:443',
  'VERIFY OK: depth=2, CN=DigiCert Global Root G2',
  'VERIFY OK: depth=0, CN=*.vpn.azure.com',
  'Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384',
  "PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,route-gateway 172.16.0.1,topology subnet,ping 10,ifconfig 172.16.0.5 255.255.255.0,cipher AES-256-GCM'",
  'OPTIONS IMPORT: --ifconfig/up options modified',
  'TUN/TAP device tun0 opened',
  'net_iface_up: set tun0 up',
  'net_addr_v4_add: 172.16.0.5/24 dev tun0',
  'Initialization Sequence Completed',
];

export const AUTH_FAILED_LOG = [
  'TCP connection established with [AF_INET]203.0.113.10:443',
  'TLS: Initial packet from [AF_INET]203.0.113.10:443',
  'VERIFY OK: depth=0, CN=*.vpn.azure.com',
  'AUTH: Received control message: AUTH_FAILED',
  'SIGTERM[soft,auth-failure] received, process exiting',
];

export const TLS_ERROR_LOG = [
  'TCP connection established with [AF_INET]203.0.113.10:443',
  'TLS Error: TLS key negotiation failed to occur within 60 seconds',
  'TLS Error: TLS handshake failed',
];

export class FakeOpenVpnProcess extends EventEmitter implements SpawnedProcess {
  readonly signals: NodeJS.Signals[] = [];
  pid: number | undefined = 4242;

  private stdoutListeners: Array<(chunk: string) => void> = [];
  private stderrListeners: Array<(chunk: string) => void> = [];
  private exited = false;

  /** Emit log lines as openvpn would, one write per line. */
  emitLog(lines: readonly string[]): void {
    for (const line of lines) {
      for (const listener of this.stdoutListeners) {
        listener(`${line}\n`);
      }
    }
  }

  /** Emit a partial line, to exercise the line buffering. */
  emitPartial(text: string): void {
    for (const listener of this.stdoutListeners) {
      listener(text);
    }
  }

  emitStderr(text: string): void {
    for (const listener of this.stderrListeners) {
      listener(text);
    }
  }

  exit(code: number | null = 0, signal: string | null = null): void {
    if (this.exited) return;
    this.exited = true;
    this.emit('exit', code, signal);
  }

  kill(signal: NodeJS.Signals): boolean {
    this.signals.push(signal);
    // A real openvpn exits on SIGTERM; the "stubborn" case is modelled by
    // FakeSpawner's ignoreSignals option.
    if (!this.ignoreSignals) {
      queueMicrotask(() => this.exit(null, signal));
    }
    return true;
  }

  ignoreSignals = false;

  onExit(listener: (code: number | null, signal: string | null) => void): void {
    this.on('exit', listener);
  }

  onError(listener: (error: Error) => void): void {
    this.on('error', listener);
  }

  onStdout(listener: (chunk: string) => void): void {
    this.stdoutListeners.push(listener);
  }

  onStderr(listener: (chunk: string) => void): void {
    this.stderrListeners.push(listener);
  }
}

export interface FakeSpawnerOptions {
  /** Lines to emit as soon as the process starts. */
  readonly script?: readonly string[];
  /** Exit with this code once the script has been emitted. */
  readonly exitAfterScript?: number | null;
  /** Model a process that ignores SIGTERM, forcing escalation to SIGKILL. */
  readonly ignoreSignals?: boolean;
  /** Throw on spawn, as if the binary were missing. */
  readonly failToSpawn?: Error;
}

export class FakeSpawner implements ProcessSpawner {
  readonly process = new FakeOpenVpnProcess();
  command: string | undefined;
  args: string[] = [];
  spawnCount = 0;

  private readonly options: FakeSpawnerOptions;

  constructor(options: FakeSpawnerOptions = {}) {
    this.options = options;
    this.process.ignoreSignals = options.ignoreSignals ?? false;
  }

  spawn(command: string, args: readonly string[]): SpawnedProcess {
    this.spawnCount += 1;
    this.command = command;
    this.args = [...args];

    if (this.options.failToSpawn) {
      const error = this.options.failToSpawn;
      queueMicrotask(() => this.process.emit('error', error));
      return this.process;
    }

    // Emit asynchronously so the caller has attached its listeners first,
    // exactly as a real child process would behave.
    if (this.options.script) {
      queueMicrotask(() => {
        this.process.emitLog(this.options.script ?? []);
        if (this.options.exitAfterScript !== undefined) {
          this.process.exit(this.options.exitAfterScript);
        }
      });
    }

    return this.process;
  }

  /** The full command line, for readable assertions. */
  get commandLine(): string {
    return [this.command, ...this.args].join(' ');
  }
}
