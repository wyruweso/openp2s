/**
 * OpenVPN process lifecycle.
 *
 * Responsibilities, in order:
 *   1. spawn the patched binary with an argv array (never a shell string);
 *   2. watch its output for the milestones that tell us the tunnel is real -
 *      which interface, which address, and whether initialisation finished;
 *   3. guarantee the process is gone when we say it is.
 *
 * The output parsing is deliberately narrow. It looks for four specific
 * OpenVPN log lines and ignores everything else, so an unexpected message
 * cannot be mistaken for a connection.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { redact, TunnelError } from '../errors.ts';

/**
 * How far the connection got.
 *
 * Ordered, and tracked as a high-water mark, so a failure can be attributed to
 * an exact stage rather than reported as a bare "it did not work".
 * "Fails at key-method-2" and "fails at TLS handshake" point at completely
 * different causes, and the distinction is most of the diagnosis.
 */
export const CONNECTION_STAGES = [
  'start',
  'tcp', // TCP connection established with the gateway
  'tls', // TLS handshake completed, control channel up
  'cert', // gateway certificate chain verified
  'auth', // key-method-2 accepted; the gateway took our Entra token
  'push', // PUSH_REPLY received: addresses and routes assigned
  'tun', // tun device opened (needs root)
  'complete', // Initialization Sequence Completed
] as const;

export type ConnectionStage = (typeof CONNECTION_STAGES)[number];

export function stageRank(stage: ConnectionStage): number {
  return CONNECTION_STAGES.indexOf(stage);
}

export interface TunnelDetails {
  /** Tunnel interface, e.g. "tun0". Known once the device is opened. */
  interfaceName: string | undefined;
  /** Address assigned to us by the gateway. */
  assignedAddress: string | undefined;
  /** Routes the gateway pushed, as they appeared in PUSH_REPLY. */
  pushedRoutes: string[];
  /** Furthest stage reached. */
  stage: ConnectionStage;
  /** Negotiated control-channel cipher, when the log reports it. */
  tlsCipher: string | undefined;
  /** Why it stopped, when we can name a reason. */
  failureReason: string | undefined;
}

/**
 * The slice of a child process this module needs.
 *
 * Separate `onExit`/`onError` rather than an overloaded `on`, so that both the
 * real adapter and the test fake can implement it without a type assertion.
 */
export interface SpawnedProcess {
  readonly pid: number | undefined;
  kill(signal: NodeJS.Signals): boolean;
  onExit(listener: (code: number | null, signal: string | null) => void): void;
  onError(listener: (error: Error) => void): void;
  onStdout(listener: (chunk: string) => void): void;
  onStderr(listener: (chunk: string) => void): void;
}

export interface ProcessSpawner {
  spawn(command: string, args: readonly string[]): SpawnedProcess;
}

/** Real spawner. shell:false is the whole point. */
export class NodeProcessSpawner implements ProcessSpawner {
  spawn(command: string, args: readonly string[]): SpawnedProcess {
    // No environment is added. Everything OpenVPN needs is a directive in the
    // generated config, which also means nothing has to survive sudo's
    // env_reset policy. See src/platform/privilege.ts.
    const child: ChildProcess = spawn(command, [...args], {
      shell: false,
      // stdin stays open: sudo may need it to prompt for a password.
      stdio: ['inherit', 'pipe', 'pipe'],
      env: { ...process.env },
    });

    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');

    return {
      get pid(): number | undefined {
        return child.pid;
      },
      kill: (signal: NodeJS.Signals): boolean => child.kill(signal),
      onExit: (listener): void => {
        child.on('exit', listener);
      },
      onError: (listener): void => {
        child.on('error', listener);
      },
      onStdout: (listener): void => {
        child.stdout?.on('data', listener);
      },
      onStderr: (listener): void => {
        child.stderr?.on('data', listener);
      },
    };
  }
}

/**
 * The OpenVPN log lines we care about.
 *
 * Matched per line, not against the accumulated stream, so a milestone cannot
 * be assembled out of two messages. Deliberately not anchored: OpenVPN prefixes
 * a timestamp, and AUTH_FAILED arrives inside "AUTH: Received control message:
 * AUTH_FAILED". A milestone can therefore be spelled inside a longer message -
 * which is why `handleLine` consumes the PUSH_REPLY echo, the one line whose
 * text the peer chooses, before any of these see it.
 */
const PATTERNS = {
  /** "TCP connection established with [AF_INET]a.b.c.d:443" */
  tcp: /TCP connection established with/,
  /** "Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384" */
  tlsCipher: /Control Channel: (TLSv[\d.]+), cipher (\S+(?: \S+)?)/,
  /** Earlier TLS evidence, before the control channel line. */
  tlsStart: /TLS: Initial packet from|TLS: soft reset|VERIFY OK/,
  /** "VERIFY OK: depth=0, CN=..." - the leaf certificate verified. */
  certOk: /VERIFY OK: depth=0/,
  /** key-method-2 accepted; the gateway took our credentials. */
  authOk: /Peer Connection Initiated|SENT CONTROL|PUSH: Received control message/,
  /** "TUN/TAP device tun0 opened" */
  device: /TUN\/TAP device (\w+) opened/,
  /** "net_addr_v4_add: 172.16.0.5/24 dev tun0" */
  address: /net_addr_v[46]_add:\s+([0-9a-fA-F.:]+)\/\d+\s+dev\s+(\w+)/,
  /** "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0,...'" */
  pushReply: /PUSH: Received control message:\s*'PUSH_REPLY,(.*)'/,
  /** The milestone that means the tunnel is usable. */
  completed: /Initialization Sequence Completed/,
  /** Authentication was rejected by the gateway. */
  authFailed: /AUTH_FAILED|auth-failure|SIGTERM\[soft,auth-failure\]/,
  /** TLS could not be established. */
  tlsError: /TLS Error:|TLS handshake failed|VERIFY ERROR/,
  /** The gateway dropped us mid-handshake, the classic OCC/peer-info rejection. */
  reset:
    /Connection reset, restarting|SIGUSR1\[soft,connection-reset\]|TLS Error: TLS key negotiation failed/,
  /** Needs root; expected and harmless during an unprivileged probe. */
  tunPermission: /Cannot open TUN\/TAP dev|Operation not permitted|ERROR: Cannot ioctl TUNSETIFF/,
} as const;

export interface OpenVpnProcessOptions {
  readonly command: string;
  readonly args: readonly string[];
  readonly spawner?: ProcessSpawner;
  /** How long to wait for "Initialization Sequence Completed". */
  readonly connectTimeoutMs?: number;
  /** Called for each output line, already redacted. */
  readonly onLogLine?: (line: string) => void;
}

export interface OpenVpnEvents {
  connected: [TunnelDetails];
  exit: [{ code: number | null; signal: string | null }];
  line: [string];
  stage: [ConnectionStage];
}

/**
 * Wraps a running openvpn process.
 *
 * Emits 'connected' exactly once, when initialisation completes; 'line' for
 * each redacted output line; and 'exit' when the process is gone.
 */
export class OpenVpnProcess extends EventEmitter<OpenVpnEvents> {
  readonly details: TunnelDetails = {
    interfaceName: undefined,
    assignedAddress: undefined,
    pushedRoutes: [],
    stage: 'start',
    tlsCipher: undefined,
    failureReason: undefined,
  };

  private process: SpawnedProcess | undefined;
  private buffer = '';
  private connected = false;
  private exited = false;
  private exitInfo: { code: number | null; signal: string | null } | undefined;
  private readonly recentLines: string[] = [];
  private readonly options: OpenVpnProcessOptions;
  private readonly spawner: ProcessSpawner;

  constructor(options: OpenVpnProcessOptions) {
    super();
    this.options = options;
    this.spawner = options.spawner ?? new NodeProcessSpawner();
  }

  get pid(): number | undefined {
    return this.process?.pid;
  }

  get hasExited(): boolean {
    return this.exited;
  }

  get stage(): ConnectionStage {
    return this.details.stage;
  }

  /** Record a stage, never going backwards. */
  private reachStage(stage: ConnectionStage): void {
    if (stageRank(stage) > stageRank(this.details.stage)) {
      this.details.stage = stage;
      this.emit('stage', stage);
    }
  }

  /**
   * Resolve once the connection reaches `target`, or reject if it stops first.
   *
   * Used by probe mode, which only needs to know whether the protocol
   * exchange got as far as PUSH_REPLY - everything past that requires root.
   */
  async waitForStage(target: ConnectionStage, timeoutMs = 60_000): Promise<ConnectionStage> {
    if (stageRank(this.details.stage) >= stageRank(target)) {
      return this.details.stage;
    }

    return await new Promise<ConnectionStage>((resolve) => {
      let settled = false;
      const finish = (action: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        action();
      };

      const timer = setTimeout(() => finish(() => resolve(this.details.stage)), timeoutMs);
      timer.unref?.();

      const onStage = (stage: ConnectionStage): void => {
        if (stageRank(stage) >= stageRank(target)) {
          finish(() => resolve(stage));
        }
      };

      this.on('stage', onStage);
      this.once('exit', () => finish(() => resolve(this.details.stage)));
      if (this.exited) finish(() => resolve(this.details.stage));
    });
  }

  start(): void {
    if (this.process) {
      throw new TunnelError('openvpn process already started');
    }

    const child = this.spawner.spawn(this.options.command, this.options.args);
    this.process = child;

    child.onStdout((chunk) => this.ingest(chunk));
    child.onStderr((chunk) => this.ingest(chunk));

    child.onError((error: Error) => {
      this.exited = true;
      this.emit('exit', { code: null, signal: null });
      this.emit('line', `openvpn failed to start: ${redact(error.message)}`);
    });

    child.onExit((code: number | null, signal: string | null) => {
      this.flush();
      this.exited = true;
      this.exitInfo = { code, signal };
      this.emit('exit', { code, signal });
    });
  }

  /**
   * Resolve when the tunnel is up, reject if openvpn dies or stalls first.
   *
   * The three outcomes are distinguished so the CLI can say something useful:
   * "authentication rejected" is a very different problem from "timed out".
   */
  async waitForConnection(): Promise<TunnelDetails> {
    if (this.connected) return this.details;

    const timeoutMs = this.options.connectTimeoutMs ?? 60_000;

    return await new Promise<TunnelDetails>((resolve, reject) => {
      let settled = false;

      const finish = (action: () => void): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        action();
      };

      const timer = setTimeout(() => {
        finish(() =>
          reject(
            new TunnelError(
              `timed out after ${Math.round(timeoutMs / 1000)}s waiting for the tunnel`,
              {
                hint: this.diagnose() ?? 'Run with --verbose to see the full OpenVPN log.',
              },
            ),
          ),
        );
      }, timeoutMs);
      timer.unref?.();

      this.once('connected', (details) => finish(() => resolve(details)));

      this.once('exit', ({ code, signal }) => {
        finish(() =>
          reject(
            new TunnelError(
              `openvpn exited before the tunnel came up (${signal ? `signal ${signal}` : `code ${code}`})`,
              { hint: this.diagnose() ?? 'Run with --verbose to see the full OpenVPN log.' },
            ),
          ),
        );
      });

      // Already gone before we got here.
      if (this.exited) {
        const info = this.exitInfo;
        finish(() =>
          reject(
            new TunnelError(
              `openvpn exited before the tunnel came up (code ${info?.code ?? 'unknown'})`,
              { hint: this.diagnose() ?? undefined },
            ),
          ),
        );
      }
    });
  }

  /**
   * Turn the tail of the log into an explanation, when we recognise one.
   *
   * Beats making a user read 200 lines of OpenVPN output to discover their
   * token was rejected.
   */
  private diagnose(): string | undefined {
    const tail = this.recentLines.join('\n');

    if (PATTERNS.authFailed.test(tail)) {
      return (
        'The gateway rejected the Entra access token (AUTH_FAILED). The token ' +
        'may have expired, or Conditional Access may require a fresh sign-in. ' +
        'Try: openp2s auth clear, then connect again.'
      );
    }
    if (/VERIFY ERROR/.test(tail)) {
      return 'The gateway certificate failed validation. OpenP2S will not connect without a valid chain.';
    }
    if (PATTERNS.tlsError.test(tail)) {
      return (
        'The TLS handshake failed. If this binary was not built from ' +
        'long-credentials.patch, the Azure gateway will reject it.'
      );
    }
    if (/Operation not permitted|Cannot open TUN\/TAP/.test(tail)) {
      return 'Could not create the tun device. openvpn needs root; check that sudo succeeded.';
    }
    return undefined;
  }

  /** Split incoming bytes into lines; OpenVPN output is line-oriented. */
  private ingest(chunk: string): void {
    this.buffer += chunk;
    let newline = this.buffer.indexOf('\n');

    while (newline !== -1) {
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      this.handleLine(line);
      newline = this.buffer.indexOf('\n');
    }
  }

  private flush(): void {
    if (this.buffer.trim().length > 0) {
      this.handleLine(this.buffer);
      this.buffer = '';
    }
  }

  private handleLine(rawLine: string): void {
    // Redact before anything else touches it. OpenVPN should never print a
    // token, but this is the one place every line passes through, so it is
    // the right place to be certain.
    const line = redact(rawLine.trimEnd());
    if (line.length === 0) return;

    this.recentLines.push(line);
    if (this.recentLines.length > 50) {
      this.recentLines.shift();
    }

    this.emit('line', line);
    this.options.onLogLine?.(line);

    // ---- the one line the peer writes -----------------------------------
    // Everything after "PUSH_REPLY," is a string the gateway chose. Consumed
    // here so no other pattern reads it: a pushed option spelling
    // "Initialization Sequence Completed" would otherwise announce a tunnel
    // that does not exist. Nothing is lost - 'push' outranks 'auth', and the
    // stage is a high-water mark.
    const push = PATTERNS.pushReply.exec(line);
    if (push?.[1]) {
      this.reachStage('push');
      this.details.pushedRoutes = push[1]
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.startsWith('route '));
      return;
    }

    // ---- stage tracking ------------------------------------------------
    if (PATTERNS.tcp.test(line)) {
      this.reachStage('tcp');
    }
    const cipher = PATTERNS.tlsCipher.exec(line);
    if (cipher) {
      this.details.tlsCipher = `${cipher[1]} / ${cipher[2]}`;
      this.reachStage('tls');
    } else if (PATTERNS.tlsStart.test(line)) {
      this.reachStage('tls');
    }
    if (PATTERNS.certOk.test(line)) {
      this.reachStage('cert');
    }
    if (PATTERNS.authOk.test(line)) {
      this.reachStage('auth');
    }
    if (PATTERNS.authFailed.test(line)) {
      this.details.failureReason = 'the gateway rejected the Entra access token (AUTH_FAILED)';
    } else if (PATTERNS.reset.test(line)) {
      this.details.failureReason ??=
        'the gateway reset the connection during the control-channel exchange';
    } else if (PATTERNS.tunPermission.test(line)) {
      this.details.failureReason ??= 'could not open the tun device (needs root)';
    }

    const device = PATTERNS.device.exec(line);
    if (device?.[1]) {
      this.details.interfaceName = device[1];
      this.reachStage('tun');
    }

    const address = PATTERNS.address.exec(line);
    if (address?.[1]) {
      this.details.assignedAddress = address[1];
      if (address[2] && !this.details.interfaceName) {
        this.details.interfaceName = address[2];
      }
    }

    if (!this.connected && PATTERNS.completed.test(line)) {
      this.connected = true;
      this.reachStage('complete');
      this.emit('connected', this.details);
    }
  }

  /**
   * Stop openvpn, escalating to SIGKILL if it will not go.
   *
   * Always resolves. A disconnect path that can throw would leave DNS and
   * credentials behind, which is exactly the state we must never be in.
   */
  async stop(gracePeriodMs: number | undefined = 5_000): Promise<void> {
    const child = this.process;
    if (!child || this.exited) return;

    await new Promise<void>((resolve) => {
      let done = false;
      const finish = (): void => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve();
      };

      this.once('exit', finish);

      const timer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          // Already gone.
        }
        finish();
      }, gracePeriodMs);
      timer.unref?.();

      try {
        child.kill('SIGTERM');
      } catch {
        finish();
      }
    });
  }
}
