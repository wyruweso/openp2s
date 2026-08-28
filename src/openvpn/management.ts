/**
 * OpenVPN management interface: in-memory credential delivery.
 *
 * The Entra access token never touches the filesystem. OpenVPN asks for
 * credentials over a private unix socket and we answer from process memory.
 *
 * The protocol's single-line form caps a parameter at 256 bytes and the token
 * is ~2.3 KB, so this uses the multi-line base64 form added in OpenVPN 2.7.2:
 *
 *     version 5          <- declare multi-line password support
 *     password "Auth"    <- no inline value: enters multi-line mode
 *     <base64 chunk>
 *     END
 *
 * The decoded password must still fit OpenVPN's USER_PASS_LEN, so this works
 * only on a patched build. The two changes are complementary.
 *
 * `management-client` means OpenVPN connects to us, so we create the socket
 * at 0600 before OpenVPN starts and there is never a window where another
 * process could connect first.
 */

import { createServer, type Server, type Socket } from 'node:net';
import { chmodSync, unlinkSync } from 'node:fs';
import { redact, TunnelError } from '../errors.ts';

/** 5 is the version at which OpenVPN accepts a multi-line base64 password. */
const CLIENT_VERSION = 5;

/**
 * Base64 characters per line.
 *
 * OpenVPN accepts up to 1024 bytes per line; 768 leaves margin and keeps
 * each line comfortably inside the command buffer.
 */
const BASE64_LINE_LENGTH = 768;

/** Minimum OpenVPN version whose management interface understands this. */
export const MIN_MULTILINE_PASSWORD_VERSION = '2.7.2';

/**
 * Longest usable unix socket path.
 *
 * sockaddr_un.sun_path is 108 bytes on Linux including the NUL terminator,
 * so 107 is the most that can be bound.
 */
export const MAX_UNIX_SOCKET_PATH = 107;

export interface ManagementCredentials {
  readonly username: string;
  /** Held in memory only. Never logged, never written, never in argv. */
  readonly password: string;
}

export interface ManagementServerOptions {
  readonly socketPath: string;
  readonly credentials: ManagementCredentials;
  /** Diagnostics. Never receives the password. */
  readonly onDebug?: (message: string) => void;
  /** Called if the gateway rejects the credentials. */
  readonly onAuthFailed?: () => void;
}

/**
 * Quote a value for a single-line management command.
 *
 * Only ever used for the username; the password goes through the base64
 * path, which needs no quoting at all.
 */
function quote(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * Is this OpenVPN known to support multi-line passwords?
 *
 * Deliberately conservative: it answers "is this a release branch we know
 * carries the feature", not "is this newer than 2.7.2". A future OpenVPN 3.x
 * is not assumed to speak the same management protocol - management
 * capabilities have been added and renumbered before, and guessing wrong
 * means the token silently fails to arrive. An unrecognised version falls
 * back to the credentials file, which works everywhere.
 */
export function supportsMultilinePassword(version: string | undefined): boolean {
  if (!version) return false;

  const [major, minor, patch] = version.split('.').map((part) => Number.parseInt(part, 10));
  if (major === undefined || minor === undefined) return false;
  if (!Number.isInteger(major) || !Number.isInteger(minor)) return false;

  // 2.7.2 introduced it.
  if (major === 2 && minor === 7) {
    return patch !== undefined && Number.isInteger(patch) && patch >= 2;
  }

  // 2.8 and later carry it forward.
  if (major === 2 && minor >= 8) return true;

  return false;
}

export class ManagementServer {
  private readonly options: ManagementServerOptions;
  private server: Server | undefined;
  private connection: Socket | undefined;
  private buffer = '';
  private authFailed = false;
  private credentialsSent = false;

  constructor(options: ManagementServerOptions) {
    this.options = options;
  }

  get path(): string {
    return this.options.socketPath;
  }

  /** True when the gateway explicitly rejected our token. */
  get sawAuthFailure(): boolean {
    return this.authFailed;
  }

  /** True once we have answered a credential request. */
  get hasSentCredentials(): boolean {
    return this.credentialsSent;
  }

  /**
   * Create and listen on the socket.
   *
   * Must complete before OpenVPN starts: with `management-client` OpenVPN
   * connects out, and a missing socket is a hard failure for it.
   */
  async start(): Promise<void> {
    // sockaddr_un.sun_path is 108 bytes on Linux, including the terminator.
    // bind() fails with a confusing EINVAL past that, and a long TMPDIR or a
    // deep XDG_RUNTIME_DIR can get there.
    const pathBytes = Buffer.byteLength(this.options.socketPath, 'utf8');
    if (pathBytes > MAX_UNIX_SOCKET_PATH) {
      throw new TunnelError(
        `the management socket path is ${pathBytes} bytes, over the ${MAX_UNIX_SOCKET_PATH}-byte limit`,
        {
          hint:
            'Unix socket paths are limited by sockaddr_un.sun_path. Set\n' +
            'XDG_RUNTIME_DIR to something shorter.',
        },
      );
    }

    // A stale socket from a crashed run would make bind fail.
    try {
      unlinkSync(this.options.socketPath);
    } catch {
      // Nothing there, which is the normal case.
    }

    const server = createServer((socket) => this.handleConnection(socket));
    this.server = server;

    await new Promise<void>((resolve, reject) => {
      server.once('error', (error) => {
        reject(new TunnelError('could not create the management socket', { cause: error }));
      });
      server.listen(this.options.socketPath, () => {
        try {
          // Only the owner may talk to this socket. OpenVPN runs as root,
          // which can connect regardless of mode.
          chmodSync(this.options.socketPath, 0o600);
          resolve();
        } catch (error) {
          reject(new TunnelError('could not restrict the management socket', { cause: error }));
        }
      });
    });

    this.options.onDebug?.(`management socket listening at ${this.options.socketPath}`);
  }

  private handleConnection(socket: Socket): void {
    // Exactly one client - OpenVPN. Refuse any second connection rather than
    // serving credentials to something unexpected.
    if (this.connection) {
      socket.destroy();
      return;
    }

    this.connection = socket;
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => this.ingest(chunk));
    socket.on('error', () => {
      /* OpenVPN exiting closes this; not worth surfacing. */
    });
    socket.on('close', () => {
      this.connection = undefined;
    });

    // Announce our version immediately, before releasing the hold, so that
    // client_version is already set if a password is requested at once.
    this.send(`version ${CLIENT_VERSION}`);
  }

  private ingest(chunk: string): void {
    this.buffer += chunk;
    let newline = this.buffer.indexOf('\n');

    while (newline !== -1) {
      const line = this.buffer.slice(0, newline).replace(/\r$/, '');
      this.buffer = this.buffer.slice(newline + 1);
      this.handleLine(line);
      newline = this.buffer.indexOf('\n');
    }
  }

  private send(command: string): void {
    this.connection?.write(`${command}\n`);
  }

  /**
   * Send the credentials.
   *
   * The username is short and goes on one line. The password is base64 and
   * split across lines, terminated by END - the only form that can carry a
   * multi-kilobyte token.
   */
  private sendCredentials(): void {
    const { username, password } = this.options.credentials;

    this.send(`username "Auth" ${quote(username)}`);

    // No inline value: this puts the management interface into multi-line
    // mode for the following base64 lines.
    this.send('password "Auth"');

    const encoded = Buffer.from(password, 'utf8').toString('base64');
    for (let offset = 0; offset < encoded.length; offset += BASE64_LINE_LENGTH) {
      this.send(encoded.slice(offset, offset + BASE64_LINE_LENGTH));
    }
    this.send('END');

    this.credentialsSent = true;
    this.options.onDebug?.(
      `management > supplied Auth credentials (${Math.ceil(encoded.length / BASE64_LINE_LENGTH)} base64 lines)`,
    );
  }

  private handleLine(rawLine: string): void {
    // Redact before anything else. OpenVPN echoes an over-long parameter
    // back at the client, and what it echoes is a slice of the token.
    const line = redact(rawLine);

    // Never log a line that could carry a credential back at us.
    if (!/^>PASSWORD:Need/.test(line)) {
      this.options.onDebug?.(`management < ${line}`);
    }

    if (line.startsWith('>HOLD:')) {
      // We start OpenVPN held so the management connection is definitely
      // established before it tries to authenticate.
      this.send('hold release');
      return;
    }

    if (line.startsWith(">PASSWORD:Need 'Auth'")) {
      this.sendCredentials();
      return;
    }

    if (line.startsWith('>PASSWORD:Verification Failed')) {
      this.authFailed = true;
      this.options.onAuthFailed?.();
      return;
    }

    if (/^ERROR:.*password too long/i.test(line)) {
      // The build's USER_PASS_LEN is smaller than the token. Worth saying
      // plainly, because the resulting failure is otherwise opaque.
      this.options.onDebug?.(
        "management: OpenVPN rejected the password as too long; this build's " +
          'USER_PASS_LEN is smaller than the Entra token',
      );
      return;
    }
  }

  /**
   * Stop the socket keeping the process alive, without closing it.
   *
   * For the one case where the socket is deliberately left open: OpenVPN could
   * not be confirmed stopped, and this is the only way left to reach it. It
   * still has to stop being a reason for the CLI to stay running - nothing
   * calls process.exit(), so a listening handle nobody is waiting on would
   * hang the command forever instead of letting it report and exit.
   */
  unref(): void {
    this.server?.unref();
    this.connection?.unref();
  }

  /** Close the socket and remove it from the filesystem. Never throws. */
  async stop(): Promise<void> {
    this.connection?.destroy();
    this.connection = undefined;

    const server = this.server;
    this.server = undefined;

    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        // close() waits for connections; ours is already destroyed.
        const timer = setTimeout(resolve, 500);
        timer.unref?.();
      });
    }

    try {
      unlinkSync(this.options.socketPath);
    } catch {
      // Already gone.
    }
  }
}
