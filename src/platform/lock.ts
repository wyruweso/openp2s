/**
 * The single-connection lock: an abstract-namespace Unix socket.
 *
 * The kernel grants the name atomically and reclaims it when the holder dies,
 * SIGKILL included. A pid file cannot do that - "read the holder, decide it is
 * dead, unlink" is not an atomic compare-and-delete, and O_EXCL publishes the
 * path before the pid is written to it - so both leave windows where two
 * connects proceed at once.
 *
 * The file beside it only *describes* the holder for error messages; it is
 * never consulted to decide ownership.
 */

import { createServer, type Server } from 'node:net';
import { readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { OpenP2SError } from '../errors.ts';

export interface LockHolder {
  readonly pid: number;
  /** From /proc; undefined if unreadable. Reported, never trusted. */
  readonly startTime: number | undefined;
  readonly acquiredAt: string;
}

/**
 * Process start time from /proc, field 22.
 *
 * Located from the last ')' because the comm field may itself contain spaces
 * and parentheses.
 */
export function processStartTime(pid: number): number | undefined {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const afterComm = stat.slice(stat.lastIndexOf(')') + 2);
    const fields = afterComm.split(' ');
    // stat field 22 is index 19 once the first two fields are removed.
    const value = Number(fields[19]);
    return Number.isFinite(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Is this exactly the process we recorded?
 *
 * EPERM counts as alive: that is the normal answer for a root-owned OpenVPN
 * seen from a user shell. The start time distinguishes it from a recycled pid.
 */
export function isProcessAlive(pid: number | undefined, startTime?: number): boolean {
  if (pid === undefined || !Number.isInteger(pid) || pid <= 0) return false;

  try {
    process.kill(pid, 0);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EPERM') return false;
  }

  if (startTime === undefined) return true;

  const current = processStartTime(pid);
  // Unreadable /proc (a process we cannot see) is not evidence of death.
  if (current === undefined) return true;
  return current === startTime;
}

export interface LockAcquisition {
  readonly acquired: boolean;
  /** Absent when the descriptive file is missing; the outcome is unchanged. */
  readonly heldBy?: LockHolder;
}

/**
 * Machine-wide, not per-user: a connection contends for the tun device, the
 * routing table and systemd-resolved, all of which are system-wide.
 *
 * The abstract namespace is not protected by the runtime directory, so another
 * local user can squat the name. That denies service; it cannot take the lock
 * or allow two connections.
 *
 * `scope` lets tests take independent locks.
 */
function lockName(scope: string | undefined): string {
  return scope ? `\0openp2s-connect-${scope}` : '\0openp2s-connect';
}

/** Held for the lifetime of a `connect`; released by the kernel if we die. */
export class ConnectionLock {
  private readonly path: string;
  private readonly name: string;
  private server: Server | undefined;

  /**
   * @param path  descriptive holder file, in the private runtime directory
   * @param scope test-only namespace suffix; production takes the global name
   */
  constructor(path: string, scope?: string) {
    this.path = path;
    this.name = lockName(scope);
  }

  get filePath(): string {
    return this.path;
  }

  get isHeld(): boolean {
    return this.server !== undefined;
  }

  /** Read the recorded holder, if the descriptive file exists and parses. */
  read(): LockHolder | undefined {
    try {
      const parsed: unknown = JSON.parse(readFileSync(this.path, 'utf8'));
      if (!parsed || typeof parsed !== 'object') return undefined;
      const record = parsed as Record<string, unknown>;
      const pid = Number(record['pid']);
      if (!Number.isInteger(pid) || pid <= 0) return undefined;
      const startTime = Number(record['startTime']);
      return {
        pid,
        startTime: Number.isFinite(startTime) ? startTime : undefined,
        acquiredAt: typeof record['acquiredAt'] === 'string' ? record['acquiredAt'] : 'unknown',
      };
    } catch {
      return undefined;
    }
  }

  /**
   * Take the lock, or report who holds it. No retry: there is no stale state.
   *
   * Async by necessity - `listen()` reports EADDRINUSE as an event, so a
   * synchronous wrapper would return "acquired" before the conflict is known.
   */
  async acquire(): Promise<LockAcquisition> {
    if (this.server) return { acquired: true };

    const server = createServer();
    // Nothing ever connects to this socket; it exists to hold a name.
    server.on('connection', (socket) => socket.destroy());
    server.unref();

    try {
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen({ path: this.name, exclusive: true }, () => {
          server.removeListener('error', reject);
          resolve();
        });
      });
    } catch (error) {
      server.close();
      return this.describeConflict(error);
    }

    // Later errors are not fatal: the name is held for the process's lifetime.
    server.on('error', () => undefined);
    this.server = server;
    this.writeHolderFile();
    return { acquired: true };
  }

  private describeConflict(error: unknown): LockAcquisition {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'EADDRINUSE') {
      throw new OpenP2SError('could not take the connection lock', { cause: error });
    }
    const holder = this.read();
    return holder ? { acquired: false, heldBy: holder } : { acquired: false };
  }

  /** Best-effort: the lock does not depend on this file. */
  private writeHolderFile(): void {
    const holder: LockHolder = {
      pid: process.pid,
      startTime: processStartTime(process.pid),
      acquiredAt: new Date().toISOString(),
    };
    try {
      writeFileSync(this.path, `${JSON.stringify(holder, null, 2)}\n`, { mode: 0o600 });
    } catch {
      // Purely descriptive; losing it costs a better error message elsewhere.
    }
  }

  /**
   * Release the lock. Never throws: this runs on teardown paths.
   *
   * Closing the socket releases ownership; the file goes only if we held it.
   */
  release(): void {
    if (!this.server) return;
    const server = this.server;
    this.server = undefined;

    try {
      server.close();
    } catch {
      // Already closed.
    }
    try {
      unlinkSync(this.path);
    } catch {
      // Already gone.
    }
  }
}
