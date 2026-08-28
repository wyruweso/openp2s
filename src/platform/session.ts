/**
 * Connection state, so `status` and `disconnect` work from another terminal.
 *
 * `connect` runs in the foreground and owns the openvpn process, but the user
 * will reasonably open a second shell to check on it or shut it down. The
 * session record in the runtime directory is how those commands find the
 * running tunnel.
 *
 * It records no secrets - only paths to credential artifacts, never a token.
 *
 * Writes are atomic. writeFile truncates first, and a reader landing in that
 * window sees an unparseable file and concludes there is no session:
 * `openp2s disconnect` answering "Not connected" over a live tunnel.
 */

import { readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { dirname, join } from 'node:path';
import { OpenP2SError } from '../errors.ts';

export interface SessionRecord {
  readonly version: 1;
  readonly profileName: string;
  readonly gateway: string;
  /** pid of the openvpn process, which may be a sudo child. */
  readonly openvpnPid: number | undefined;
  /**
   * Start time of that process, from /proc.
   *
   * Recorded so a recycled pid cannot make a dead tunnel look alive. See
   * src/platform/lock.ts.
   */
  readonly openvpnStartTime?: number | undefined;
  /**
   * Set by `openp2s disconnect` before it signals OpenVPN.
   *
   * Without it, a foreground `connect` cannot tell "the user asked for this"
   * from "the tunnel died", and would report a requested disconnect as a
   * failure.
   */
  readonly disconnectRequestedAt?: string | undefined;
  /** pid of the openp2s process that owns this session. */
  readonly ownerPid: number;
  readonly interfaceName: string | undefined;
  readonly assignedAddress: string | undefined;
  readonly dnsServers: readonly string[];
  readonly dnsDomains: readonly string[];
  readonly pushedRoutes: readonly string[];
  readonly includeRoutes: readonly string[];
  readonly account: string | undefined;
  readonly connectedAt: string;
  /**
   * The OpenVPN that started this tunnel. Recorded, not looked up later: the
   * binary found now may not be the one running.
   */
  readonly openvpn?: {
    readonly path: string;
    readonly version: string | undefined;
    readonly commit: string | undefined;
    readonly patchStack: string | undefined;
    readonly binarySha256: string | undefined;
    readonly userPassLen: number;
    readonly azureCompatAvailable: boolean;
  };
  /** Paths to remove on teardown. */
  readonly credentialsPath: string;
  readonly managementSocket: string;
  readonly configPath: string;
}

export class SessionStore {
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  get filePath(): string {
    return this.path;
  }

  /**
   * Replace the record via temp file + rename, so a concurrent reader sees
   * either the old record or the new one.
   *
   * No fsync: this is tmpfs. It must survive a concurrent read, not a crash.
   */
  async write(record: SessionRecord): Promise<void> {
    const temp = join(
      dirname(this.path),
      `.session.${process.pid}.${randomBytes(6).toString('hex')}`,
    );

    try {
      await writeFile(temp, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
      await rename(temp, this.path);
    } catch (error) {
      await unlink(temp).catch(() => undefined);
      throw new OpenP2SError('could not write the session record', { cause: error });
    }
  }

  /**
   * Read the session record.
   *
   * Returns undefined when there is no session. A corrupt record is also
   * treated as "no session" rather than an error, because the useful response
   * either way is to clean up and move on.
   */
  async read(): Promise<SessionRecord | undefined> {
    let contents: string;
    try {
      contents = await readFile(this.path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new OpenP2SError('could not read the session record', { cause: error });
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(contents);
    } catch {
      return undefined;
    }
    return isSessionRecord(parsed) ? parsed : undefined;
  }

  /**
   * Forget the session. Only a missing file counts as success - a failed
   * removal must not look like completed cleanup.
   */
  async clear(): Promise<void> {
    try {
      await unlink(this.path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw new OpenP2SError(`could not remove the session record at ${this.path}`, {
        cause: error,
      });
    }
  }
}

export { isProcessAlive, processStartTime } from './lock.ts';

/**
 * Shape check over the fields the lifecycle depends on. Not a schema library -
 * enough that teardown never reads an undefined path or pid.
 */
function isSessionRecord(value: unknown): value is SessionRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;

  if (record['version'] !== 1) return false;

  for (const field of ['profileName', 'gateway', 'connectedAt'] as const) {
    if (typeof record[field] !== 'string' || record[field] === '') return false;
  }

  // Teardown interpolates these into paths.
  for (const field of ['credentialsPath', 'managementSocket', 'configPath'] as const) {
    if (typeof record[field] !== 'string') return false;
  }

  for (const field of ['dnsServers', 'dnsDomains', 'pushedRoutes', 'includeRoutes'] as const) {
    if (!Array.isArray(record[field])) return false;
    if ((record[field] as unknown[]).some((entry) => typeof entry !== 'string')) return false;
  }

  if (typeof record['ownerPid'] !== 'number') return false;
  if (record['openvpnPid'] !== undefined && typeof record['openvpnPid'] !== 'number') return false;

  return true;
}
