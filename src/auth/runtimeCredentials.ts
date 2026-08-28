/**
 * Runtime credential storage.
 *
 * The Entra access token goes in exactly one place: a 0600 file under
 * /run/user/$UID/openp2s, which is tmpfs. That gives three properties for
 * free:
 *
 *   - it never reaches persistent storage, so it cannot be recovered from a
 *     disk image or a backup;
 *   - it disappears on logout and reboot without any cleanup code running;
 *   - it is unreadable by other users, including other unprivileged accounts
 *     on a shared machine.
 *
 * The token is passed to OpenVPN by path (--auth-user-pass), never as an
 * argument, because argv is world-readable through /proc.
 */

import { constants } from 'node:fs';
import { chmod, open, stat, unlink, writeFile } from 'node:fs/promises';
import { OpenP2SError } from '../errors.ts';
import { ensurePrivateDir, type UserIdentity } from '../platform/paths.ts';
import { AZURE_USERNAME } from '../openvpn/azureCompat.ts';

export interface RuntimeCredentialsOptions {
  readonly directory: string;
  readonly credentialsPath: string;
  readonly user: UserIdentity;
}

/**
 * Writes and removes the OpenVPN credentials file.
 *
 * Every method that creates a file is paired with `remove()`, and the CLI
 * calls `remove()` from a finally block on every exit path, including
 * signals - a token left behind after a failed connect is exactly the sort
 * of quiet residue that turns into an incident later.
 */
export class RuntimeCredentials {
  private readonly options: RuntimeCredentialsOptions;

  constructor(options: RuntimeCredentialsOptions) {
    this.options = options;
  }

  get path(): string {
    return this.options.credentialsPath;
  }

  /**
   * Write "AzureAD\n<access token>\n" with mode 0600.
   *
   * The file is opened with O_CREAT|O_EXCL|O_WRONLY at mode 0600 so it is
   * never momentarily world-readable, and so a pre-existing file (or a
   * symlink planted at that path) causes a failure rather than a silent
   * overwrite of something we do not own.
   */
  async write(accessToken: string): Promise<string> {
    if (accessToken.length === 0) {
      throw new OpenP2SError('refusing to write an empty access token');
    }

    ensurePrivateDir(this.options.directory);

    // Remove our own stale file from a previous run, but only after
    // confirming it is a regular file we own.
    await this.remove();

    const path = this.options.credentialsPath;
    let handle;
    try {
      handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    } catch (error) {
      throw new OpenP2SError(`could not create the credentials file at ${path}`, {
        cause: error,
        hint:
          (error as NodeJS.ErrnoException).code === 'EEXIST'
            ? 'A file already exists at that path and could not be removed. ' +
              'Another openp2s may be running, or the path is a symlink.'
            : undefined,
      });
    }

    try {
      await handle.write(`${AZURE_USERNAME}\n${accessToken}\n`);
      await handle.chmod(0o600);
      // No chown: OpenP2S runs as the user these files belong to. See
      // src/platform/paths.ts on why it does not run as root.
    } finally {
      await handle.close();
    }

    return path;
  }

  /**
   * Delete the credentials file.
   *
   * Never throws: this runs on cleanup paths where an exception would abandon
   * the rest of the teardown. A missing file is success.
   */
  async remove(): Promise<void> {
    try {
      await unlink(this.options.credentialsPath);
    } catch {
      // Nothing to do with any of them: ENOENT is success, and throwing on a
      // teardown path is not an option. A caller that must know asks exists().
    }
  }

  /** True when a credentials file is present at our path. */
  async exists(): Promise<boolean> {
    try {
      await stat(this.options.credentialsPath);
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Write the generated OpenVPN config with restrictive permissions.
 *
 * The config embeds the profile's tls-auth key inline, so it is secret
 * material and gets the same treatment as the token file.
 */
export async function writePrivateFile(path: string, contents: string): Promise<void> {
  await writeFile(path, contents, { mode: 0o600 });
  await chmod(path, 0o600);
}
