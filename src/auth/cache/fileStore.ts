/**
 * File-backed token cache.
 *
 * The MVP backend: one 0600 file per (tenant, audience, client) triple in the
 * 0700 state directory. Not as strong as a keyring - the blob is readable by
 * anything running as this user - but it is honest about that, and it sits
 * behind TokenCacheStore so a Secret Service backend can replace it without
 * touching the authenticator.
 *
 * The blob holds a refresh token, so every write goes through a private
 * temporary file and an atomic rename. A partially written cache would at
 * best force a re-login, and at worst leave a truncated credential readable
 * for a moment at the wrong mode.
 */

import { constants } from 'node:fs';
import { chmod, mkdir, readdir, readFile, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { OpenP2SError } from '../../errors.ts';
import type { TokenCacheStore } from './store.ts';

const SUFFIX = '.msal.json';

export interface FileTokenCacheOptions {
  readonly directory: string;
}

export class FileTokenCacheStore implements TokenCacheStore {
  private readonly directory: string;

  constructor(options: FileTokenCacheOptions) {
    this.directory = options.directory;
  }

  private path(key: string): string {
    // Keys come from cacheKey(), which is a hex digest - but this value
    // becomes a path, so verify rather than trust.
    if (!/^[a-f0-9]{8,64}$/.test(key)) {
      throw new OpenP2SError(`refusing to use malformed cache key: ${key}`);
    }
    return join(this.directory, `${key}${SUFFIX}`);
  }

  private async ensureDirectory(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await chmod(this.directory, 0o700);
  }

  async load(key: string): Promise<string | undefined> {
    const path = this.path(key);

    let contents: string;
    try {
      contents = await readFile(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new OpenP2SError('could not read the token cache', { cause: error });
    }

    // A cache that became group- or world-readable is treated as
    // compromised: refuse it and force a fresh login rather than keep using
    // a credential other users may have seen.
    const stats = await stat(path);
    if (stats.mode & (constants.S_IRWXG | constants.S_IRWXO)) {
      await unlink(path).catch(() => undefined);
      throw new OpenP2SError(
        `token cache ${path} was readable by other users; it has been deleted`,
        { hint: 'Sign in again with: openp2s connect <profile>' },
      );
    }

    return contents;
  }

  async save(key: string, value: string): Promise<void> {
    await this.ensureDirectory();

    const path = this.path(key);
    // Same directory, so the rename is atomic; pid-suffixed so two concurrent
    // connects cannot clobber each other's temporary file.
    const temporary = `${path}.${process.pid}.tmp`;

    try {
      await writeFile(temporary, value, { mode: 0o600, flag: 'wx' });
      await chmod(temporary, 0o600);
      await rename(temporary, path);
    } catch (error) {
      await unlink(temporary).catch(() => undefined);
      throw new OpenP2SError('could not write the token cache', { cause: error });
    }
  }

  async delete(key: string): Promise<void> {
    try {
      await unlink(this.path(key));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw new OpenP2SError('could not delete the token cache', { cause: error });
      }
    }
  }

  async list(): Promise<string[]> {
    try {
      const entries = await readdir(this.directory);
      return entries
        .filter((entry) => entry.endsWith(SUFFIX))
        .map((entry) => entry.slice(0, -SUFFIX.length));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw new OpenP2SError('could not list the token cache', { cause: error });
    }
  }
}
