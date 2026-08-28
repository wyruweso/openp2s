/**
 * Persistent token cache.
 *
 * The blob under test holds a refresh token, so the interesting properties
 * are about file modes and atomicity rather than about contents.
 */

import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { FileTokenCacheStore } from '../src/auth/cache/fileStore.ts';
import { cacheKey } from '../src/auth/cache/identity.ts';
import { OpenP2SError } from '../src/errors.ts';

let directory: string;
let store: FileTokenCacheStore;

const IDENTITY = {
  authority: 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555',
  audience: '41b23e61-6c1e-4545-b367-cd054e0ed4b4',
  clientId: '41b23e61-6c1e-4545-b367-cd054e0ed4b4',
};

beforeEach(() => {
  directory = join(mkdtempSync(join(tmpdir(), 'openp2s-cache-')), 'cache');
  store = new FileTokenCacheStore({ directory });
});

afterEach(() => {
  rmSync(join(directory, '..'), { recursive: true, force: true });
});

describe('cacheKey', () => {
  it('is stable for the same identity', () => {
    assert.equal(cacheKey(IDENTITY), cacheKey({ ...IDENTITY }));
  });

  it('changes when the tenant changes', () => {
    const other = {
      ...IDENTITY,
      authority: 'https://login.microsoftonline.com/99999999-8888-7777-6666-555555555555',
    };
    assert.notEqual(cacheKey(IDENTITY), cacheKey(other));
  });

  it('changes when the audience changes', () => {
    // Two audiences in one tenant must not share a cache: the tokens carry
    // different scopes and are not interchangeable.
    const other = { ...IDENTITY, audience: 'c632b3df-fb67-4d84-bdcf-b95ad541b5c8' };
    assert.notEqual(cacheKey(IDENTITY), cacheKey(other));
  });

  it('changes when the client id changes', () => {
    const other = { ...IDENTITY, clientId: 'c632b3df-fb67-4d84-bdcf-b95ad541b5c8' };
    assert.notEqual(cacheKey(IDENTITY), cacheKey(other));
  });

  it('ignores case, so a differently-cased profile reuses the session', () => {
    const upper = {
      authority: IDENTITY.authority.toUpperCase(),
      audience: IDENTITY.audience.toUpperCase(),
      clientId: IDENTITY.clientId.toUpperCase(),
    };
    assert.equal(cacheKey(IDENTITY), cacheKey(upper));
  });

  it('is filesystem-safe even for URI audiences', () => {
    const uriAudience = { ...IDENTITY, audience: 'https://vpn.contoso.example/gateway' };
    assert.match(cacheKey(uriAudience), /^[a-f0-9]{32}$/);
  });
});

describe('FileTokenCacheStore', () => {
  it('returns undefined for a key that was never saved', async () => {
    assert.equal(await store.load(cacheKey(IDENTITY)), undefined);
  });

  it('round-trips a cache blob', async () => {
    const key = cacheKey(IDENTITY);
    const blob = JSON.stringify({ Account: {}, RefreshToken: {} });

    await store.save(key, blob);
    assert.equal(await store.load(key), blob);
  });

  it('creates the cache directory 0700', async () => {
    await store.save(cacheKey(IDENTITY), '{}');
    assert.equal(statSync(directory).mode & 0o777, 0o700);
  });

  it('writes the cache file 0600', async () => {
    const key = cacheKey(IDENTITY);
    await store.save(key, '{}');

    const [file] = readdirSync(directory);
    assert.ok(file);
    assert.equal(statSync(join(directory, file)).mode & 0o777, 0o600);
  });

  it('overwrites an existing entry atomically, leaving no temp file', async () => {
    const key = cacheKey(IDENTITY);
    await store.save(key, '{"v":1}');
    await store.save(key, '{"v":2}');

    assert.equal(await store.load(key), '{"v":2}');
    assert.deepEqual(
      readdirSync(directory).filter((entry) => entry.includes('.tmp')),
      [],
      'no temporary file should survive a save',
    );
  });

  it('lists saved keys', async () => {
    const first = cacheKey(IDENTITY);
    const second = cacheKey({ ...IDENTITY, audience: 'c632b3df-fb67-4d84-bdcf-b95ad541b5c8' });

    await store.save(first, '{}');
    await store.save(second, '{}');

    const listed = await store.list();
    assert.equal(listed.length, 2);
    assert.ok(listed.includes(first));
    assert.ok(listed.includes(second));
  });

  it('lists nothing when the directory does not exist yet', async () => {
    assert.deepEqual(await store.list(), []);
  });

  it('deletes an entry', async () => {
    const key = cacheKey(IDENTITY);
    await store.save(key, '{}');
    await store.delete(key);

    assert.equal(await store.load(key), undefined);
    assert.deepEqual(await store.list(), []);
  });

  it('treats deleting a missing entry as success', async () => {
    await store.delete(cacheKey(IDENTITY));
  });

  it('refuses a cache that became readable by other users', async () => {
    // A world-readable refresh token is treated as compromised: better to
    // force a fresh sign-in than to keep using it.
    const key = cacheKey(IDENTITY);
    await store.save(key, '{"secret":"x"}');

    const file = join(directory, `${key}.msal.json`);
    chmodSync(file, 0o644);

    await assert.rejects(
      () => store.load(key),
      (error: unknown) => {
        assert.ok(error instanceof OpenP2SError);
        assert.match(error.message, /readable by other users/);
        return true;
      },
    );

    assert.ok(!existsSync(file), 'the exposed cache must be deleted, not merely rejected');
  });

  it('refuses a malformed cache key rather than building a path from it', async () => {
    // The key becomes a file name, so path traversal must be impossible even
    // though every real key comes from cacheKey().
    for (const bad of ['../escape', 'a/b', '..', 'NOTHEX', '']) {
      await assert.rejects(() => store.load(bad), /malformed cache key/);
      await assert.rejects(() => store.save(bad, '{}'), /malformed cache key/);
    }
  });

  it('ignores unrelated files in the cache directory', async () => {
    await store.save(cacheKey(IDENTITY), '{}');
    writeFileSync(join(directory, 'README.txt'), 'not a cache');

    assert.deepEqual(await store.list(), [cacheKey(IDENTITY)]);
  });
});
