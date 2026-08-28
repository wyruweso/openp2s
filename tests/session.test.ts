/**
 * The session record: how `status` and `disconnect` find a tunnel that
 * `connect` owns in another terminal.
 *
 * The failure that matters is a reader concluding there is no session when
 * there is one.
 */

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { OpenP2SError } from '../src/errors.ts';
import { SessionStore, type SessionRecord } from '../src/platform/session.ts';

let workDir: string;
let store: SessionStore;
let path: string;

const RECORD: SessionRecord = {
  version: 1,
  profileName: 'Contoso',
  gateway: 'gw.example.invalid',
  openvpnPid: 4242,
  openvpnStartTime: 99,
  ownerPid: 1234,
  interfaceName: 'tun0',
  assignedAddress: '10.0.0.2',
  dnsServers: ['10.0.0.53'],
  dnsDomains: ['corp.example'],
  pushedRoutes: ['10.0.0.0/16'],
  includeRoutes: [],
  account: 'user@example.com',
  connectedAt: '2026-08-28T12:00:00.000Z',
  credentialsPath: '',
  managementSocket: '/run/user/1000/openp2s/mgmt.sock',
  configPath: '/run/user/1000/openp2s/openvpn.conf',
};

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-session-'));
  path = join(workDir, 'session.json');
  store = new SessionStore(path);
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

describe('writes are atomic', () => {
  it('never lets a reader see a partial record', async () => {
    const large: SessionRecord = { ...RECORD, configPath: 'x'.repeat(1_000_000) };
    await store.write(large);

    let done = false;
    let reads = 0;
    let missing = 0;
    const reader = (async () => {
      while (!done) {
        reads += 1;
        if (!(await store.read())) missing += 1;
      }
    })();

    for (let i = 0; i < 30; i += 1) await store.write(large);
    done = true;
    await reader;

    assert.ok(reads > 0, 'the reader should have run');
    assert.equal(missing, 0, `${missing} of ${reads} reads saw no session`);
  });

  it('leaves no temporary files behind', async () => {
    await store.write(RECORD);
    await store.write(RECORD);
    assert.deepEqual(readdirSync(workDir), ['session.json']);
  });

  it('writes 0600', async () => {
    await store.write(RECORD);
    assert.equal(statSync(path).mode & 0o777, 0o600);
  });

  it('round-trips a record', async () => {
    await store.write(RECORD);
    assert.deepEqual(await store.read(), RECORD);
  });
});

describe('reading rejects what it cannot act on', () => {
  it('returns undefined when there is no file', async () => {
    assert.equal(await store.read(), undefined);
  });

  it('returns undefined for unparseable content', async () => {
    writeFileSync(path, 'not json');
    assert.equal(await store.read(), undefined);
  });

  it('rejects a record of the wrong version', async () => {
    writeFileSync(path, JSON.stringify({ ...RECORD, version: 2 }));
    assert.equal(await store.read(), undefined);
  });

  it('rejects a record that is only a version', async () => {
    writeFileSync(path, JSON.stringify({ version: 1 }));
    assert.equal(await store.read(), undefined);
  });

  it('rejects a record whose teardown paths are not strings', async () => {
    for (const field of ['credentialsPath', 'managementSocket', 'configPath']) {
      writeFileSync(path, JSON.stringify({ ...RECORD, [field]: 42 }));
      assert.equal(await store.read(), undefined, `${field} must be a string`);
    }
  });

  it('rejects a record whose list fields are not lists of strings', async () => {
    writeFileSync(path, JSON.stringify({ ...RECORD, dnsServers: 'not-a-list' }));
    assert.equal(await store.read(), undefined);

    writeFileSync(path, JSON.stringify({ ...RECORD, dnsServers: [1, 2] }));
    assert.equal(await store.read(), undefined);
  });

  it('accepts a record with no openvpn pid, which is a real state', async () => {
    const { openvpnPid: _pid, ...withoutPid } = RECORD;
    writeFileSync(path, JSON.stringify(withoutPid));
    assert.ok(await store.read());
  });
});

describe('clearing', () => {
  it('removes the record', async () => {
    await store.write(RECORD);
    await store.clear();
    assert.equal(await store.read(), undefined);
  });

  it('treats an already-missing record as success', async () => {
    await store.clear();
  });

  it('reports a removal it could not perform', async () => {
    // A failed removal must not look like completed cleanup.
    const unwritable = new SessionStore(join(workDir, 'no-such-dir', 'session.json'));
    await store.write(RECORD);
    // A directory in place of the file: unlink fails with EISDIR, not ENOENT.
    const asDir = join(workDir, 'dir-session');
    rmSync(asDir, { recursive: true, force: true });
    mkdirSync(asDir);
    const blocked = new SessionStore(asDir);

    await assert.rejects(() => blocked.clear(), OpenP2SError);
    assert.ok(unwritable);
  });
});
