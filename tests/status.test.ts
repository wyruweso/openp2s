/**
 * `openp2s status`
 *
 * Two things are worth pinning down here.
 *
 * The first is the JSON contract: it is an explicit projection of the session
 * record, not the record itself, so that an internal field added tomorrow does
 * not silently become part of a public API.
 *
 * The second is that "connected" is a derived claim. A live pid is not enough
 * - OpenVPN outlives a dropped gateway connection - so the states below are
 * exercised directly.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { processStartTime } from '../src/platform/lock.ts';
import type { SessionRecord } from '../src/platform/session.ts';

const RUN = join(import.meta.dirname, '../src/cli/run.ts');

let runtimeDir: string;

beforeEach(() => {
  runtimeDir = mkdtempSync(join(tmpdir(), 'openp2s-status-'));
  mkdirSync(join(runtimeDir, 'openp2s'), { mode: 0o700 });
});

afterEach(() => {
  rmSync(runtimeDir, { recursive: true, force: true });
});

function writeSession(record: Partial<SessionRecord>): void {
  const full: SessionRecord = {
    version: 1,
    profileName: 'Contoso',
    gateway: 'gw.example.invalid',
    openvpnPid: process.pid,
    openvpnStartTime: processStartTime(process.pid),
    ownerPid: process.pid,
    interfaceName: 'lo',
    assignedAddress: '10.0.0.2',
    dnsServers: ['10.0.0.53'],
    dnsDomains: ['corp.example'],
    pushedRoutes: ['10.0.0.0/16'],
    includeRoutes: [],
    account: 'user@example.com',
    connectedAt: new Date(Date.now() - 3725_000).toISOString(),
    credentialsPath: '',
    managementSocket: '',
    configPath: '',
    ...record,
  };
  writeFileSync(join(runtimeDir, 'openp2s/session.json'), JSON.stringify(full), { mode: 0o600 });
}

function status(args: readonly string[] = []): {
  code: number;
  stdout: string;
  stderr: string;
} {
  const result = spawnSync(process.execPath, [RUN, 'status', ...args], {
    encoding: 'utf8',
    env: { ...process.env, XDG_RUNTIME_DIR: runtimeDir, NO_COLOR: '1' },
  });
  return { code: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
}

describe('status states', () => {
  it('reports disconnected with no session record', () => {
    const { code, stdout } = status(['--json']);
    const result = JSON.parse(stdout) as Record<string, unknown>;

    assert.equal(result['state'], 'disconnected');
    assert.equal(result['connected'], false);
    assert.equal(code, 1);
  });

  it('reports connected when the process is alive and its interface exists', () => {
    // `lo` always exists, which is what makes this assertable without root.
    writeSession({ interfaceName: 'lo' });
    const { code, stdout } = status(['--json']);
    const result = JSON.parse(stdout) as Record<string, unknown>;

    assert.equal(result['state'], 'connected');
    assert.equal(result['connected'], true);
    assert.equal(code, 0);
  });

  it('reports reconnecting when the process is alive but the interface is gone', () => {
    // The failure a pid check alone cannot see: OpenVPN survives a dropped
    // gateway connection and keeps retrying, carrying no traffic meanwhile.
    writeSession({ interfaceName: 'tun-openp2s-absent' });
    const { code, stdout } = status(['--json']);
    const result = JSON.parse(stdout) as Record<string, unknown>;

    assert.equal(result['state'], 'reconnecting');
    assert.equal(result['connected'], false);
    assert.equal(code, 1);
  });

  it('reports disconnecting once a disconnect has been requested', () => {
    writeSession({ disconnectRequestedAt: new Date().toISOString() });
    const { stdout } = status(['--json']);
    assert.equal((JSON.parse(stdout) as Record<string, unknown>)['state'], 'disconnecting');
  });

  it('reports stale when the recorded process is gone', () => {
    writeSession({ openvpnPid: 2 ** 30, openvpnStartTime: 1 });
    const { code, stdout } = status(['--json']);
    const result = JSON.parse(stdout) as Record<string, unknown>;

    assert.equal(result['state'], 'stale');
    assert.equal(code, 1);
  });

  it('reports stale when the pid was recycled by another process', () => {
    // Our own pid, but a start time that cannot match.
    writeSession({ openvpnStartTime: (processStartTime(process.pid) ?? 0) + 1 });
    const { stdout } = status(['--json']);
    assert.equal((JSON.parse(stdout) as Record<string, unknown>)['state'], 'stale');
  });

  it('tells the user how to clean up a stale record rather than clearing it', () => {
    writeSession({ openvpnPid: 2 ** 30, openvpnStartTime: 1 });
    const { stderr } = status();
    assert.match(stderr, /stale session record/);
    assert.match(stderr, /openp2s disconnect/);
  });
});

describe('the --json contract', () => {
  it('does not leak internal session fields', () => {
    // Spreading the session record would make teardown paths, the owner pid
    // and every future internal field part of a public API by accident.
    writeSession({
      credentialsPath: '/run/user/1000/openp2s/credentials',
      managementSocket: '/run/user/1000/openp2s/mgmt.sock',
      configPath: '/run/user/1000/openp2s/openvpn.conf',
    });
    const { stdout } = status(['--json']);
    const result = JSON.parse(stdout) as Record<string, unknown>;

    for (const internal of [
      'credentialsPath',
      'managementSocket',
      'configPath',
      'ownerPid',
      'openvpnPid',
      'openvpnStartTime',
      'version',
      'profileName',
      'interfaceName',
    ]) {
      assert.ok(!(internal in result), `${internal} must not appear in the public output`);
    }
    assert.ok(!stdout.includes('mgmt.sock'), 'no runtime paths in the output');
  });

  it('publishes exactly the documented keys', () => {
    writeSession({});
    const { stdout } = status(['--json']);
    const keys = Object.keys(JSON.parse(stdout) as Record<string, unknown>).sort();

    assert.deepEqual(keys, [
      'account',
      'address',
      'connected',
      'connectedAt',
      'dnsDomains',
      'dnsServers',
      'gateway',
      'includeRoutes',
      'interface',
      'openvpn',
      'profile',
      'pushedRoutes',
      'state',
      'uptimeSeconds',
    ]);
  });

  it('gives uptime as a number, not a phrase', () => {
    writeSession({ connectedAt: new Date(Date.now() - 3725_000).toISOString() });
    const { stdout } = status(['--json']);
    const result = JSON.parse(stdout) as Record<string, unknown>;

    assert.equal(typeof result['uptimeSeconds'], 'number');
    assert.ok((result['uptimeSeconds'] as number) >= 3720);
  });

  it('keeps stdout to exactly one JSON document', () => {
    writeSession({});
    const { stdout } = status(['--json', '--verbose']);
    assert.doesNotThrow(() => JSON.parse(stdout));
  });
});

describe('status provenance', () => {
  it('reports the build recorded at connect time', () => {
    // Not whatever binary would be located now: --openvpn-binary, or a
    // rebuilt default, would otherwise make status describe a build that is
    // not the one running.
    writeSession({
      openvpn: {
        path: '/tmp/openvpn-experiment',
        version: '2.7.6',
        commit: 'abc123',
        patchStack: 'long-credentials',
        binarySha256: 'f'.repeat(64),
        userPassLen: 4096,
        azureCompatAvailable: false,
      },
    });

    const { stdout } = status(['--json']);
    const openvpn = (JSON.parse(stdout) as Record<string, Record<string, unknown>>)['openvpn'];
    assert.equal(openvpn?.['version'], '2.7.6');
    assert.equal(openvpn?.['patchStack'], 'long-credentials');
    assert.equal(openvpn?.['userPassLen'], 4096);
    // The local path is recovery state, not part of the published result.
    assert.ok(!('path' in (openvpn ?? {})), 'binary path must not be published');
  });

  it('survives a session written before provenance was recorded', () => {
    writeSession({});
    const { code, stdout } = status(['--json']);
    assert.equal((JSON.parse(stdout) as Record<string, unknown>)['openvpn'], null);
    assert.equal(code, 0);
  });

  it('names the patch stack and credential ceiling in verbose output', () => {
    // What a bug report needs: which patches this build carries and how large
    // a token it can take. A generic "Azure patch" said neither.
    writeSession({
      openvpn: {
        path: '/usr/sbin/openvpn-openp2s',
        version: '2.7.6',
        commit: 'abc123',
        patchStack: 'long-credentials',
        binarySha256: 'f'.repeat(64),
        userPassLen: 4096,
        azureCompatAvailable: false,
      },
    });
    const { stdout } = status(['--verbose']);
    assert.match(stdout, /long-credentials/);
    assert.match(stdout, /4096/);
  });
});
