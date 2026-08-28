/**
 * `openp2s probe`
 *
 * The three properties worth holding down by test:
 *
 *   1. a probe cannot alter the host, because of what its *config* says -
 *      not because of the uid it happens to run as;
 *   2. a probe never shares runtime paths with a live connect, or with
 *      another probe;
 *   3. verbose mode raises OpenVPN to verb 7, so nothing resembling a
 *      credential may reach any output stream.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { renderOpenVpnConfig } from '../src/openvpn/config.ts';
import { MAX_UNIX_SOCKET_PATH } from '../src/openvpn/management.ts';
import { probePaths, resolvePaths } from '../src/platform/paths.ts';
import { AzureProfileParser } from '../src/profile/parser.ts';

const PROFILE = new AzureProfileParser().parse(
  readFileSync(join(import.meta.dirname, 'fixtures/azure-schema.xml'), 'utf8'),
);

function probeConfig(): string {
  return renderOpenVpnConfig({
    profile: PROFILE,
    credentials: { kind: 'management', socketPath: '/run/user/1000/openp2s/probe/p1-ab/m.sock' },
    caPath: '/etc/ssl/certs/DigiCert_Global_Root_G2.pem',
    probe: true,
    verb: 7,
  });
}

describe('a probe cannot alter the host', () => {
  it('opens no interface', () => {
    // `dev null` is the guarantee. An unprivileged process is not one:
    // `sudo openp2s probe` is something a user can type, and an OpenVPN with
    // CAP_NET_ADMIN would not need sudo at all.
    const lines = probeConfig().split('\n');
    assert.ok(lines.includes('dev null'), 'probe must use the null device');
    assert.ok(!lines.includes('dev tun'), 'probe must not ask for a tun device');
  });

  it('refuses to act on a pushed address or route', () => {
    const lines = probeConfig().split('\n');
    assert.ok(lines.includes('route-noexec'), 'pushed routes must not be installed');
    assert.ok(lines.includes('ifconfig-noexec'), 'a pushed address must not be applied');
  });

  it('does not sit in a retry loop', () => {
    assert.ok(probeConfig().split('\n').includes('connect-retry-max 1'));
  });

  it('leaves a normal connect config unchanged', () => {
    // The directives above must be probe-only: a real connect has to open its
    // tun device and install the routes the gateway pushes.
    const lines = renderOpenVpnConfig({
      profile: PROFILE,
      credentials: { kind: 'management', socketPath: '/run/x.sock' },
      caPath: '/etc/ssl/certs/ca.pem',
    }).split('\n');

    assert.ok(lines.includes('dev tun'));
    assert.ok(!lines.includes('route-noexec'));
    assert.ok(!lines.includes('ifconfig-noexec'));
    assert.ok(!lines.includes('dev null'));
  });
});

describe('probe runtime isolation', () => {
  const base = resolvePaths({ XDG_RUNTIME_DIR: '/run/user/1000' }, { euid: 1000, egid: 1000 });

  it('shares no runtime path with a connect', () => {
    // Sharing them would let a probe's own cleanup delete the management
    // socket, config and credentials of a running tunnel.
    const probe = probePaths(base, 'p1234-abcdef01');

    for (const key of [
      'runtimeDir',
      'sessionFile',
      'lockFile',
      'credentialsFile',
      'managementSocket',
      'configFile',
      'logFile',
    ] as const) {
      assert.notEqual(probe[key], base[key], `${key} must not be shared with connect`);
    }
  });

  it('shares no runtime path between two probes', () => {
    const a = probePaths(base, 'p1-aaaaaaaa');
    const b = probePaths(base, 'p1-bbbbbbbb');
    assert.notEqual(a.managementSocket, b.managementSocket);
    assert.notEqual(a.runtimeDir, b.runtimeDir);
  });

  it('keeps the persistent token cache shared', () => {
    // Re-running a device-code login for every probe would be worse in every
    // way, and the cache is not runtime state.
    const probe = probePaths(base, 'p1-aaaaaaaa');
    assert.equal(probe.stateDir, base.stateDir);
    assert.equal(probe.cacheDir, base.cacheDir);
  });

  it('keeps the management socket inside the sun_path limit', () => {
    // The directory is nested one level deeper than a connect's, and
    // sockaddr_un.sun_path is 108 bytes.
    const probe = probePaths(base, `p${'9'.repeat(7)}-abcdef01`);
    assert.ok(
      probe.managementSocket.length <= MAX_UNIX_SOCKET_PATH,
      `${probe.managementSocket} is ${probe.managementSocket.length} bytes`,
    );
  });

  it('rejects an id that could escape the directory', () => {
    assert.throws(() => probePaths(base, '../../etc'));
    assert.throws(() => probePaths(base, 'a/b'));
    assert.throws(() => probePaths(base, ''));
  });
});

// Probe runs OpenVPN at verb 7, so anything token-shaped in its output must
// be scrubbed. That is redact()'s job and redaction.test.ts's subject; probe
// only has to route its log lines through it, which it does in one line.
describe('probe output and credentials', () => {
  it('does not put a credential in the generated config', () => {
    // The token reaches OpenVPN over the management socket, never the config.
    const config = probeConfig();
    assert.ok(config.includes('management-query-passwords'));
    const credentialsFile = config.split('\n').find((line) => /^auth-user-pass\s+\S/.test(line));
    assert.equal(credentialsFile, undefined, 'no credentials file is referenced');
  });
});

describe('probe --json', () => {
  function probe(args: readonly string[]): { code: number; stdout: string; stderr: string } {
    const result = spawnSync(
      process.execPath,
      [join(import.meta.dirname, '../src/cli/run.ts'), 'probe', ...args],
      { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } },
    );
    return { code: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
  }

  it('emits JSON even when the preflight fails', () => {
    // Scripts need the output most at the moment something is wrong; a
    // human-readable error on stdout would break `probe --json | jq`.
    const { code, stdout } = probe([join(tmpdir(), 'openp2s-no-such-profile.xml'), '--json']);

    const report = JSON.parse(stdout) as Record<string, unknown>;
    assert.equal(report['stage'], 'start');
    assert.equal(report['authenticated'], false);
    assert.match(String(report['error']), /profile not found/);
    assert.equal(code, 1);
  });

  it('separates the credential exchange from authentication', () => {
    // key-method-2 completing means the credential fitted through the control
    // channel - the thing a stock 128-byte USER_PASS_LEN breaks. The gateway
    // can still answer AUTH_FAILED straight afterwards, so the two must be
    // reported as different facts.
    const { stdout } = probe([join(tmpdir(), 'openp2s-no-such-profile.xml'), '--json']);
    const report = JSON.parse(stdout) as Record<string, unknown>;

    assert.ok('credentialExchangeCompleted' in report);
    assert.ok('authenticated' in report);
    assert.ok(!('reachedAuth' in report), 'the old, overclaiming name is gone');
  });

  it('rejects a nonsensical timeout', () => {
    const { stdout } = probe([
      join(import.meta.dirname, 'fixtures/azure-schema.xml'),
      '--json',
      '--timeout',
      '99999',
    ]);
    assert.match(String((JSON.parse(stdout) as Record<string, unknown>)['error']), /--timeout/);
  });
});
