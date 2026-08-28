/**
 * Connection lifecycle and cleanup.
 *
 * The central claim these tests defend is: whatever goes wrong, the access
 * token does not survive it. Each case drives a different failure and then
 * asserts on the state of the runtime directory afterwards.
 *
 * Nothing here spawns a process, touches the network, or changes DNS.
 */

import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import type { AuthOutcome, TokenSource } from '../src/auth/entra.ts';
import { AuthError, NetworkError, TunnelError } from '../src/errors.ts';
import type { DnsConfigurator } from '../src/network/dns.ts';
import type { OpenVpnBinary } from '../src/openvpn/binary.ts';
import { AzureProfileParser } from '../src/profile/parser.ts';
import type { AzureVpnProfile } from '../src/profile/types.ts';
import type { OpenP2SPaths, UserIdentity } from '../src/platform/paths.ts';
import { Elevator } from '../src/platform/privilege.ts';
import { SessionStore } from '../src/platform/session.ts';
import { Connection } from '../src/cli/connection.ts';
import {
  AUTH_FAILED_LOG,
  FakeSpawner,
  SUCCESSFUL_CONNECT_LOG,
  TLS_ERROR_LOG,
} from './helpers/fakeOpenVpn.ts';
import { syntheticJwt } from './helpers/syntheticToken.ts';

const FAKE_TOKEN = syntheticJwt();

const USER: UserIdentity = {
  uid: 1000,
  gid: 1000,
  username: 'test',
  home: '/home/test',
};

class FakeTokenSource implements TokenSource {
  calls = 0;
  private readonly outcome: AuthOutcome | Error;

  constructor(outcome: AuthOutcome | Error) {
    this.outcome = outcome;
  }

  async acquireToken(): Promise<AuthOutcome> {
    this.calls += 1;
    if (this.outcome instanceof Error) throw this.outcome;
    return this.outcome;
  }
}

class FakeDns implements DnsConfigurator {
  readonly configured: Array<{ iface: string; servers: string[]; domains: string[] }> = [];
  readonly reverted: string[] = [];
  failOnConfigure: Error | undefined;

  async configure(
    iface: string,
    servers: readonly string[],
    domains: readonly string[],
  ): Promise<void> {
    if (this.failOnConfigure) throw this.failOnConfigure;
    this.configured.push({ iface, servers: [...servers], domains: [...domains] });
  }

  async revert(iface: string): Promise<void> {
    this.reverted.push(iface);
  }
}

const BINARY: OpenVpnBinary = {
  path: '/opt/openp2s/openvpn',
  upstreamVersion: '2.7.6',
  upstreamCommit: '327a33de',
  patchSha256: 'deadbeef',
  binarySha256: 'cafebabe',
  azureCompatAvailable: true,
  provenanceKnown: true,
  userPassLen: 4096,
  patchStack: 'long-credentials experimental-azure-compat',
};

function successOutcome(): AuthOutcome {
  return {
    accessToken: FAKE_TOKEN,
    expiresOn: new Date(Date.now() + 3600_000),
    account: 'user@contoso.example',
    tenantId: '11111111-2222-3333-4444-555555555555',
    fromCache: true,
  };
}

let workDir: string;
let paths: OpenP2SPaths;
let profile: AzureVpnProfile;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-test-'));
  paths = {
    user: USER,
    runtimeDir: join(workDir, 'runtime'),
    stateDir: join(workDir, 'state'),
    cacheDir: join(workDir, 'state', 'cache'),
    sessionFile: join(workDir, 'runtime', 'session.json'),
    lockFile: join(workDir, 'runtime', 'connect.lock'),
    credentialsFile: join(workDir, 'runtime', 'credentials'),
    managementSocket: join(workDir, 'runtime', 'mgmt.sock'),
    configFile: join(workDir, 'runtime', 'openvpn.conf'),
    logFile: join(workDir, 'runtime', 'openvpn.log'),
  };
  const xml = readFileSync(join(import.meta.dirname, 'fixtures', 'valid-full.xml'), 'utf8');
  profile = new AzureProfileParser().parse(xml, { name: 'contoso' });
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

interface BuildOptions {
  readonly auth?: TokenSource;
  readonly dns?: FakeDns;
  readonly spawner?: FakeSpawner;
  readonly skipDns?: boolean;
  readonly connectTimeoutMs?: number;
  readonly stopGracePeriodMs?: number;
  readonly profile?: AzureVpnProfile;
  readonly azureCompat?: boolean;
  /** Force the 0600 credentials file instead of the management socket. */
  readonly useCredentialsFile?: boolean;
  readonly binaryVersion?: string;
  /** What the build reports as its USER_PASS_LEN, as BUILDINFO would. */
  readonly credentialLimits?: { readonly userPassLen: number };
  /** Overrides the token the fake authenticator returns. */
  readonly accessToken?: string;
}

function build(options: BuildOptions = {}): {
  connection: Connection;
  dns: FakeDns;
  spawner: FakeSpawner;
  warnings: string[];
} {
  const dns = options.dns ?? new FakeDns();
  const spawner = options.spawner ?? new FakeSpawner({ script: SUCCESSFUL_CONNECT_LOG });
  const warnings: string[] = [];

  const connection = new Connection({
    profile: options.profile ?? profile,
    paths,
    binary: options.binaryVersion ? { ...BINARY, upstreamVersion: options.binaryVersion } : BINARY,
    caPath: '/etc/ssl/certs/DigiCert_Global_Root_G2.pem',
    authenticator:
      options.auth ??
      new FakeTokenSource(
        options.accessToken
          ? { ...successOutcome(), accessToken: options.accessToken }
          : successOutcome(),
      ),
    dns,
    elevator: new Elevator({ euid: 0 }),
    spawner,
    connectTimeoutMs: options.connectTimeoutMs ?? 2_000,
    stopGracePeriodMs: options.stopGracePeriodMs ?? 200,
    ...(options.credentialLimits ? { credentialLimits: options.credentialLimits } : {}),
    ...(options.azureCompat ? { azureCompat: true } : {}),
    ...(options.useCredentialsFile ? { useCredentialsFile: true } : {}),
    ...(options.skipDns ? { skipDns: true } : {}),
    events: { onWarning: (message) => warnings.push(message) },
  });

  return { connection, dns, spawner, warnings };
}

/**
 * Assert that no secret material is left anywhere under the runtime dir.
 *
 * The guarantee is "once teardown completes". Where OpenVPN could not be
 * confirmed stopped, these files are kept deliberately - a live process may
 * still be reading them, and they are how a retry finds what to clean up. That
 * case is asserted separately, including that the residue is reported rather
 * than silently left.
 */
function assertNoSecretsLeftBehind(): void {
  assert.ok(!existsSync(paths.credentialsFile), 'credentials file must be removed');
  assert.ok(!existsSync(paths.configFile), 'generated config must be removed');
  assert.ok(!existsSync(paths.managementSocket), 'management socket must be removed');
}

describe('lifecycle: successful connection', () => {
  it('brings the tunnel up and records the session', async () => {
    const { connection, dns } = build();
    const record = await connection.connect();

    assert.equal(record.gateway, 'azuregateway-fake-0000.vpn.azure.com');
    assert.equal(record.interfaceName, 'tun0');
    assert.equal(record.assignedAddress, '172.16.0.5');
    assert.equal(record.account, 'user@contoso.example');
    assert.deepEqual(record.pushedRoutes, ['route 10.20.0.0 255.255.0.0']);
    assert.deepEqual(record.includeRoutes, ['10.20.0.0/16', '10.30.0.0/24']);
    assert.equal(dns.configured.length, 1);

    await connection.disconnect();
  });

  it('configures DNS only after the interface exists', async () => {
    const { connection, dns } = build();
    await connection.connect();

    assert.deepEqual(dns.configured, [
      {
        iface: 'tun0',
        servers: ['10.10.0.4', '10.10.0.5'],
        domains: ['wvd.microsoft.com', 'corp.contoso.example'],
      },
    ]);

    await connection.disconnect();
  });

  it('emits no Azure directives by default', async () => {
    // Measured against a live gateway: the patch's buffer sizes are the only
    // load-bearing change, so a normal connection needs no Azure-specific
    // directives at all. See README.md.
    const { connection, spawner } = build();
    await connection.connect();

    const config = readFileSync(paths.configFile, 'utf8');
    assert.ok(!/^azure-/m.test(config), 'default config must contain no azure directives');

    // And nothing Azure-specific reaches openvpn any other way. The old design
    // used OPENVPN_* environment variables, which broke under sudo's env_reset
    // and treated VAR=0 as enabled. The config is now the only channel, which
    // "never puts the token in argv" pins from the other side.
    assert.ok(!spawner.commandLine.includes('azure'), 'no azure flag reaches argv');

    await connection.disconnect();
  });

  it('emits experimental-azure-compat as a directive when requested', async () => {
    const { connection } = build({ azureCompat: true });
    await connection.connect();

    const config = readFileSync(paths.configFile, 'utf8');
    assert.match(config, /^experimental-azure-compat$/m);
    // Still a directive, never an environment variable.
    assert.ok(!config.includes('OPENVPN_'));

    await connection.disconnect();
  });

  it('never puts the token in argv', async () => {
    // /proc/<pid>/cmdline is readable by other processes of the same user.
    //
    // The environment is covered structurally rather than here: ProcessSpawner
    // takes only (command, args), so there is no channel through which the
    // connection could pass one, and the elevator has no way to carry anything
    // across sudo's env_reset. Asserting that on the fake would only be
    // asserting something about the fake.
    const { connection, spawner } = build();
    await connection.connect();

    assert.ok(!spawner.commandLine.includes(FAKE_TOKEN), 'token must not appear in argv');
    assert.deepEqual(spawner.args, ['--config', paths.configFile], 'argv is only --config');

    await connection.disconnect();
  });

  it('writes the credentials file 0600 with the token when forced to use one', async () => {
    const { connection } = build({ useCredentialsFile: true });
    await connection.connect();

    const mode = statSync(paths.credentialsFile).mode & 0o777;
    assert.equal(mode, 0o600, `credentials must be 0600, got ${mode.toString(8)}`);
    assert.equal(readFileSync(paths.credentialsFile, 'utf8'), `AzureAD\n${FAKE_TOKEN}\n`);

    await connection.disconnect();
  });

  it('writes the generated config 0600, because it embeds the tls-auth key', async () => {
    const { connection } = build();
    await connection.connect();

    const mode = statSync(paths.configFile).mode & 0o777;
    assert.equal(mode, 0o600, `config must be 0600, got ${mode.toString(8)}`);
    assert.match(readFileSync(paths.configFile, 'utf8'), /<tls-auth>/);

    await connection.disconnect();
  });

  it('delivers the token over the management socket, creating no file', async () => {
    // The default path. The token stays in process memory; there is no
    // credentials file to write, leak, or forget to delete.
    const { connection } = build();
    await connection.connect();

    assert.ok(
      !existsSync(paths.credentialsFile),
      'no credentials file should exist in management mode',
    );
    const config = readFileSync(paths.configFile, 'utf8');
    assert.match(config, /^management .*mgmt\.sock unix$/m);
    assert.match(config, /^management-client$/m);
    assert.match(config, /^management-query-passwords$/m);
    assert.match(config, /^auth-user-pass$/m, 'auth-user-pass must carry no path');

    await connection.disconnect();
  });

  it('falls back to a credentials file on OpenVPN older than 2.7.2', async () => {
    // The multi-line management password landed in 2.7.2; before that a
    // parameter is capped at 256 bytes and cannot carry a token.
    const { connection, warnings } = build({ binaryVersion: '2.7.1' });
    await connection.connect();

    assert.ok(existsSync(paths.credentialsFile), 'older builds need the file');
    assert.ok(
      warnings.some((w) => w.includes('2.7.2')),
      `expected a fallback warning, got ${JSON.stringify(warnings)}`,
    );

    await connection.disconnect();
  });

  it('skips DNS entirely when asked to', async () => {
    const { connection, dns } = build({ skipDns: true });
    const record = await connection.connect();

    assert.deepEqual(dns.configured, []);
    assert.deepEqual(record.dnsServers, []);

    await connection.disconnect();
  });
});

describe('lifecycle: the token has to fit', () => {
  it('refuses an oversized token before anything is started', async () => {
    // The check exists because OpenVPN truncates silently: the gateway would
    // reject a credential that looked valid here, and the user would see a
    // bare AUTH_FAILED. Refusing has to happen before the token is written
    // anywhere or openvpn is spawned, or the diagnosis costs a live tunnel.
    const { connection, dns, spawner } = build({
      credentialLimits: { userPassLen: 128 },
      accessToken: 'x'.repeat(2300),
    });

    await assert.rejects(() => connection.connect(), AuthError);

    assert.equal(spawner.spawnCount, 0, 'openvpn must not start with a token that cannot fit');
    assert.deepEqual(dns.configured, []);
    assertNoSecretsLeftBehind();
  });

  it('warns but proceeds when the token is close to the limit', async () => {
    // Group membership grows; a token at 95% today breaks in a few months,
    // and the failure then gives no hint that it was gradual.
    const { connection, warnings, spawner } = build({
      credentialLimits: { userPassLen: 4096 },
      accessToken: 'x'.repeat(3900),
    });

    await connection.connect();

    assert.equal(spawner.spawnCount, 1, 'a token that fits must still connect');
    assert.ok(
      warnings.some((warning) => /3900 bytes/.test(warning) && /limit/.test(warning)),
      `expected a pressure warning, got ${JSON.stringify(warnings)}`,
    );

    await connection.disconnect();
  });

  it('measures against the build in hand, not the shipped default', async () => {
    // A binary located with --openvpn-binary may be a stock build. Assuming
    // 4096 for it is how a token gets truncated by an OpenVPN that never
    // said it could not take one.
    const oversizedForStock = 'x'.repeat(200);

    await assert.rejects(
      () =>
        build({
          credentialLimits: { userPassLen: 128 },
          accessToken: oversizedForStock,
        }).connection.connect(),
      AuthError,
    );

    // The same token is unremarkable on the patched build.
    const patched = build({
      credentialLimits: { userPassLen: 4096 },
      accessToken: oversizedForStock,
    });
    await patched.connection.connect();
    assert.deepEqual(patched.warnings, [], 'no warning is warranted at 200 of 4095 bytes');
    await patched.connection.disconnect();
  });
});

describe('lifecycle: cleanup on failure', () => {
  it('leaves nothing behind when authentication fails', async () => {
    const auth = new FakeTokenSource(new AuthError('device code expired'));
    const { connection, dns, spawner } = build({ auth });

    await assert.rejects(() => connection.connect(), AuthError);

    // Nothing should have been started or written: authentication is first.
    assert.equal(spawner.spawnCount, 0, 'openvpn must not start if auth failed');
    assert.deepEqual(dns.configured, []);
    assertNoSecretsLeftBehind();
  });

  it('cleans up when openvpn exits before the tunnel comes up', async () => {
    const spawner = new FakeSpawner({ script: AUTH_FAILED_LOG, exitAfterScript: 1 });
    const { connection, dns } = build({ spawner });

    await assert.rejects(
      () => connection.connect(),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(error.message, /exited before the tunnel came up/);
        return true;
      },
    );

    assert.deepEqual(dns.configured, [], 'DNS must not be touched if the tunnel never came up');
    assertNoSecretsLeftBehind();
  });

  it('explains an AUTH_FAILED rejection rather than just reporting an exit code', async () => {
    const spawner = new FakeSpawner({ script: AUTH_FAILED_LOG, exitAfterScript: 1 });
    const { connection } = build({ spawner });

    await assert.rejects(
      () => connection.connect(),
      (error: unknown) => {
        const hint = (error as { hint?: string }).hint ?? '';
        assert.match(hint, /rejected the Entra access token/);
        assert.match(hint, /openp2s auth clear/);
        return true;
      },
    );
  });

  it('explains a TLS handshake failure', async () => {
    const spawner = new FakeSpawner({ script: TLS_ERROR_LOG, exitAfterScript: 1 });
    const { connection } = build({ spawner });

    await assert.rejects(
      () => connection.connect(),
      (error: unknown) => {
        assert.match((error as { hint?: string }).hint ?? '', /long-credentials\.patch/);
        return true;
      },
    );
  });

  it('stops openvpn and removes the token when DNS setup fails', async () => {
    // The tunnel is up but unusable; leaving it running with a live token
    // file would be the worst of both worlds.
    const dns = new FakeDns();
    dns.failOnConfigure = new NetworkError('resolvectl exited with code 1');

    const spawner = new FakeSpawner({ script: SUCCESSFUL_CONNECT_LOG });
    const { connection } = build({ dns, spawner });

    await assert.rejects(() => connection.connect(), NetworkError);

    assert.ok(spawner.process.signals.includes('SIGTERM'), 'openvpn must be stopped');
    assertNoSecretsLeftBehind();
    assert.ok(!existsSync(paths.sessionFile), 'no session record for a failed connect');
  });

  it('cleans up when the tunnel never finishes initialising', async () => {
    // openvpn is alive and chatty but never reaches the completion line.
    const spawner = new FakeSpawner({
      script: SUCCESSFUL_CONNECT_LOG.filter((line) => !line.includes('Initialization Sequence')),
    });
    const { connection, dns } = build({ spawner, connectTimeoutMs: 300 });

    await assert.rejects(
      () => connection.connect(),
      (error: unknown) => {
        assert.match((error as Error).message, /timed out after/);
        return true;
      },
    );

    assert.deepEqual(dns.configured, []);
    assert.ok(spawner.process.signals.includes('SIGTERM'));
    assertNoSecretsLeftBehind();
  });

  it('cleans up when openvpn cannot be spawned at all', async () => {
    const spawner = new FakeSpawner({ failToSpawn: new Error('ENOENT: no such file') });
    const { connection } = build({ spawner });

    await assert.rejects(() => connection.connect());
    assertNoSecretsLeftBehind();
  });

  it('escalates to SIGKILL when openvpn ignores SIGTERM', async () => {
    const dns = new FakeDns();
    dns.failOnConfigure = new NetworkError('resolvectl failed');
    const spawner = new FakeSpawner({ script: SUCCESSFUL_CONNECT_LOG, ignoreSignals: true });
    const { connection } = build({ dns, spawner });

    await assert.rejects(() => connection.connect(), NetworkError);

    assert.ok(spawner.process.signals.includes('SIGTERM'));
    assert.ok(spawner.process.signals.includes('SIGKILL'), 'must escalate to SIGKILL');
  });

  it('keeps the runtime files when openvpn would not die, and says so', async () => {
    // A process that survived SIGKILL is still running, and may still be
    // reading its config and credentials. Removing them would not stop it; it
    // would only destroy what a retry needs. So they stay, and the caller is
    // told rather than left to assume a clean teardown.
    const dns = new FakeDns();
    dns.failOnConfigure = new NetworkError('resolvectl failed');
    const spawner = new FakeSpawner({ script: SUCCESSFUL_CONNECT_LOG, ignoreSignals: true });
    const { connection, warnings } = build({ dns, spawner });

    await assert.rejects(() => connection.connect(), NetworkError);

    assert.ok(existsSync(paths.configFile), 'the config a live openvpn may re-read stays');
    assert.ok(
      warnings.some((message) => /may still be running/.test(message)),
      `expected a warning about the surviving process, got: ${JSON.stringify(warnings)}`,
    );
  });

  it('does not let the gateway announce a tunnel through PUSH_REPLY', async () => {
    // The milestone patterns are unanchored substring matches, so a pushed
    // option spelling the completion message would announce a tunnel that was
    // never opened - `connect` printing "VPN connected" over nothing.
    const spawner = new FakeSpawner({
      script: [
        'TCP connection established with [AF_INET]203.0.113.10:443',
        'VERIFY OK: depth=0, CN=*.vpn.azure.com',
        "PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0," +
          "Initialization Sequence Completed'",
      ],
      exitAfterScript: 1,
    });
    const { connection } = build({ spawner });

    await assert.rejects(() => connection.connect(), TunnelError);

    // Still parsed for what it legitimately carries.
    assert.deepEqual(connection.details?.pushedRoutes, ['route 10.20.0.0 255.255.0.0']);
    assert.equal(connection.stage, 'push');
  });

  it('reports the residue, so the CLI does not claim a clean disconnect', async () => {
    // `connect` decides its exit code from this: without it Ctrl+C printed
    // "Disconnected" and exited 0 with openvpn still running.
    const dns = new FakeDns();
    dns.failOnConfigure = new NetworkError('resolvectl failed');
    const spawner = new FakeSpawner({ script: SUCCESSFUL_CONNECT_LOG, ignoreSignals: true });
    const { connection } = build({ dns, spawner });

    await assert.rejects(() => connection.connect(), NetworkError);

    assert.equal(connection.hasResidue, true, 'a teardown that left files behind must say so');
  });

  it('does not keep the process alive with the socket it left open', async () => {
    // The socket stays open on purpose - it is the only way left to reach a
    // surviving openvpn - but it must not be a reason for the CLI to keep
    // running. Nothing calls process.exit(), so a listening handle nobody is
    // waiting on would hang the command after it had already reported the
    // failure. This is asserted through the handle count rather than the
    // socket's state, because "open" and "keeping us alive" are the two
    // things that have to be true at once.
    const dns = new FakeDns();
    dns.failOnConfigure = new NetworkError('resolvectl failed');
    const spawner = new FakeSpawner({ script: SUCCESSFUL_CONNECT_LOG, ignoreSignals: true });
    const { connection } = build({ dns, spawner });

    await assert.rejects(() => connection.connect(), NetworkError);

    assert.ok(existsSync(paths.managementSocket), 'the socket is still there to be reached');

    const holding = (
      process as unknown as { _getActiveHandles: () => Array<{ listening?: boolean }> }
    )
      ._getActiveHandles()
      .filter((handle) => handle.listening === true);

    assert.deepEqual(holding, [], 'no listening handle may still be holding the event loop open');
  });
});

describe('lifecycle: disconnect', () => {
  it('reverts DNS, stops openvpn, and removes secrets in that order', async () => {
    const { connection, dns, spawner } = build();
    await connection.connect();

    // Management mode: the socket exists, no credentials file does.
    assert.ok(existsSync(paths.managementSocket));
    assert.ok(!existsSync(paths.credentialsFile));
    assert.ok(existsSync(paths.sessionFile));

    await connection.disconnect();

    assert.deepEqual(dns.reverted, ['tun0']);
    assert.ok(spawner.process.signals.includes('SIGTERM'));
    assertNoSecretsLeftBehind();
    assert.ok(!existsSync(paths.sessionFile), 'session record must be cleared');
    // The other half: a finished teardown must not make Ctrl+C exit 5.
    assert.equal(connection.hasResidue, false);
  });

  it('is idempotent', async () => {
    const { connection, dns } = build();
    await connection.connect();

    await connection.disconnect();
    await connection.disconnect();
    await connection.cleanup();

    // Cleanup runs exactly once, so DNS is not reverted repeatedly.
    assert.deepEqual(dns.reverted, ['tun0']);
    assertNoSecretsLeftBehind();
  });

  it('warns but still removes the token when reverting DNS throws', async () => {
    const dns = new FakeDns();
    const { connection, warnings } = build({ dns });
    await connection.connect();

    dns.revert = async () => {
      throw new Error('resolvectl vanished');
    };

    // Does not throw: disconnect must not abandon the remaining cleanup.
    await connection.disconnect();

    assertNoSecretsLeftBehind();
    assert.ok(
      warnings.some((warning) => warning.includes('revert DNS')),
      `expected a DNS warning, got ${JSON.stringify(warnings)}`,
    );
  });
});

describe('lifecycle: session record', () => {
  it('can be stamped as an intentional disconnect', async () => {
    // How a foreground `connect` tells "the user asked for this" from "the
    // tunnel died". Without the stamp, a normal disconnect from a second
    // terminal is reported as a failure.
    const { connection } = build();
    const record = await connection.connect();
    assert.equal(record.disconnectRequestedAt, undefined);

    const store = new SessionStore(paths.sessionFile);
    await store.write({ ...record, disconnectRequestedAt: new Date().toISOString() });

    const stamped = await store.read();
    assert.ok(stamped?.disconnectRequestedAt, 'the stamp must survive a round trip');

    await connection.disconnect();
  });

  it('records the pid, and the start time when the process is real', async () => {
    // A pid alone can be recycled, so teardown and status identify the
    // process by the (pid, start time) pair. The fake openvpn is not a real
    // process, so 4242 has no start time to read - which is itself the
    // behaviour to pin: an unreadable start time is recorded as absent rather
    // than as a wrong number that a later liveness check would trust.
    const { connection } = build();
    const record = await connection.connect();

    assert.equal(record.openvpnPid, 4242);
    assert.equal(record.openvpnStartTime, undefined, 'an unreadable start time stays absent');

    await connection.disconnect();
  });

  it('records no secrets', async () => {
    const { connection } = build();
    await connection.connect();

    const contents = readFileSync(paths.sessionFile, 'utf8');
    assert.ok(!contents.includes(FAKE_TOKEN), 'session record must not contain the token');
    assert.ok(!contents.includes(profile.serverSecret), 'session record must not contain the key');

    await connection.disconnect();
  });

  it('is readable by another command through SessionStore', async () => {
    const { connection } = build();
    await connection.connect();

    const record = await new SessionStore(paths.sessionFile).read();
    assert.equal(record?.gateway, 'azuregateway-fake-0000.vpn.azure.com');
    assert.equal(record?.interfaceName, 'tun0');

    await connection.disconnect();
  });

  it('is written 0600', async () => {
    const { connection } = build();
    await connection.connect();

    assert.equal(statSync(paths.sessionFile).mode & 0o777, 0o600);
    await connection.disconnect();
  });
});
