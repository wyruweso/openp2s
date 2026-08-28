/**
 * Management-interface credential delivery.
 *
 * These tests speak the real protocol over a real unix socket, with a fake
 * OpenVPN on the other end. Nothing here touches the network.
 *
 * The behaviour under test is the reason the credentials file is gone: a
 * ~2.3 KB Entra token cannot go through the single-line management form
 * (256-byte parameter cap), so it must be base64 and split across lines.
 */

import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { connect, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  MAX_UNIX_SOCKET_PATH,
  ManagementServer,
  supportsMultilinePassword,
} from '../src/openvpn/management.ts';
import { syntheticLongJwt } from './helpers/syntheticToken.ts';

/** A token of realistic size: base64 of this is ~3 KB and must be split. */
const LONG_TOKEN = syntheticLongJwt();

let workDir: string;
let socketPath: string;
let server: ManagementServer | undefined;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-mgmt-'));
  socketPath = join(workDir, 'mgmt.sock');
  // A long TMPDIR in CI would push the socket past sun_path and make these
  // tests fail for a reason that has nothing to do with what they check.
  assert.ok(
    Buffer.byteLength(socketPath) <= MAX_UNIX_SOCKET_PATH,
    `TMPDIR is too long for a unix socket: ${socketPath}`,
  );
});

afterEach(async () => {
  await server?.stop();
  server = undefined;
  rmSync(workDir, { recursive: true, force: true });
});

/**
 * Stand in for OpenVPN: connect, collect lines, and let the test drive the
 * conversation.
 */
class FakeOpenVpnClient {
  readonly received: string[] = [];
  private socket: Socket | undefined;
  private buffer = '';

  async connect(path: string): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const socket = connect(path);
      this.socket = socket;
      socket.setEncoding('utf8');
      socket.on('connect', () => resolve());
      socket.on('error', reject);
      socket.on('data', (chunk: string) => {
        this.buffer += chunk;
        let nl = this.buffer.indexOf('\n');
        while (nl !== -1) {
          this.received.push(this.buffer.slice(0, nl));
          this.buffer = this.buffer.slice(nl + 1);
          nl = this.buffer.indexOf('\n');
        }
      });
    });
  }

  send(line: string): void {
    this.socket?.write(`${line}\n`);
  }

  close(): void {
    this.socket?.destroy();
  }

  /** Wait until `predicate` holds over the received lines, or time out. */
  async until(predicate: () => boolean, timeoutMs = 2000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (predicate()) return;
      await new Promise((r) => setTimeout(r, 10));
    }
    throw new Error(`timed out; received:\n${this.received.join('\n')}`);
  }
}

async function startServer(password: string): Promise<ManagementServer> {
  const created = new ManagementServer({
    socketPath,
    credentials: { username: 'AzureAD', password },
  });
  await created.start();
  server = created;
  return created;
}

describe('supportsMultilinePassword', () => {
  it('requires OpenVPN 2.7.2, where the feature was added', () => {
    // The multi-line form landed in 2.7.2.
    assert.equal(supportsMultilinePassword('2.7.2'), true);
    assert.equal(supportsMultilinePassword('2.7.6'), true);
    assert.equal(supportsMultilinePassword('2.8.0'), true);
  });

  it('does not assume a future major speaks the same protocol', () => {
    // Management capabilities have been added and renumbered before. Guessing
    // wrong means the token silently fails to arrive, so an unknown branch
    // falls back to the credentials file, which works everywhere.
    assert.equal(supportsMultilinePassword('3.0.0'), false);
    assert.equal(supportsMultilinePassword('4.1.0'), false);
  });

  it('rejects older builds, which cap a parameter at 256 bytes', () => {
    assert.equal(supportsMultilinePassword('2.7.1'), false);
    assert.equal(supportsMultilinePassword('2.7.0'), false);
    assert.equal(supportsMultilinePassword('2.6.14'), false);
    assert.equal(supportsMultilinePassword('1.9.9'), false);
  });

  it('treats an unknown version as unsupported', () => {
    assert.equal(supportsMultilinePassword(undefined), false);
    assert.equal(supportsMultilinePassword('not-a-version'), false);
  });
});

describe('ManagementServer: socket', () => {
  it('refuses a socket path longer than sun_path', async () => {
    // bind() fails with a confusing EINVAL past 108 bytes; say what is wrong.
    const tooLong = join(workDir, 'x'.repeat(MAX_UNIX_SOCKET_PATH));
    const created = new ManagementServer({
      socketPath: tooLong,
      credentials: { username: 'AzureAD', password: 'short' },
    });
    await assert.rejects(() => created.start(), /over the \d+-byte limit/);
  });

  it('creates the socket 0600 before OpenVPN starts', async () => {
    await startServer('short');

    assert.ok(existsSync(socketPath));
    const mode = statSync(socketPath).mode & 0o777;
    assert.equal(mode, 0o600, `socket must be 0600, got ${mode.toString(8)}`);
  });

  it('removes the socket on stop', async () => {
    const created = await startServer('short');
    await created.stop();
    server = undefined;
    assert.ok(!existsSync(socketPath));
  });

  it('replaces a stale socket left by a crashed run', async () => {
    // A crash leaves the path occupied with nothing listening on it, and
    // bind() then fails with EADDRINUSE. The previous version of this test
    // called stop() first, which unlinks - so there was never anything stale
    // to replace, and removing the cleanup from start() broke nothing.
    writeFileSync(socketPath, '');
    assert.ok(existsSync(socketPath), 'the path is occupied before we start');

    await startServer('short');

    // Not merely present: a working socket, which a leftover regular file
    // would not be.
    const client = new FakeOpenVpnClient();
    await client.connect(socketPath);
    await client.until(() => client.received.includes('version 5'));
    client.close();
  });

  it('accepts only one client', async () => {
    await startServer('short');

    const first = new FakeOpenVpnClient();
    await first.connect(socketPath);
    await first.until(() => first.received.length > 0);

    const second = new FakeOpenVpnClient();
    await second.connect(socketPath);
    // The second connection is destroyed rather than served.
    await new Promise((r) => setTimeout(r, 100));
    assert.deepEqual(second.received, [], 'a second client must not be served');

    first.close();
    second.close();
  });
});

describe('ManagementServer: protocol', () => {
  it('announces client version 5 on connect', async () => {
    // Version 5 is MCV_MULTILINE_PASSWORD; without it OpenVPN rejects a
    // bare `password "Auth"` line.
    await startServer('short');
    const client = new FakeOpenVpnClient();
    await client.connect(socketPath);

    await client.until(() => client.received.includes('version 5'));
    client.close();
  });

  it('releases the hold', async () => {
    await startServer('short');
    const client = new FakeOpenVpnClient();
    await client.connect(socketPath);
    await client.until(() => client.received.includes('version 5'));

    client.send('>HOLD:Waiting for hold release:0');
    await client.until(() => client.received.includes('hold release'));
    client.close();
  });

  it('sends a long token as base64 lines terminated by END', async () => {
    await startServer(LONG_TOKEN);
    const client = new FakeOpenVpnClient();
    await client.connect(socketPath);
    await client.until(() => client.received.includes('version 5'));

    client.send(">PASSWORD:Need 'Auth' username/password");
    await client.until(() => client.received.includes('END'));

    const lines = client.received;
    const usernameIndex = lines.indexOf('username "Auth" "AzureAD"');
    const passwordIndex = lines.indexOf('password "Auth"');
    const endIndex = lines.indexOf('END');

    assert.ok(usernameIndex !== -1, 'username must be sent');
    assert.ok(passwordIndex !== -1, 'bare password line must be sent');
    assert.ok(passwordIndex < endIndex, 'password line precedes END');

    // The bare `password "Auth"` form is what enters multi-line mode. A value
    // on that line would hit the 256-byte parameter cap.
    assert.ok(
      !lines.some((line) => line.startsWith('password "Auth" "')),
      'the token must never be inlined on the password command',
    );

    const body = lines.slice(passwordIndex + 1, endIndex);
    assert.ok(body.length > 1, `a ~2.3 KB token must span several lines, got ${body.length}`);

    for (const line of body) {
      assert.ok(line.length <= 1024, `line of ${line.length} exceeds the 1024-byte limit`);
      assert.match(line, /^[A-Za-z0-9+/=]+$/, 'body lines must be base64');
    }

    // Reassembled, it must decode back to exactly the token: OpenVPN
    // concatenates the lines with no separator before decoding.
    assert.equal(Buffer.from(body.join(''), 'base64').toString('utf8'), LONG_TOKEN);

    client.close();
  });

  it('never writes the token to the filesystem', async () => {
    await startServer(LONG_TOKEN);
    const client = new FakeOpenVpnClient();
    await client.connect(socketPath);
    await client.until(() => client.received.includes('version 5'));
    client.send(">PASSWORD:Need 'Auth' username/password");
    await client.until(() => client.received.includes('END'));

    // The socket is the only thing in the directory.
    const { readdirSync } = await import('node:fs');
    assert.deepEqual(readdirSync(workDir), ['mgmt.sock']);

    client.close();
  });

  it('notices when the gateway rejects the token', async () => {
    let failed = false;
    const created = new ManagementServer({
      socketPath,
      credentials: { username: 'AzureAD', password: 'short' },
      onAuthFailed: () => {
        failed = true;
      },
    });
    await created.start();
    server = created;

    const client = new FakeOpenVpnClient();
    await client.connect(socketPath);
    await client.until(() => client.received.includes('version 5'));

    client.send(">PASSWORD:Verification Failed: 'Auth'");
    await client.until(() => failed);

    assert.ok(created.sawAuthFailure);
    client.close();
  });

  it('never logs the password', async () => {
    const debug: string[] = [];
    const created = new ManagementServer({
      socketPath,
      credentials: { username: 'AzureAD', password: LONG_TOKEN },
      onDebug: (message) => debug.push(message),
    });
    await created.start();
    server = created;

    const client = new FakeOpenVpnClient();
    await client.connect(socketPath);
    await client.until(() => client.received.includes('version 5'));
    client.send(">PASSWORD:Need 'Auth' username/password");
    await client.until(() => client.received.includes('END'));

    const joined = debug.join('\n');
    assert.ok(!joined.includes(LONG_TOKEN), 'debug output must not contain the token');
    assert.ok(!joined.includes(LONG_TOKEN.slice(0, 24)), 'not even the token prefix');

    client.close();
  });
});
