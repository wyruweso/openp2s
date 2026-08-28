/**
 * The shared teardown policy.
 *
 * The rules under test are the ones that make a partial failure recoverable:
 * DNS is not reverted while the tunnel may still be up, artifacts that cannot
 * be removed are reported rather than forgotten, and `complete` is false
 * whenever anything is outstanding — because the caller uses it to decide
 * whether it is safe to delete the session record.
 */

import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import type { DnsConfigurator } from '../src/network/dns.ts';
import { isProcessAlive, processStartTime } from '../src/platform/lock.ts';
import { teardownConnection, type TeardownOptions } from '../src/cli/teardown.ts';

class FakeDns implements DnsConfigurator {
  readonly reverted: string[] = [];
  failOnRevert: Error | undefined;

  async configure(): Promise<void> {
    throw new Error('teardown must never configure DNS');
  }

  async revert(iface: string): Promise<void> {
    if (this.failOnRevert) throw this.failOnRevert;
    this.reverted.push(iface);
  }
}

let workDir: string;
let dns: FakeDns;
let children: ChildProcess[] = [];

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-teardown-'));
  dns = new FakeDns();
  children = [];
});

afterEach(() => {
  // Whatever a test left running, including anything it deliberately failed
  // to stop. SIGKILL because some of them ignore SIGTERM on purpose.
  for (const child of children) {
    try {
      child.kill('SIGKILL');
    } catch {
      // Already gone.
    }
  }
  rmSync(workDir, { recursive: true, force: true });
});

function artifact(name: string): { label: string; path: string } {
  const path = join(workDir, name);
  writeFileSync(path, 'x', { mode: 0o600 });
  return { label: name, path };
}

describe('teardown: ordering', () => {
  it('reverts DNS once the tunnel is confirmed gone', async () => {
    const result = await teardownConnection(
      { interfaceName: 'tun0', dnsConfigured: true },
      { dns, stopTunnel: async () => true },
    );

    assert.deepEqual(dns.reverted, ['tun0']);
    assert.equal(result.dnsReverted, true);
    assert.equal(result.complete, true);
  });

  it('does NOT revert DNS while the tunnel may still be running', async () => {
    // The failure this ordering exists to prevent: private names would start
    // resolving through the public resolver over a live private link.
    const result = await teardownConnection(
      { interfaceName: 'tun0', dnsConfigured: true },
      { dns, stopTunnel: async () => false },
    );

    assert.deepEqual(dns.reverted, [], 'DNS must be left alone');
    assert.equal(result.dnsReverted, false);
    assert.equal(result.complete, false);
    assert.ok(result.problems.some((p) => /leaving DNS configured/.test(p)));
  });

  it('does not touch DNS when none was configured', async () => {
    const result = await teardownConnection(
      { interfaceName: 'tun0', dnsConfigured: false },
      { dns, stopTunnel: async () => true },
    );
    assert.deepEqual(dns.reverted, []);
    assert.equal(result.complete, true);
  });
});

describe('teardown: artifacts', () => {
  it('removes every artifact', async () => {
    const creds = artifact('credentials');
    const config = artifact('openvpn.conf');

    const result = await teardownConnection(
      { artifacts: [creds, config] },
      { dns, stopTunnel: async () => true },
    );

    assert.ok(!existsSync(creds.path));
    assert.ok(!existsSync(config.path));
    assert.deepEqual(result.residue, []);
    assert.equal(result.complete, true);
  });

  it('treats a missing artifact as already done', async () => {
    const result = await teardownConnection(
      { artifacts: [{ label: 'gone', path: join(workDir, 'never-existed') }] },
      { dns, stopTunnel: async () => true },
    );
    assert.deepEqual(result.residue, []);
    assert.equal(result.complete, true);
  });

  it('keeps artifacts when the tunnel could not be stopped', async () => {
    // The recovery contract. A live OpenVPN may still need the management
    // socket, and on the fallback path the credentials file; and these paths
    // are how a retry finds what to clean up. Removing them from under a
    // running tunnel turns a retryable failure into an unrecoverable one.
    const creds = artifact('credentials');
    const socket = artifact('mgmt.sock');

    const result = await teardownConnection(
      { artifacts: [creds, socket] },
      { dns, stopTunnel: async () => false },
    );

    assert.ok(existsSync(creds.path), 'the credentials file must be kept for a retry');
    assert.ok(existsSync(socket.path), 'the management socket must stay reachable');
    assert.equal(result.complete, false);
    assert.deepEqual(result.residue.sort(), [creds.path, socket.path].sort());
    assert.ok(result.problems.some((p) => /may still be running/.test(p)));
  });

  it('removes them on the retry that does stop the tunnel', async () => {
    const creds = artifact('credentials');

    await teardownConnection({ artifacts: [creds] }, { dns, stopTunnel: async () => false });
    assert.ok(existsSync(creds.path));

    const second = await teardownConnection(
      { artifacts: [creds] },
      { dns, stopTunnel: async () => true },
    );

    assert.ok(!existsSync(creds.path), 'the retry must finish the job');
    assert.equal(second.complete, true);
  });

  it('reports residue rather than losing track of it', async () => {
    // A directory cannot be unlinked, which stands in for EACCES/EROFS.
    const stubborn = join(workDir, 'undeletable');
    const { mkdirSync } = await import('node:fs');
    mkdirSync(stubborn);

    const result = await teardownConnection(
      { artifacts: [{ label: 'stubborn', path: stubborn }] },
      { dns, stopTunnel: async () => true },
    );

    assert.deepEqual(result.residue, [stubborn]);
    assert.equal(result.complete, false, 'residue must block "complete"');
  });
});

describe('teardown: completeness', () => {
  it('is complete when there was nothing to do', async () => {
    const result = await teardownConnection({}, { dns });
    assert.equal(result.complete, true);
    assert.equal(result.tunnelStopped, true);
  });

  it('is incomplete when the tunnel survived', async () => {
    const result = await teardownConnection({}, { dns, stopTunnel: async () => false });
    assert.equal(result.complete, false);
  });

  it('is incomplete when the DNS revert failed', async () => {
    dns.failOnRevert = new Error('resolvectl is gone');
    const result = await teardownConnection(
      { interfaceName: 'tun0', dnsConfigured: true },
      { dns, stopTunnel: async () => true },
    );
    assert.equal(result.complete, false);
    assert.ok(result.problems.some((p) => /could not revert DNS/.test(p)));
  });

  it('never throws, whatever fails', async () => {
    dns.failOnRevert = new Error('boom');
    await teardownConnection(
      { interfaceName: 'tun0', dnsConfigured: true, artifacts: [artifact('c')] },
      {
        dns,
        stopTunnel: () => {
          throw new Error('stop exploded');
        },
      },
    );
  });
});

/**
 * A real child process, so the liveness checks read a real /proc entry.
 *
 * The escalation logic is entirely about what is actually alive at each step,
 * and a fake pid cannot exercise that: `isProcessAlive` would answer from
 * whatever the fake was told to say, which is the thing under test.
 */
async function spawnChild(options: { ignoresSigterm: boolean }): Promise<ChildProcess> {
  const script = options.ignoresSigterm
    ? "process.on('SIGTERM', () => {}); process.stdout.write('up\\n'); setInterval(() => {}, 1000);"
    : "process.stdout.write('up\\n'); setInterval(() => {}, 1000);";

  const child = spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'ignore'] });
  children.push(child);

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('child never started')), 10_000);
    child.stdout?.once('data', () => {
      clearTimeout(timer);
      resolve();
    });
  });
  return child;
}

/** Deliver the signal for real, and record what was sent. */
function realSignal(sent: string[]): NonNullable<TeardownOptions['signal']> {
  return async (pid: number, signal: 'SIGTERM' | 'SIGKILL') => {
    sent.push(signal);
    process.kill(pid, signal);
  };
}

describe('teardown: stopping a process it did not spawn', () => {
  it('stops a well-behaved openvpn with SIGTERM alone', async () => {
    const child = await spawnChild({ ignoresSigterm: false });
    const start = processStartTime(child.pid ?? 0);
    const sent: string[] = [];

    const result = await teardownConnection(
      { openvpnPid: child.pid, openvpnStartTime: start },
      { dns, signal: realSignal(sent), graceMs: 2_000 },
    );

    assert.deepEqual(sent, ['SIGTERM'], 'a process that exits needs nothing further');
    assert.equal(result.tunnelStopped, true);
    assert.equal(result.complete, true);
  });

  it('escalates to SIGKILL when SIGTERM is ignored', async () => {
    // openvpn can be wedged in a syscall, or trapping SIGTERM while it tries
    // to close a tunnel that is already gone. Without escalation the teardown
    // reports a process it never actually stopped.
    const child = await spawnChild({ ignoresSigterm: true });
    const start = processStartTime(child.pid ?? 0);
    const sent: string[] = [];

    const result = await teardownConnection(
      { openvpnPid: child.pid, openvpnStartTime: start },
      { dns, signal: realSignal(sent), graceMs: 300 },
    );

    assert.deepEqual(sent, ['SIGTERM', 'SIGKILL']);
    assert.equal(result.tunnelStopped, true, 'SIGKILL must actually have stopped it');
    assert.equal(isProcessAlive(child.pid, start), false, 'the process must really be gone');
  });

  it('gives the process its grace period before escalating', async () => {
    // SIGKILL denies openvpn the chance to close its tun device and restore
    // what it changed, so it is a last resort rather than the first move.
    const child = await spawnChild({ ignoresSigterm: true });
    const start = processStartTime(child.pid ?? 0);
    const sent: Array<{ signal: string; at: number }> = [];
    const began = Date.now();

    await teardownConnection(
      { openvpnPid: child.pid, openvpnStartTime: start },
      {
        dns,
        graceMs: 500,
        signal: async (pid, signal) => {
          sent.push({ signal, at: Date.now() - began });
          process.kill(pid, signal);
        },
      },
    );

    const kill = sent.find((entry) => entry.signal === 'SIGKILL');
    assert.ok(kill, 'expected an escalation');
    assert.ok(kill.at >= 500, `SIGKILL came after ${kill.at}ms, before the 500ms grace elapsed`);
  });
});

describe('teardown: signalling by pid', () => {
  it('never signals when the recorded process is not alive', async () => {
    // The pid-reuse guard: a dead pid must not be signalled, because the
    // number may now belong to something else.
    const signals: string[] = [];
    const result = await teardownConnection(
      { openvpnPid: 2 ** 30, openvpnStartTime: 12345 },
      {
        dns,
        signal: async (_pid, signal) => {
          signals.push(signal);
        },
      },
    );

    assert.deepEqual(signals, [], 'a dead pid must not be signalled');
    assert.equal(result.tunnelStopped, true);
  });

  it('does not signal a live pid whose start time does not match', async () => {
    // Our own pid with a wrong start time: the recorded process is gone even
    // though the number is in use. Signalling it would hit a stranger.
    const { processStartTime } = await import('../src/platform/lock.ts');
    const start = processStartTime(process.pid);
    assert.ok(start !== undefined);

    const signals: string[] = [];
    await teardownConnection(
      { openvpnPid: process.pid, openvpnStartTime: start + 1 },
      {
        dns,
        signal: async (_pid, signal) => {
          signals.push(signal);
        },
      },
    );

    assert.deepEqual(signals, [], 'a recycled pid must not be signalled');
  });
});

describe('teardown: incomplete DNS state', () => {
  it('does not report success when DNS was configured but no interface is known', async () => {
    // The record says DNS was applied, but not to what. It cannot be reverted
    // here, so the teardown is not complete and the operator needs telling.
    const result = await teardownConnection(
      { dnsConfigured: true },
      { dns, stopTunnel: async () => true },
    );

    assert.equal(result.dnsReverted, false);
    assert.equal(result.complete, false, 'unrevertable DNS must not read as complete');
    assert.ok(result.problems.some((p) => /records no interface name/.test(p)));
    assert.ok(result.problems.some((p) => /resolvectl status/.test(p)));
  });
});

describe('teardown: signalling', () => {
  it('treats an already-dead process as stopped, with no way to signal', async () => {
    const result = await teardownConnection({ openvpnPid: 2 ** 30, openvpnStartTime: 1 }, { dns });
    assert.equal(result.tunnelStopped, true);
  });

  it('will not escalate to SIGKILL without a recorded start time', async () => {
    // Without one, "is this pid alive" cannot tell the process we signalled
    // from whatever inherited its number. SIGTERM to a stranger is
    // survivable; SIGKILL is not, so it is not sent on a guess.
    const sent: string[] = [];
    const result = await teardownConnection(
      { openvpnPid: process.pid },
      {
        dns,
        graceMs: 50,
        signal: (_pid, signal) => {
          sent.push(signal);
          return Promise.resolve();
        },
      },
    );

    assert.deepEqual(sent, ['SIGTERM'], 'SIGKILL must not be sent without a start time');
    assert.equal(result.tunnelStopped, false, 'and the tunnel is reported as still running');
  });
});
