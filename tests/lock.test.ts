/**
 * The single-connection lock.
 *
 * Acquisition must be exclusive, and a crash must not leave it held. Ownership
 * is an abstract-namespace Unix socket, so these exercise the kernel's
 * behaviour rather than the descriptive file beside it.
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { ConnectionLock, isProcessAlive, processStartTime } from '../src/platform/lock.ts';

let workDir: string;
let lockPath: string;
let scope: string;
let held: ConnectionLock[] = [];

/** A distinct uid per test, so tests cannot collide over one lock name. */
let nextScope = 0;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-lock-'));
  lockPath = join(workDir, 'connect.lock');
  scope = `test-${process.pid}-${nextScope++}`;
  held = [];
});

afterEach(() => {
  for (const lock of held) lock.release();
  rmSync(workDir, { recursive: true, force: true });
});

function newLock(path = lockPath): ConnectionLock {
  const lock = new ConnectionLock(path, scope);
  held.push(lock);
  return lock;
}

describe('processStartTime', () => {
  it('reads our own start time from /proc', () => {
    const value = processStartTime(process.pid);
    assert.ok(typeof value === 'number' && value > 0, `got ${String(value)}`);
  });

  it('returns undefined for a pid that does not exist', () => {
    assert.equal(processStartTime(2 ** 30), undefined);
  });
});

describe('isProcessAlive', () => {
  it('recognises this process', () => {
    assert.equal(isProcessAlive(process.pid), true);
  });

  it('rejects a mismatched start time', () => {
    // Pid reuse: the number is alive, but it is not our process.
    const start = processStartTime(process.pid);
    assert.ok(start !== undefined);
    assert.equal(isProcessAlive(process.pid, start + 1), false);
  });

  it('rejects nonsense', () => {
    assert.equal(isProcessAlive(undefined), false);
    assert.equal(isProcessAlive(0), false);
    assert.equal(isProcessAlive(-1), false);
  });
});

describe('exclusivity', () => {
  it('acquires when nothing holds it', async () => {
    const lock = newLock();
    assert.equal((await lock.acquire()).acquired, true);
    assert.equal(lock.isHeld, true);
  });

  it('refuses a second acquisition while the first is held', async () => {
    // The race the lock exists to prevent: two connects, both proceeding.
    const first = newLock();
    assert.equal((await first.acquire()).acquired, true);

    const second = newLock();
    const result = await second.acquire();
    assert.equal(result.acquired, false);
    assert.equal(second.isHeld, false);
  });

  it('reports who holds it, from the descriptive file', () => {
    return (async () => {
      await newLock().acquire();
      const result = await newLock().acquire();
      assert.equal(result.acquired, false);
      assert.equal(result.heldBy?.pid, process.pid);
    })();
  });

  it('still refuses when the descriptive file has been deleted', async () => {
    // The file is not the lock.
    await newLock().acquire();
    rmSync(lockPath, { force: true });

    const result = await newLock().acquire();
    assert.equal(result.acquired, false, 'deleting the file must not release the lock');
  });

  it('still refuses when the descriptive file is empty', async () => {
    await newLock().acquire();
    writeFileSync(lockPath, '');

    const result = await newLock().acquire();
    assert.equal(result.acquired, false, 'an empty file must not look like a free lock');
  });

  it('still refuses when the descriptive file is corrupt', async () => {
    await newLock().acquire();
    writeFileSync(lockPath, 'not json at all');

    assert.equal((await newLock().acquire()).acquired, false);
  });

  it('grants the lock again once released', async () => {
    const first = newLock();
    await first.acquire();
    first.release();

    assert.equal((await newLock().acquire()).acquired, true);
  });
});

describe('the kernel reclaims it', () => {
  it('frees the name when the holding process dies', async () => {
    // The property the whole design rests on: no stale file to clean up and no
    // pid to interrogate, because the name disappears with the process -
    // SIGKILL included, where no cleanup handler could have run.
    const name = `openp2s-reclaim-${scope}`;
    const script =
      "const net=require('node:net');const s=net.createServer();" +
      `s.listen(String.fromCharCode(0)+'${name}',()=>{process.stdout.write('held\\n')});` +
      'setInterval(()=>{},1000);';

    const child = spawn(process.execPath, ['-e', script], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });

    try {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('child never bound')), 10_000);
        child.stdout.once('data', () => {
          clearTimeout(timer);
          resolve();
        });
      });

      assert.equal(await canBind(name), false, 'the live child should hold its name');

      child.kill('SIGKILL');
      await new Promise<void>((resolve) => child.once('exit', () => resolve()));

      assert.equal(await canBind(name), true, 'the kernel should have released it');
    } finally {
      child.kill('SIGKILL');
    }
  });
});

/** Can this abstract name be bound right now? */
function canBind(name: string): Promise<boolean> {
  return new Promise((resolve) => {
    const server = createServer();
    server.once('error', () => resolve(false));
    server.listen({ path: `\0${name}`, exclusive: true }, () => {
      server.close(() => resolve(true));
    });
  });
}

describe('the descriptive file', () => {
  it('is written 0600 and names the holder', async () => {
    await newLock().acquire();

    assert.equal(statSync(lockPath).mode & 0o777, 0o600);
    const holder = JSON.parse(readFileSync(lockPath, 'utf8')) as Record<string, unknown>;
    assert.equal(holder['pid'], process.pid);
    assert.equal(holder['startTime'], processStartTime(process.pid));
  });

  it('is removed on release', async () => {
    const lock = newLock();
    await lock.acquire();
    lock.release();
    assert.ok(!existsSync(lockPath));
  });

  it('is not removed by a process that never held the lock', async () => {
    const owner = newLock();
    await owner.acquire();

    const other = newLock();
    await other.acquire(); // fails: the owner has it
    other.release(); // must be a no-op

    assert.ok(existsSync(lockPath), "a non-holder must not clear the owner's file");
  });

  it('release is idempotent and never throws', async () => {
    const lock = newLock();
    await lock.acquire();
    lock.release();
    lock.release();
    assert.equal(lock.isHeld, false);
  });
});
