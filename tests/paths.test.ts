/**
 * Where OpenP2S keeps its files, and who it runs as.
 *
 * The property: OpenP2S never manages a directory belonging to a different
 * user than the one it runs as.
 */

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { OpenP2SError } from '../src/errors.ts';
import { ensurePrivateDir, resolvePaths, resolveUserIdentity } from '../src/platform/paths.ts';

let workDir: string;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-paths-'));
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

describe("OpenP2S does not run as root on a user's behalf", () => {
  it("refuses sudo rather than serving another user's directories", () => {
    assert.throws(
      () => resolveUserIdentity({ SUDO_UID: '1000' }, { euid: 0 }),
      (error: unknown) => {
        assert.ok(error instanceof OpenP2SError);
        assert.match(error.message, /do not run openp2s under sudo/);
        return true;
      },
    );
  });

  it('explains where elevation actually happens', () => {
    // The refusal has to be actionable: OpenP2S still needs root for openvpn
    // and resolvectl, and the user needs to know it handles that itself.
    try {
      resolveUserIdentity({ SUDO_UID: '1000' }, { euid: 0 });
      assert.fail('expected a refusal');
    } catch (error) {
      assert.ok(error instanceof OpenP2SError);
      assert.match(error.hint ?? '', /openvpn/);
      assert.match(error.hint ?? '', /systemd-resolved/);
    }
  });

  it('allows genuine root, which owns its own directories', () => {
    // A container with no sudo involved. There is no other user's state to
    // mismanage, so nothing is unsafe here.
    const identity = resolveUserIdentity({}, { euid: 0, egid: 0 });
    assert.equal(identity.uid, 0);
  });

  it('exposes no sudo mode for callers to branch on', () => {
    const identity = resolveUserIdentity({}, { euid: 1000, egid: 1000 });
    assert.ok(!('viaSudo' in identity), 'the sudo special case must be gone entirely');
  });
});

describe('private directories', () => {
  it('creates one 0700', () => {
    const dir = join(workDir, 'runtime');
    ensurePrivateDir(dir);
    assert.equal(statSync(dir).mode & 0o777, 0o700);
  });

  it('refuses a symlink instead of validating what it points at', () => {
    // The escalation shape: mkdir -p succeeds on an existing symlink and stat
    // reports the target's mode, so the permission check passed on a directory
    // the caller never intended to use.
    const target = join(workDir, 'target');
    mkdirSync(target, { mode: 0o700 });
    const link = join(workDir, 'link');
    symlinkSync(target, link);

    assert.throws(() => ensurePrivateDir(link), /symbolic link/);
  });

  it('refuses a directory that is group- or world-accessible', () => {
    const dir = join(workDir, 'loose');
    mkdirSync(dir, { mode: 0o755 });
    assert.throws(() => ensurePrivateDir(dir), /group- or world-accessible/);
  });

  it('is idempotent on a directory it already made', () => {
    const dir = join(workDir, 'runtime');
    ensurePrivateDir(dir);
    ensurePrivateDir(dir);
    assert.equal(statSync(dir).mode & 0o777, 0o700);
  });
});

describe('XDG variables', () => {
  it('ignores a relative path, which would follow the working directory', () => {
    // The spec defines these as absolute. A relative value would put the token
    // cache somewhere that depends on where the command was run from.
    const paths = resolvePaths({ XDG_STATE_HOME: 'relative/state' }, { euid: 1000, egid: 1000 });
    assert.ok(paths.stateDir.startsWith('/'), paths.stateDir);
    assert.ok(!paths.stateDir.includes('relative/state'));
  });

  it('honours an absolute path', () => {
    const paths = resolvePaths({ XDG_STATE_HOME: '/abs/state' }, { euid: 1000, egid: 1000 });
    assert.equal(paths.stateDir, '/abs/state/openp2s');
  });

  it('applies the same rule to XDG_RUNTIME_DIR', () => {
    const relative = resolvePaths({ XDG_RUNTIME_DIR: 'run' }, { euid: 1000, egid: 1000 });
    assert.equal(relative.runtimeDir, '/run/user/1000/openp2s');

    const absolute = resolvePaths(
      { XDG_RUNTIME_DIR: '/run/user/1000' },
      { euid: 1000, egid: 1000 },
    );
    assert.equal(absolute.runtimeDir, '/run/user/1000/openp2s');
  });
});
