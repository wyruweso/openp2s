/**
 * Where OpenP2S looks for its OpenVPN.
 *
 * The ordering is a security property: the distribution's /usr/sbin/openvpn
 * must never be picked up, because a stock build truncates the Entra token and
 * the resulting failure looks like a server fault.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  INSTALLED_BINARY_PATHS,
  locateOpenVpnBinary,
  openVpnCandidates,
} from '../src/openvpn/binary.ts';
import { OpenP2SError } from '../src/errors.ts';

let workDir: string;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-locate-'));
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

/** A stand-in for an OpenVPN binary, with the BUILDINFO a real one carries. */
function plantBundle(dir: string, name: string): string {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, name);
  writeFileSync(path, '#!/bin/sh\nexit 0\n');
  chmodSync(path, 0o755);
  return path;
}

/** Write a BUILDINFO beside a binary, optionally describing a different one. */
function plantBuildInfo(dir: string, binary: string, options: { matching: boolean }): void {
  const sha = options.matching
    ? createHash('sha256').update(readFileSync(binary)).digest('hex')
    : 'f'.repeat(64);
  writeFileSync(
    join(dir, 'BUILDINFO'),
    [
      'openvpn_version=2.7.6',
      'patch_stack=long-credentials experimental-azure-compat',
      'user_pass_len=4096',
      'azure_compat_available=1',
      `binary_sha256=${sha}`,
    ].join('\n'),
  );
}

describe('sibling discovery', () => {
  it('finds openvpn-openp2s beside the executable', () => {
    const bundle = join(workDir, 'openp2s-0.2.0-linux-amd64');
    const openvpn = plantBundle(bundle, 'openvpn-openp2s');
    const cli = plantBundle(bundle, 'openp2s');

    const found = locateOpenVpnBinary({ execPath: cli, env: {} });
    assert.equal(found.path, openvpn);
  });

  it('does not mind when there is no sibling', () => {
    // Under a plain `node` the sibling simply does not exist.
    const repoRoot = join(workDir, 'repo');
    const openvpn = plantBundle(join(repoRoot, 'build/openvpn/sbin'), 'openvpn');

    const found = locateOpenVpnBinary({
      repoRoot,
      execPath: join(workDir, 'nowhere', 'node'),
      env: {},
    });
    assert.equal(found.path, openvpn);
  });
});

describe('discovery precedence', () => {
  it('prefers an explicit override to everything else', () => {
    const bundle = join(workDir, 'bundle');
    plantBundle(bundle, 'openvpn-openp2s');
    const override = plantBundle(join(workDir, 'custom'), 'openvpn');

    const found = locateOpenVpnBinary({
      override,
      execPath: join(bundle, 'openp2s'),
      env: {},
    });
    assert.equal(found.path, override);
  });

  it('prefers the environment override to a sibling', () => {
    const bundle = join(workDir, 'bundle');
    plantBundle(bundle, 'openvpn-openp2s');
    const fromEnv = plantBundle(join(workDir, 'env'), 'openvpn');

    const found = locateOpenVpnBinary({
      execPath: join(bundle, 'openp2s'),
      env: { OPENP2S_OPENVPN_BINARY: fromEnv },
    });
    assert.equal(found.path, fromEnv);
  });

  it('prefers a source checkout to a sibling', () => {
    const repoRoot = join(workDir, 'repo');
    const built = plantBundle(join(repoRoot, 'build/openvpn/sbin'), 'openvpn');
    const bundle = join(workDir, 'bundle');
    plantBundle(bundle, 'openvpn-openp2s');

    const found = locateOpenVpnBinary({
      repoRoot,
      execPath: join(bundle, 'openp2s'),
      env: {},
    });
    assert.equal(found.path, built);
  });
});

describe('what discovery must never do', () => {
  it('never considers the distribution openvpn', () => {
    // A stock build silently truncates the Entra token, and the gateway then
    // rejects a credential that looked fine on this side. Picking one up by
    // accident is the failure mode the private paths exist to prevent.
    // The real shipped list, not one this test supplied: that is the one a
    // release actually searches, and the only one worth asserting about.
    for (const path of ['/usr/sbin/openvpn', '/usr/bin/openvpn', '/sbin/openvpn']) {
      assert.ok(!INSTALLED_BINARY_PATHS.includes(path), `${path} must not be an install location`);
    }
    for (const path of INSTALLED_BINARY_PATHS) {
      assert.match(path, /\/openp2s\//, `${path} is not an openp2s-private directory`);
    }

    // And the assembled list adds nothing outside that rule either.
    const searched = openVpnCandidates({
      repoRoot: join(workDir, 'repo'),
      execPath: join(workDir, 'bin', 'openp2s'),
      env: {},
    });
    for (const candidate of searched) {
      assert.ok(
        candidate.includes('openp2s') || candidate.endsWith('openvpn-openp2s'),
        `${candidate} is not an openp2s-private location`,
      );
    }
  });

  it('fails rather than falling back when nothing is found', () => {
    // The alternative - running the system openvpn - produces a failure that
    // looks like a server fault, so discovery has to refuse instead.
    //
    // Every candidate is pointed inside workDir, installedPaths included, so
    // this reaches the not-found path on any machine. Leaving the real
    // absolute locations in made the outcome depend on whether the openp2s
    // package was installed on the machine running the tests.
    assert.throws(
      () =>
        locateOpenVpnBinary({
          repoRoot: join(workDir, 'repo'),
          execPath: join(workDir, 'bin', 'openp2s'),
          env: { OPENP2S_OPENVPN_BINARY: join(workDir, 'nope') },
          installedPaths: [join(workDir, 'not-installed', 'openvpn')],
        }),
      (error: unknown) => {
        assert.ok(error instanceof OpenP2SError);
        assert.match(error.message, /was not found/);
        assert.match(error.hint ?? '', /will not fall back to the system openvpn/);
        return true;
      },
    );
  });

  it('lists everywhere it looked, so the refusal is actionable', () => {
    // "not found" without the search path leaves a user with nowhere to start.
    const installed = join(workDir, 'not-installed', 'openvpn');
    try {
      locateOpenVpnBinary({
        execPath: join(workDir, 'bin', 'openp2s'),
        env: {},
        installedPaths: [installed],
      });
      assert.fail('expected a refusal');
    } catch (error) {
      assert.ok(error instanceof OpenP2SError);
      assert.ok(error.hint?.includes(installed), 'the hint must name the paths it tried');
      assert.ok(error.hint?.includes(join(workDir, 'bin', 'openvpn-openp2s')), 'sibling too');
      assert.match(error.hint ?? '', /build-openvpn\.sh|OPENP2S_OPENVPN_BINARY/);
    }
  });
});

describe('an install rooted anywhere', () => {
  it('finds the OpenVPN under its own prefix', () => {
    // Deriving the prefix from the executable covers /usr, /usr/local and a
    // relocated tree without enumerating them.
    const prefix = join(workDir, 'opt', 'somewhere');
    const cli = plantBundle(join(prefix, 'bin'), 'openp2s');
    const openvpn = plantBundle(join(prefix, 'lib', 'openp2s'), 'openvpn');

    const found = locateOpenVpnBinary({ execPath: cli, env: {} });
    assert.equal(found.path, openvpn);
  });
});

describe('provenance that does not describe this binary', () => {
  it('trusts BUILDINFO when it matches', () => {
    const dir = join(workDir, 'lib', 'openp2s');
    const openvpn = plantBundle(dir, 'openvpn');
    plantBuildInfo(dir, openvpn, { matching: true });

    const found = locateOpenVpnBinary({ override: openvpn, env: {} });
    assert.equal(found.provenanceKnown, true);
    assert.equal(found.userPassLen, 4096);
    assert.equal(found.patchStack, 'long-credentials experimental-azure-compat');
  });

  it('believes nothing in a BUILDINFO that names a different binary', () => {
    // The record describes different bytes, so nothing in it may be believed.
    // 128 is the assumption that fails safe.
    const dir = join(workDir, 'lib', 'openp2s');
    const openvpn = plantBundle(dir, 'openvpn');
    plantBuildInfo(dir, openvpn, { matching: false });

    const found = locateOpenVpnBinary({ override: openvpn, env: {} });
    assert.equal(found.provenanceKnown, false);
    assert.equal(found.userPassLen, 128, 'must not inherit 4096 from an unverified record');
    assert.equal(found.patchStack, undefined);
    assert.equal(found.upstreamVersion, undefined);
    assert.equal(
      found.azureCompatAvailable,
      false,
      'an untrusted record must not grant the capability',
    );
  });

  it('still reports the declared hash, so the mismatch can be seen', () => {
    const dir = join(workDir, 'lib', 'openp2s');
    const openvpn = plantBundle(dir, 'openvpn');
    plantBuildInfo(dir, openvpn, { matching: false });

    const found = locateOpenVpnBinary({ override: openvpn, env: {} });
    assert.equal(found.binarySha256, 'f'.repeat(64));
  });
});
