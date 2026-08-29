/**
 * THIRD_PARTY_NOTICES generation.
 *
 * Deriving the list from the build can still get the wrong answer - several
 * versions of one package, a nested copy, a package shipping no licence text -
 * so those cases are pinned here rather than left to the dependency tree.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';

const GENERATOR = join(import.meta.dirname, '../scripts/generate-notices.ts');

let workDir: string;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-notices-'));
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

/** A package in a node_modules tree, with whatever files the case needs. */
function plantPackage(
  root: string,
  relative: string,
  manifest: Record<string, unknown>,
  files: Record<string, string> = {},
): string {
  const dir = join(root, relative);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest));
  writeFileSync(join(dir, 'index.js'), '// code\n');
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  return `${relative}/index.js`;
}

/** A metafile whose single output is fed by the given inputs. */
function writeMetafile(inputs: ReadonlyArray<readonly [string, number]>): string {
  const path = join(workDir, 'meta.json');
  writeFileSync(
    path,
    JSON.stringify({
      inputs: Object.fromEntries(inputs.map(([p]) => [p, { bytes: 1 }])),
      outputs: {
        'out.cjs': {
          inputs: Object.fromEntries(inputs.map(([p, bytes]) => [p, { bytesInOutput: bytes }])),
        },
      },
    }),
  );
  return path;
}

const BUILDINFO = [
  'openvpn_version=2.7.6',
  'patch_stack=long-credentials experimental-azure-compat',
  'azure_compat_available=1',
  'binary_sha256=' + 'a'.repeat(64),
].join('\n');

const CLI_BUILDINFO = [
  'openp2s_version=0.1.1',
  'cli_node_version=24.13.0',
  'cli_node_sha256=' + 'b'.repeat(64),
].join('\n');

function run(
  metafile: string,
  overrides: { buildinfo?: string; cliBuildinfo?: string } = {},
): { code: number; stdout: string; stderr: string } {
  const buildinfo = join(workDir, 'BUILDINFO');
  const cliBuildinfo = join(workDir, 'CLI-BUILDINFO');
  const copying = join(workDir, 'openvpn-COPYING');
  const nodeLicense = join(workDir, 'NODE_LICENSE');
  const source = join(workDir, 'openvpn-2.7.6-openp2s-source.tar.gz');

  writeFileSync(buildinfo, overrides.buildinfo ?? BUILDINFO);
  writeFileSync(cliBuildinfo, overrides.cliBuildinfo ?? CLI_BUILDINFO);
  for (const path of [copying, nodeLicense, source]) writeFileSync(path, 'x');

  const result = spawnSync(
    process.execPath,
    [GENERATOR, metafile, buildinfo, cliBuildinfo, copying, nodeLicense, source],
    { encoding: 'utf8', cwd: workDir },
  );
  return { code: result.status ?? -1, stdout: result.stdout, stderr: result.stderr };
}

describe('package identity', () => {
  it('keeps two versions of the same package apart', () => {
    const a = plantPackage(
      workDir,
      'node_modules/foo',
      { name: 'foo', version: '2.1.0', license: 'MIT' },
      { LICENSE: 'MIT text for foo 2' },
    );
    const b = plantPackage(
      workDir,
      'node_modules/holder/node_modules/foo',
      { name: 'foo', version: '1.4.0', license: 'Apache-2.0' },
      { LICENSE: 'Apache text for foo 1' },
    );
    const { stdout, code } = run(
      writeMetafile([
        [a, 10],
        [b, 10],
      ]),
    );

    assert.equal(code, 0, stdout);
    assert.match(stdout, /foo\s+2\.1\.0\s+MIT/);
    assert.match(stdout, /foo\s+1\.4\.0\s+Apache-2\.0/);
    assert.ok(stdout.includes('MIT text for foo 2'));
    assert.ok(stdout.includes('Apache text for foo 1'));
  });

  it('reads the nested package, not the top-level one of the same name', () => {
    // Version and licence must come from the copy actually bundled.
    plantPackage(
      workDir,
      'node_modules/foo',
      { name: 'foo', version: '2.1.0', license: 'MIT' },
      { LICENSE: 'wrong' },
    );
    const nested = plantPackage(
      workDir,
      'node_modules/holder/node_modules/foo',
      { name: 'foo', version: '1.4.0', license: 'Apache-2.0' },
      { LICENSE: 'right' },
    );
    const { stdout } = run(writeMetafile([[nested, 10]]));

    assert.match(stdout, /foo\s+1\.4\.0\s+Apache-2\.0/);
    assert.ok(!stdout.includes('2.1.0'), 'the unbundled top-level copy must not appear');
    assert.ok(stdout.includes('right') && !stdout.includes('wrong'));
  });

  it('handles scoped packages', () => {
    const scoped = plantPackage(
      workDir,
      'node_modules/@scope/thing',
      { name: '@scope/thing', version: '1.0.0', license: 'MIT' },
      { LICENSE: 'scoped text' },
    );
    const { stdout, code } = run(writeMetafile([[scoped, 10]]));

    assert.equal(code, 0, stdout);
    assert.match(stdout, /@scope\/thing\s+1\.0\.0\s+MIT/);
  });
});

describe('what counts as bundled', () => {
  it('ignores a package esbuild read but tree-shook away entirely', () => {
    // metafile.inputs lists everything read; only contributors are shipped.
    const kept = plantPackage(
      workDir,
      'node_modules/kept',
      { name: 'kept', version: '1.0.0', license: 'MIT' },
      { LICENSE: 'kept' },
    );
    const shaken = plantPackage(
      workDir,
      'node_modules/shaken',
      { name: 'shaken', version: '1.0.0', license: 'MIT' },
      { LICENSE: 'shaken' },
    );
    const { stdout } = run(
      writeMetafile([
        [kept, 10],
        [shaken, 0],
      ]),
    );

    assert.ok(stdout.includes('kept'));
    assert.ok(!/^\s+shaken\s/m.test(stdout), 'a package contributing no bytes must not be listed');
  });
});

describe('licence handling fails closed', () => {
  it('refuses a package that ships no licence text', () => {
    // "MIT" in package.json is a declaration, not the notice.
    const p = plantPackage(workDir, 'node_modules/bare', {
      name: 'bare',
      version: '1.0.0',
      license: 'MIT',
    });
    const { code, stderr } = run(writeMetafile([[p, 10]]));

    assert.equal(code, 1);
    assert.match(stderr, /ships no license text/);
    assert.match(stderr, /packaging\/licenses/);
  });

  it('refuses a package that declares no licence at all', () => {
    const p = plantPackage(
      workDir,
      'node_modules/nolicense',
      { name: 'nolicense', version: '1.0.0' },
      { LICENSE: 'text' },
    );
    const { code, stderr } = run(writeMetafile([[p, 10]]));

    assert.equal(code, 1);
    assert.match(stderr, /declares no license/);
  });

  it('refuses an UNLICENSED package', () => {
    const p = plantPackage(
      workDir,
      'node_modules/private',
      { name: 'private', version: '1.0.0', license: 'UNLICENSED' },
      { LICENSE: 'text' },
    );
    const { code, stderr } = run(writeMetafile([[p, 10]]));

    assert.equal(code, 1);
    assert.match(stderr, /UNLICENSED/);
  });

  it('follows SEE LICENSE IN to the named file', () => {
    const p = plantPackage(
      workDir,
      'node_modules/custom',
      { name: 'custom', version: '1.0.0', license: 'SEE LICENSE IN terms.md' },
      { 'terms.md': 'the actual custom terms', LICENSE: 'a decoy' },
    );
    const { stdout, code } = run(writeMetafile([[p, 10]]));

    assert.equal(code, 0, stdout);
    assert.ok(stdout.includes('the actual custom terms'));
    assert.ok(!stdout.includes('a decoy'));
  });

  it('refuses SEE LICENSE IN pointing at a missing file', () => {
    const p = plantPackage(workDir, 'node_modules/broken', {
      name: 'broken',
      version: '1.0.0',
      license: 'SEE LICENSE IN nowhere.txt',
    });
    const { code, stderr } = run(writeMetafile([[p, 10]]));

    assert.equal(code, 1);
    assert.match(stderr, /nowhere\.txt/);
  });

  it('includes NOTICE files alongside the licence', () => {
    // Apache-2.0 requires NOTICE content, which is not in the licence text.
    const p = plantPackage(
      workDir,
      'node_modules/apache',
      { name: 'apache', version: '1.0.0', license: 'Apache-2.0' },
      { LICENSE: 'Apache licence body', NOTICE: 'Required attribution here' },
    );
    const { stdout } = run(writeMetafile([[p, 10]]));

    assert.ok(stdout.includes('Apache licence body'));
    assert.ok(stdout.includes('Required attribution here'));
  });
});

describe('provenance claims are checked, not assumed', () => {
  /** A well-formed package, so each case fails only on the provenance. */
  const good = (root: string): string =>
    plantPackage(
      root,
      'node_modules/ok',
      { name: 'ok', version: '1.0.0', license: 'MIT' },
      { LICENSE: 'text' },
    );

  it('refuses to describe a differently-patched build as the shipped one', () => {
    const p = good(workDir);
    const { code, stderr } = run(writeMetafile([[p, 10]]), {
      buildinfo: BUILDINFO.replace(
        'patch_stack=long-credentials experimental-azure-compat',
        'patch_stack=long-credentials some-research-patch',
      ),
    });

    assert.equal(code, 1);
    assert.match(stderr, /shipped patch stack/);
  });

  it('refuses a build missing the compat patch', () => {
    const p = good(workDir);
    const { code, stderr } = run(writeMetafile([[p, 10]]), {
      buildinfo: BUILDINFO.replace('azure_compat_available=1', 'azure_compat_available=0'),
    });

    assert.equal(code, 1);
    assert.match(stderr, /not the shipped build/);
  });

  it('refuses a BUILDINFO missing a field it would print', () => {
    const p = good(workDir);
    const { code, stderr } = run(writeMetafile([[p, 10]]), {
      cliBuildinfo: 'openp2s_version=0.1.1\ncli_node_version=24.13.0',
    });

    assert.equal(code, 1);
    assert.match(stderr, /cli_node_sha256/);
  });

  it('refuses a BUILDINFO with a duplicated key', () => {
    const p = good(workDir);
    const { code, stderr } = run(writeMetafile([[p, 10]]), {
      buildinfo: `${BUILDINFO}\npatch_stack=something-else`,
    });

    assert.equal(code, 1);
    assert.match(stderr, /duplicate key/);
  });
});
