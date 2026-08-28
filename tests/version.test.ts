/**
 * The version the CLI reports is the version being packaged.
 *
 * `src/cli/main.ts` holds it as a literal: the single-file executable has no
 * package.json to read at runtime. Until now that literal was only checked by
 * the build scripts, so bumping package.json alone stayed green through
 * `npm run check` and failed minutes into a release instead.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { buildProgram } from '../src/cli/main.ts';

interface PackageManifest {
  readonly version?: unknown;
  readonly engines?: { readonly node?: unknown };
}

function packageManifest(): PackageManifest {
  const contents = readFileSync(join(import.meta.dirname, '..', 'package.json'), 'utf8');
  return JSON.parse(contents) as PackageManifest;
}

describe('the reported version', () => {
  it('matches package.json', () => {
    // Through buildProgram(), so this is what `--version` actually prints.
    const reported = buildProgram().version();
    const declared = packageManifest().version;

    assert.equal(
      reported,
      declared,
      'src/cli/main.ts VERSION and package.json "version" have drifted; ' +
        'scripts/build-cli.sh would fail the release on this',
    );
  });

  it('is a plain semantic version', () => {
    // release.yml compares this to `${GITHUB_REF_NAME#v}`: anything a v-tag
    // cannot spell can be published but never tagged.
    assert.match(String(packageManifest().version), /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  });
});

describe('the pinned Node version', () => {
  it('satisfies the engines range', () => {
    // .node-version is the Node the executable is built from - what OpenP2S
    // actually ships on. engines is the floor it claims. They must not drift.
    const pinned = readFileSync(join(import.meta.dirname, '..', '.node-version'), 'utf8').trim();
    const engines = String(packageManifest().engines?.node);

    const floor = /^>=\s*(\d+\.\d+\.\d+)$/.exec(engines)?.[1];
    assert.ok(floor, `engines.node should be a ">=x.y.z" floor, got ${engines}`);
    assert.match(pinned, /^\d+\.\d+\.\d+$/);

    const order = (version: string): number[] => version.split('.').map(Number);
    const [pinnedMajor = 0, pinnedMinor = 0, pinnedPatch = 0] = order(pinned);
    const [floorMajor = 0, floorMinor = 0, floorPatch = 0] = order(floor);

    const satisfied =
      pinnedMajor > floorMajor ||
      (pinnedMajor === floorMajor &&
        (pinnedMinor > floorMinor || (pinnedMinor === floorMinor && pinnedPatch >= floorPatch)));

    assert.ok(satisfied, `.node-version ${pinned} is below the engines floor ${floor}`);
  });
});
