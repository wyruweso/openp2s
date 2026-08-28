/**
 * `openp2s convert` file handling.
 *
 * The output embeds the profile serversecret as an inline tls-auth key, so how
 * it reaches disk matters as much as what is in it.
 */

import assert from 'node:assert/strict';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { convertCommand } from '../src/cli/commands/convert.ts';
import { OpenP2SError } from '../src/errors.ts';

const FIXTURE = join(import.meta.dirname, 'fixtures', 'azure-schema.xml');

let workDir: string;
let output: string;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-convert-'));
  output = join(workDir, 'profile.ovpn');
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

describe('convert: writing', () => {
  it('writes the config 0600', async () => {
    await convertCommand(FIXTURE, { output, quiet: true });
    assert.equal(statSync(output).mode & 0o777, 0o600);
  });

  it('refuses to overwrite without --force', async () => {
    writeFileSync(output, 'existing');
    await assert.rejects(() => convertCommand(FIXTURE, { output, quiet: true }), OpenP2SError);
    assert.equal(readFileSync(output, 'utf8'), 'existing');
  });

  it('overwrites with --force', async () => {
    writeFileSync(output, 'existing');
    await convertCommand(FIXTURE, { output, force: true, quiet: true });
    assert.match(readFileSync(output, 'utf8'), /^client$/m);
  });

  it('replaces a symlink rather than writing through it', async () => {
    // The attack: point the output path at something else and pass --force.
    // rename() replaces the link; opening the path for writing would follow
    // it and overwrite the target.
    const target = join(workDir, 'target.txt');
    writeFileSync(target, 'PRECIOUS');
    symlinkSync(target, output);

    await convertCommand(FIXTURE, { output, force: true, quiet: true });

    assert.equal(readFileSync(target, 'utf8'), 'PRECIOUS', 'the link target must be untouched');
    assert.ok(!lstatSync(output).isSymbolicLink(), 'the link itself must have been replaced');
    assert.match(readFileSync(output, 'utf8'), /^client$/m);
  });

  it('leaves no temporary file behind', async () => {
    await convertCommand(FIXTURE, { output, quiet: true });
    assert.deepEqual(
      readdirSync(workDir).filter((entry) => entry.includes('.tmp')),
      [],
    );
  });

  it('reports a real stat error rather than treating it as "does not exist"', async () => {
    // A path whose parent is a file, not a directory: ENOTDIR, not ENOENT.
    const notADirectory = join(workDir, 'file.txt');
    writeFileSync(notADirectory, 'x');
    await assert.rejects(
      () => convertCommand(FIXTURE, { output: join(notADirectory, 'out.ovpn'), quiet: true }),
      OpenP2SError,
    );
  });
});

describe('convert: option validation', () => {
  it('refuses --stdout with --output', async () => {
    await assert.rejects(
      () => convertCommand(FIXTURE, { stdout: true, output, quiet: true }),
      /--stdout cannot be combined with --output/,
    );
  });

  it('refuses --stdout with --force', async () => {
    await assert.rejects(
      () => convertCommand(FIXTURE, { stdout: true, force: true, quiet: true }),
      /--force applies only when writing a file/,
    );
  });

  it('refuses a credentials path containing a newline', async () => {
    await assert.rejects(
      () =>
        convertCommand(FIXTURE, {
          output,
          quiet: true,
          credentials: '/tmp/x\nscript-security 2',
        }),
      /control character/,
    );
    assert.ok(!existsSync(output), 'nothing should have been written');
  });
});

describe('convert: what lands in the file', () => {
  it('names no credential source by default', async () => {
    await convertCommand(FIXTURE, { output, quiet: true });
    const config = readFileSync(output, 'utf8');

    const directives = config
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'));

    assert.ok(!directives.some((line) => line.startsWith('auth-user-pass')));
    assert.ok(!directives.some((line) => line.startsWith('management')));
  });

  it('names one when --credentials is given', async () => {
    await convertCommand(FIXTURE, { output, quiet: true, credentials: '/run/user/1000/creds' });
    assert.match(readFileSync(output, 'utf8'), /^auth-user-pass \/run\/user\/1000\/creds$/m);
  });

  it('embeds the serversecret as an inline tls-auth key', async () => {
    await convertCommand(FIXTURE, { output, quiet: true });
    const config = readFileSync(output, 'utf8');
    assert.match(config, /^<tls-auth>$/m);
    assert.match(config, /-----BEGIN OpenVPN Static key V1-----/);
  });

  it('never contains a token', async () => {
    await convertCommand(FIXTURE, { output, quiet: true });
    assert.ok(!/eyJ[A-Za-z0-9_-]+\./.test(readFileSync(output, 'utf8')));
  });
});
