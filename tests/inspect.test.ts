/**
 * `openp2s inspect`
 *
 * The command is read-only, so what is worth testing is what it *says*: that
 * the serversecret never reaches the output in any form, and that a profile
 * whose DNS settings would silently do nothing is called out rather than
 * printed as an ordinary value.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { loadProfile } from '../src/cli/context.ts';

const FIXTURE = join(import.meta.dirname, 'fixtures/azure-schema.xml');

let workDir: string;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), 'openp2s-inspect-'));
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

/**
 * Run the real CLI and capture what a user would see.
 *
 * A subprocess rather than an in-process call with process.stdout patched:
 * these assertions are about the bytes that reach a terminal, and patching
 * stdout inside the test runner also swallows the runner's own output.
 */
function runInspect(
  profilePath: string,
  args: readonly string[] = [],
): {
  code: number;
  output: string;
} {
  const result = spawnSync(
    process.execPath,
    [join(import.meta.dirname, '../src/cli/run.ts'), 'inspect', profilePath, ...args],
    { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } },
  );
  return { code: result.status ?? -1, output: `${result.stdout}${result.stderr}` };
}

/** A copy of the fixture with the given substitutions applied. */
function variant(replacements: ReadonlyArray<readonly [RegExp | string, string]>): string {
  let xml = readFileSync(FIXTURE, 'utf8');
  for (const [from, to] of replacements) xml = xml.replace(from, to);
  const path = join(workDir, 'profile.xml');
  writeFileSync(path, xml);
  return path;
}

describe('inspect and the serversecret', () => {
  it('never prints the serversecret, or any part of it', async () => {
    // The strongest form of the promise in the module docstring: not the
    // value, not a prefix, not a fingerprint-sized fragment of it.
    const profile = await loadProfile(FIXTURE);
    const { output } = runInspect(FIXTURE);

    assert.ok(profile.serverSecret.length >= 64, 'fixture should carry a realistic secret');
    assert.ok(!output.includes(profile.serverSecret), 'full secret leaked');
    assert.ok(!output.includes(profile.serverSecret.slice(0, 16)), 'secret prefix leaked');
    assert.ok(!output.includes(profile.serverSecret.slice(-16)), 'secret suffix leaked');
  });

  it('confirms the secret is present and well-formed instead', async () => {
    const { output } = runInspect(FIXTURE);
    assert.match(output, /Server secret:\s+present, valid \(\d+ bytes\)/);
  });
});

describe('inspect and the non-secret identity fields', () => {
  it('prints tenant, audience and client id in full', async () => {
    // These are how you tell "the profile points at a different application"
    // from "the gateway is refusing us", which is the whole point of inspect.
    // They are not secrets and must not be abbreviated or redacted.
    const profile = await loadProfile(FIXTURE);
    const { output } = runInspect(FIXTURE);

    assert.ok(output.includes(profile.auth.tenantId), 'tenant id');
    assert.ok(output.includes(profile.auth.audience), 'audience');
    assert.ok(output.includes(profile.auth.clientId), 'client id');
    assert.ok(output.includes(profile.gateway), 'gateway');
  });
});

describe('inspect and DNS', () => {
  it('describes the profile without promising a runtime outcome', async () => {
    // inspect cannot see the options a later connect will be given: --no-dns,
    // or an absent systemd-resolved, both change the answer.
    const { output } = runInspect(FIXTURE);

    assert.ok(output.includes('DNS settings in this profile:'));
    assert.ok(!/split DNS will be applied/.test(output), 'must not promise an outcome');
    assert.ok(output.includes('unless --no-dns is used'));
  });

  it('states what default route: no actually means', async () => {
    // Not "the VPN will not become the system resolver": with a ~. routing
    // domain every name matches the link regardless of the default route.
    const { output } = runInspect(FIXTURE);
    assert.ok(output.includes('the link is not used as the fallback DNS route'));
  });

  it('warns when servers are set but no routing domains are', async () => {
    // The Private Link trap: resolvectl only queries a link's servers when a
    // routing domain matches, so this configuration sends them nothing.
    const path = variant([[/\s*<dnssuffix>[^<]*<\/dnssuffix>/g, '']]);
    const { output } = runInspect(path);

    assert.match(output, /sets DNS servers but no routing domains/);
    assert.match(output, /--dns-domain or --dns-all/);
  });

  it('does not warn when routing domains are present', async () => {
    const { output } = runInspect(FIXTURE);
    assert.ok(!/no routing domains/.test(output));
  });

  it('says nothing will change when the profile has no DNS servers', async () => {
    const path = variant([[/\s*<dnsservers>[\s\S]*?<\/dnsservers>/, '']]);
    const { output } = runInspect(path);
    assert.match(output, /system resolution is left unchanged/);
  });
});

describe('inspect and the pinned root', () => {
  it('flags a profile that connect would refuse', async () => {
    const path = variant([
      ['<usepinnedroot>false</usepinnedroot>', '<usepinnedroot>true</usepinnedroot>'],
    ]);
    const { output, code } = runInspect(path);

    assert.match(output, /pinned-root validation/);
    assert.match(output, /--allow-system-trust-store/);
    // Still a successful inspection: the profile parsed, and reporting on it
    // is the command's job.
    assert.equal(code, 0);
  });
});

describe('inspect exit code', () => {
  it('succeeds even when local state is incomplete', async () => {
    // A missing OpenVPN binary does not make an inspection unsuccessful; the
    // profile is what was asked about.
    const { code } = runInspect(FIXTURE, ['--openvpn-binary', join(workDir, 'does-not-exist')]);
    assert.equal(code, 0);
  });
});
