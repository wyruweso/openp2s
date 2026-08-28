/**
 * `openp2s doctor` output parsing.
 *
 * The value of a doctor is that a green tick means something. These tests
 * cover the parser it relies on, because the checks compare what the profile
 * asked for against what `resolvectl` actually reports — and a parser that
 * silently returns nothing would turn every comparison into a false result.
 *
 * Scope: the parser only. The checks built on top of it - environmentChecks,
 * profileChecks, liveChecks - are not covered here and are worth their own
 * tests.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { liveChecks, parseResolvectlField, type Check } from '../src/cli/commands/doctor.ts';
import type { CommandContext } from '../src/cli/context.ts';
import { Ui } from '../src/cli/ui.ts';
import { RecordingCommandRunner, type CommandResult } from '../src/platform/exec.ts';
import { processStartTime } from '../src/platform/lock.ts';
import { resolvePaths } from '../src/platform/paths.ts';
import { Elevator } from '../src/platform/privilege.ts';
import { SessionStore, type SessionRecord } from '../src/platform/session.ts';

let runtimeDir: string;

beforeEach(() => {
  runtimeDir = mkdtempSync(join(tmpdir(), 'openp2s-doctor-'));
});

afterEach(() => {
  rmSync(runtimeDir, { recursive: true, force: true });
});

const SINGLE = `Link 5 (tun0)
    Current Scopes: DNS
         Protocols: -DefaultRoute
       DNS Servers: 10.0.0.53
        DNS Domain: ~wvd.microsoft.com
     Default Route: no`;

const MULTIPLE = `Link 5 (tun0)
       DNS Servers: 10.10.0.4 10.10.0.5
        DNS Domain: ~wvd.microsoft.com
                    ~corp.contoso.example
     Default Route: no`;

/**
 * A link that routes every name but is still not the default route.
 *
 * The two are different: `~.` sends all queries to this link, while Default
 * Route decides eligibility only when no routing domain matches. The doctor
 * reports them separately, so the parser has to read them separately.
 */
const ROUTES_EVERYTHING = `Link 5 (tun0)
       DNS Servers: 10.0.0.53
        DNS Domain: ~.
     Default Route: no`;

describe('parseResolvectlField', () => {
  it('reads a single value', () => {
    assert.deepEqual(parseResolvectlField(SINGLE, 'DNS Servers'), ['10.0.0.53']);
  });

  it('reads several values on one line', () => {
    assert.deepEqual(parseResolvectlField(MULTIPLE, 'DNS Servers'), ['10.10.0.4', '10.10.0.5']);
  });

  it('reads values wrapped onto continuation lines', () => {
    // resolvectl indents extra domains under the label. A single-line regex
    // would see only the first, and the doctor would then report a missing
    // domain that is actually installed.
    assert.deepEqual(parseResolvectlField(MULTIPLE, 'DNS Domain'), [
      '~wvd.microsoft.com',
      '~corp.contoso.example',
    ]);
  });

  it('stops at the next labelled field', () => {
    assert.deepEqual(parseResolvectlField(MULTIPLE, 'Default Route'), ['no']);
  });

  it('recognises the route-everything domain', () => {
    assert.deepEqual(parseResolvectlField(ROUTES_EVERYTHING, 'DNS Domain'), ['~.']);
  });

  it('returns nothing for an absent field', () => {
    assert.deepEqual(parseResolvectlField(SINGLE, 'Nonexistent Field'), []);
  });

  it('is case-insensitive about the label', () => {
    assert.deepEqual(parseResolvectlField(SINGLE, 'dns servers'), ['10.0.0.53']);
  });

  it('handles empty input', () => {
    assert.deepEqual(parseResolvectlField('', 'DNS Servers'), []);
  });

  it('handles a label with no value', () => {
    assert.deepEqual(parseResolvectlField('       DNS Servers:\n', 'DNS Servers'), []);
  });
});

/**
 * The live DNS checks.
 *
 * This is what the command exists for. A tunnel can be authenticated, routed
 * and pingable while Azure Virtual Desktop still fails with "Access is
 * forbidden from this network", because the name resolved through public DNS
 * to a public endpoint. Nothing about the tunnel looks wrong in that state, so
 * these checks have to distinguish "some DNS is attached" from "the DNS the
 * profile asked for is attached, and something is routed to it".
 *
 * The runner records argv instead of executing, so no resolvectl runs and the
 * host's resolver is never touched.
 */

/** Build a context whose runner answers `ip` and `resolvectl` from a script. */
function liveContext(responses: {
  interfaceExists?: boolean | Error;
  status?: string | Error;
  query?: (name: string) => CommandResult;
}): { context: CommandContext; runner: RecordingCommandRunner } {
  const runner = new RecordingCommandRunner((command, args) => {
    if (command === 'ip') {
      if (responses.interfaceExists instanceof Error) return responses.interfaceExists;
      return { code: responses.interfaceExists === false ? 1 : 0, stdout: '', stderr: '' };
    }
    if (command === 'resolvectl' && args[0] === 'status') {
      if (responses.status instanceof Error) return responses.status;
      return {
        code: responses.status === undefined ? 1 : 0,
        stdout: responses.status ?? '',
        stderr: '',
      };
    }
    if (command === 'resolvectl' && args[0] === 'query') {
      return responses.query?.(args.at(-1) ?? '') ?? { code: 0, stdout: '', stderr: '' };
    }
    return { code: 0, stdout: '', stderr: '' };
  });

  const paths = resolvePaths({ XDG_RUNTIME_DIR: runtimeDir }, { euid: 1000, egid: 1000 });
  return {
    runner,
    context: {
      ui: new Ui({ quiet: true }),
      paths,
      runner,
      elevator: new Elevator({ euid: 0 }),
      session: new SessionStore(join(runtimeDir, 'session.json')),
      repoRoot: undefined,
    },
  };
}

async function writeLiveSession(record: Partial<SessionRecord>): Promise<void> {
  await new SessionStore(join(runtimeDir, 'session.json')).write({
    version: 1,
    profileName: 'contoso',
    gateway: 'azuregateway-fake-0000.vpn.azure.com',
    openvpnPid: process.pid,
    openvpnStartTime: processStartTime(process.pid),
    ownerPid: process.pid,
    interfaceName: 'tun0',
    assignedAddress: '172.16.0.5',
    dnsServers: ['10.10.0.4'],
    dnsDomains: ['wvd.microsoft.com'],
    pushedRoutes: [],
    includeRoutes: [],
    account: 'user@contoso.example',
    connectedAt: new Date().toISOString(),
    credentialsPath: '',
    managementSocket: '',
    configPath: '',
    ...record,
  });
}

/** The one check with this label, so a test says which claim it is about. */
function check(checks: readonly Check[], pattern: RegExp): Check {
  const found = checks.find((entry) => pattern.test(entry.label));
  assert.ok(found, `no check matching ${pattern}; got:\n${checks.map((c) => c.label).join('\n')}`);
  return found;
}

const HEALTHY_STATUS = `Link 5 (tun0)
    Current Scopes: DNS
       DNS Servers: 10.10.0.4
        DNS Domain: ~wvd.microsoft.com
     Default Route: no`;

describe('doctor: live DNS checks', () => {
  it('passes a correctly configured link', async () => {
    const { context } = liveContext({ interfaceExists: true, status: HEALTHY_STATUS });
    await writeLiveSession({});

    const checks = await liveChecks(context, undefined, undefined);

    assert.equal(check(checks, /DNS servers are attached/).status, 'ok');
    assert.equal(check(checks, /routing domains are installed/).status, 'ok');
    assert.equal(check(checks, /not eligible as the default DNS route/).status, 'ok');
  });

  it('fails when a resolver is attached but not the one the profile requires', async () => {
    // DNS is present, so a check for
    // "any DNS" passes, while every private name still resolves publicly.
    const { context } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS.replace('10.10.0.4', '8.8.8.8'),
    });
    await writeLiveSession({ dnsServers: ['10.10.0.4'] });

    const result = check(await liveChecks(context, undefined, undefined), /different DNS servers/);

    assert.equal(result.status, 'fail');
    assert.match(result.detail ?? '', /expected 10\.10\.0\.4, found 8\.8\.8\.8/);
    assert.match(result.fix ?? '', /resolvectl dns tun0 10\.10\.0\.4/);
  });

  it('fails when servers are attached but nothing is routed to them', async () => {
    // The Private Link trap: resolvectl only queries a link's servers when a
    // routing domain matches, so this configuration sends them nothing.
    const { context } = liveContext({
      interfaceExists: true,
      status: `Link 5 (tun0)\n       DNS Servers: 10.10.0.4\n     Default Route: no`,
    });
    await writeLiveSession({});

    const result = check(
      await liveChecks(context, undefined, undefined),
      /routing domains are not/,
    );

    assert.equal(result.status, 'fail');
    assert.match(result.fix ?? '', /sudo resolvectl domain tun0 ~wvd\.microsoft\.com/);
  });

  it('fails when the expected domain is missing but another is present', async () => {
    const { context } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS.replace('~wvd.microsoft.com', '~unrelated.example'),
    });
    await writeLiveSession({});

    const result = check(await liveChecks(context, undefined, undefined), /expected DNS routing/);
    assert.equal(result.status, 'fail');
    assert.match(result.detail ?? '', /expected ~wvd\.microsoft\.com, found ~unrelated\.example/);
  });

  it('accepts ~. as covering any expected domain', async () => {
    // ~. routes every name to the link, so a specific suffix is matched by it
    // even though the literal string is absent.
    const { context } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS.replace('~wvd.microsoft.com', '~.'),
    });
    await writeLiveSession({ dnsDomains: ['wvd.microsoft.com'] });

    const checks = await liveChecks(context, undefined, undefined);
    assert.equal(check(checks, /routing domains are installed/).status, 'ok');
    // But ~. was not asked for, so it is still worth flagging.
    assert.equal(check(checks, /every DNS name is routed/).status, 'warn');
  });

  it('treats ~. as expected when --dns-all asked for it', async () => {
    const { context } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS.replace('~wvd.microsoft.com', '~.'),
    });
    await writeLiveSession({ dnsDomains: ['.'] });

    const result = check(
      await liveChecks(context, undefined, undefined),
      /every DNS name is routed/,
    );
    assert.equal(result.status, 'ok');
    assert.match(result.detail ?? '', /requested with --dns-all/);
  });

  it('warns when the link is eligible as the default DNS route', async () => {
    // Distinct from ~.: this decides where a name that matches no routing
    // domain goes, which is not something a VPN profile asked for.
    const { context } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS.replace('Default Route: no', 'Default Route: yes'),
    });
    await writeLiveSession({});

    const result = check(
      await liveChecks(context, undefined, undefined),
      /eligible as the default/,
    );
    assert.equal(result.status, 'warn');
    assert.match(result.fix ?? '', /resolvectl default-route tun0 no/);
  });
});

describe('doctor: live state that is not a DNS problem', () => {
  it('reports "not connected" and stops when there is no session', async () => {
    const { context, runner } = liveContext({});
    const checks = await liveChecks(context, undefined, undefined);

    assert.deepEqual(
      checks.map((entry) => entry.status),
      ['skip'],
    );
    assert.deepEqual(runner.calls, [], 'nothing should be probed when nothing is connected');
  });

  it('distinguishes a stale record from being disconnected', async () => {
    // There is state to clean up, which "not connected" would not tell you.
    const { context } = liveContext({});
    await writeLiveSession({ openvpnPid: 2 ** 30, openvpnStartTime: 1 });

    const result = check(await liveChecks(context, undefined, undefined), /session record remains/);
    assert.equal(result.status, 'warn');
    assert.match(result.fix ?? '', /openp2s disconnect/);
  });

  it('fails, and stops, when the interface is gone although OpenVPN runs', async () => {
    // A live pid is not a working tunnel: OpenVPN keeps retrying after a
    // dropped connection, carrying no traffic. Checking DNS on a link that
    // does not exist would produce noise, not a diagnosis.
    const { context } = liveContext({ interfaceExists: false });
    await writeLiveSession({});

    const checks = await liveChecks(context, undefined, undefined);
    assert.equal(check(checks, /does not exist/).status, 'fail');
    assert.equal(checks.length, 1, 'no DNS checks should follow a missing interface');
  });

  it('says it could not tell, rather than guessing, when ip is unavailable', async () => {
    const { context } = liveContext({
      interfaceExists: new Error('spawn ip ENOENT'),
      status: HEALTHY_STATUS,
    });
    await writeLiveSession({});

    const checks = await liveChecks(context, undefined, undefined);
    assert.equal(check(checks, /could not check whether tun0 exists/).status, 'warn');
    // And it carries on: the DNS checks are still worth running.
    assert.equal(check(checks, /DNS servers are attached/).status, 'ok');
  });

  it('skips DNS checks entirely when the connection configured none', async () => {
    const { context } = liveContext({ interfaceExists: true, status: HEALTHY_STATUS });
    await writeLiveSession({ dnsServers: [] });

    const checks = await liveChecks(context, undefined, undefined);
    assert.equal(check(checks, /no DNS was configured/).status, 'skip');
  });
});

describe('doctor: the Private Link probe', () => {
  it('passes only when the name resolves to a private address', async () => {
    // The whole point: a public answer for a Private Link name is the silent
    // failure, and it looks identical to success from every other angle.
    const { context } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS,
      query: () => ({ code: 0, stdout: 'app.privatelink.example: 10.20.0.7\n', stderr: '' }),
    });
    await writeLiveSession({});

    const result = check(
      await liveChecks(context, undefined, 'app.privatelink.example'),
      /resolves through the VPN/,
    );
    assert.equal(result.status, 'ok');
  });

  it('warns when the name resolves to a public address', async () => {
    const { context } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS,
      query: () => ({ code: 0, stdout: 'app.privatelink.example: 203.0.113.10\n', stderr: '' }),
    });
    await writeLiveSession({});

    const result = check(
      await liveChecks(context, undefined, 'app.privatelink.example'),
      /resolves through the VPN/,
    );
    assert.equal(result.status, 'warn', 'a public answer is the failure this check exists for');
    assert.match(result.fix ?? '', /answered publicly/);
  });

  it('recognises every RFC1918 range as private', async () => {
    for (const address of ['10.0.0.1', '192.168.1.1', '172.16.0.1', '172.31.255.254']) {
      const { context } = liveContext({
        interfaceExists: true,
        status: HEALTHY_STATUS,
        query: () => ({ code: 0, stdout: `host.example: ${address}\n`, stderr: '' }),
      });
      await writeLiveSession({});

      const result = check(
        await liveChecks(context, undefined, 'host.example'),
        /resolves through the VPN/,
      );
      assert.equal(result.status, 'ok', `${address} should count as private`);
    }
  });

  it('does not mistake 172.32 for a private address', async () => {
    // The RFC1918 block is 172.16-31 only; 172.32 is public.
    const { context } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS,
      query: () => ({ code: 0, stdout: 'host.example: 172.32.0.1\n', stderr: '' }),
    });
    await writeLiveSession({});

    const result = check(
      await liveChecks(context, undefined, 'host.example'),
      /resolves through the VPN/,
    );
    assert.equal(result.status, 'warn');
  });

  it('queries through the VPN interface, not the system resolver', async () => {
    // Asking the system resolver would answer the wrong question entirely.
    const { context, runner } = liveContext({
      interfaceExists: true,
      status: HEALTHY_STATUS,
      query: () => ({ code: 0, stdout: 'host.example: 10.0.0.1\n', stderr: '' }),
    });
    await writeLiveSession({});

    await liveChecks(context, undefined, 'host.example');

    assert.ok(
      runner.commandLines.includes('resolvectl query --interface tun0 host.example'),
      `expected an interface-scoped query, got ${JSON.stringify(runner.commandLines)}`,
    );
  });

  it('runs no probe when none was requested', async () => {
    const { context, runner } = liveContext({ interfaceExists: true, status: HEALTHY_STATUS });
    await writeLiveSession({});

    await liveChecks(context, undefined, undefined);

    assert.ok(!runner.commandLines.some((line) => line.includes('query')));
  });
});
