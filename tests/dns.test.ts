/**
 * Split DNS behaviour.
 *
 * These tests never touch the host's resolver: the command runner records
 * argv instead of executing it, which is the whole reason DNS goes through
 * the CommandRunner abstraction.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { privateLinkWarning, toRoutingDomain, toRoutingDomains } from '../src/network/dns.ts';
import { SystemdResolvedConfigurator } from '../src/network/systemdResolved.ts';
import { RecordingCommandRunner } from '../src/platform/exec.ts';
import { Elevator } from '../src/platform/privilege.ts';
import { NetworkError } from '../src/errors.ts';

/**
 * A stand-in for resolvectl at a known absolute path.
 *
 * The elevator resolves commands to absolute paths before they cross the
 * privilege boundary, so the assertions below name this path rather than a
 * bare `resolvectl` - which is the point: what runs under sudo should not
 * depend on sudo's PATH.
 */
const RESOLVECTL = '/usr/bin/openp2s-test-resolvectl';

function makeConfigurator(runner: RecordingCommandRunner, euid = 0): SystemdResolvedConfigurator {
  return new SystemdResolvedConfigurator({
    runner,
    elevator: new Elevator({ euid }),
    resolvectlPath: RESOLVECTL,
  });
}

describe('routing domain normalisation', () => {
  it('converts a leading-dot suffix to a route-only domain', () => {
    assert.equal(toRoutingDomain('.wvd.microsoft.com'), '~wvd.microsoft.com');
  });

  it('converts a bare suffix to a route-only domain', () => {
    assert.equal(toRoutingDomain('wvd.microsoft.com'), '~wvd.microsoft.com');
  });

  it('is idempotent for an already-prefixed domain', () => {
    assert.equal(toRoutingDomain('~wvd.microsoft.com'), '~wvd.microsoft.com');
  });

  it('strips a trailing dot', () => {
    assert.equal(toRoutingDomain('wvd.microsoft.com.'), '~wvd.microsoft.com');
  });

  it('deduplicates suffixes that normalise to the same domain', () => {
    assert.deepEqual(
      toRoutingDomains(['.wvd.microsoft.com', 'wvd.microsoft.com', 'corp.example']),
      ['~wvd.microsoft.com', '~corp.example'],
    );
  });

  it('drops an empty suffix rather than emitting a bare tilde', () => {
    // A bare "~" would be a route-only domain matching everything, i.e. the
    // exact global-takeover we are trying to avoid.
    assert.deepEqual(toRoutingDomains(['', '.', '~']), []);
  });
});

describe('SystemdResolvedConfigurator.configure', () => {
  it('sets servers, routing domains, and disables default-route', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure(
      'tun0',
      ['10.10.0.4', '10.10.0.5'],
      ['.wvd.microsoft.com', 'corp.contoso.example'],
    );

    assert.deepEqual(runner.commandLines, [
      `${RESOLVECTL} dns tun0 10.10.0.4 10.10.0.5`,
      `${RESOLVECTL} domain tun0 ~wvd.microsoft.com ~corp.contoso.example`,
      `${RESOLVECTL} default-route tun0 no`,
    ]);
  });

  it('always disables default-route, even with no suffixes', async () => {
    // This is the invariant that keeps the VPN from becoming the system
    // resolver. It must hold on every path through configure().
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure('tun0', ['10.10.0.4'], []);

    assert.deepEqual(runner.commandLines, [
      `${RESOLVECTL} dns tun0 10.10.0.4`,
      `${RESOLVECTL} default-route tun0 no`,
    ]);
  });

  it('never issues a domain without the route-only tilde', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure('tun0', ['10.0.0.1'], ['example.com']);

    const domainCall = runner.calls.find((call) => call.args[0] === 'domain');
    assert.ok(domainCall, 'expected a domain call');
    for (const domain of domainCall.args.slice(2)) {
      assert.ok(domain.startsWith('~'), `domain ${domain} must be route-only`);
    }
  });

  it('does nothing at all when the profile supplies no DNS servers', async () => {
    // Issuing `resolvectl dns tun0` with no servers would clear the link.
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure('tun0', [], ['.wvd.microsoft.com']);
    assert.deepEqual(runner.calls, []);
  });

  it('escalates through sudo when not running as root', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner, 1000).configure('tun0', ['10.0.0.1'], []);

    assert.deepEqual(runner.commandLines, [
      `sudo -- ${RESOLVECTL} dns tun0 10.0.0.1`,
      `sudo -- ${RESOLVECTL} default-route tun0 no`,
    ]);
  });

  it('passes each value as its own argv entry, never a shell string', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure('tun0', ['10.0.0.1', '10.0.0.2'], []);

    const call = runner.calls[0];
    assert.ok(call);
    assert.deepEqual(call.args, ['dns', 'tun0', '10.0.0.1', '10.0.0.2']);
    for (const arg of call.args) {
      assert.ok(!arg.includes(' '), 'no argument should be a packed command string');
    }
  });

  it('raises NetworkError with a diagnosis when resolvectl fails', async () => {
    const runner = new RecordingCommandRunner(() => ({
      code: 1,
      stdout: '',
      stderr:
        'Failed to set DNS configuration: Unit dbus-org.freedesktop.resolve1.service not found',
    }));

    await assert.rejects(
      () => makeConfigurator(runner).configure('tun0', ['10.0.0.1'], []),
      (error: unknown) => {
        assert.ok(error instanceof NetworkError);
        assert.match(error.message, /failed to configure DNS on tun0/);
        assert.match(error.hint ?? '', /systemd-resolved/);
        return true;
      },
    );
  });
});

describe('SystemdResolvedConfigurator.revert', () => {
  it('reverts the link', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).revert('tun0');
    assert.deepEqual(runner.commandLines, [`${RESOLVECTL} revert tun0`]);
  });

  it('never throws, because it runs on the cleanup path', async () => {
    // If revert threw, a failed connect would abandon the remaining cleanup
    // and leave credentials on disk.
    const runner = new RecordingCommandRunner(() => new Error('resolvectl is gone'));
    await makeConfigurator(runner).revert('tun0');
  });
});

describe('~. is opt-in only', () => {
  it('never emits ~. from profile suffixes alone', async () => {
    // The oal project uses ~. as a general workaround. We have the profile, so
    // we route only the suffixes it names; sending every query to the
    // corporate resolver would leak the user's whole browsing history.
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure('tun0', ['10.0.0.1'], ['wvd.microsoft.com']);

    const domainCall = runner.calls.find((call) => call.args[0] === 'domain');
    assert.ok(domainCall);
    assert.ok(!domainCall.args.includes('~.'), 'must not route all domains implicitly');
  });

  it('does not infer ~. when a profile has servers but no suffixes', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure('tun0', ['10.0.0.1'], []);
    assert.ok(!runner.commandLines.some((line) => line.includes('~.')));
  });

  it('emits ~. only when explicitly asked', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure('tun0', ['10.0.0.1'], ['wvd.microsoft.com'], {
      allDomains: true,
    });

    assert.deepEqual(runner.commandLines, [
      `${RESOLVECTL} dns tun0 10.0.0.1`,
      `${RESOLVECTL} domain tun0 ~.`,
      `${RESOLVECTL} default-route tun0 no`,
    ]);
  });

  it('still refuses to become the default route even with ~.', async () => {
    // ~. makes this link preferred for unmatched names; default-route yes
    // would make it authoritative. Those are different, and we only ever want
    // the first.
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).configure('tun0', ['10.0.0.1'], [], { allDomains: true });
    assert.ok(runner.commandLines.includes(`${RESOLVECTL} default-route tun0 no`));
  });
});

describe('only touches the interface it was given', () => {
  it('rejects an implausible interface name', async () => {
    // OpenP2S never enumerates tun* and reconfigures what it finds; it only
    // ever touches the interface its own openvpn process created. This guard
    // makes that structural.
    const runner = new RecordingCommandRunner();
    for (const bad of ['tun0; rm -rf /', '../../etc', 'a'.repeat(16), '', '.', '..']) {
      await assert.rejects(
        () => makeConfigurator(runner).configure(bad, ['10.0.0.1'], []),
        NetworkError,
      );
    }
    assert.deepEqual(runner.calls, [], 'nothing should have been executed');
  });

  it('reverts only the named interface', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).revert('tun3');
    assert.deepEqual(runner.commandLines, [`${RESOLVECTL} revert tun3`]);
  });

  it('ignores a revert for an implausible interface name', async () => {
    const runner = new RecordingCommandRunner();
    await makeConfigurator(runner).revert('tun0 tun1');
    assert.deepEqual(runner.calls, []);
  });
});

describe('Private Link diagnostics', () => {
  it('warns when servers are set but nothing is routed to them', () => {
    // The exact failure the oal project diagnosed: healthy tunnel, corporate
    // resolver attached, queries still answered by public DNS.
    const warning = privateLinkWarning(['10.0.0.53'], [], false);
    assert.ok(warning);
    assert.match(warning, /Private Link/);
  });

  it('does not warn when routing domains are present', () => {
    assert.equal(privateLinkWarning(['10.0.0.53'], ['wvd.microsoft.com'], false), undefined);
  });

  it('does not warn when all domains are routed', () => {
    assert.equal(privateLinkWarning(['10.0.0.53'], [], true), undefined);
  });

  it('does not warn when the profile sets no DNS at all', () => {
    assert.equal(privateLinkWarning([], [], false), undefined);
  });
});
