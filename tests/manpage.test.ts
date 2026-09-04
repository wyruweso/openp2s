/**
 * The man page's security and exit-status claims.
 *
 * A `.SH SECURITY` section is read as a contract, so its statements are held
 * to the implementation. These assert which claims are present or absent, and
 * that the documented exit codes are the ones the code defines.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { AuthError, NetworkError, OpenP2SError, ProfileError, TunnelError } from '../src/errors.ts';
import { renderOpenVpnConfig } from '../src/openvpn/config.ts';
import { resolveUserIdentity } from '../src/platform/paths.ts';
import { Elevator } from '../src/platform/privilege.ts';
import { AzureProfileParser } from '../src/profile/parser.ts';

const root = (path: string): string => readFileSync(join(import.meta.dirname, '..', path), 'utf8');

/** The page as written, for assertions about roff structure. */
const MAN = root('packaging/openp2s.1');

/**
 * The page as read, for assertions about what it says.
 *
 * Drops the macro name from each request but keeps its arguments, unwraps the
 * font and character escapes, and collapses whitespace - so a claim can be
 * matched as the sentence a reader sees rather than as the lines it happens
 * to be wrapped into today.
 */
const PROSE = MAN.split('\n')
  .map((line) => (line.startsWith('.') ? line.replace(/^\.[A-Za-z]+\s*/, '') : line))
  .join(' ')
  .replace(/\\f[BIRP]/g, '')
  .replace(/\\\(em/g, '-')
  .replace(/\\-/g, '-')
  .replace(/\s+/g, ' ')
  .trim();

/** The default connect config, for claims about what OpenVPN is told. */
function renderedConfig(): string {
  const profile = new AzureProfileParser().parse(root('tests/fixtures/valid-full.xml'), {
    name: 'contoso',
  });
  return renderOpenVpnConfig({
    profile,
    credentials: { kind: 'management', socketPath: '/run/user/1000/openp2s/mgmt.sock' },
    caPath: '/etc/ssl/certs/DigiCert_Global_Root_G2.pem',
  });
}

function directives(config: string): string[] {
  return config
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

describe('claims the man page must not make', () => {
  it('does not claim the token is never written to a file', () => {
    // True only on the management-socket path. The compatibility fallback
    // writes a 0600 file for the lifetime of the connection.
    assert.ok(!/never written to a file/i.test(PROSE));
    assert.ok(!/never appears in a file/i.test(PROSE));
  });

  it('documents the credentials-file fallback instead', () => {
    assert.match(PROSE, /falls back to a temporary credentials file/i);
    assert.match(PROSE, /0600/);
    assert.match(PROSE, /removed during teardown/i);
  });

  it('does not describe probe as unprivileged or as changing nothing', () => {
    assert.ok(!/Run the gateway exchange unprivileged/i.test(PROSE));
    assert.ok(!/without changing anything on the machine/i.test(PROSE));
  });

  it('describes what actually makes a probe non-mutating', () => {
    for (const directive of ['dev null', 'route', 'ifconfig']) {
      assert.ok(PROSE.includes(directive), `probe section should mention ${directive}`);
    }
    assert.match(PROSE, /without creating a tunnel or altering routes or DNS/i);
  });

  it('does not reduce the failure to a single 128-byte buffer', () => {
    assert.match(PROSE, /USER_PASS_LEN/);
    assert.match(PROSE, /TLS_CHANNEL_BUF_SIZE/);
    assert.match(PROSE, /Raising either alone is not sufficient/i);
  });

  it('does not claim the shipped OpenVPN has no Azure-specific code', () => {
    // It does now: the compat patch is compiled in. What is true is that it is
    // inert unless asked for, which is a different statement.
    assert.ok(!/contains no Azure-specific protocol behaviour/i.test(PROSE));
  });
});

describe('the single-binary compat claims', () => {
  it('says the option is compiled in but not used by default', () => {
    assert.match(PROSE, /compiled in but inert/i);
    assert.match(PROSE, /OpenP2S does not use it/i);
  });

  it('says only the local configuration can enable it', () => {
    // This is the property that makes shipping the code safe, so it must be
    // stated - and it must be true.
    assert.match(PROSE, /a server cannot push it/i);
    assert.match(PROSE, /no environment variable affects it/i);
  });

  it('matches the option permission the patch actually sets', () => {
    // OPT_P_GENERAL is not in the pushable set, so a pushed option cannot
    // satisfy it. This one has to read the patch: it is the artifact.
    const patch = root('patches/2.7.6/experimental-azure-compat.patch');
    assert.ok(
      patch.includes('VERIFY_PERMISSION(OPT_P_GENERAL);'),
      'the patch must set a permission mask a pushed option cannot satisfy',
    );
  });

  it('matches the build, which compiles the patch in', () => {
    // If build-openvpn.sh ever stopped applying it, the man page would be
    // describing a capability the binary does not have.
    const build = root('scripts/build-openvpn.sh');
    assert.match(build, /^add_patch experimental-azure-compat experimental_azure_compat$/m);
    assert.match(build, /^azure_compat_available=1$/m);
  });

  it('still says the TLS-shaping experiments are not shipped', () => {
    assert.match(PROSE, /No TLS ClientHello shaping or key-logging code is compiled in/i);

    // And the binary policy is what enforces it.
    const policy = root('scripts/check-binary-policy.sh');
    for (const option of ['azure-tls-sni', 'azure-tls-alpn', 'azure-tls-pha', 'tls-keylog']) {
      assert.ok(policy.includes(option), `${option} must remain on the forbidden list`);
    }
    assert.ok(
      !/^experimental-azure-compat$/m.test(
        policy.split('FORBIDDEN_OPTIONS="')[1]?.split('"')[0] ?? '',
      ),
      'the compat option must no longer be forbidden: it ships',
    );
  });
});

describe('documented exit codes match the code', () => {
  it('documents every code the error classes define', () => {
    const defined = [
      ['ProfileError', new ProfileError('x').exitCode],
      ['AuthError', new AuthError('x').exitCode],
      ['TunnelError', new TunnelError('x').exitCode],
      ['NetworkError', new NetworkError('x').exitCode],
      ['OpenP2SError', new OpenP2SError('x').exitCode],
    ] as const;

    for (const [name, code] of defined) {
      // Structural, so it matches the raw page: each code is its own .B line.
      assert.match(
        MAN,
        new RegExp(`^\\.B ${code}$`, 'm'),
        `exit code ${code} (${name}) undocumented`,
      );
    }
  });

  it('documents 1, which status and doctor both return', () => {
    assert.match(MAN, /^\.B 1$/m);
    assert.match(PROSE, /status returns 1 when no tunnel is connected/i);
  });

  it('describes 5 as covering cleanup, not only configuration', () => {
    assert.match(PROSE, /could not be fully cleaned up/i);
  });
});

describe('claims that are enforced, and so may be stated absolutely', () => {
  it('says certificate verification cannot be disabled, and the renderer agrees', () => {
    assert.match(PROSE, /Certificate verification is never disabled/i);

    const lines = directives(renderedConfig());
    assert.ok(
      lines.includes('remote-cert-tls server'),
      'the renderer must pin peer certificate usage',
    );
    for (const bypass of [
      'peer-fingerprint',
      'tls-cert-profile insecure',
      'verify-client-cert none',
    ]) {
      assert.ok(
        !lines.some((line) => line.startsWith(bypass)),
        `the renderer must never emit ${bypass}`,
      );
    }
  });

  it('says no CA is read from the profile, and the parser ignores one', () => {
    assert.match(PROSE, /no CA is ever read from the profile/i);

    // A profile that tries to supply its own trust anchor. It must parse -
    // unknown elements are tolerated - and the certificate must go nowhere.
    const hostile = `<?xml version="1.0"?>
<AzVpnProfile>
  <fqdn>gw.vpn.azure.com</fqdn>
  <tenant>https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555</tenant>
  <audience>41b23e61-6c1e-4545-b367-cd054e0ed4b4</audience>
  <serversecret>${'ab'.repeat(256)}</serversecret>
  <cacert>-----BEGIN CERTIFICATE-----\nMIIattacker\n-----END CERTIFICATE-----</cacert>
  <cacertificate>MIIalsoattacker</cacertificate>
  <rootcert>MIIthirdattacker</rootcert>
</AzVpnProfile>`;

    const profile = new AzureProfileParser().parse(hostile, { name: 'hostile' });
    const serialised = JSON.stringify(profile);
    for (const marker of ['MIIattacker', 'MIIalsoattacker', 'MIIthirdattacker']) {
      assert.ok(!serialised.includes(marker), `${marker} must not reach the parsed profile`);
    }

    // And it must not reach the config the gateway is validated with either.
    const config = renderOpenVpnConfig({
      profile,
      credentials: { kind: 'management', socketPath: '/run/user/1000/openp2s/mgmt.sock' },
      caPath: '/etc/ssl/certs/DigiCert_Global_Root_G2.pem',
    });
    assert.ok(!config.includes('attacker'), 'no profile-supplied CA may reach the config');
    assert.match(config, /^ca \/etc\/ssl\/certs\/DigiCert_Global_Root_G2\.pem$/m);
  });
});

describe('privileges', () => {
  it('says sudo openp2s is refused, and it is', () => {
    assert.match(PROSE, /Running it as sudo openp2s is refused/i);

    assert.throws(
      () => resolveUserIdentity({ SUDO_UID: '1000' }, { euid: 0 }),
      (error: unknown) => {
        assert.ok(error instanceof OpenP2SError);
        assert.match(error.message, /do not run openp2s under sudo/);
        return true;
      },
    );
  });

  it('leaves no chown behind for a symlink to redirect', () => {
    // A source-policy check on purpose: "no chown anywhere" has no behavioural
    // surface to assert from a test running as one uid, and reintroducing one
    // is what made the sudo path exploitable.
    assert.ok(!root('src/platform/paths.ts').includes('chownSync'));
  });

  it('says elevation is by absolute path, and the elevator resolves one', () => {
    assert.match(PROSE, /by absolute path/i);

    const plan = new Elevator({ euid: 1000, path: '/usr/bin:/bin' }).plan('sh', ['-c', 'true']);
    assert.equal(plan.elevated, true);
    const [dashes, resolved] = plan.args;
    assert.equal(dashes, '--', 'sudo must stop parsing options');
    assert.ok(resolved?.startsWith('/'), `expected an absolute path, got ${String(resolved)}`);
    assert.ok(resolved?.endsWith('/sh'));
  });

  it('refuses a relative path rather than letting sudo resolve it', () => {
    // What sudo finds on its own PATH is not necessarily what this process
    // would have found, so an unresolvable command must fail here.
    const elevator = new Elevator({ euid: 1000, path: '/usr/bin:/bin' });
    assert.throws(() => elevator.plan('./openvpn', []), /refusing to run a relative path/);
    assert.throws(() => elevator.plan('openp2s-no-such-command', []), /was not found on PATH/);
  });
});

describe('file modes', () => {
  it('does not describe a directory as mode 0600', () => {
    assert.ok(!/token cache, mode 0600/i.test(PROSE));
    assert.match(PROSE, /directory is mode 0700; the files in it are mode 0600/i);
  });
});

describe('the documented sign-in flows', () => {
  it('documents the browser flow as the default', () => {
    assert.match(MAN, /browser authorization-code flow with PKCE/i);
  });

  it('says device code is opt-in and why', () => {
    assert.match(MAN, /opt-in/i);
    assert.match(MAN, /phishing/i);
  });

  it('says a missing browser fails rather than waiting', () => {
    assert.match(MAN, /fails rather\s+than waiting/i);
  });

  it('says the two flows never fall back to one another', () => {
    assert.match(MAN, /does not fall back from one flow to the other/i);
  });

  it('says sessions are scoped to their flow', () => {
    assert.match(MAN, /scoped to the flow/i);
  });
});
