/**
 * OpenVPN config rendering.
 *
 * A golden test plus a set of invariants. The golden file catches accidental
 * drift; the invariants state the things that must be true for the config to
 * be safe, so that a future edit which changes the layout still has to keep
 * the guarantees.
 */

import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { azureCompatDirectives } from '../src/openvpn/azureCompat.ts';
import { openVpnValue, renderCredentials, renderOpenVpnConfig } from '../src/openvpn/config.ts';
import { AzureProfileParser } from '../src/profile/parser.ts';
import type { AzureVpnProfile } from '../src/profile/types.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures');
const GOLDEN = join(FIXTURES, 'expected-openvpn.conf');

const CREDENTIALS_PATH = '/run/user/1000/openp2s/credentials';
const CA_PATH = '/etc/ssl/certs/DigiCert_Global_Root_G2.pem';

function loadProfile(name = 'valid-full'): AzureVpnProfile {
  const xml = readFileSync(join(FIXTURES, `${name}.xml`), 'utf8');
  return new AzureProfileParser().parse(xml, { name: 'contoso' });
}

const MANAGEMENT_SOCKET = '/run/user/1000/openp2s/mgmt.sock';

/** What `connect` renders: credentials over the management socket. */
function render(profile = loadProfile(), overrides: Record<string, unknown> = {}): string {
  return renderOpenVpnConfig({
    profile,
    credentials: { kind: 'management', socketPath: MANAGEMENT_SOCKET },
    caPath: CA_PATH,
    ...overrides,
  });
}

/** The fallback, for OpenVPN older than 2.7.2. */
function renderWithFile(profile = loadProfile()): string {
  return renderOpenVpnConfig({
    profile,
    credentials: { kind: 'file', path: CREDENTIALS_PATH },
    caPath: CA_PATH,
  });
}

/** What `convert` writes: portable, naming no credential source. */
function renderPortable(profile = loadProfile()): string {
  return renderOpenVpnConfig({
    profile,
    credentials: { kind: 'external' },
    caPath: CA_PATH,
    standalone: true,
  });
}

/**
 * The directives only, with comments and blank lines dropped.
 *
 * Assertions about what a config does must look at what OpenVPN reads. The
 * explanatory comments legitimately discuss credentials, key logging and the
 * management socket, so matching against the whole document turns a prose
 * edit into a test failure.
 */
function directives(config: string): string[] {
  return config
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

describe('renderOpenVpnConfig: golden output', () => {
  it('matches the checked-in golden config', () => {
    const actual = render();

    // Regenerate with: UPDATE_GOLDEN=1 node --test tests/openvpn-config.test.ts
    if (process.env['UPDATE_GOLDEN'] === '1') {
      writeFileSync(GOLDEN, actual);
    }

    const expected = readFileSync(GOLDEN, 'utf8');
    assert.equal(actual, expected);
  });
});

describe('renderOpenVpnConfig: security invariants', () => {
  // These restate things the golden file already pins byte-for-byte, on
  // purpose: `UPDATE_GOLDEN=1` is a one-line command, and a regenerated golden
  // would otherwise accept a silently dropped guarantee.
  const config = render();

  it('names no credentials file at all in the default configuration', () => {
    // The token goes over the management socket, so there is no file to name.
    assert.match(config, /^auth-user-pass$/m);
    assert.ok(!config.includes(CREDENTIALS_PATH));
  });

  it('configures OpenVPN to connect to our socket, not create its own', () => {
    // management-client is what lets OpenP2S create the socket at 0600
    // before OpenVPN starts. Without it OpenVPN listens and would replace it.
    assert.match(config, new RegExp(`^management ${MANAGEMENT_SOCKET} unix$`, 'm'));
    assert.match(config, /^management-client$/m);
    assert.match(config, /^management-query-passwords$/m);
    assert.match(config, /^management-hold$/m);
  });

  it('still references a credentials file in the fallback configuration', () => {
    const fallback = renderWithFile();
    assert.match(fallback, new RegExp(`^auth-user-pass ${CREDENTIALS_PATH}$`, 'm'));
    assert.ok(!fallback.includes('management'));
  });

  it('names no credential source in portable output', () => {
    // `convert` output is meant to be read, copied and diffed, so it must not
    // bake in a runtime path. And a bearer token must never be stored.
    const portable = renderPortable();

    const lines = directives(portable);

    assert.ok(
      !lines.some((line) => line.startsWith('auth-user-pass')),
      'must not name a credentials file',
    );
    assert.ok(
      !lines.some((line) => line.startsWith('management')),
      'must not name a runtime socket',
    );
    assert.ok(
      !lines.some((line) => line.includes('/run/user/')),
      'must not contain a runtime path',
    );
    assert.match(portable, /Authentication credentials are supplied by OpenP2S at runtime/);
  });

  it('sets auth-nocache so the credential is not retained', () => {
    assert.match(config, /^auth-nocache$/m);
  });

  it('requires the peer to present a server certificate', () => {
    assert.match(config, /^remote-cert-tls server$/m);
  });

  it('never disables certificate verification', () => {
    // Directives, not the whole document: a comment explaining why something
    // is insecure is not the same as a directive making it so.
    for (const forbidden of [
      'verify-client-cert none',
      'tls-verify',
      'tls-cert-profile insecure',
      'peer-fingerprint',
      'verify-x509-name none',
    ]) {
      assert.ok(
        !directives(config).some((line) => line.startsWith(forbidden)),
        `config must not contain a "${forbidden}" directive`,
      );
    }
  });

  it('contains no TLS key logging directive', () => {
    assert.ok(
      !directives(config).some((line) => /keylog/i.test(line)),
      'config must never enable key logging',
    );
  });

  it('does not enable scripting hooks', () => {
    // script-security > 0 would let a pushed option run a command.
    for (const forbidden of ['script-security', 'up ', 'down ', 'route-up']) {
      assert.ok(
        !directives(config).some((line) => line.startsWith(forbidden)),
        `config must not contain a "${forbidden}" directive`,
      );
    }
  });

  it('embeds the tls-auth key inline with key-direction 1', () => {
    assert.match(config, /^key-direction 1$/m);
    assert.match(config, /^<tls-auth>$/m);
    assert.match(config, /^<\/tls-auth>$/m);
    assert.match(config, /-----BEGIN OpenVPN Static key V1-----/);
    assert.match(config, /-----END OpenVPN Static key V1-----/);
  });

  it('pins AES-256-GCM rather than leaving negotiation open', () => {
    assert.match(config, /^cipher AES-256-GCM$/m);
    assert.match(config, /^data-ciphers AES-256-GCM$/m);
    assert.match(config, /^data-ciphers-fallback AES-256-GCM$/m);
  });

  it('disables renegotiation, which a short-lived token cannot survive', () => {
    assert.match(config, /^reneg-sec 0$/m);
  });

  it('adds no route directives, leaving PUSH_REPLY routes to OpenVPN', () => {
    // Duplicating pushed routes here would fight with what the gateway sends.
    const routeLines = config.split('\n').filter((line) => /^route\s/.test(line.trim()));
    assert.deepEqual(routeLines, []);
  });
});

describe('renderOpenVpnConfig: options', () => {
  it('omits verify-x509-name by default', () => {
    assert.ok(!render().includes('verify-x509-name'));
  });

  it('emits verify-x509-name when a name is requested', () => {
    const config = render(loadProfile(), { verifyName: '*.vpn.azure.com' });
    assert.match(config, /^verify-x509-name \*\.vpn\.azure\.com name$/m);
  });

  it('honours a custom verbosity', () => {
    assert.match(render(loadProfile(), { verb: 4 }), /^verb 4$/m);
  });

  it('renders a minimal profile without a clientconfig', () => {
    const config = render(loadProfile('valid-minimal'));
    assert.match(config, /^remote azuregateway-minimal-0001\.vpn\.azure\.com 443$/m);
  });
});

describe('renderCredentials', () => {
  it('writes username then token, each on its own line', () => {
    assert.equal(renderCredentials('AzureAD', 'TOKEN'), 'AzureAD\nTOKEN\n');
  });
});

describe('azureCompatDirectives', () => {
  it('emits nothing by default', () => {
    // Measured against a live gateway: the patch's buffer sizes are the only
    // load-bearing change, so the generated config needs no Azure directives
    // at all. See README.md.
    assert.deepEqual(azureCompatDirectives(), []);
  });

  it('emits experimental-azure-compat only when explicitly requested', () => {
    assert.deepEqual(azureCompatDirectives({ compat: true }), ['experimental-azure-compat']);
  });

  it('names the option "experimental", so its status is visible in the config', () => {
    // Measurement showed it is not required; the name says so wherever it
    // appears, including in the generated config a user might read.
    const [directive] = azureCompatDirectives({ compat: true });
    assert.ok(directive?.startsWith('experimental-'), `got "${directive}"`);
  });

  it('can never emit a key-logging directive', () => {
    // No shipped binary understands a key-logging directive, and nothing
    // here can produce one.
    for (const directives of [azureCompatDirectives(), azureCompatDirectives({ compat: true })]) {
      assert.ok(!directives.some((line) => /keylog/i.test(line)));
    }
  });

  it('emits no TLS shaping directives at all', () => {
    // TLS ClientHello shaping is not carried at all: a shipped binary does
    // not understand these options.
    const directives = azureCompatDirectives({ compat: true });
    for (const gone of ['azure-tls-sni', 'azure-tls-alpn', 'azure-tls-pha']) {
      assert.ok(!directives.some((line) => line.startsWith(gone)), `${gone} should be gone`);
    }
  });

  it('emits no environment variables at all', () => {
    // Regression guard: the old design used OPENVPN_* env vars, which broke
    // under sudo env_reset and treated VAR=0 as enabled.
    for (const line of azureCompatDirectives({ compat: true })) {
      assert.ok(!line.startsWith('OPENVPN_'), `"${line}" looks like an environment variable`);
    }
  });
});

describe('connect = convert + credential delivery', () => {
  // The layering is inspect < convert < connect: convert renders the same
  // artifacts connect runs, so convert is a tested slice of the main path
  // rather than a parallel implementation. This test pins that down - the
  // *only* difference permitted between the two is the credential block.
  // Only the two directive prefixes that actually differ between modes. The
  // explanatory prose about credentials differs too, but `directives()`
  // already drops comments - a longer list would be dead weight, and a
  // loosely-worded entry in it could quietly filter away real drift.
  const CREDENTIAL_MARKERS = ['auth-user-pass', 'management'];

  /** The directives, minus every credential-related one. */
  const skeleton = (config: string): string[] =>
    directives(config).filter(
      (line) => !CREDENTIAL_MARKERS.some((marker) => line.startsWith(marker)),
    );

  it('renders an identical connection skeleton in all three modes', () => {
    const viaManagement = skeleton(render());
    const viaFile = skeleton(renderWithFile());
    const portable = skeleton(renderPortable());

    assert.deepEqual(viaFile, viaManagement, 'file mode must differ only in credentials');
    assert.deepEqual(portable, viaManagement, 'portable mode must differ only in credentials');
  });

  it('carries the same gateway, cipher, CA and tls-auth key in every mode', () => {
    const profile = loadProfile();
    for (const config of [render(), renderWithFile(), renderPortable()]) {
      assert.match(config, new RegExp(`^remote ${profile.gateway} 443$`, 'm'));
      assert.match(config, /^cipher AES-256-GCM$/m);
      assert.match(config, new RegExp(`^ca ${CA_PATH.replace(/\./g, '\\.')}$`, 'm'));
      assert.match(config, /^key-direction 1$/m);
      const body = config
        .slice(config.indexOf('<tls-auth>'), config.indexOf('</tls-auth>'))
        .split('\n')
        .filter((line) => /^[0-9a-f]{32}$/.test(line));
      assert.equal(body.join(''), profile.serverSecret);
    }
  });

  it('never renders a token in any mode', () => {
    for (const config of [render(), renderWithFile(), renderPortable()]) {
      assert.ok(!/eyJ[A-Za-z0-9_-]+\./.test(config), 'no JWT anywhere');
    }
  });
});

describe('config value escaping', () => {
  // Paths and names reaching the renderer from the CLI are user input, and the
  // generated config is read by a process running as root.

  it('rejects a newline, which would append an arbitrary directive', () => {
    assert.throws(() => openVpnValue('/tmp/x\nscript-security 2', '--ca'), /control character/);
  });

  it('rejects carriage returns, NUL and escape', () => {
    for (const bad of ['/tmp/a\rb', '/tmp/a\0b', '/tmp/a\x1bb']) {
      assert.throws(() => openVpnValue(bad, '--ca'), /control character/);
    }
  });

  it('rejects an empty value', () => {
    assert.throws(() => openVpnValue('', '--ca'), /is empty/);
  });

  it('leaves an ordinary path alone', () => {
    assert.equal(openVpnValue('/etc/ssl/certs/ca.pem', '--ca'), '/etc/ssl/certs/ca.pem');
  });

  it('leaves a wildcard certificate name alone', () => {
    assert.equal(openVpnValue('*.vpn.azure.com', '--verify-name'), '*.vpn.azure.com');
  });

  it('quotes a path containing spaces', () => {
    assert.equal(openVpnValue('/home/me/My VPN/creds', '--credentials'), '"/home/me/My VPN/creds"');
  });

  it('quotes values containing comment characters', () => {
    // # and ; introduce comments in an OpenVPN config; unquoted, the rest of
    // the directive would be silently dropped.
    assert.equal(openVpnValue('/tmp/a#b', '--ca'), '"/tmp/a#b"');
    assert.equal(openVpnValue('/tmp/a;b', '--ca'), '"/tmp/a;b"');
  });

  it('escapes quotes and backslashes inside a quoted value', () => {
    assert.equal(openVpnValue('/tmp/we"ird', '--ca'), '"/tmp/we\\"ird"');
    assert.equal(openVpnValue('/tmp/back\\slash', '--ca'), '"/tmp/back\\\\slash"');
  });

  it('escapes a hostile path when it reaches the config', () => {
    const config = renderOpenVpnConfig({
      profile: loadProfile(),
      credentials: { kind: 'file', path: '/home/me/My VPN/creds' },
      caPath: CA_PATH,
    });
    assert.match(config, /^auth-user-pass "\/home\/me\/My VPN\/creds"$/m);
  });

  it('refuses to render a config with an injected directive', () => {
    assert.throws(
      () =>
        renderOpenVpnConfig({
          profile: loadProfile(),
          credentials: { kind: 'file', path: '/tmp/x\nscript-security 2' },
          caPath: CA_PATH,
        }),
      /control character/,
    );
  });
});

describe('inline CA', () => {
  const PEM = '-----BEGIN CERTIFICATE-----\nMIIsynthetic\n-----END CERTIFICATE-----\n';

  it('embeds the certificate instead of naming a path', () => {
    // A distribution-specific path is meaningless on another machine.
    const config = renderOpenVpnConfig({
      profile: loadProfile(),
      credentials: { kind: 'external' },
      caPath: CA_PATH,
      inlineCa: PEM,
      standalone: true,
    });

    assert.match(config, /^<ca>$/m);
    assert.match(config, /^<\/ca>$/m);
    assert.match(config, /BEGIN CERTIFICATE/);
    assert.ok(!config.includes(`ca ${CA_PATH}`), 'must not also reference the path');
  });

  it('references a path when not inlining', () => {
    const config = renderOpenVpnConfig({
      profile: loadProfile(),
      credentials: { kind: 'external' },
      caPath: CA_PATH,
      standalone: true,
    });
    assert.match(config, new RegExp(`^ca ${CA_PATH.replace(/\./g, '\\.')}$`, 'm'));
    assert.ok(!config.includes('<ca>'));
  });
});
