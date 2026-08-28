/**
 * Azure XML profile parsing.
 *
 * Fixtures contain fabricated GUIDs, hostnames and key material only. There is
 * no real tenant, gateway or serversecret anywhere in this repository.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { AzureProfileParser } from '../src/profile/parser.ts';
import { ProfileError } from '../src/errors.ts';
import { validateAudience, validateTenantUrl } from '../src/profile/validate.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures');
const parser = new AzureProfileParser();

function fixture(name: string): string {
  return readFileSync(join(FIXTURES, `${name}.xml`), 'utf8');
}

/** Build a profile document from parts, for negative cases. */
function buildXml(overrides: Record<string, string | null> = {}): string {
  const fields: Record<string, string | null> = {
    fqdn: 'azuregateway-test-0000.vpn.azure.com',
    tenant: 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555',
    audience: '41b23e61-6c1e-4545-b367-cd054e0ed4b4',
    serversecret: 'ab'.repeat(256),
    ...overrides,
  };

  const body = Object.entries(fields)
    .filter(([, value]) => value !== null)
    .map(([key, value]) => `  <${key}>${value}</${key}>`)
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>\n<AzVpnProfile>\n${body}\n</AzVpnProfile>\n`;
}

describe('AzureProfileParser: well-formed profiles', () => {
  it('parses a full profile into the normalised model', () => {
    const profile = parser.parse(fixture('valid-full'), { name: 'contoso' });

    assert.equal(profile.name, 'contoso');
    assert.equal(profile.gateway, 'azuregateway-fake-0000.vpn.azure.com');
    assert.equal(profile.port, 443);
    assert.equal(
      profile.auth.authority,
      'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555',
    );
    assert.equal(profile.auth.tenantId, '11111111-2222-3333-4444-555555555555');
    assert.equal(profile.auth.audience, '41b23e61-6c1e-4545-b367-cd054e0ed4b4');
    assert.equal(profile.auth.scope, '41b23e61-6c1e-4545-b367-cd054e0ed4b4/.default');
    assert.equal(profile.auth.clientId, '41b23e61-6c1e-4545-b367-cd054e0ed4b4');
    assert.equal(profile.serverSecret.length, 512);
  });

  it('reads multiple DNS servers in document order', () => {
    const profile = parser.parse(fixture('valid-full'));
    assert.deepEqual(profile.dnsServers, ['10.10.0.4', '10.10.0.5']);
  });

  it('reads a single DNS server as a one-element array', () => {
    // fast-xml-parser returns an object rather than an array for one child;
    // this is the case that regresses if toArray() is ever dropped.
    const profile = parser.parse(fixture('valid-namespaced'));
    assert.deepEqual(profile.dnsServers, ['172.16.0.10']);
  });

  it('normalises DNS suffixes by stripping a leading dot', () => {
    const profile = parser.parse(fixture('valid-full'));
    assert.deepEqual(profile.dnsSuffixes, ['wvd.microsoft.com', 'corp.contoso.example']);
  });

  it('parses include routes given as prefix length and as dotted netmask', () => {
    const profile = parser.parse(fixture('valid-full'));
    assert.deepEqual(
      profile.includeRoutes.map((route) => route.cidr),
      ['10.20.0.0/16', '10.30.0.0/24'],
    );
    assert.equal(profile.includeRoutes[0]?.family, 4);
    assert.equal(profile.includeRoutes[1]?.prefixLength, 24);
  });

  it('parses a minimal profile with no clientconfig at all', () => {
    const profile = parser.parse(fixture('valid-minimal'));
    assert.equal(profile.gateway, 'azuregateway-minimal-0001.vpn.azure.com');
    assert.deepEqual(profile.dnsServers, []);
    assert.deepEqual(profile.dnsSuffixes, []);
    assert.deepEqual(profile.includeRoutes, []);
  });

  it('handles namespace-prefixed elements', () => {
    const profile = parser.parse(fixture('valid-namespaced'));
    assert.equal(profile.gateway, 'azuregateway-ns-0002.vpn.azure.com');
    assert.deepEqual(profile.dnsSuffixes, ['wvd.microsoft.com']);
  });

  it('ignores unknown sections instead of failing', () => {
    // Microsoft adds elements over time; an unrecognised block must not stop
    // a profile that is otherwise perfectly usable from working.
    const profile = parser.parse(fixture('valid-extra-sections'));
    assert.equal(profile.gateway, 'azuregateway-extra-0003.vpn.azure.com');
    assert.deepEqual(profile.dnsServers, ['10.0.0.53']);
  });

  it('derives the profile name from the file name', () => {
    const profile = parser.parseFile('/tmp/company-vpn.xml', fixture('valid-minimal'));
    assert.equal(profile.name, 'company-vpn');
  });

  it('lowercases the gateway so config and SNI always agree', () => {
    const profile = parser.parse(buildXml({ fqdn: 'AzureGateway-Mixed.VPN.Azure.Com' }));
    assert.equal(profile.gateway, 'azuregateway-mixed.vpn.azure.com');
  });

  it('deduplicates repeated DNS servers and routes', () => {
    const xml = `<?xml version="1.0"?>
<AzVpnProfile>
  <fqdn>gw.vpn.azure.com</fqdn>
  <tenant>https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555</tenant>
  <audience>41b23e61-6c1e-4545-b367-cd054e0ed4b4</audience>
  <serversecret>${'ab'.repeat(256)}</serversecret>
  <clientconfig>
    <dnsservers><dnsserver>10.0.0.1</dnsserver><dnsserver>10.0.0.1</dnsserver></dnsservers>
    <includeroutes>
      <route><destination>10.1.0.0</destination><mask>16</mask></route>
      <route><destination>10.1.0.0</destination><mask>255.255.0.0</mask></route>
    </includeroutes>
  </clientconfig>
</AzVpnProfile>`;
    const profile = parser.parse(xml);
    assert.deepEqual(profile.dnsServers, ['10.0.0.1']);
    assert.deepEqual(
      profile.includeRoutes.map((r) => r.cidr),
      ['10.1.0.0/16'],
    );
  });
});

describe('AzureProfileParser: rejects bad input', () => {
  const rejects = (xml: string, pattern: RegExp): void => {
    assert.throws(
      () => parser.parse(xml),
      (error: unknown) => {
        assert.ok(error instanceof ProfileError, `expected ProfileError, got ${String(error)}`);
        assert.match(error.message, pattern);
        return true;
      },
    );
  };

  it('rejects malformed XML with a position', () => {
    rejects('<AzVpnProfile><fqdn>x.example.com</AzVpnProfile>', /not well-formed XML at line/);
  });

  it('rejects a document that is not a profile', () => {
    rejects(
      '<?xml version="1.0"?><unrelated><thing>1</thing></unrelated>',
      /missing required element <fqdn>/,
    );
  });

  for (const field of ['fqdn', 'tenant', 'audience', 'serversecret']) {
    it(`rejects a profile missing <${field}>`, () => {
      rejects(buildXml({ [field]: null }), new RegExp(`missing required element <${field}>`));
    });

    it(`rejects a profile with an empty <${field}>`, () => {
      rejects(buildXml({ [field]: '' }), new RegExp(`missing required element <${field}>`));
    });
  }

  it('rejects a tenant that is not a Microsoft login endpoint', () => {
    rejects(
      buildXml({ tenant: 'https://login.evil.example/11111111-2222-3333-4444-555555555555' }),
      /not a recognised Microsoft Entra endpoint/,
    );
  });

  it('rejects a plaintext-http tenant', () => {
    rejects(buildXml({ tenant: 'http://login.microsoftonline.com/common' }), /must use https/);
  });

  it('rejects a tenant that is not a URL at all', () => {
    rejects(buildXml({ tenant: 'not-a-url' }), /not a valid URL/);
  });

  it('rejects a tenant URL carrying embedded credentials', () => {
    rejects(
      buildXml({ tenant: 'https://user:pass@login.microsoftonline.com/common' }),
      /must not contain credentials/,
    );
  });

  it('rejects an invalid DNS server address', () => {
    const xml = buildXml().replace(
      '</AzVpnProfile>',
      '<clientconfig><dnsservers><dnsserver>10.0.0.999</dnsserver></dnsservers></clientconfig></AzVpnProfile>',
    );
    rejects(xml, /not a valid IP address: 10\.0\.0\.999/);
  });

  it('rejects an octal-looking DNS server address', () => {
    // 010.0.0.1 is parsed as octal by some resolvers and decimal by others;
    // ambiguity in an address that decides where DNS goes is not acceptable.
    const xml = buildXml().replace(
      '</AzVpnProfile>',
      '<clientconfig><dnsservers><dnsserver>010.0.0.1</dnsserver></dnsservers></clientconfig></AzVpnProfile>',
    );
    rejects(xml, /not a valid IP address/);
  });

  it('rejects an out-of-range route prefix length', () => {
    const xml = buildXml().replace(
      '</AzVpnProfile>',
      '<clientconfig><includeroutes><route><destination>10.0.0.0</destination><mask>33</mask></route></includeroutes></clientconfig></AzVpnProfile>',
    );
    rejects(xml, /exceeds the maximum for IPv4/);
  });

  it('rejects a non-contiguous netmask', () => {
    const xml = buildXml().replace(
      '</AzVpnProfile>',
      '<clientconfig><includeroutes><route><destination>10.0.0.0</destination><mask>255.0.255.0</mask></route></includeroutes></clientconfig></AzVpnProfile>',
    );
    rejects(xml, /not a contiguous netmask/);
  });

  it('rejects a serversecret of the wrong length', () => {
    rejects(
      buildXml({ serversecret: 'ab'.repeat(255) }),
      /is 510 characters, expected exactly 512/,
    );
  });

  it('rejects a non-hexadecimal serversecret', () => {
    rejects(buildXml({ serversecret: 'zz'.repeat(256) }), /contains non-hexadecimal characters/);
  });

  it('never echoes the serversecret in an error message', () => {
    const secret = 'ab'.repeat(255);
    try {
      parser.parse(buildXml({ serversecret: secret }));
      assert.fail('expected the parser to reject a short serversecret');
    } catch (error) {
      assert.ok(error instanceof ProfileError);
      assert.ok(!error.message.includes('abab'), 'error message must not quote key material');
    }
  });

  it('rejects a gateway hostname carrying shell metacharacters', () => {
    rejects(buildXml({ fqdn: 'gw.vpn.azure.com; touch /tmp/pwned' }), /not a valid hostname/);
  });

  it('rejects a gateway hostname carrying a newline', () => {
    // A newline would let a profile append arbitrary directives to the
    // generated OpenVPN config.
    rejects(buildXml({ fqdn: 'gw.vpn.azure.com\nscript-security 2' }), /not a valid hostname/);
  });

  it('rejects a bare IP as the gateway', () => {
    rejects(buildXml({ fqdn: '203.0.113.10' }), /must be a hostname, not an IP address/);
  });

  it('rejects an audience that is neither GUID nor URI', () => {
    rejects(buildXml({ audience: 'not an audience' }), /neither a GUID nor a URI/);
  });

  it('rejects an oversized profile before parsing it', () => {
    rejects(`<AzVpnProfile>${' '.repeat(1024 * 1024 + 1)}</AzVpnProfile>`, /refusing to parse/);
  });
});

describe('AzureProfileParser: entity handling', () => {
  it('does not expand internal entities', () => {
    // Entity expansion is disabled outright. A profile has no legitimate need
    // for it, and leaving it on invites billion-laughs and XXE-adjacent bugs.
    const xml = `<?xml version="1.0"?>
<!DOCTYPE AzVpnProfile [ <!ENTITY xxe "azuregateway-injected.vpn.azure.com"> ]>
<AzVpnProfile>
  <fqdn>&xxe;</fqdn>
  <tenant>https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555</tenant>
  <audience>41b23e61-6c1e-4545-b367-cd054e0ed4b4</audience>
  <serversecret>${'ab'.repeat(256)}</serversecret>
</AzVpnProfile>`;

    let gateway: string | undefined;
    try {
      gateway = parser.parse(xml).gateway;
    } catch {
      // Rejecting outright is an equally acceptable outcome.
      return;
    }
    assert.notEqual(
      gateway,
      'azuregateway-injected.vpn.azure.com',
      'entity must not be expanded into the gateway',
    );
  });
});

describe('tenant and audience URL hygiene', () => {
  it('rejects a tenant URL carrying more than a tenant', () => {
    // Not a security bypass - the host allowlist still decides where
    // credentials go - but a malformed profile should say so rather than be
    // quietly reinterpreted.
    const base = 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555';
    for (const suffix of ['/foo', '?x=1', '#bar', '/foo?x=1#bar']) {
      assert.throws(
        () => validateTenantUrl(`${base}${suffix}`),
        ProfileError,
        `${suffix} should be rejected`,
      );
    }
  });

  it('still accepts the ordinary forms, with or without a trailing slash', () => {
    const base = 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555';
    assert.equal(validateTenantUrl(base).authority, base);
    assert.equal(validateTenantUrl(`${base}/`).authority, base);
  });

  it('rejects an audience URI that would build a nonsense scope', () => {
    // The scope is this string with "/.default" appended, so a query or
    // fragment yields "https://vpn.example/x?foo=bar/.default".
    for (const uri of [
      'https://vpn.example/x?foo=bar',
      'https://vpn.example/x#frag',
      'https://user:pass@vpn.example/x',
    ]) {
      assert.throws(() => validateAudience(uri), ProfileError, `${uri} should be rejected`);
    }
  });

  it('accepts a bare application ID URI', () => {
    assert.equal(
      validateAudience('https://vpn.example.com').scope,
      'https://vpn.example.com/.default',
    );
    assert.equal(validateAudience('api://11111111-2222-3333-4444-555555555555').kind, 'uri');
  });
});
