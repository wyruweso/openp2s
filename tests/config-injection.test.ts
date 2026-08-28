/**
 * The generated OpenVPN config must contain nothing the profile controls.
 *
 * It is run by OpenVPN as root. Directive values go through openVpnValue(),
 * which rejects control characters; comments carry no values at all, because a
 * newline in one would end the comment and make the rest directives.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { renderOpenVpnConfig } from '../src/openvpn/config.ts';
import { AzureProfileParser } from '../src/profile/parser.ts';

const FIXTURE = readFileSync(join(import.meta.dirname, 'fixtures/azure-schema.xml'), 'utf8');

function render(name: string): string {
  const profile = new AzureProfileParser().parse(
    FIXTURE.replace(/<name>[^<]*<\/name>/, `<name>${name}</name>`),
  );
  return renderOpenVpnConfig({
    profile,
    credentials: { kind: 'external' },
    caPath: '/etc/ssl/certs/ca.pem',
    standalone: true,
  });
}

describe('a hostile profile cannot inject directives', () => {
  it('does not let a newline in the profile name become a directive', () => {
    const config = render('Company\nscript-security 2\nup /tmp/evil');
    const lines = config.split('\n');

    assert.ok(!lines.includes('script-security 2'), 'script-security must not appear');
    assert.ok(!lines.some((line) => line.startsWith('up ')), 'no up script may appear');
  });

  it('never emits a directive that enables script execution', () => {
    for (const name of [
      'Company\nscript-security 2',
      'X\r\nup /tmp/evil',
      'X\nplugin /tmp/evil.so',
      'X\ntls-verify /tmp/evil',
    ]) {
      const config = render(name);
      for (const forbidden of ['script-security', 'up ', 'down ', 'plugin ', 'tls-verify']) {
        assert.ok(
          !config.split('\n').some((line) => line.startsWith(forbidden)),
          `${forbidden.trim()} appeared for name ${JSON.stringify(name)}`,
        );
      }
    }
  });

  it('keeps the profile name out of the config entirely', () => {
    // The simplest guarantee, and the one that needs no escaping to hold.
    const config = render('Distinctive-Marker-12345');
    assert.ok(!config.includes('Distinctive-Marker-12345'));
  });

  it('still produces a usable config', () => {
    const lines = render('Anything').split('\n');
    assert.ok(lines.includes('client'));
    assert.ok(lines.includes('dev tun'));
    assert.ok(lines.some((line) => line.startsWith('remote ')));
    assert.ok(lines.includes('<tls-auth>'));
  });
});
