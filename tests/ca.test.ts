/**
 * Which authorities may vouch for a gateway, and where they come from.
 *
 * The filesystem is faked, so no real trust store is needed.
 */

import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { describe, it } from 'node:test';
import { AZURE_GATEWAY_ROOTS, azureRootsPem } from '../src/openvpn/azureRoots.ts';
import { resolveCaPath, usesBuiltInRoots } from '../src/openvpn/ca.ts';
import { OpenP2SError } from '../src/errors.ts';

const G2_PATH = '/etc/ssl/certs/DigiCert_Global_Root_G2.pem';
const BUNDLE_PATH = '/etc/ssl/certs/ca-certificates.crt';
const AZURE = ['azuregateway-fake-0000.vpn.azure.com'];

const onlyFiles =
  (...files: string[]) =>
  (path: string): boolean =>
    files.includes(path);

describe('the roots that ship with OpenP2S', () => {
  it('are the certificates their recorded fingerprints say they are', () => {
    for (const root of AZURE_GATEWAY_ROOTS) {
      const certificate = new X509Certificate(root.pem);
      assert.equal(
        certificate.fingerprint256.replaceAll(':', '').toLowerCase(),
        root.sha256,
        root.name,
      );
      assert.ok(certificate.ca, `${root.name} must be a CA`);
      assert.equal(certificate.subject, certificate.issuer, `${root.name} must be self-signed`);
      assert.match(certificate.subject, new RegExp(`CN=${root.name}`));
    }
  });

  it('are the two DigiCert roots gateways use, and no others', () => {
    assert.deepEqual(
      AZURE_GATEWAY_ROOTS.map((root) => root.name),
      ['DigiCert Global Root G2', 'DigiCert Global Root CA'],
    );
  });

  it('all reach OpenVPN', () => {
    const pem = azureRootsPem();
    assert.equal(pem.match(/-----BEGIN CERTIFICATE-----/g)?.length, AZURE_GATEWAY_ROOTS.length);
    assert.ok(pem.endsWith('-----END CERTIFICATE-----\n'));
  });
});

describe('resolveCaPath', () => {
  it('uses the built-in roots for an Azure gateway, whatever the system has', () => {
    for (const exists of [onlyFiles(), onlyFiles(G2_PATH), onlyFiles(BUNDLE_PATH)]) {
      const ca = resolveCaPath(undefined, { gateways: AZURE, exists });
      assert.equal(ca.inlinePem, azureRootsPem());
      assert.equal(ca.pinned, true);
    }
  });

  it('accepts every Azure hostname form, in any case', () => {
    const forms = [
      'gateway.vpn.azure.com',
      'GATEWAY.VPN.AZURE.COM',
      'azuregateway-11111111-2222-3333-4444-555555555555-aaaaaaaaaaaa.ln.vpn.azure.com',
    ];
    assert.ok(usesBuiltInRoots(forms));
  });

  it('lets --ca replace the built-in roots', () => {
    const ca = resolveCaPath('/home/user/root.pem', {
      gateways: AZURE,
      exists: onlyFiles('/home/user/root.pem'),
    });
    assert.equal(ca.path, '/home/user/root.pem');
    assert.equal(ca.inlinePem, undefined);
  });

  it('still refuses a --ca file that does not exist', () => {
    assert.throws(
      () => resolveCaPath('/nope.pem', { gateways: AZURE, exists: onlyFiles() }),
      OpenP2SError,
    );
  });

  it('uses the system store for any other host', () => {
    const ca = resolveCaPath(undefined, {
      gateways: ['vpn.example.com'],
      exists: onlyFiles(G2_PATH),
    });
    assert.equal(ca.path, G2_PATH);
    assert.equal(ca.inlinePem, undefined);
  });

  it('is not fooled by a hostname that only looks like an Azure gateway', () => {
    for (const host of [
      'vpn.azure.com',
      'evil-vpn.azure.com',
      'gateway.vpn.azure.com.evil.example',
      'gateway.vpn.azure.com.',
    ]) {
      assert.ok(!usesBuiltInRoots([host]), host);
    }
  });

  it('uses the built-in roots only when every gateway in the profile is Azure', () => {
    const gateways = ['gateway.vpn.azure.com', 'vpn.example.com'];
    assert.ok(!usesBuiltInRoots(gateways));
    const ca = resolveCaPath(undefined, { gateways, exists: onlyFiles(BUNDLE_PATH) });
    assert.equal(ca.path, BUNDLE_PATH);
    assert.equal(ca.pinned, false);
  });

  it('does not treat a profile with no gateways as Azure', () => {
    assert.ok(!usesBuiltInRoots([]));
  });

  it('fails clearly when another host has no system store to use', () => {
    assert.throws(
      () => resolveCaPath(undefined, { gateways: ['vpn.example.com'], exists: onlyFiles() }),
      OpenP2SError,
    );
  });
});
