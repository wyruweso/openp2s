/**
 * Certificate-name checking: which name is expected, that the leaf's name is
 * what a probe reports, and that a mismatch stops rather than retries.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { OpenP2SError } from '../src/errors.ts';
import {
  expectedCertificateName,
  requireCertificateName,
  resolveCertificateName,
} from '../src/openvpn/certificateName.ts';
import { OpenVpnProcess } from '../src/openvpn/process.ts';
import { FakeSpawner } from './helpers/fakeOpenVpn.ts';

function start(): { tunnel: OpenVpnProcess; spawner: FakeSpawner } {
  const spawner = new FakeSpawner();
  const tunnel = new OpenVpnProcess({ command: 'openvpn', args: [], spawner });
  tunnel.start();
  return { tunnel, spawner };
}

describe('the certificate name', () => {
  it('is read from the leaf certificate only', () => {
    const { tunnel, spawner } = start();
    spawner.process.emitLog([
      'VERIFY OK: depth=1, C=US, O=Microsoft Corporation, CN=Some Issuing CA',
      'VERIFY OK: depth=0, C=US, ST=WA, O=Microsoft Corporation, CN=*.vpn.azure.com',
    ]);
    assert.equal(tunnel.details.certificateName, '*.vpn.azure.com');
  });

  it('is named in the failure when the pin does not match', async () => {
    const { tunnel, spawner } = start();
    const failure = tunnel.waitForConnection();
    spawner.process.emitLog([
      'VERIFY X509NAME ERROR: C=US, CN=other.example, must be pinned.example',
    ]);
    await assert.rejects(failure, (error: { hint?: string }) => {
      assert.match(error.hint ?? '', /CN=other\.example/);
      assert.match(error.hint ?? '', /--verify-name/);
      return true;
    });
    assert.deepEqual(spawner.process.signals, ['SIGTERM'], 'it must stop, not retry');
    // A probe reports the reason, not the hint, and needs the name as much.
    assert.match(tunnel.details.failureReason ?? '', /CN=other\.example/);
  });
});

const GUID = '11111111-2222-3333-4444-555555555555';

describe('the expected certificate name', () => {
  it('is the shared wildcard for a host directly under vpn.azure.com', () => {
    for (const host of [
      'azuregateway-fake-0000.vpn.azure.com',
      `azuregateway-${GUID}-aaaaaaaaaaaa.vpn.azure.com`,
    ]) {
      assert.equal(expectedCertificateName(host), '*.vpn.azure.com');
    }
  });

  it('is the per-gateway name for an azuregateway host under ln.vpn.azure.com', () => {
    assert.equal(
      expectedCertificateName(`azuregateway-${GUID}-bcfb8337a624.ln.vpn.azure.com`),
      `${GUID}.ln.vpn.azure.com`,
    );
  });

  it('is lowercase whatever the profile wrote, because OpenVPN compares exactly', () => {
    assert.equal(expectedCertificateName('GATEWAY.VPN.AZURE.COM'), '*.vpn.azure.com');
  });

  it('cannot be worked out for anything else', () => {
    for (const host of [
      'vpn.example.com',
      'vpn.azure.com',
      'evil-vpn.azure.com',
      'gateway.vpn.azure.com.evil.example',
      'two.labels.vpn.azure.com',
      'gateway.ln.vpn.azure.com',
      `azuregateway-${GUID}-aaaaaaaaaaaa.ln.vpn.chinacloudapi.cn`,
    ]) {
      assert.equal(expectedCertificateName(host), undefined, host);
    }
  });

  it('gives way to an explicit name', () => {
    assert.equal(
      resolveCertificateName(['gateway.vpn.azure.com'], 'gateway.example'),
      'gateway.example',
    );
  });

  it('does not treat an empty override as a way to turn the check off', () => {
    assert.equal(resolveCertificateName(['gateway.vpn.azure.com'], ''), '*.vpn.azure.com');
  });

  it('needs every gateway in the profile to agree, since OpenVPN holds one name', () => {
    assert.equal(resolveCertificateName(['a.vpn.azure.com', 'b.vpn.azure.com']), '*.vpn.azure.com');
    assert.equal(resolveCertificateName(['a.vpn.azure.com', 'vpn.example.com']), undefined);
    assert.equal(
      resolveCertificateName(['a.vpn.azure.com', `azuregateway-${GUID}-a.ln.vpn.azure.com`]),
      undefined,
    );
  });
});

describe('connecting without a certificate name', () => {
  const unknown = { gateway: 'vpn.example.com', gateways: ['vpn.example.com'] };

  it('is refused, and the error says how to find the name', () => {
    assert.throws(
      () => requireCertificateName(unknown),
      (error: OpenP2SError) => {
        assert.ok(error instanceof OpenP2SError);
        assert.match(error.message, /vpn\.example\.com/);
        assert.match(error.hint ?? '', /openp2s probe/);
        assert.match(error.hint ?? '', /--verify-name/);
        return true;
      },
    );
  });

  it('is allowed once the user names the certificate', () => {
    assert.equal(requireCertificateName(unknown, 'gateway.example'), 'gateway.example');
  });
});
