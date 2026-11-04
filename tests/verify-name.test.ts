/**
 * Certificate-name pinning: the leaf's name is what a probe reports, and a
 * mismatch stops rather than retries.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
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
  });
});
