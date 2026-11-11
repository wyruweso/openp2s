/**
 * Redaction.
 *
 * Two failure modes matter equally: leaking a credential, and eating output
 * that is supposed to be readable. The second is not hypothetical - a pattern
 * added to catch token fragments also matched every SHA-256 hash OpenP2S
 * prints, which made the provenance display useless.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { describeError, redact } from '../src/errors.ts';
import {
  syntheticLongJwt,
  syntheticOpaqueCredential,
  syntheticServerSecret,
} from './helpers/syntheticToken.ts';

const TOKEN = syntheticLongJwt(2000);

describe('redact: secrets', () => {
  it('removes a complete JWT', () => {
    const out = redact(`password=${TOKEN}`);
    assert.ok(!out.includes(TOKEN));
    assert.ok(!out.includes(TOKEN.slice(0, 32)));
  });

  it('removes a token fragment with no recognisable structure', () => {
    // What OpenVPN's management interface echoes back when a parameter is too
    // long: the middle of a token, with no leading segment marker and no
    // dot-separated structure. Taken from the middle of a synthetic token so
    // the shape is right without embedding anyone's credential.
    //
    // Sized like the real thing rather than at the detection threshold: what
    // gets echoed is a 256-byte parameter, not a borderline run.
    const fragment = TOKEN.slice(200, 456);
    assert.ok(!/\./.test(fragment), 'a mid-token slice has no segment separator');
    assert.ok(!redact(`CMD '${fragment}'`).includes(fragment));
  });

  it('removes the 512-hex serversecret', () => {
    const secret = syntheticServerSecret();
    const out = redact(`serversecret ${secret}`);
    assert.ok(!out.includes(secret));
    assert.match(out, /redacted]-secret/);
  });

  it('removes named secret fields whatever the value looks like', () => {
    assert.ok(!redact('{"access_token":"short"}').includes('short'));
    assert.ok(!redact('refresh_token=abc123').includes('abc123'));
  });

  it('removes management password commands', () => {
    const out = redact('MANAGEMENT: CMD \'password "Auth" "hunter2"\'');
    assert.ok(!out.includes('hunter2'));
  });

  // Each segment of these is shorter than the opaque-run threshold, so none
  // of them is caught by length alone. That is the case these rules exist for.
  describe('opaque credentials too short or too dotted for the shape rules', () => {
    const segmentsOf = (credential: string): string[] => credential.split('.').slice(1);

    it('removes a refresh token whatever its version digit, and every segment', () => {
      for (const version of [0, 1, 2]) {
        const credential = syntheticOpaqueCredential(version);
        const out = redact(`refresh failed for ${credential} at the token endpoint`);
        for (const segment of segmentsOf(credential)) {
          assert.ok(!out.includes(segment), `version ${version} left a segment behind`);
        }
        assert.match(out, /at the token endpoint$/);
      }
    });

    it('removes an authorization code in a query string or a form body', () => {
      const code = syntheticOpaqueCredential(1, [50, 40]).slice(2);
      for (const text of [`GET /?code=${code}&state=s1 HTTP/1.1`, `code=${code}&client_info=c1`]) {
        const out = redact(text);
        for (const segment of code.split('.')) assert.ok(!out.includes(segment), text);
      }
    });

    it('removes a bearer credential', () => {
      const credential = syntheticOpaqueCredential(1, [70, 70]).slice(2);
      const out = redact(`Authorization: Bearer ${credential}`);
      for (const segment of credential.split('.')) assert.ok(!out.includes(segment));
      assert.match(out, /^Authorization: Bearer /);
    });

    it('removes the token fields of a serialised MSAL cache', () => {
      const credential = syntheticOpaqueCredential(1, [60, 60]);
      const out = redact(`{"credential_type": "RefreshToken", "secret": "${credential}"}`);
      for (const segment of segmentsOf(credential)) assert.ok(!out.includes(segment));
      assert.match(out, /"credential_type": "RefreshToken"/);
    });

    it('removes a device code, which is enough on its own to finish a sign-in', () => {
      assert.ok(!redact('{"device_code": "short-device-code"}').includes('short-device-code'));
      assert.ok(!redact('device_code=short-device-code&x=1').includes('short-device-code'));
    });
  });
});

describe('redact: must not eat legitimate output', () => {
  it('keeps a SHA-256 hash', () => {
    // Printed by build, provenance and inspect. Redacting these was a real
    // regression, not a theoretical one.
    // 64 hex characters, obviously synthetic: the assertion is about length
    // and shape, and a real build hash here would only be scanner noise.
    const sha = 'deadbeef'.repeat(8);
    assert.equal(redact(`binary_sha256=${sha}`), `binary_sha256=${sha}`);
  });

  it('keeps a SHA-1 certificate thumbprint', () => {
    const sha1 = '0123456789abcdef0123456789abcdef01234567';
    assert.equal(redact(`hash ${sha1}`), `hash ${sha1}`);
  });

  it('keeps a SHA-512 hash', () => {
    // 128 hex characters, which is also where the serversecret rule starts.
    // Without the exemption a SHA-512 comes out as "[redacted]-secret"
    // even though the digest exemption named SHA-512 as a length to keep.
    const sha512 = '0123456789abcdef'.repeat(8);
    assert.equal(sha512.length, 128);
    assert.equal(redact(`sha512=${sha512}`), `sha512=${sha512}`);
  });

  it('still removes a hex run that is not a digest length', () => {
    // The exemption is for known digest lengths only; the 512-hex
    // serversecret and anything else long and hex still goes.
    const notADigest = 'ab'.repeat(70);
    assert.ok(!redact(`value ${notADigest}`).includes(notADigest));
  });

  it('keeps an embedded PEM certificate readable', () => {
    // `convert --inline-ca` embeds the CA, and a base64 body line is 64
    // columns. The opaque-run rule used to start at 64, so every line that
    // happened to contain no + or / was replaced - eight of the twenty-three
    // lines of the DigiCert root this project pins. The result still looked
    // like a certificate and could not be used as one.
    const body = [
      'MIIDdzCCAl2gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ',
      'RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD',
    ];
    const pem = ['-----BEGIN CERTIFICATE-----', ...body, '-----END CERTIFICATE-----'].join('\n');

    for (const line of body) {
      assert.equal(line.length, 64, 'a PEM body line is 64 columns');
    }
    assert.equal(redact(pem), pem);
  });

  it('keeps a MIME-wrapped base64 line readable', () => {
    // The other standard wrapping width, 76 columns.
    const line = `${'Zm9vYmFy'.repeat(9)}abcd`;
    assert.equal(line.length, 76);
    assert.equal(redact(line), line);
  });

  it('keeps gateway hostnames and file paths', () => {
    for (const text of [
      'remote azuregateway-fake-0000.vpn.azure.com 443',
      'config = /run/user/1000/openp2s/openvpn.conf',
      'TCP connection established with [AF_INET]203.0.113.10:443',
    ]) {
      assert.equal(redact(text), text);
    }
  });

  it('keeps exit codes, version numbers and prose about bearer tokens', () => {
    // The rules that recognise a credential by its key or prefix require a
    // value of credential length, because these are the shapes OpenP2S and
    // the tools it runs print. The values are synthetic: what matters is the
    // shape, not any real version or commit.
    for (const text of [
      'openvpn exited with code=1',
      'resolvectl exited with code 1',
      // A version starts the way an opaque Entra token does: digit, dot.
      'OpenVPN 1.2.3 (tag v1.2.3)',
      // A SHA-1 commit id, which is a digest and stays readable.
      `commit ${'0123456789abcdef'.repeat(3).slice(0, 40)}`,
      'the gateway rejected the bearer token',
    ]) {
      assert.equal(redact(text), text);
    }
  });

  it('needs 40 characters after the version digit before calling it a token', () => {
    // The boundary of the refresh-token rule, so a long file or package name
    // that happens to follow a digit and a dot is not redacted by accident.
    const justShort = `1.${'a'.repeat(39)}`;
    assert.equal(redact(justShort), justShort);
    assert.notEqual(redact(`1.${'a'.repeat(40)}`), `1.${'a'.repeat(40)}`);
  });

  it('keeps ordinary OpenVPN log lines intact', () => {
    const line = "PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0 255.0.0.0'";
    assert.equal(redact(line), line);
  });
});

describe('describeError', () => {
  it('follows cause chains and redacts each level', () => {
    const inner = new Error(`inner ${TOKEN}`);
    const outer = new Error('outer failed', { cause: inner });
    const described = describeError(outer);
    assert.match(described, /outer failed/);
    assert.ok(!described.includes(TOKEN.slice(0, 32)));
  });

  it('handles non-Error values', () => {
    assert.equal(describeError('plain string'), 'plain string');
    assert.equal(describeError(42), '42');
  });
});
