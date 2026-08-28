/**
 * serversecret -> OpenVPN static key conversion.
 *
 * A bug here produces a key that fails authentication in a way that looks
 * like a gateway problem, so the transform is asserted exactly rather than
 * approximately.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { ProfileError } from '../src/errors.ts';
import {
  fromOpenVpnStaticKey,
  SERVER_SECRET_HEX_LENGTH,
  STATIC_KEY_LINES,
  toOpenVpnStaticKey,
  validateServerSecret,
} from '../src/profile/serversecret.ts';

const BEGIN = '-----BEGIN OpenVPN Static key V1-----';
const END = '-----END OpenVPN Static key V1-----';

/** Deterministic fake key material. Not a real secret. */
function fakeSecret(seed = 7): string {
  let out = '';
  for (let index = 0; index < 256; index += 1) {
    out += ((index * seed + 11) % 256).toString(16).padStart(2, '0');
  }
  return out;
}

describe('validateServerSecret', () => {
  it('accepts exactly 512 hex characters', () => {
    const secret = fakeSecret();
    assert.equal(secret.length, SERVER_SECRET_HEX_LENGTH);
    assert.equal(validateServerSecret(secret), secret);
  });

  it('lowercases so cache keys and comparisons are stable', () => {
    assert.equal(validateServerSecret('AB'.repeat(256)), 'ab'.repeat(256));
  });

  it('tolerates surrounding whitespace from XML pretty-printing', () => {
    assert.equal(validateServerSecret(`\n  ${'ab'.repeat(256)}\n  `), 'ab'.repeat(256));
  });

  it('rejects a secret that is one character short', () => {
    assert.throws(() => validateServerSecret('a'.repeat(511)), ProfileError);
  });

  it('rejects a secret that is one character too long', () => {
    assert.throws(() => validateServerSecret('a'.repeat(513)), ProfileError);
  });

  it('rejects non-hex characters', () => {
    assert.throws(() => validateServerSecret('g'.repeat(512)), /non-hexadecimal/);
  });

  it('rejects internal whitespace', () => {
    const spaced = `${'ab'.repeat(128)} ${'ab'.repeat(127)}`;
    assert.throws(() => validateServerSecret(spaced), ProfileError);
  });

  it('rejects an empty value', () => {
    assert.throws(() => validateServerSecret('   '), /is empty/);
  });

  it('never includes the secret in its error message', () => {
    const secret = 'deadbeef'.repeat(60);
    try {
      validateServerSecret(secret);
      assert.fail('expected rejection');
    } catch (error) {
      assert.ok(error instanceof ProfileError);
      assert.ok(!error.message.includes('deadbeef'));
    }
  });
});

describe('toOpenVpnStaticKey', () => {
  const key = toOpenVpnStaticKey(fakeSecret());
  const lines = key.trimEnd().split('\n');

  it('emits the BEGIN and END markers', () => {
    assert.equal(lines[0], BEGIN);
    assert.equal(lines.at(-1), END);
  });

  it('emits exactly STATIC_KEY_LINES body lines', () => {
    // 16 lines of 32 hex characters is the OpenVPN static key format; the two
    // assertions below together pin the 512-character total.
    assert.equal(lines.length - 2, STATIC_KEY_LINES);
  });

  it('emits body lines of exactly 32 characters', () => {
    for (const line of lines.slice(1, -1)) {
      assert.equal(line.length, 32, `line "${line.slice(0, 8)}..." should be 32 characters`);
    }
  });

  it('preserves the secret exactly, in order', () => {
    assert.equal(lines.slice(1, -1).join(''), fakeSecret());
  });

  it('ends with a trailing newline so it composes into a config', () => {
    assert.ok(key.endsWith('\n'));
  });

  it('rejects an invalid secret rather than emitting a malformed key', () => {
    assert.throws(() => toOpenVpnStaticKey('abc'), ProfileError);
  });
});

describe('static key round trip', () => {
  it('recovers the original secret', () => {
    for (const seed of [1, 7, 13, 251]) {
      const secret = fakeSecret(seed);
      assert.equal(fromOpenVpnStaticKey(toOpenVpnStaticKey(secret)), secret);
    }
  });

  it('round-trips an all-zero secret', () => {
    const secret = '0'.repeat(512);
    assert.equal(fromOpenVpnStaticKey(toOpenVpnStaticKey(secret)), secret);
  });

  it('round-trips an all-f secret', () => {
    const secret = 'f'.repeat(512);
    assert.equal(fromOpenVpnStaticKey(toOpenVpnStaticKey(secret)), secret);
  });

  it('rejects a block with the wrong number of body lines', () => {
    const truncated = [BEGIN, ...Array(15).fill('ab'.repeat(16)), END].join('\n');
    assert.throws(() => fromOpenVpnStaticKey(truncated), /expected 16/);
  });

  it('rejects a block with no markers', () => {
    assert.throws(() => fromOpenVpnStaticKey('ab'.repeat(256)), /not a valid OpenVPN static key/);
  });
});
