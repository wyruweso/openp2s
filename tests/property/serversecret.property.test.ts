/**
 * Properties of the serversecret <-> OpenVPN static key transform.
 *
 * serversecret.test.ts pins the transform against six fixed secrets. Two
 * things are worth stating over all of them instead: the conversion loses
 * nothing, and a rejection never puts key material into a log.
 *
 * The second is the reason this file exists. A leak there is silent - the
 * value reaches a terminal or a crash report and nothing fails - so no
 * example test can be evidence that it does not happen.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import fc from 'fast-check';
import { ProfileError } from '../../src/errors.ts';
import {
  fromOpenVpnStaticKey,
  SERVER_SECRET_HEX_LENGTH,
  STATIC_KEY_LINES,
  toOpenVpnStaticKey,
  validateServerSecret,
} from '../../src/profile/serversecret.ts';

const LINE_LENGTH = SERVER_SECRET_HEX_LENGTH / STATIC_KEY_LINES;

/** A well-formed serversecret: exactly 512 hex characters, either case. */
const serverSecret = fc.string({
  unit: fc.constantFrom(...'0123456789abcdefABCDEF'),
  minLength: SERVER_SECRET_HEX_LENGTH,
  maxLength: SERVER_SECRET_HEX_LENGTH,
});

/**
 * Input validateServerSecret must reject: the wrong length, or not hex.
 *
 * Lowercase alphanumerics only, minimum 16 characters. Both bounds exist to
 * keep a generated value from turning up inside a rejection message by
 * coincidence and failing the test below for the wrong reason - the longest
 * run of those characters in any of those messages is "hexadecimal", at 11.
 */
const malformed = fc
  .string({
    unit: fc.constantFrom(...'0123456789abcdefghijklmnopqrstuvwxyz'),
    minLength: 16,
    maxLength: 600,
  })
  .filter(
    (candidate) => candidate.length !== SERVER_SECRET_HEX_LENGTH || /[^0-9a-f]/.test(candidate),
  );

describe('serversecret: properties', () => {
  it('round-trips every valid secret through the static key envelope', () => {
    fc.assert(
      fc.property(serverSecret, (secret) => {
        assert.equal(fromOpenVpnStaticKey(toOpenVpnStaticKey(secret)), secret.toLowerCase());
      }),
    );
  });

  it('lays every valid secret out as 16 lines of 32 characters, in order', () => {
    fc.assert(
      fc.property(serverSecret, (secret) => {
        const body = toOpenVpnStaticKey(secret).trimEnd().split('\n').slice(1, -1);

        assert.equal(body.length, STATIC_KEY_LINES);
        for (const line of body) {
          assert.equal(line.length, LINE_LENGTH);
        }
        // Wrapping must not reorder or drop a byte: a wrong key fails
        // authentication in a way that reads like a gateway problem.
        assert.equal(body.join(''), secret.toLowerCase());
      }),
    );
  });

  it('never echoes the rejected value in the message or the hint', () => {
    fc.assert(
      fc.property(malformed, (candidate) => {
        assert.throws(
          () => validateServerSecret(candidate),
          (error: unknown) => {
            assert.ok(error instanceof ProfileError);
            assert.ok(!error.message.includes(candidate), 'the message echoed the value');
            assert.ok(!(error.hint ?? '').includes(candidate), 'the hint echoed the value');
            return true;
          },
        );
      }),
    );
  });
});
