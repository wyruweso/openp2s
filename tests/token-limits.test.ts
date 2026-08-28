/**
 * The credential size ceiling.
 *
 * This is the check that turns the project's central failure mode into a
 * legible error. OpenVPN copies the password into a `char[USER_PASS_LEN]` and
 * truncates anything longer *without saying so*; the gateway then rejects a
 * credential that looked perfectly valid on this side, and what the user sees
 * is a bare AUTH_FAILED. Stock builds have 128 bytes, an Entra access token is
 * ~2.3 KB, so on an unpatched OpenVPN every connection fails this way.
 *
 * So the assertions below are about the boundary being in exactly the right
 * place - off by one in either direction is either a spurious refusal or the
 * silent truncation coming back.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { AuthError } from '../src/errors.ts';
import {
  assertTokenFits,
  DEFAULT_USER_PASS_LEN,
  tokenPressureWarning,
  usableCredentialBytes,
} from '../src/auth/tokenLimits.ts';
import { syntheticLongJwt } from './helpers/syntheticToken.ts';

/** A stock, unpatched OpenVPN. */
const STOCK = { userPassLen: 128 };
/** What the long-credentials patch gives us. */
const PATCHED = { userPassLen: DEFAULT_USER_PASS_LEN };

describe('usableCredentialBytes', () => {
  it('reserves one byte for the NUL terminator', () => {
    // The buffer is a C string: USER_PASS_LEN bytes hold USER_PASS_LEN - 1
    // characters. Getting this wrong by one is the difference between a token
    // that fits and one that is truncated by a single character - which fails
    // authentication just as completely, and far more confusingly.
    assert.equal(usableCredentialBytes(PATCHED), 4095);
    assert.equal(usableCredentialBytes(STOCK), 127);
  });
});

describe('assertTokenFits', () => {
  it('accepts a token that exactly fills the buffer', () => {
    assert.doesNotThrow(() => assertTokenFits('x'.repeat(4095), PATCHED));
  });

  it('rejects a token one byte over', () => {
    assert.throws(() => assertTokenFits('x'.repeat(4096), PATCHED), AuthError);
  });

  it('rejects a real-sized Entra token on a stock OpenVPN', () => {
    // The whole reason the patched binary exists. Without this check the
    // token would be cut to 127 bytes and sent anyway.
    const token = syntheticLongJwt();
    assert.ok(token.length > 2000, 'the fixture should be realistically large');
    assert.throws(() => assertTokenFits(token, STOCK), AuthError);
  });

  it('accepts the same token on a patched OpenVPN', () => {
    assert.doesNotThrow(() => assertTokenFits(syntheticLongJwt(), PATCHED));
  });

  it('assumes the patched size when no limit is given', () => {
    // The default has to be the patched value: it is what OpenP2S ships. A
    // caller that knows better passes the BUILDINFO value instead.
    assert.doesNotThrow(() => assertTokenFits('x'.repeat(4095)));
    assert.throws(() => assertTokenFits('x'.repeat(4096)), AuthError);
  });

  it('counts bytes, not characters', () => {
    // A JWT is ASCII, so this never fires in practice - but the buffer being
    // compared against is a byte buffer, and a length check in characters
    // would under-count anything non-ASCII that reached it.
    const multiByte = 'é'.repeat(64); // 128 bytes, 64 characters
    assert.equal(multiByte.length, 64);
    assert.equal(Buffer.byteLength(multiByte, 'utf8'), 128);
    assert.throws(() => assertTokenFits(multiByte, STOCK), AuthError);
  });

  it('says what happened, in bytes, and how to fix it', () => {
    // The error is the entire point: an AUTH_FAILED from the gateway says
    // nothing, so this message has to carry the diagnosis.
    try {
      assertTokenFits('x'.repeat(5000), PATCHED);
      assert.fail('expected a refusal');
    } catch (error) {
      assert.ok(error instanceof AuthError);
      assert.match(error.message, /5000 bytes/);
      assert.match(error.message, /maximum of 4095 bytes/);
      assert.match(error.hint ?? '', /truncate/);
      assert.match(error.hint ?? '', /long-credentials\.patch/);
    }
  });

  it('never puts the token in the error', () => {
    // The message is printed, logged and pasted into bug reports.
    const token = `${'A'.repeat(200)}.${'B'.repeat(200)}`;
    try {
      assertTokenFits(token, STOCK);
      assert.fail('expected a refusal');
    } catch (error) {
      assert.ok(error instanceof AuthError);
      assert.ok(!error.message.includes('AAAA'), 'the error must not quote the token');
      assert.ok(!(error.hint ?? '').includes('AAAA'));
    }
  });
});

describe('tokenPressureWarning', () => {
  it('says nothing about a token with room to spare', () => {
    assert.equal(tokenPressureWarning('x'.repeat(2000), PATCHED), undefined);
  });

  it('says nothing at exactly 90% of the limit', () => {
    // The threshold is "more than 90%", so the boundary itself is quiet.
    assert.equal(tokenPressureWarning('x'.repeat(Math.floor(4095 * 0.9)), PATCHED), undefined);
  });

  it('warns once past 90%', () => {
    // Group membership grows over time, so a token at 95% today is a
    // connection that breaks confusingly in a few months - and the failure
    // then gives no clue that it was gradual.
    const warning = tokenPressureWarning('x'.repeat(3900), PATCHED);
    assert.ok(warning, 'expected a warning');
    assert.match(warning, /3900 bytes/);
    assert.match(warning, /95%/);
    assert.match(warning, /4095-byte limit/);
  });

  it('warns for a token that still fits exactly', () => {
    // The last byte that is accepted is also the most urgent to warn about.
    const warning = tokenPressureWarning('x'.repeat(4095), PATCHED);
    assert.ok(warning);
    assert.match(warning, /100%/);
    assert.doesNotThrow(() => assertTokenFits('x'.repeat(4095), PATCHED));
  });

  it('reports the limit of the build in hand, not the default', () => {
    // status and doctor show this number; quoting 4095 for a binary whose
    // real ceiling is 127 would send someone looking in the wrong place.
    const warning = tokenPressureWarning('x'.repeat(120), STOCK);
    assert.ok(warning);
    assert.match(warning, /127-byte limit/);
  });
});
