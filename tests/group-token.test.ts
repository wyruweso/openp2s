import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { groupCredential, groupTokenWarning, isProfileTenant } from '../src/auth/groupToken.ts';
import { assertTokenFits } from '../src/auth/tokenLimits.ts';
import { AuthError, redact } from '../src/errors.ts';
import { syntheticLongJwt } from './helpers/syntheticToken.ts';

describe('Azure group credentials', () => {
  it('encodes the VPN and Graph tokens as ordered ASCII TLV fields', () => {
    assert.equal(groupCredential('vpn', 'graph'), 'TlvToken:0000000003vpn0100000005graph');
    assert.equal(
      groupCredential('x'.repeat(16), 'y'),
      'TlvToken:0000000010' + 'x'.repeat(16) + '0100000001y',
    );
  });

  it('rejects missing tokens, non-ASCII and protocol separators without leaking them', () => {
    for (const token of ['', 'abc\nsecret', 'é', 'abc"secret', 'abc<secret']) {
      assert.throws(() => groupCredential('vpn', token), AuthError);
      assert.throws(() => groupCredential(token, 'graph'), AuthError);
    }
  });

  it('redacts the whole credential even though JWTs have no word boundary', () => {
    const credential = groupCredential(syntheticLongJwt(), syntheticLongJwt());
    assert.equal(redact('credential=' + credential), 'credential=[redacted]-group-credential');
  });

  it('checks the combined length against the actual OpenVPN build', () => {
    const credential = groupCredential('a'.repeat(1900), 'b'.repeat(2700));
    assert.throws(() => assertTokenFits(credential, { userPassLen: 4096 }), AuthError);
    assert.doesNotThrow(() => assertTokenFits(credential, { userPassLen: 8192 }));
  });
});

describe('the tenant a profile names', () => {
  const TID = 'aaaaaaaa-2222-3333-4444-555555555555';

  it('matches a GUID in any case', () => {
    assert.ok(isProfileTenant(TID, TID));
    assert.ok(isProfileTenant(TID.toUpperCase(), TID));
  });

  it('does not match a different GUID', () => {
    assert.ok(!isProfileTenant('bbbbbbbb-2222-3333-4444-555555555555', TID));
  });

  it('cannot be compared when it is a domain, so that is not a mismatch', () => {
    assert.ok(isProfileTenant('contoso.onmicrosoft.com', TID));
  });
});

describe('the warning when no group token could be used', () => {
  it('says what it means for the connection and gives the reason', () => {
    const warning = groupTokenWarning('consent required');
    assert.match(warning, /VPN token alone/);
    assert.match(warning, /default address pool/);
    assert.match(warning, /consent required/);
  });
});
