/**
 * Entra authentication.
 *
 * MSAL owns the OAuth work; what this module decides is everything around it,
 * and that is what these tests drive:
 *
 *   - a cached session is reused without interaction, and a stale one falls
 *     through to sign-in rather than failing - Conditional Access can revoke a
 *     session at any moment, so a silent miss is an ordinary outcome;
 *   - the cache is scoped per tenant/audience/client, so one profile can never
 *     answer for another;
 *   - a device-code response that carries no code is refused loudly, because
 *     printing it verbatim gives the user "Open: undefined";
 *   - an AADSTS code is translated into something a person can act on.
 *
 * A substitute MSAL client stands in for the network. Nothing here reaches a
 * tenant, and nothing here needs one.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import type { AccountInfo, AuthenticationResult, Configuration } from '@azure/msal-node';
import { FileTokenCacheStore } from '../src/auth/cache/fileStore.ts';
import { EntraAuthenticator, explainAuthFailure, type MsalClient } from '../src/auth/entra.ts';
import { AuthError } from '../src/errors.ts';
import type { EntraAuthConfig } from '../src/profile/types.ts';
import { syntheticLongJwt } from './helpers/syntheticToken.ts';

const AUTH: EntraAuthConfig = {
  authority: 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555',
  tenantId: '11111111-2222-3333-4444-555555555555',
  audience: '41b23e61-6c1e-4545-b367-cd054e0ed4b4',
  clientId: '41b23e61-6c1e-4545-b367-cd054e0ed4b4',
  scope: '41b23e61-6c1e-4545-b367-cd054e0ed4b4/.default',
};

const TOKEN = syntheticLongJwt();

const ACCOUNT = {
  homeAccountId: 'home-id',
  environment: 'login.microsoftonline.com',
  tenantId: AUTH.tenantId,
  username: 'user@contoso.example',
  localAccountId: 'local-id',
} as AccountInfo;

function authResult(overrides: Partial<AuthenticationResult> = {}): AuthenticationResult {
  return {
    accessToken: TOKEN,
    account: ACCOUNT,
    tenantId: AUTH.tenantId,
    expiresOn: new Date('2030-01-01T00:00:00Z'),
    ...overrides,
  } as AuthenticationResult;
}

/** A scripted MSAL, recording what it was asked for. */
class FakeMsal implements MsalClient {
  readonly silentRequests: Array<{ account: AccountInfo; scopes: string[] }> = [];
  readonly deviceCodeRequests: Array<{ scopes: string[] }> = [];

  accounts: AccountInfo[] = [];
  silent: AuthenticationResult | Error | null = null;
  deviceCode: AuthenticationResult | Error | null = null;
  /** What MSAL hands the device-code callback. */
  deviceCodeResponse: {
    verificationUri: string;
    userCode: string;
    expiresIn: number;
    message: string;
  } = {
    verificationUri: 'https://microsoft.com/devicelogin',
    userCode: 'FAKECODE',
    expiresIn: 900,
    message: 'To sign in, use a web browser to open the page...',
  };

  getTokenCache(): { getAllAccounts(): Promise<AccountInfo[]> } {
    return { getAllAccounts: async () => this.accounts };
  }

  async acquireTokenSilent(request: {
    account: AccountInfo;
    scopes: string[];
  }): Promise<AuthenticationResult | null> {
    this.silentRequests.push(request);
    if (this.silent instanceof Error) throw this.silent;
    return this.silent;
  }

  async acquireTokenByDeviceCode(request: {
    scopes: string[];
    deviceCodeCallback: (response: {
      verificationUri: string;
      userCode: string;
      expiresIn: number;
      message: string;
    }) => void;
  }): Promise<AuthenticationResult | null> {
    this.deviceCodeRequests.push({ scopes: request.scopes });
    request.deviceCodeCallback(this.deviceCodeResponse);
    if (this.deviceCode instanceof Error) throw this.deviceCode;
    return this.deviceCode;
  }
}

let cacheDir: string;
let store: FileTokenCacheStore;
let msal: FakeMsal;
let prompts: Array<{ userCode: string; verificationUri: string }>;
let debug: string[];

beforeEach(() => {
  cacheDir = join(mkdtempSync(join(tmpdir(), 'openp2s-entra-')), 'cache');
  store = new FileTokenCacheStore({ directory: cacheDir });
  msal = new FakeMsal();
  prompts = [];
  debug = [];
});

afterEach(() => {
  rmSync(join(cacheDir, '..'), { recursive: true, force: true });
});

function authenticator(
  auth: EntraAuthConfig = AUTH,
  client: MsalClient = msal,
): EntraAuthenticator {
  return new EntraAuthenticator({
    auth,
    store,
    clientFactory: (_configuration: Configuration) => client,
    onDeviceCode: (prompt) =>
      prompts.push({ userCode: prompt.userCode, verificationUri: prompt.verificationUri }),
    onDebug: (message) => debug.push(message),
  });
}

describe('cache scoping', () => {
  it('asks for the gateway scope, not a generic one', () => {
    // "<audience>/.default" is what the gateway will accept; a token for any
    // other scope authenticates nothing.
    assert.deepEqual(authenticator().scopes, ['41b23e61-6c1e-4545-b367-cd054e0ed4b4/.default']);
  });

  it('gives two audiences in one tenant different cache keys', () => {
    // Their tokens carry different scopes and are not interchangeable, so
    // sharing a cache entry would hand one gateway the other's token.
    const other = { ...AUTH, audience: 'c632b3df-fb67-4d84-bdcf-b95ad541b5c8' };
    assert.notEqual(authenticator().cacheKey, authenticator(other).cacheKey);
  });

  it('exposes the identity the key is derived from', () => {
    assert.deepEqual(authenticator().identity, {
      authority: AUTH.authority,
      audience: AUTH.audience,
      clientId: AUTH.clientId,
    });
  });
});

describe('silent acquisition', () => {
  it('reuses a cached session without any interaction', async () => {
    msal.accounts = [ACCOUNT];
    msal.silent = authResult();

    const outcome = await authenticator().acquireToken();

    assert.equal(outcome.accessToken, TOKEN);
    assert.equal(outcome.fromCache, true, 'a silent hit must be reported as cached');
    assert.equal(outcome.account, 'user@contoso.example');
    assert.equal(outcome.tenantId, AUTH.tenantId);
    assert.deepEqual(outcome.expiresOn, new Date('2030-01-01T00:00:00Z'));
    assert.deepEqual(msal.deviceCodeRequests, [], 'no sign-in should have been requested');
    assert.deepEqual(prompts, [], 'the user must not be prompted for a cached session');
  });

  it('requests the gateway scope for the cached account', async () => {
    msal.accounts = [ACCOUNT];
    msal.silent = authResult();

    await authenticator().acquireToken();

    assert.deepEqual(msal.silentRequests, [{ account: ACCOUNT, scopes: [AUTH.scope] }]);
  });

  it('falls through to sign-in when the cached session is rejected', async () => {
    // Conditional Access, a revoked session and an expired refresh token all
    // look the same from here, and all have the same remedy. Treating it as
    // an error would strand the user with no way forward.
    msal.accounts = [ACCOUNT];
    msal.silent = new Error('AADSTS50076: multi-factor authentication required');
    msal.deviceCode = authResult();

    const outcome = await authenticator().acquireToken();

    assert.equal(outcome.fromCache, false, 'an interactive token is not a cached one');
    assert.equal(msal.deviceCodeRequests.length, 1);
    assert.equal(prompts.length, 1, 'the user must be prompted to sign in');
  });

  it('falls through when there is no cached account at all', async () => {
    msal.accounts = [];
    msal.deviceCode = authResult();

    await authenticator().acquireToken();

    assert.deepEqual(msal.silentRequests, [], 'nothing to try silently');
    assert.equal(msal.deviceCodeRequests.length, 1);
  });

  it('tries each cached account before giving up', async () => {
    // More than one identity can be cached for a tenant; the first is not
    // necessarily the one that still has a valid session.
    const second: AccountInfo = { ...ACCOUNT, username: 'other@contoso.example' };
    msal.accounts = [ACCOUNT, second];

    let call = 0;
    const client: MsalClient = {
      ...msal,
      getTokenCache: () => msal.getTokenCache(),
      acquireTokenByDeviceCode: (request) => msal.acquireTokenByDeviceCode(request),
      acquireTokenSilent: async (request) => {
        call += 1;
        if (call === 1) throw new Error('AADSTS50173: session revoked');
        return authResult({ account: request.account });
      },
    };

    const outcome = await authenticator(AUTH, client).acquireToken();

    assert.equal(call, 2, 'the second account must be tried');
    assert.equal(outcome.account, 'other@contoso.example');
    assert.equal(outcome.fromCache, true);
  });

  it('skips the cache entirely when told to', async () => {
    // What connect does after the gateway rejects a cached token: trying the
    // same one again would loop.
    msal.accounts = [ACCOUNT];
    msal.silent = authResult();
    msal.deviceCode = authResult();

    const outcome = await authenticator().acquireToken(true);

    assert.deepEqual(msal.silentRequests, [], 'the silent path must be skipped');
    assert.equal(msal.deviceCodeRequests.length, 1);
    assert.equal(outcome.fromCache, false);
  });

  it('does not log the token when a silent attempt fails', async () => {
    // MSAL error strings can carry token material.
    msal.accounts = [ACCOUNT];
    msal.silent = new Error(`refresh failed for ${TOKEN}`);
    msal.deviceCode = authResult();

    await authenticator().acquireToken();

    const joined = debug.join('\n');
    assert.ok(joined.includes('silent acquisition failed'), 'the failure is still reported');
    assert.ok(!joined.includes(TOKEN), 'but not with the token in it');
  });
});

describe('device code sign-in', () => {
  it('hands the caller the code and the URL to open', async () => {
    msal.deviceCode = authResult();

    await authenticator().acquireToken();

    assert.deepEqual(prompts, [
      { userCode: 'FAKECODE', verificationUri: 'https://microsoft.com/devicelogin' },
    ]);
  });

  it('refuses a device-code response carrying no code', async () => {
    // MSAL invokes the callback with whatever the endpoint returned, error
    // bodies included. Passing that on gives the user "Open: undefined /
    // Code: undefined" and no clue that the tenant is the problem.
    msal.deviceCodeResponse = {
      verificationUri: '',
      userCode: '',
      expiresIn: 0,
      message: '',
    };

    await assert.rejects(
      () => authenticator().acquireToken(),
      (error: unknown) => {
        assert.ok(error instanceof AuthError);
        assert.match(error.message, /did not return a device code/);
        // The hint names the tenant, which is the thing to go and check. It
        // must not be lost: an outer catch could re-wrap it and replace
        // the hint with what explainAuthFailure() made of our own wording,
        // which is nothing.
        assert.match(error.hint ?? '', /Tenant: /);
        assert.ok(error.hint?.includes(AUTH.authority), 'the hint must name the tenant');
        return true;
      },
    );

    assert.deepEqual(prompts, [], 'nothing usable must be shown to the user');
  });

  it('rejects a result with no access token rather than returning an empty one', async () => {
    msal.deviceCode = authResult({ accessToken: '' });

    await assert.rejects(
      () => authenticator().acquireToken(),
      (error: unknown) => {
        assert.ok(error instanceof AuthError);
        assert.match(error.message, /no access token/);
        return true;
      },
    );
  });

  it('rejects a null result', async () => {
    msal.deviceCode = null;
    await assert.rejects(() => authenticator().acquireToken(), AuthError);
  });

  it('reports a sign-in failure as an AuthError, with the cause kept', async () => {
    const cause = new Error('AADSTS70016: authorization_pending');
    msal.deviceCode = cause;

    await assert.rejects(
      () => authenticator().acquireToken(),
      (error: unknown) => {
        assert.ok(error instanceof AuthError);
        assert.equal(error.exitCode, 3);
        assert.equal(error.cause, cause, 'the original error must be preserved for debugging');
        return true;
      },
    );
  });

  it('does not leak a token that appears in an MSAL error', async () => {
    msal.deviceCode = new Error(`endpoint said ${TOKEN}`);

    await assert.rejects(
      () => authenticator().acquireToken(),
      (error: unknown) => {
        assert.ok(error instanceof AuthError);
        assert.ok(!error.message.includes(TOKEN), 'the token must not reach the message');
        return true;
      },
    );
  });
});

describe('listAccounts', () => {
  it('returns what the cache holds', async () => {
    msal.accounts = [ACCOUNT];
    assert.deepEqual(await authenticator().listAccounts(), [ACCOUNT]);
  });

  it('answers "none" rather than throwing when the cache cannot be read', async () => {
    // `openp2s auth status` calls this; a corrupt cache should report an empty
    // session, not crash the command that exists to diagnose it.
    const broken: MsalClient = {
      getTokenCache: () => {
        throw new Error('cache unreadable');
      },
      acquireTokenSilent: async () => null,
      acquireTokenByDeviceCode: async () => null,
    };

    assert.deepEqual(await authenticator(AUTH, broken).listAccounts(), []);
  });
});

describe('clearCache', () => {
  it('removes this identity from the store, and only this one', async () => {
    const other = { ...AUTH, audience: 'c632b3df-fb67-4d84-bdcf-b95ad541b5c8' };
    const mine = authenticator();
    const theirs = authenticator(other);

    await store.save(mine.cacheKey, '{"mine":1}');
    await store.save(theirs.cacheKey, '{"theirs":1}');

    await mine.clearCache();

    assert.equal(await store.load(mine.cacheKey), undefined);
    assert.equal(await store.load(theirs.cacheKey), '{"theirs":1}', 'other sessions must survive');
  });
});

describe('explainAuthFailure', () => {
  // The raw MSAL message is an AADSTS code and a correlation id. On its own it
  // sends the user to a search engine; these map the codes actually seen
  // against Azure P2S onto the thing to go and do.
  const cases: ReadonlyArray<readonly [string, RegExp]> = [
    ['AADSTS50059: No tenant-identifying information found', /tenant.*could not be found/i],
    ['AADSTS700016: Application not found in directory', /application id was rejected/i],
    ['AADSTS65001: The user or administrator has not consented', /grant consent/i],
    ['AADSTS50076: Due to a configuration change', /Multi-factor authentication/i],
    ['AADSTS50079: Strong authentication enrollment required', /Multi-factor authentication/i],
    ['AADSTS53003: Access has been blocked by Conditional Access', /Conditional Access/i],
    ['expired_token: the device code has expired', /device code expired/i],
  ];

  for (const [message, expected] of cases) {
    it(`explains ${message.split(':')[0]}`, () => {
      assert.match(explainAuthFailure(new Error(message)) ?? '', expected);
    });
  }

  it('offers nothing rather than guessing at an unrecognised failure', () => {
    // A wrong hint is worse than none: it sends someone to check a tenant URL
    // that was never the problem.
    assert.equal(explainAuthFailure(new Error('ECONNRESET')), undefined);
    assert.equal(explainAuthFailure(new Error('AADSTS99999: something new')), undefined);
  });

  it('reads through a cause chain', () => {
    // MSAL failures usually arrive wrapped.
    const wrapped = new Error('token request failed', {
      cause: new Error('AADSTS53003: blocked by Conditional Access policy'),
    });
    assert.match(explainAuthFailure(wrapped) ?? '', /Conditional Access/);
  });

  it('handles a non-Error value', () => {
    assert.equal(explainAuthFailure(undefined), undefined);
    assert.match(explainAuthFailure('AADSTS65001: consent required') ?? '', /grant consent/);
  });
});
