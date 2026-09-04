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
import { legacyCacheKey } from '../src/auth/cache/identity.ts';
import {
  DEFAULT_FLOW,
  EntraAuthenticator,
  explainAuthFailure,
  type InteractiveFlow,
  type MsalClient,
} from '../src/auth/entra.ts';
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

  interactiveRequests: Array<{ scopes: string[] }> = [];
  openedUrls: string[] = [];
  interactive: AuthenticationResult | Error | null = null;

  async acquireTokenInteractive(request: {
    scopes: string[];
    openBrowser: (url: string) => Promise<void>;
  }): Promise<AuthenticationResult | null> {
    this.interactiveRequests.push({ scopes: request.scopes });
    await request.openBrowser('https://login.microsoftonline.com/fake/authorize');
    if (this.interactive instanceof Error) throw this.interactive;
    return this.interactive;
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
  // Pinned, so changing DEFAULT_FLOW does not move this whole file onto the
  // other flow.
  flow: InteractiveFlow = 'device-code',
): EntraAuthenticator {
  return new EntraAuthenticator({
    auth,
    store,
    flow,
    clientFactory: (_configuration: Configuration) => client,
    onDeviceCode: (prompt) =>
      prompts.push({ userCode: prompt.userCode, verificationUri: prompt.verificationUri }),
    onDebug: (message) => debug.push(message),
    openBrowser: async (url) => {
      msal.openedUrls.push(url);
    },
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
      flow: 'device-code',
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
      acquireTokenInteractive: (request) => msal.acquireTokenInteractive(request),
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
      acquireTokenInteractive: async () => null,
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

describe('flow selection', () => {
  it('defaults to the browser, whatever the environment says', () => {
    assert.equal(DEFAULT_FLOW, 'browser');
  });

  it('uses the browser when no flow is given', async () => {
    msal.interactive = authResult({});
    const auth = new EntraAuthenticator({
      auth: AUTH,
      store,
      clientFactory: () => msal,
      openBrowser: async (url) => {
        msal.openedUrls.push(url);
      },
    });

    await auth.acquireToken();
    assert.equal(auth.flow, 'browser');
    assert.deepEqual(msal.deviceCodeRequests, []);
  });
});

describe('cache scoping by flow', () => {
  it('keys browser and device-code sessions separately', () => {
    // Entra carries "this session came from device code" through refreshes,
    // so a shared cache would let --auth browser reuse one and never open a
    // browser - handing the user the flow their org may have blocked.
    const browser = new EntraAuthenticator({
      auth: AUTH,
      store,
      flow: 'browser',
      clientFactory: () => msal,
    });
    const device = new EntraAuthenticator({
      auth: AUTH,
      store,
      flow: 'device-code',
      clientFactory: () => msal,
    });

    assert.notEqual(browser.cacheKey, device.cacheKey);
  });

  it('does not reuse a device-code session for a browser sign-in', async () => {
    msal.accounts = [ACCOUNT];
    msal.silent = authResult({ account: ACCOUNT });
    await authenticator(AUTH, msal, 'device-code').acquireToken();

    // A fresh authenticator on the browser flow sees an empty cache.
    const fresh = new FakeMsal();
    fresh.interactive = authResult({});
    const browser = new EntraAuthenticator({
      auth: AUTH,
      store,
      flow: 'browser',
      clientFactory: () => fresh,
      openBrowser: async (url) => {
        fresh.openedUrls.push(url);
      },
    });

    await browser.acquireToken();
    assert.equal(fresh.interactiveRequests.length, 1, 'browser flow must sign in afresh');
  });
});

describe('the 0.1.x cache entry', () => {
  const LEGACY = legacyCacheKey(AUTH);

  it('is removed when the cache could not serve the token', async () => {
    await store.save(LEGACY, '{"stale":true}');
    msal.deviceCode = authResult({});

    await authenticator().acquireToken();

    assert.equal(await store.load(LEGACY), undefined);
  });

  it('is removed even when the cache serves the token silently', async () => {
    await store.save(LEGACY, '{"stale":true}');
    msal.accounts = [ACCOUNT];
    msal.silent = authResult();

    await authenticator().acquireToken();

    assert.equal(await store.load(LEGACY), undefined);
  });

  it('leaves the current entry alone', async () => {
    const auth = authenticator();
    await store.save(auth.cacheKey, '{"current":true}');
    msal.accounts = [ACCOUNT];
    msal.silent = authResult();

    await auth.acquireToken();

    assert.notEqual(await store.load(auth.cacheKey), undefined);
  });

  it('is cleared along with the current one', async () => {
    const auth = authenticator();
    await store.save(LEGACY, '{"stale":true}');
    await store.save(auth.cacheKey, '{"current":true}');

    await auth.clearCache();

    assert.equal(await store.load(LEGACY), undefined);
    assert.equal(await store.load(auth.cacheKey), undefined);
  });
});

describe('browser sign-in', () => {
  it('uses the browser flow and never the device code one', async () => {
    msal.interactive = authResult({});

    const outcome = await authenticator(AUTH, msal, 'browser').acquireToken();

    assert.equal(outcome.accessToken.length > 0, true);
    assert.equal(msal.interactiveRequests.length, 1);
    assert.deepEqual(msal.deviceCodeRequests, [], 'device code must not be used');
    assert.deepEqual(prompts, [], 'no device code prompt should be shown');
  });

  it('asks for the gateway scope', async () => {
    msal.interactive = authResult({});
    await authenticator(AUTH, msal, 'browser').acquireToken();
    assert.deepEqual(msal.interactiveRequests[0]?.scopes, [`${AUTH.audience}/.default`]);
  });

  it('hands the sign-in URL to the opener', async () => {
    msal.interactive = authResult({});
    await authenticator(AUTH, msal, 'browser').acquireToken();
    assert.equal(msal.openedUrls.length, 1);
    assert.match(msal.openedUrls[0] ?? '', /^https:\/\//);
  });

  it('turns an MSAL failure into an AuthError', async () => {
    msal.interactive = new Error('AADSTS50011: redirect URI mismatch');

    await assert.rejects(
      () => authenticator(AUTH, msal, 'browser').acquireToken(),
      (error: unknown) => {
        assert.ok(error instanceof AuthError);
        assert.match(error.message, /Entra authentication failed/);
        return true;
      },
    );
  });

  it('does not fall back to device code when the browser flow fails', async () => {
    // A Conditional Access denial or a redirect-URI mismatch must surface.
    // Retrying on another flow would hide the one error worth reading.
    msal.interactive = new Error('AADSTS53003: blocked by Conditional Access');

    await assert.rejects(() => authenticator(AUTH, msal, 'browser').acquireToken());
    assert.deepEqual(msal.deviceCodeRequests, []);
  });

  it('keeps the token out of a failure message', async () => {
    const token = syntheticLongJwt();
    msal.interactive = new Error(`request failed with token ${token}`);

    await assert.rejects(
      () => authenticator(AUTH, msal, 'browser').acquireToken(),
      (error: unknown) => {
        const text = String(error);
        assert.ok(!text.includes(token), 'full token leaked');
        assert.ok(!text.includes(token.slice(32, 96)), 'token fragment leaked');
        return true;
      },
    );
  });

  it("keeps the opener's own error and hint", async () => {
    // Wrapping it would replace a hint naming --auth device-code with whatever
    // explainAuthFailure() makes of the message, which is nothing.
    const opener = new EntraAuthenticator({
      auth: AUTH,
      store,
      flow: 'browser',
      clientFactory: () => msal,
      openBrowser: async () => {
        throw new AuthError('could not open a browser on this machine', {
          hint: 'On a headless machine, run again with --auth device-code.',
        });
      },
    });

    await assert.rejects(
      () => opener.acquireToken(),
      (error: unknown) => {
        assert.ok(error instanceof AuthError);
        assert.equal(error.message, 'could not open a browser on this machine');
        assert.match(error.hint ?? '', /--auth device-code/);
        return true;
      },
    );
  });

  it('raises a clear error when no opener was supplied', async () => {
    // Nothing in src/auth may spawn a browser of its own, so a caller that
    // forgets must fail loudly rather than open tabs on whoever runs the code.
    const bare = new EntraAuthenticator({
      auth: AUTH,
      store,
      flow: 'browser',
      clientFactory: () => msal,
    });

    await assert.rejects(() => bare.acquireToken(), /needs a way to open a URL/);
    assert.equal(msal.interactiveRequests.length, 0);
  });

  it('honours forceInteractive on the selected flow', async () => {
    msal.interactive = authResult({});
    await authenticator(AUTH, msal, 'browser').acquireToken(true);
    assert.equal(msal.interactiveRequests.length, 1);
    assert.deepEqual(msal.deviceCodeRequests, []);
  });

  it('opens no browser when the cache can serve the token', async () => {
    msal.accounts = [ACCOUNT];
    msal.silent = authResult({ account: ACCOUNT });

    const outcome = await authenticator(AUTH, msal, 'browser').acquireToken();

    assert.equal(outcome.fromCache, true);
    assert.deepEqual(msal.openedUrls, [], 'a cached token must not open a browser');
    assert.equal(msal.interactiveRequests.length, 0);
  });
});

describe('flow-specific failure hints', () => {
  it('explains a loopback rejection in terms of the browser flow', () => {
    const hint = explainAuthFailure(new Error('AADSTS50011: redirect URI mismatch'), 'browser');
    assert.match(hint ?? '', /loopback redirect/);
    assert.match(hint ?? '', /--auth device-code/);
    assert.match(hint ?? '', /--client-id/);
  });

  it('does not blame a device code when the browser flow times out', () => {
    // The same message on the wrong flow sends the user looking for a code
    // they were never shown.
    const hint = explainAuthFailure(new Error('request timed out'), 'browser');
    assert.ok(!/device code expired/i.test(hint ?? ''), hint);
    assert.match(hint ?? '', /Browser sign-in timed out/i);
  });

  it('still explains an expired device code on that flow', () => {
    const hint = explainAuthFailure(new Error('expired_token'), 'device-code');
    assert.match(hint ?? '', /device code expired/i);
  });

  it('separates a code never approved from a code that expired', () => {
    // authorization_pending is the polling response: the code is still good.
    const pending = explainAuthFailure(new Error('authorization_pending'), 'device-code');
    assert.match(pending ?? '', /still pending/i);
    assert.ok(!/expired/i.test(pending ?? ''), pending);
  });

  it('keeps flow-independent advice for both', () => {
    for (const flow of ['browser', 'device-code'] as const) {
      const hint = explainAuthFailure(new Error('AADSTS53003: conditional access'), flow);
      assert.match(hint ?? '', /Conditional Access/i);
    }
  });
});
