/**
 * Handing a URL to the system browser: what may be opened, and what happens
 * when nothing can open it.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  OPENER_SETTLE_MS,
  openInBrowser,
  validateAuthenticationUrl,
  type OpenerProcess,
  type Spawner,
} from '../src/auth/browser.ts';
import { entraLoginHosts } from '../src/auth/loginHosts.ts';
import { AuthError } from '../src/errors.ts';
import { validateTenantUrl } from '../src/profile/validate.ts';

type Behaviour =
  'missing' | 'opens' | 'runs' | { readonly exitCode: number; readonly afterMs?: number };

/** A spawner scripted per command, recording every attempt in order. */
function fakeSpawner(
  behaviours: Readonly<Record<string, Behaviour>>,
  attempts: string[] = [],
): Spawner {
  return (command, args) => {
    attempts.push([command, ...args].join(' '));
    const listeners = new Map<string, (code: number | null) => void>();
    const behaviour = behaviours[command] ?? 'missing';

    // Real spawn reports every outcome as an event, never synchronously.
    queueMicrotask(() => {
      if (behaviour === 'missing') {
        listeners.get('error')?.(null);
        return;
      }
      listeners.get('spawn')?.(null);
      if (behaviour === 'runs') return;
      if (behaviour === 'opens') {
        listeners.get('exit')?.(0);
        return;
      }
      setTimeout(() => listeners.get('exit')?.(behaviour.exitCode), behaviour.afterMs ?? 1);
    });

    const child: OpenerProcess = {
      once(event: string, listener: (code: number | null) => void) {
        listeners.set(event, listener);
        return child;
      },
      unref() {},
    };
    return child;
  };
}

const AUTHORIZE = '/common/oauth2/v2.0/authorize?client_id=x&code_challenge_method=S256';

describe('validateAuthenticationUrl', () => {
  it('accepts every host OpenP2S is willing to sign in at', () => {
    for (const host of entraLoginHosts()) {
      const url = validateAuthenticationUrl(`https://${host}${AUTHORIZE}`);
      assert.equal(url.hostname, host);
    }
  });

  it('accepts exactly the hosts the profile parser accepts', () => {
    for (const host of entraLoginHosts()) {
      const tenant = validateTenantUrl(`https://${host}/11111111-2222-3333-4444-555555555555`);
      assert.equal(tenant.host, host);
    }
  });

  it('accepts the endpoint Azure Germany profiles actually name', () => {
    // login-us, not the bare login.microsoftonline.de MSAL authority.
    assert.equal(
      validateAuthenticationUrl(`https://login-us.microsoftonline.de${AUTHORIZE}`).hostname,
      'login-us.microsoftonline.de',
    );
    assert.equal(
      validateTenantUrl('https://login-us.microsoftonline.de/contoso.de').host,
      'login-us.microsoftonline.de',
    );
  });

  it('rejects a non-Microsoft host', () => {
    assert.throws(
      () => validateAuthenticationUrl('https://evil.example/authorize'),
      (error) => {
        assert.ok(error instanceof AuthError);
        assert.match(error.message, /unexpected authentication host/);
        return true;
      },
    );
  });

  it('rejects a lookalike host', () => {
    assert.throws(
      () => validateAuthenticationUrl('https://login.microsoftonline.com.evil.example/x'),
      /unexpected authentication host/,
    );
  });

  it('rejects a host that only contains an allowed one', () => {
    assert.throws(
      () => validateAuthenticationUrl('https://notlogin.microsoftonline.com/x'),
      /unexpected authentication host/,
    );
  });

  it('rejects plain http, even to a Microsoft host', () => {
    assert.throws(
      () => validateAuthenticationUrl(`http://login.microsoftonline.com${AUTHORIZE}`),
      /non-https/,
    );
  });

  it('rejects a non-web scheme', () => {
    assert.throws(() => validateAuthenticationUrl('file:///etc/passwd'), /non-https/);
  });

  it('rejects embedded credentials', () => {
    assert.throws(
      () => validateAuthenticationUrl(`https://user:pass@login.microsoftonline.com${AUTHORIZE}`),
      /credentials/,
    );
  });

  it('rejects a non-standard port', () => {
    assert.throws(
      () => validateAuthenticationUrl(`https://login.microsoftonline.com:8443${AUTHORIZE}`),
      /port 8443/,
    );
  });

  it('accepts the default port written out', () => {
    // WHATWG URL erases :443, so this is the same URL - not an exception.
    const url = validateAuthenticationUrl(`https://login.microsoftonline.com:443${AUTHORIZE}`);
    assert.equal(url.port, '');
  });

  it('rejects a malformed URL', () => {
    assert.throws(() => validateAuthenticationUrl('not a url'), /malformed/);
  });

  it('is case-insensitive about the host', () => {
    const url = validateAuthenticationUrl(`https://LOGIN.MicrosoftOnline.com${AUTHORIZE}`);
    assert.equal(url.hostname, 'login.microsoftonline.com');
  });
});

describe('openInBrowser', () => {
  const URL_TO_OPEN = `https://login.microsoftonline.com${AUTHORIZE}`;

  // Short enough to keep the suite quick; the real window is asserted below.
  const SETTLE = { settleMs: 20 };

  it('stops at the first opener that starts', async () => {
    const attempts: string[] = [];
    await openInBrowser(URL_TO_OPEN, {
      ...SETTLE,
      spawner: fakeSpawner({ 'xdg-open': 'opens' }, attempts),
    });

    assert.equal(attempts.length, 1);
    assert.match(attempts[0] ?? '', /^xdg-open https:\/\/login\.microsoftonline\.com/);
  });

  it('falls through to the next opener when one is missing', async () => {
    const attempts: string[] = [];
    await openInBrowser(URL_TO_OPEN, {
      ...SETTLE,
      spawner: fakeSpawner({ 'x-www-browser': 'opens' }, attempts),
    });

    assert.deepEqual(
      attempts.map((attempt) => attempt.split(' ')[0]),
      ['xdg-open', 'gio', 'x-www-browser'],
    );
  });

  it('falls through when an opener starts and then fails', async () => {
    // The headless case: xdg-open exists and spawns, then exits non-zero for
    // want of a handler. Believing the spawn would leave the user waiting.
    const attempts: string[] = [];
    await openInBrowser(URL_TO_OPEN, {
      ...SETTLE,
      spawner: fakeSpawner({ 'xdg-open': { exitCode: 3 }, gio: 'opens' }, attempts),
    });

    assert.deepEqual(
      attempts.map((attempt) => attempt.split(' ')[0]),
      ['xdg-open', 'gio'],
    );
  });

  it('fails when every opener starts and then exits non-zero', async () => {
    const attempts: string[] = [];
    await assert.rejects(
      () =>
        openInBrowser(URL_TO_OPEN, {
          ...SETTLE,
          spawner: fakeSpawner(
            {
              'xdg-open': { exitCode: 3 },
              gio: { exitCode: 1 },
              'x-www-browser': { exitCode: 127 },
              'sensible-browser': { exitCode: 127 },
            },
            attempts,
          ),
        }),
      /could not open a browser/,
    );
    assert.equal(attempts.length, 4, 'every opener should have been tried');
  });

  it('accepts an opener that is still running', async () => {
    // x-www-browser execs the browser in place: waiting for its exit would hang.
    const attempts: string[] = [];
    await openInBrowser(URL_TO_OPEN, {
      ...SETTLE,
      spawner: fakeSpawner({ 'xdg-open': 'runs' }, attempts),
    });

    assert.equal(attempts.length, 1);
  });

  it('waits long enough to see an early failure', () => {
    assert.ok(OPENER_SETTLE_MS >= 300, `settle window is only ${OPENER_SETTLE_MS}ms`);
  });

  it('passes the URL through gio as a subcommand argument', async () => {
    const attempts: string[] = [];
    await openInBrowser(URL_TO_OPEN, {
      ...SETTLE,
      spawner: fakeSpawner({ gio: 'opens' }, attempts),
    });

    assert.equal(attempts[1], `gio open ${URL_TO_OPEN}`);
  });

  it('fails, rather than waiting, when nothing can open a URL', async () => {
    await assert.rejects(
      () => openInBrowser(URL_TO_OPEN, { ...SETTLE, spawner: fakeSpawner({}) }),
      (error: unknown) => {
        assert.ok(error instanceof AuthError);
        assert.match(error.message, /could not open a browser/);
        assert.match(error.hint ?? '', /--auth device-code/);
        return true;
      },
    );
  });

  it('treats a spawner that throws as an absent opener', async () => {
    const thrower: Spawner = () => {
      throw new Error('EACCES');
    };
    await assert.rejects(
      () => openInBrowser(URL_TO_OPEN, { ...SETTLE, spawner: thrower }),
      /could not open a browser/,
    );
  });

  it('validates before spawning anything', async () => {
    const attempts: string[] = [];
    await assert.rejects(
      () =>
        openInBrowser('https://evil.example/authorize', {
          ...SETTLE,
          spawner: fakeSpawner({ 'xdg-open': 'opens' }, attempts),
        }),
      /unexpected authentication host/,
    );
    assert.deepEqual(attempts, [], 'nothing should be spawned for a rejected URL');
  });
});
