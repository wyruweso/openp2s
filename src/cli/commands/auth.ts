/**
 * `openp2s auth login|status|clear`
 *
 * Manages the persistent Entra token cache.
 *
 * Two rules hold across all three:
 *
 *   - **The identity comes from `resolveAuthIdentity()`.** The cache key is
 *     (authority, audience, clientId, flow), so if these commands computed it
 *     differently a `--client-id` override would make `login` write a session
 *     that `status` cannot see and `clear` cannot delete. `status` and `clear`
 *     take no flow: they cover every key the identity could live under.
 *   - **Storage is reached only through `TokenCacheStore`.** Reading the cache
 *     files directly would defeat the abstraction whose whole purpose is to
 *     allow a Secret Service or KWallet backend later, and would bypass the
 *     permission check that refuses a cache other users can read.
 *
 * Token values are never accessed, returned or printed. `summariseCacheBlob`
 * parses the MSAL document - so the secrets are in memory, as they must be for
 * MSAL to work at all - but reads only usernames, realms and expiry, and
 * touches no `secret` field.
 */

import type { InteractiveFlow } from '../../auth/entra.ts';
import { cacheKeysForIdentity } from '../../auth/cache/identity.ts';
import type { TokenCacheStore } from '../../auth/cache/store.ts';
import { AuthError } from '../../errors.ts';
import {
  createAuthenticator,
  createCacheStore,
  createContext,
  loadProfile,
  resolveAuthIdentity,
  type GlobalOptions,
} from '../context.ts';

export interface AuthStatusOptions extends GlobalOptions {
  /** Limit the report to the identity implied by this profile. */
  readonly profile?: string;
  /** The same overrides as `login`, so both compute the same cache key. */
  readonly clientId?: string;
  readonly scope?: string;
}

export interface AuthLoginOptions extends GlobalOptions {
  readonly clientId?: string;
  /** Which interactive sign-in flow to use. */
  readonly authFlow?: InteractiveFlow;
  readonly scope?: string;
  /** Ignore any cached session and force an interactive sign-in. */
  readonly force?: boolean;
}

export interface AuthClearOptions extends GlobalOptions {
  readonly profile?: string;
  readonly all?: boolean;
  readonly clientId?: string;
  readonly scope?: string;
}

interface CacheSummary {
  readonly key: string;
  readonly accounts: string[];
  readonly tenants: string[];
  /** How many access tokens the cache holds, across scopes and accounts. */
  readonly accessTokenCount: number;
  /** Expiry of the earliest-expiring of them. */
  readonly earliestExpiry: Date | undefined;
  readonly hasRefreshToken: boolean;
}

function emptySummary(key: string): CacheSummary {
  return {
    key,
    accounts: [],
    tenants: [],
    accessTokenCount: 0,
    earliestExpiry: undefined,
    hasRefreshToken: false,
  };
}

/**
 * Summarise an MSAL cache document.
 *
 * MSAL's format is JSON with Account, AccessToken and RefreshToken sections
 * keyed by long composite strings. Only display fields are read: usernames,
 * realms, expiry, and whether a refresh token exists. The `secret` fields that
 * hold the tokens are never touched.
 */
export function summariseCacheBlob(key: string, blob: string): CacheSummary {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(blob) as Record<string, unknown>;
  } catch {
    return emptySummary(key);
  }

  const accounts: string[] = [];
  const tenants: string[] = [];

  const accountSection = parsed['Account'];
  if (accountSection && typeof accountSection === 'object') {
    for (const entry of Object.values(accountSection as Record<string, unknown>)) {
      if (!entry || typeof entry !== 'object') continue;
      const record = entry as Record<string, unknown>;
      const username = typeof record['username'] === 'string' ? record['username'] : undefined;
      const realm = typeof record['realm'] === 'string' ? record['realm'] : undefined;
      if (username && !accounts.includes(username)) accounts.push(username);
      if (realm && !tenants.includes(realm)) tenants.push(realm);
    }
  }

  let accessTokenCount = 0;
  let earliest: number | undefined;

  const tokenSection = parsed['AccessToken'];
  if (tokenSection && typeof tokenSection === 'object') {
    for (const entry of Object.values(tokenSection as Record<string, unknown>)) {
      if (!entry || typeof entry !== 'object') continue;
      accessTokenCount += 1;
      const epoch = Number((entry as Record<string, unknown>)['expires_on']);
      if (Number.isFinite(epoch) && (earliest === undefined || epoch < earliest)) {
        earliest = epoch;
      }
    }
  }

  const refreshSection = parsed['RefreshToken'];
  const hasRefreshToken =
    Boolean(refreshSection) &&
    typeof refreshSection === 'object' &&
    Object.keys(refreshSection as Record<string, unknown>).length > 0;

  return {
    key,
    accounts,
    tenants,
    accessTokenCount,
    earliestExpiry: earliest !== undefined ? new Date(earliest * 1000) : undefined,
    hasRefreshToken,
  };
}

/** Read and summarise one cache entry, through the store. */
async function summariseCache(store: TokenCacheStore, key: string): Promise<CacheSummary> {
  const blob = await store.load(key);
  return blob ? summariseCacheBlob(key, blob) : emptySummary(key);
}

/**
 * Describe the cached access tokens.
 *
 * A cache can hold several, for different scopes or accounts, so this reports
 * the count and the earliest expiry rather than implying there is one token
 * whose expiry is "the" expiry.
 */
function describeAccessTokens(summary: CacheSummary): string {
  if (summary.accessTokenCount === 0) return 'none cached';

  const count = summary.accessTokenCount === 1 ? '1 token' : `${summary.accessTokenCount} tokens`;
  const expiry = summary.earliestExpiry;
  if (!expiry) return `${count}, expiry unknown`;

  const remainingMs = expiry.getTime() - Date.now();
  if (remainingMs <= 0) {
    return `${count}, earliest expired ${expiry.toISOString()}`;
  }

  const minutes = Math.floor(remainingMs / 60_000);
  const hours = Math.floor(minutes / 60);
  const readable = hours > 0 ? `${hours}h ${minutes % 60}m` : `${minutes}m`;
  return `${count}, earliest expires in ${readable}`;
}

/**
 * `openp2s auth login <profile.xml>`
 *
 * Sign in and populate the token cache, without connecting. Necessary before
 * anything non-interactive, since neither a browser nor a device-code prompt
 * can be answered by a script.
 */
export async function authLoginCommand(
  profilePath: string,
  options: AuthLoginOptions = {},
): Promise<number> {
  const context = createContext(options);
  const { ui } = context;

  const profile = await loadProfile(profilePath);
  const identity = resolveAuthIdentity(profile, options);
  const authenticator = createAuthenticator(context, profile, {
    ...options,
    ...(options.authFlow ? { flow: options.authFlow } : {}),
  });

  ui.heading(`Sign in: ${profile.name}`);
  ui.fields([
    ['Gateway', profile.gateway],
    ['Tenant', identity.tenantId],
    ['Audience', identity.audience],
    ['Client ID', identity.clientId],
  ]);

  const outcome = await authenticator.acquireToken(options.force ?? false);

  ui.line();
  if (outcome.fromCache) {
    ui.ok(`Already signed in${outcome.account ? ` as ${outcome.account}` : ''}`);
    ui.line('Use --force to sign in again.');
  } else {
    ui.ok(`Signed in${outcome.account ? ` as ${outcome.account}` : ''}`);
  }

  // Never the token itself; only how long it is good for.
  if (outcome.expiresOn) {
    const minutes = Math.max(0, Math.round((outcome.expiresOn.getTime() - Date.now()) / 60_000));
    ui.fields([['Token valid for', `${minutes} minutes`]]);
  }

  ui.line();
  ui.line('The session is cached. Later connects will normally sign in silently.');
  ui.line('You will be prompted again if silent renewal is no longer possible, or');
  ui.line('if Conditional Access requires fresh authentication.');

  return 0;
}

/**
 * `openp2s auth status [profile.xml]`
 *
 * Informational, and therefore always exits 0: nothing is broken when there is
 * no cached session. A script that needs to branch on connectivity should use
 * `openp2s doctor`, which does report failure.
 */
export async function authStatusCommand(options: AuthStatusOptions = {}): Promise<number> {
  const context = createContext(options);
  const { ui } = context;
  const store = createCacheStore(context);

  let keys = await store.list();

  // The key is a digest, so its flow is only knowable from an identity.
  // Without a profile the listing omits the field rather than guessing.
  const flowByKey = new Map<string, string>();

  // Narrow to one identity when a profile is given, computed exactly as
  // `login` and `clear` compute it.
  if (options.profile) {
    const profile = await loadProfile(options.profile);
    for (const ref of cacheKeysForIdentity(resolveAuthIdentity(profile, options))) {
      flowByKey.set(ref.key, ref.flow ?? 'device-code (cached by OpenP2S 0.1.x)');
    }
    keys = keys.filter((key) => flowByKey.has(key));
  }

  if (keys.length === 0) {
    ui.line(
      options.profile ? 'No cached Entra session for this profile.' : 'No cached Entra sessions.',
    );
    ui.line();
    ui.line('The next connect will sign in through your browser, or sign in now with:');
    ui.line('  openp2s auth login <profile.xml>');
    ui.line();
    ui.line('On a machine with no browser, add --auth device-code.');
    return 0;
  }

  ui.heading(`Cached Entra sessions (${context.paths.cacheDir})`);

  for (const key of keys) {
    const summary = await summariseCache(store, key);
    ui.line();
    ui.fields([
      ['Cache', key],
      // Two flows against one tenant are otherwise told apart only by a digest.
      ['Flow', flowByKey.get(key)],
      ['Accounts', summary.accounts.length > 0 ? summary.accounts : ['(none recorded)']],
      ['Tenants', summary.tenants.length > 0 ? summary.tenants : ['(none recorded)']],
      ['Access tokens', describeAccessTokens(summary)],
      // "cached" is a statement about the store. Whether a silent acquisition
      // will actually succeed is up to Entra, not up to us.
      ['Refresh token', summary.hasRefreshToken ? 'cached' : 'not cached'],
    ]);
  }

  ui.line();
  ui.line('A cached refresh token usually means the next connect signs in silently,');
  ui.line('but Conditional Access or a revoked session can require fresh authentication');
  ui.line('at any time. OpenP2S then repeats the sign-in flow you asked for; it never');
  ui.line('switches to device code on its own.');

  return 0;
}

/**
 * `openp2s auth clear <profile.xml>` / `--all`
 *
 * Deletes through the store, and derives the key exactly as `login` does, so a
 * session created with `--client-id` is the one actually removed.
 */
export async function authClearCommand(options: AuthClearOptions = {}): Promise<number> {
  const context = createContext(options);
  const { ui } = context;
  const store = createCacheStore(context);

  if (options.all) {
    const keys = await store.list();
    if (keys.length === 0) {
      ui.line('No cached Entra sessions to clear.');
      return 0;
    }
    for (const key of keys) {
      await store.delete(key);
    }
    ui.ok(`Cleared ${keys.length} cached Entra session${keys.length === 1 ? '' : 's'}`);
    return 0;
  }

  if (!options.profile) {
    throw new AuthError('specify which session to clear', {
      hint: 'Either: openp2s auth clear <profile.xml>\n    or: openp2s auth clear --all',
    });
  }

  const profile = await loadProfile(options.profile);
  // A store operation, not an auth operation: no MSAL client is needed.
  // Every key the identity could live under: "forget this profile" means all
  // of it, whichever flow or version wrote it.
  for (const ref of cacheKeysForIdentity(resolveAuthIdentity(profile, options))) {
    await store.delete(ref.key);
  }

  ui.ok(`Cleared the cached Entra session for ${profile.name}`);
  return 0;
}
