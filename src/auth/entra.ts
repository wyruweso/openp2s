/**
 * Microsoft Entra ID authentication.
 *
 * Deliberately thin. MSAL does the OAuth work - device code flow, silent
 * acquisition, refresh token rotation, expiry - and OpenP2S only decides
 * where the cache lives and how the result is surfaced. There is no manual
 * refresh-token handling anywhere in this codebase, on purpose: it is the
 * part of an OAuth client most likely to be got subtly wrong, and MSAL
 * already gets it right.
 *
 * Flow:
 *
 *   load cache -> acquireTokenSilent
 *      hit  -> use it
 *      miss -> device code flow (MFA happens in the browser) -> cache updated
 *
 * Conditional Access can invalidate a cached session at any moment, so a
 * silent failure is an ordinary outcome that falls through to interactive
 * sign-in, not an error.
 */

import {
  LogLevel,
  PublicClientApplication,
  type AccountInfo,
  type AuthenticationResult,
  type Configuration,
  type ICachePlugin,
  type TokenCacheContext,
} from '@azure/msal-node';
import { AuthError, describeError } from '../errors.ts';
import type { EntraAuthConfig } from '../profile/types.ts';
import { cacheKey, type CacheIdentity } from './cache/identity.ts';
import type { TokenCacheStore } from './cache/store.ts';

export interface DeviceCodePrompt {
  readonly verificationUri: string;
  readonly userCode: string;
  readonly expiresInSeconds: number;
  /** The full message MSAL suggests. Never contains a token. */
  readonly message: string;
}

export interface AuthOutcome {
  /**
   * The Entra access token.
   */
  readonly accessToken: string;
  readonly expiresOn: Date | undefined;
  readonly account: string | undefined;
  readonly tenantId: string | undefined;
  /** True when the token came from cache without user interaction. */
  readonly fromCache: boolean;
}

/**
 * The slice of authentication the connection orchestrator actually needs.
 *
 * Depending on this rather than on EntraAuthenticator keeps the lifecycle
 * tests free of MSAL and of any network at all, and makes it obvious that
 * connect() never reaches for anything else on the authenticator.
 */
export interface TokenSource {
  acquireToken(forceInteractive?: boolean): Promise<AuthOutcome>;
}

/**
 * The part of MSAL's client this module actually uses.
 *
 * `PublicClientApplication` satisfies it structurally. Naming the surface
 * separately is what lets the flow above - silent hit, silent miss falling
 * through to device code, error mapping - be exercised without a network or
 * a tenant, which is otherwise the whole of this file.
 */
export interface MsalClient {
  getTokenCache(): { getAllAccounts(): Promise<AccountInfo[]> };
  acquireTokenSilent(request: {
    account: AccountInfo;
    scopes: string[];
  }): Promise<AuthenticationResult | null>;
  acquireTokenByDeviceCode(request: {
    scopes: string[];
    deviceCodeCallback: (response: {
      verificationUri: string;
      userCode: string;
      expiresIn: number;
      message: string;
    }) => void;
  }): Promise<AuthenticationResult | null>;
}

export interface EntraAuthenticatorOptions {
  readonly auth: EntraAuthConfig;
  readonly store: TokenCacheStore;
  /** Called when interactive sign-in is required. */
  readonly onDeviceCode?: (prompt: DeviceCodePrompt) => void;
  /** Diagnostics sink. Receives redacted strings only. */
  readonly onDebug?: (message: string) => void;
  /**
   * Builds the MSAL client. Defaults to a real PublicClientApplication.
   *
   * The configuration passed in is the one this module assembled, so a
   * substitute still sees the authority and the cache plugin that would have
   * been used.
   */
  readonly clientFactory?: (configuration: Configuration) => MsalClient;
}

/**
 * Turn a common Entra failure into something actionable.
 *
 * The raw MSAL message is an AADSTS code and a correlation id, which tells a
 * user nothing about what to do. Free-standing because it depends only on the
 * error: nothing about which tenant or account was involved changes the
 * advice.
 */
export function explainAuthFailure(error: unknown): string | undefined {
  const message = describeError(error);

  if (/AADSTS50059|tenant.*not found/i.test(message)) {
    return 'The tenant in the profile could not be found. Check the <tenant> URL.';
  }
  if (/AADSTS700016|application.*not found|unauthorized_client/i.test(message)) {
    return (
      'The application id was rejected by this tenant. The profile audience ' +
      'may not be registered here; try passing --client-id explicitly.'
    );
  }
  if (/AADSTS65001|consent/i.test(message)) {
    return 'An administrator must grant consent for the VPN application in this tenant.';
  }
  if (/AADSTS50076|AADSTS50079|multi-factor/i.test(message)) {
    return 'Multi-factor authentication is required. Complete the sign-in in the browser.';
  }
  if (/AADSTS53003|conditional access/i.test(message)) {
    return 'A Conditional Access policy blocked this sign-in. Contact your administrator.';
  }
  if (/expired_token|authorization_pending|timed out/i.test(message)) {
    return 'The device code expired before sign-in completed. Run connect again.';
  }
  return undefined;
}

/**
 * Bridge MSAL's cache plugin contract onto TokenCacheStore.
 *
 * MSAL hands us an opaque serialised blob and tells us when it changed. We
 * never inspect or modify it - doing so would mean taking responsibility for
 * a format that is not ours.
 */
function createCachePlugin(store: TokenCacheStore, key: string): ICachePlugin {
  return {
    async beforeCacheAccess(context: TokenCacheContext): Promise<void> {
      const cached = await store.load(key);
      if (cached) {
        context.tokenCache.deserialize(cached);
      }
    },
    async afterCacheAccess(context: TokenCacheContext): Promise<void> {
      if (context.cacheHasChanged) {
        await store.save(key, context.tokenCache.serialize());
      }
    },
  };
}

export class EntraAuthenticator implements TokenSource {
  private readonly auth: EntraAuthConfig;
  private readonly store: TokenCacheStore;
  private readonly options: EntraAuthenticatorOptions;
  private readonly key: string;
  private client: MsalClient | undefined;

  constructor(options: EntraAuthenticatorOptions) {
    this.options = options;
    this.auth = options.auth;
    this.store = options.store;
    this.key = cacheKey(this.identity);
  }

  get identity(): CacheIdentity {
    return {
      authority: this.auth.authority,
      audience: this.auth.audience,
      clientId: this.auth.clientId,
    };
  }

  get cacheKey(): string {
    return this.key;
  }

  /** The scope requested for the VPN gateway: "<audience>/.default". */
  get scopes(): string[] {
    return [this.auth.scope];
  }

  private getClient(): MsalClient {
    if (this.client) return this.client;

    const configuration: Configuration = {
      auth: {
        clientId: this.auth.clientId,
        // Validated against Microsoft's published login hosts by the profile
        // parser before it ever reaches here.
        authority: this.auth.authority,
      },
      cache: {
        cachePlugin: createCachePlugin(this.store, this.key),
      },
      system: {
        loggerOptions: {
          // MSAL logs can carry token fragments at Verbose. Warning and above
          // only, routed through describeError() so anything that slips
          // through is redacted before a human sees it.
          logLevel: LogLevel.Warning,
          piiLoggingEnabled: false,
          loggerCallback: (_level, message, containsPii) => {
            if (containsPii) return;
            this.options.onDebug?.(describeError(message));
          },
        },
      },
    };

    this.client = this.options.clientFactory
      ? this.options.clientFactory(configuration)
      : new PublicClientApplication(configuration);
    return this.client;
  }

  /** Accounts in the cache for this tenant/audience. Safe to display. */
  async listAccounts(): Promise<AccountInfo[]> {
    try {
      const cache = this.getClient().getTokenCache();
      return await cache.getAllAccounts();
    } catch {
      return [];
    }
  }

  /**
   * Get an access token, silently if the cache allows it.
   *
   * `forceInteractive` skips the silent attempt, for when the gateway has
   * already rejected a cached token.
   */
  async acquireToken(forceInteractive = false): Promise<AuthOutcome> {
    if (!forceInteractive) {
      const silent = await this.trySilent();
      if (silent) return silent;
    }
    return await this.acquireByDeviceCode();
  }

  /**
   * Attempt silent acquisition.
   *
   * Returns undefined rather than throwing on any failure. A stale cache,
   * a revoked session and a Conditional Access policy change all look the
   * same from here, and all have the same remedy: sign in again.
   */
  private async trySilent(): Promise<AuthOutcome | undefined> {
    let accounts: AccountInfo[];
    try {
      accounts = await this.listAccounts();
    } catch {
      return undefined;
    }

    for (const account of accounts) {
      try {
        const result = await this.getClient().acquireTokenSilent({
          account,
          scopes: this.scopes,
        });
        if (result?.accessToken) {
          return this.toOutcome(result, true);
        }
      } catch (error) {
        this.options.onDebug?.(`silent acquisition failed: ${describeError(error)}`);
      }
    }
    return undefined;
  }

  /**
   * Device code flow.
   *
   * Chosen over an interactive browser redirect because OpenP2S has to work
   * over SSH and on headless machines, where no local browser or loopback
   * redirect is available.
   */
  private async acquireByDeviceCode(): Promise<AuthOutcome> {
    let result: AuthenticationResult | null;

    try {
      result = await this.getClient().acquireTokenByDeviceCode({
        scopes: this.scopes,
        deviceCodeCallback: (response) => {
          // MSAL invokes this with whatever the devicecode endpoint returned,
          // including an error body - which has no userCode. Printing that
          // verbatim gives the user "Open: undefined / Code: undefined" and no
          // idea that the tenant in their profile is the problem.
          if (!response?.verificationUri || !response.userCode) {
            throw new AuthError('Entra did not return a device code', {
              hint:
                `Tenant: ${this.auth.authority}\n` +
                'Check that the profile is current and its tenant still exists.',
            });
          }
          this.options.onDeviceCode?.({
            verificationUri: response.verificationUri,
            userCode: response.userCode,
            expiresInSeconds: response.expiresIn,
            message: response.message,
          });
        },
      });
    } catch (error) {
      // An AuthError from here is one we raised inside the callback, with a
      // hint written for that specific failure. Wrapping it would replace
      // that hint with whatever explainAuthFailure() makes of the message -
      // which, for our own wording, is nothing at all.
      if (error instanceof AuthError) throw error;

      throw new AuthError(`Entra authentication failed: ${describeError(error)}`, {
        cause: error,
        hint: explainAuthFailure(error),
      });
    }

    if (!result?.accessToken) {
      throw new AuthError('Entra returned no access token');
    }

    return this.toOutcome(result, false);
  }

  private toOutcome(result: AuthenticationResult, fromCache: boolean): AuthOutcome {
    return {
      accessToken: result.accessToken,
      expiresOn: result.expiresOn ?? undefined,
      account: result.account?.username,
      tenantId: result.tenantId,
      fromCache,
    };
  }

  /** Forget the cached session for this tenant/audience/client. */
  async clearCache(): Promise<void> {
    await this.store.delete(this.key);
  }
}
