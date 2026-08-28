/**
 * Persistent token cache abstraction.
 *
 * MSAL owns the cache contents - refresh tokens, expiry, accounts - and we own
 * only where the opaque blob is kept. Hand-rolling refresh-token logic in a
 * VPN client is a reliable way to introduce a credential bug.
 *
 * The interface exists so the file backend can be swapped for the Secret
 * Service without any other module changing.
 */

export interface TokenCacheStore {
  load(key: string): Promise<string | undefined>;
  save(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  /** Every key this store holds. Used by `auth status` and `auth clear --all`. */
  list(): Promise<string[]>;
}
