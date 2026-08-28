/**
 * Cache identity: tenant, audience and client application.
 *
 * A cached login is reusable only for all three; mixing them would serve a
 * token with the wrong scope or reuse another tenant's session.
 *
 * The account is not part of the key - MSAL stores several in one blob and
 * selects between them, which is what lets `auth status` list them.
 */

import { createHash } from 'node:crypto';

export interface CacheIdentity {
  readonly authority: string;
  readonly audience: string;
  readonly clientId: string;
}

/**
 * Derive a stable, filesystem-safe cache key.
 *
 * Hashed rather than concatenated because tenant identifiers can be domain
 * names and audiences can be URIs, neither of which is safe as a file name.
 * The hash is not a security boundary - the directory is 0700 - it is just a
 * naming scheme.
 */
export function cacheKey(identity: CacheIdentity): string {
  const material = [
    identity.authority.toLowerCase(),
    identity.audience.toLowerCase(),
    identity.clientId.toLowerCase(),
  ].join(' ');

  return createHash('sha256').update(material).digest('hex').slice(0, 32);
}

/** Short human label for `auth status`, safe to print. */
export function describeIdentity(identity: CacheIdentity): string {
  const tenant = identity.authority.split('/').pop() ?? identity.authority;
  return `tenant ${tenant}, audience ${identity.audience}`;
}
