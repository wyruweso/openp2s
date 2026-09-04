/**
 * Cache identity: tenant, audience, client application and sign-in flow.
 *
 * A cached login is reusable only for all four; mixing them would serve a
 * token with the wrong scope or reuse another tenant's session.
 *
 * The account is not part of the key - MSAL stores several in one blob and
 * selects between them, which is what lets `auth status` list them.
 */

import { createHash } from 'node:crypto';

/** Every flow a session can be established with, and cached under. */
export const CACHEABLE_FLOWS = ['browser', 'device-code'] as const;

export type InteractiveFlow = (typeof CACHEABLE_FLOWS)[number];

export interface CacheIdentity {
  readonly authority: string;
  readonly audience: string;
  readonly clientId: string;
  /**
   * Entra carries "this session came from device code" through refreshes, so
   * one shared cache would let `--auth browser` reuse such a session and never
   * open a browser - handing the user the flow their organisation blocked.
   */
  readonly flow: InteractiveFlow;
}

/**
 * Hashed rather than concatenated because tenant identifiers can be domain
 * names and audiences can be URIs, neither of which is safe as a file name.
 * The hash is not a security boundary - the directory is 0700 - it is just a
 * naming scheme.
 */
function digest(parts: readonly string[]): string {
  const material = parts.map((part) => part.toLowerCase()).join(' ');
  return createHash('sha256').update(material).digest('hex').slice(0, 32);
}

/**
 * The key's meaning is versioned, so an entry written under a different scheme
 * is not found rather than misread. v2 keys cover the flow as well.
 */
const KEY_VERSION = 'v2';

export function cacheKey(identity: CacheIdentity): string {
  return digest([
    KEY_VERSION,
    identity.authority,
    identity.audience,
    identity.clientId,
    identity.flow,
  ]);
}

/**
 * The key OpenP2S 0.1.x wrote: the same identity, with no version and no flow.
 *
 * Nothing reads it. It is named here so the entry can be found and removed
 * rather than left on disk as a refresh token nothing will use.
 */
export function legacyCacheKey(identity: Omit<CacheIdentity, 'flow'>): string {
  return digest([identity.authority, identity.audience, identity.clientId]);
}

export interface CacheKeyRef {
  readonly key: string;
  /** undefined for the 0.1.x key, which predates per-flow caching. */
  readonly flow: InteractiveFlow | undefined;
}

/**
 * Every key an identity's session could live under. `auth status` and `auth
 * clear` take a profile, so the user need not remember which flow, or which
 * version of OpenP2S, established the session.
 */
export function cacheKeysForIdentity(identity: Omit<CacheIdentity, 'flow'>): CacheKeyRef[] {
  return [
    ...CACHEABLE_FLOWS.map((flow) => ({ key: cacheKey({ ...identity, flow }), flow })),
    { key: legacyCacheKey(identity), flow: undefined },
  ];
}

/** Short human label for `auth status`, safe to print. */
export function describeIdentity(identity: CacheIdentity): string {
  const tenant = identity.authority.split('/').pop() ?? identity.authority;
  return `tenant ${tenant}, audience ${identity.audience}`;
}
