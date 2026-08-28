/**
 * The normalised profile model.
 *
 * This is the boundary between "an XML file someone sent us" and the rest of
 * OpenP2S. Nothing downstream ever sees the raw document: the authenticator,
 * the config renderer and the network configurator all consume this type, so
 * every value they touch has already been validated exactly once, here.
 */

import type { ParsedPrefix } from './validate.ts';

export interface AzureVpnRoute {
  /** Canonical "address/prefix" form, e.g. "10.20.0.0/16". */
  readonly cidr: string;
  readonly address: string;
  readonly prefixLength: number;
  readonly family: 4 | 6;
}

export interface EntraAuthConfig {
  /** Normalised authority, e.g. https://login.microsoftonline.com/<tenant>. */
  readonly authority: string;
  readonly tenantId: string;
  /** Raw <audience> value, normalised. */
  readonly audience: string;
  /** OAuth scope to request: "<audience>/.default". */
  readonly scope: string;
  /** Public client application id to authenticate as. */
  readonly clientId: string;
  /** <issuer> from the profile. Recorded for diagnostics; not used for auth. */
  readonly issuer?: string;
}

export interface AzureVpnProfile {
  /** Profile name, derived from the file name. Display only. */
  readonly name: string;
  /** Primary gateway FQDN. Validated as a hostname; safe for argv and config. */
  readonly gateway: string;
  /**
   * Every gateway in <serverlist>, primary first.
   *
   * Azure profiles may list several entries; they become additional `remote`
   * lines so OpenVPN can fail over the way the official client does.
   */
  readonly gateways: readonly string[];
  readonly port: number;
  readonly auth: EntraAuthConfig;
  /**
   * The 512-hex-character tls-auth key, lowercased.
   *
   * Held in memory only. It is written exactly once, inline into the
   * generated OpenVPN config in the 0700 runtime directory, and never to a
   * persistent file or a log.
   */
  readonly serverSecret: string;
  /**
   * SHA-1 thumbprint from <servervalidation><Cert><hash>, if present.
   *
   * Recorded and reported, but not used as a trust anchor: it is SHA-1, which
   * OpenVPN's --peer-fingerprint does not accept (that wants SHA-256), and
   * pinning on a SHA-1 digest would be a downgrade rather than an
   * improvement. See docs/SECURITY.md.
   */
  readonly certificateThumbprint?: string;
  /**
   * <servervalidation><usepinnedroot>.
   *
   * When false - the usual case - the gateway is validated against the system
   * trust store. When true the profile is asking for the embedded root to be
   * the sole anchor, which OpenP2S does not yet implement and refuses rather
   * than silently ignoring.
   */
  readonly usePinnedRoot: boolean;
  readonly dnsServers: readonly string[];
  readonly dnsSuffixes: readonly string[];
  /** Client-side routes from <clientconfig>, distinct from PUSH_REPLY routes. */
  readonly includeRoutes: readonly AzureVpnRoute[];
}

export function routeFromPrefix(prefix: ParsedPrefix): AzureVpnRoute {
  return {
    cidr: prefix.cidr,
    address: prefix.address,
    prefixLength: prefix.prefixLength,
    family: prefix.family,
  };
}

/**
 * A redacted view for `inspect` and diagnostics.
 *
 * The serversecret is reduced to a statement that it exists and is
 * well-formed. There is no flag to print it: nothing in a troubleshooting
 * workflow is improved by having a tls-auth key on a terminal.
 */
export interface ProfileSummary {
  readonly name: string;
  readonly gateway: string;
  readonly additionalGateways: readonly string[];
  readonly port: number;
  readonly authority: string;
  readonly tenantId: string;
  readonly audience: string;
  readonly clientId: string;
  readonly serverSecret: string;
  readonly certificateThumbprint: string;
  readonly dnsServers: readonly string[];
  readonly dnsSuffixes: readonly string[];
  readonly includeRoutes: readonly string[];
}

export function summariseProfile(profile: AzureVpnProfile): ProfileSummary {
  return {
    name: profile.name,
    gateway: profile.gateway,
    additionalGateways: profile.gateways.slice(1),
    port: profile.port,
    authority: profile.auth.authority,
    tenantId: profile.auth.tenantId,
    audience: profile.auth.audience,
    clientId: profile.auth.clientId,
    serverSecret: `present, valid (${profile.serverSecret.length / 2} bytes)`,
    certificateThumbprint: profile.certificateThumbprint
      ? `present (SHA-1, informational only)`
      : 'not present',
    dnsServers: profile.dnsServers,
    dnsSuffixes: profile.dnsSuffixes,
    includeRoutes: profile.includeRoutes.map((route) => route.cidr),
  };
}
