/**
 * Validators for values that arrive in the Azure XML profile.
 *
 * Every function here treats its input as hostile. A profile is a file the
 * user was handed by someone else, and its contents end up in an OpenVPN
 * config file and in argv for a root process. The parser's job is to reject
 * anything it does not positively recognise, rather than to sanitise.
 */

import { ProfileError } from '../errors.ts';

/** Longest legal DNS name, and longest legal label. */
const MAX_HOSTNAME_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;

/**
 * RFC 1123 host label: alphanumeric, may contain hyphens internally.
 *
 * Note what this excludes: whitespace, quotes, semicolons, backslashes,
 * newlines, and anything else that could change the meaning of an OpenVPN
 * directive or a command line. This is the gate the gateway hostname passes
 * through before it becomes `remote <host> 443` and OPENVPN_SNI.
 */
const LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;

export interface HostnameOptions {
  /**
   * Permit a single-label name. Off for the gateway (which must be an FQDN),
   * on for DNS search suffixes, where a bare AD-style label like `corp` is
   * legitimate.
   */
  readonly allowSingleLabel?: boolean;
}

export function validateHostname(
  value: string,
  field: string,
  options: HostnameOptions = {},
): string {
  const host = value.trim();

  if (host.length === 0) {
    throw new ProfileError(`<${field}> is empty`);
  }
  if (host.length > MAX_HOSTNAME_LENGTH) {
    throw new ProfileError(`<${field}> is longer than ${MAX_HOSTNAME_LENGTH} characters`);
  }
  // A trailing dot is legal in DNS but has no place in an OpenVPN remote.
  if (host.endsWith('.') || host.startsWith('.')) {
    throw new ProfileError(`<${field}> must not start or end with a dot: ${host}`);
  }
  if (host.includes('..')) {
    throw new ProfileError(`<${field}> contains an empty DNS label: ${host}`);
  }

  const labels = host.split('.');
  for (const label of labels) {
    if (label.length > MAX_LABEL_LENGTH) {
      throw new ProfileError(`<${field}> has a DNS label longer than ${MAX_LABEL_LENGTH}: ${host}`);
    }
    if (!LABEL.test(label)) {
      throw new ProfileError(`<${field}> is not a valid hostname: ${host}`);
    }
  }

  // An all-numeric final label means this is an IP address, not a hostname.
  // Azure gateways are always named, and accepting a bare IP here would skip
  // the SNI/certificate-name checks that make the connection safe.
  const last = labels[labels.length - 1] ?? '';
  if (/^[0-9]+$/.test(last)) {
    throw new ProfileError(`<${field}> must be a hostname, not an IP address: ${host}`);
  }
  if (labels.length < 2 && !options.allowSingleLabel) {
    throw new ProfileError(`<${field}> must be a fully qualified domain name: ${host}`);
  }

  return host.toLowerCase();
}

/** Strict dotted-quad IPv4, rejecting leading zeros (which invite parser confusion). */
export function isIPv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^[0-9]{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    return Number(part) <= 255;
  });
}

/**
 * IPv6, including the compressed `::` form and IPv4-mapped tails.
 *
 * Node's net.isIPv6 would do this, but doing it here keeps every profile
 * validation rule in one readable place and lets the error messages name the
 * offending XML element.
 */
export function isIPv6(value: string): boolean {
  if (!/^[0-9A-Fa-f:.]+$/.test(value)) return false;

  const doubleColons = value.split('::').length - 1;
  if (doubleColons > 1) return false;

  let head = value;
  let tailGroups = 0;

  // An IPv4 tail (::ffff:192.0.2.1) counts as two groups.
  const lastColon = value.lastIndexOf(':');
  const tail = value.slice(lastColon + 1);
  if (tail.includes('.')) {
    if (!isIPv4(tail)) return false;
    head = value.slice(0, lastColon);
    tailGroups = 2;
  }

  const [left, right] = doubleColons === 1 ? head.split('::') : [head, undefined];
  const leftGroups = left && left.length > 0 ? left.split(':') : [];
  const rightGroups = right && right.length > 0 ? right.split(':') : [];

  for (const group of [...leftGroups, ...rightGroups]) {
    if (!/^[0-9A-Fa-f]{1,4}$/.test(group)) return false;
  }

  const total = leftGroups.length + rightGroups.length + tailGroups;
  return doubleColons === 1 ? total <= 7 : total === 8;
}

export function validateIpAddress(value: string, field: string): string {
  const address = value.trim();
  if (!isIPv4(address) && !isIPv6(address)) {
    throw new ProfileError(`<${field}> is not a valid IP address: ${address}`);
  }
  return address;
}

export interface ParsedPrefix {
  readonly address: string;
  readonly prefixLength: number;
  readonly family: 4 | 6;
  /** Canonical "address/length" form. */
  readonly cidr: string;
}

/**
 * Parse a route prefix in CIDR form.
 *
 * Azure profiles express include-routes as `10.0.0.0/16`. Bare addresses are
 * accepted and treated as host routes (/32 or /128), because some profiles in
 * the wild omit the length.
 */
export function validatePrefix(value: string, field: string): ParsedPrefix {
  const raw = value.trim();
  const slash = raw.lastIndexOf('/');
  const address = slash === -1 ? raw : raw.slice(0, slash);
  const lengthText = slash === -1 ? undefined : raw.slice(slash + 1);

  let family: 4 | 6;
  if (isIPv4(address)) {
    family = 4;
  } else if (isIPv6(address)) {
    family = 6;
  } else {
    throw new ProfileError(`<${field}> is not a valid route prefix: ${raw}`);
  }

  const maxLength = family === 4 ? 32 : 128;
  let prefixLength = maxLength;

  if (lengthText !== undefined) {
    if (!/^[0-9]{1,3}$/.test(lengthText)) {
      throw new ProfileError(`<${field}> has a malformed prefix length: ${raw}`);
    }
    prefixLength = Number(lengthText);
    if (prefixLength > maxLength) {
      throw new ProfileError(
        `<${field}> prefix length /${prefixLength} exceeds the maximum for IPv${family}: ${raw}`,
      );
    }
  }

  return { address, prefixLength, family, cidr: `${address}/${prefixLength}` };
}

/**
 * Hosts we will accept as an Entra authority.
 *
 * The tenant URL decides where OpenP2S sends an authentication request, so it
 * is the single most security-sensitive field in the profile: a hostile
 * profile that redirected it elsewhere would be a credential-phishing
 * primitive. Restricting it to Microsoft's published login endpoints (global
 * plus the sovereign clouds) means a malicious profile cannot point the login
 * at an attacker's server.
 */
const ENTRA_AUTHORITY_HOSTS: ReadonlySet<string> = new Set([
  'login.microsoftonline.com',
  'login.microsoftonline.us',
  'login.partner.microsoftonline.cn',
  'login.microsoftonline.de',
  'login.chinacloudapi.cn',
  'login.usgovcloudapi.net',
]);

export interface ParsedTenant {
  /**
   * Normalised authority URL: https, the recognised host, and the tenant
   * identifier. No trailing slash - MSAL accepts it in this form, and changing
   * a value that works to match a comment would be the wrong way round.
   */
  readonly authority: string;
  readonly host: string;
  /** Tenant GUID, domain name, or "common"/"organizations". */
  readonly tenantId: string;
}

export function validateTenantUrl(value: string, field = 'tenant'): ParsedTenant {
  const raw = value.trim();
  if (raw.length === 0) {
    throw new ProfileError(`<${field}> is empty`);
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ProfileError(`<${field}> is not a valid URL: ${raw}`, {
      hint: 'Expected something like https://login.microsoftonline.com/<tenant-id>',
    });
  }

  if (url.protocol !== 'https:') {
    throw new ProfileError(`<${field}> must use https, got ${url.protocol}//: ${raw}`);
  }
  if (url.username || url.password) {
    throw new ProfileError(`<${field}> must not contain credentials: ${raw}`);
  }

  const host = url.hostname.toLowerCase();
  if (!ENTRA_AUTHORITY_HOSTS.has(host)) {
    throw new ProfileError(`<${field}> is not a recognised Microsoft Entra endpoint: ${host}`, {
      hint:
        'OpenP2S only sends credentials to Microsoft login endpoints. ' +
        `Recognised hosts: ${[...ENTRA_AUTHORITY_HOSTS].join(', ')}`,
    });
  }

  // A tenant URL is a host and a tenant identifier, nothing more. Anything
  // else was silently discarded before: `.../tenant/foo?x=1#bar` normalised to
  // `.../tenant` and validated clean. That is not a security bypass - the host
  // allowlist above still decides where credentials go - but a profile with
  // junk in its tenant URL is malformed, and saying so beats quietly
  // reinterpreting it.
  if (url.search) {
    throw new ProfileError(`<${field}> must not contain a query string: ${raw}`);
  }
  if (url.hash) {
    throw new ProfileError(`<${field}> must not contain a fragment: ${raw}`);
  }

  const segments = url.pathname.split('/').filter((segment) => segment.length > 0);
  if (segments.length > 1) {
    throw new ProfileError(`<${field}> must name only a tenant, got path ${url.pathname}: ${raw}`, {
      hint: 'Expected https://login.microsoftonline.com/<tenant-id>',
    });
  }

  const tenantId = segments[0];
  if (!tenantId) {
    throw new ProfileError(`<${field}> does not name a tenant: ${raw}`, {
      hint: 'Expected https://login.microsoftonline.com/<tenant-id>',
    });
  }
  if (!isTenantIdentifier(tenantId)) {
    throw new ProfileError(`<${field}> has a malformed tenant identifier: ${tenantId}`);
  }

  return { authority: `https://${host}/${tenantId}`, host, tenantId };
}

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

function isTenantIdentifier(value: string): boolean {
  if (GUID.test(value)) return true;
  if (value === 'common' || value === 'organizations' || value === 'consumers') return true;
  // Verified domain names are also valid tenant identifiers.
  return /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(value) && value.includes('.');
}

/**
 * Validate the audience the access token is requested for.
 *
 * Azure profiles use either a bare application GUID (the newer
 * Microsoft-registered app) or an application ID URI (the older manually
 * registered form). Both are accepted; neither is hardcoded, because which
 * one a tenant uses depends on when and how its gateway was configured.
 */
export interface ParsedAudience {
  readonly value: string;
  readonly kind: 'guid' | 'uri';
  /** The OAuth scope to request, always "<audience>/.default". */
  readonly scope: string;
  /** Application id to authenticate as, when the audience implies one. */
  readonly clientId: string | undefined;
}

export function validateAudience(value: string, field = 'audience'): ParsedAudience {
  const raw = value.trim();
  if (raw.length === 0) {
    throw new ProfileError(`<${field}> is empty`);
  }

  if (GUID.test(raw)) {
    const normalised = raw.toLowerCase();
    return {
      value: normalised,
      kind: 'guid',
      scope: `${normalised}/.default`,
      clientId: normalised,
    };
  }

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ProfileError(`<${field}> is neither a GUID nor a URI: ${raw}`, {
      hint: 'Expected an application GUID or an application ID URI such as https://vpn.example.com',
    });
  }

  if (url.protocol !== 'https:' && url.protocol !== 'api:') {
    throw new ProfileError(`<${field}> URI must use https or api scheme: ${raw}`);
  }

  // The scope is built by appending "/.default" to this string verbatim, so a
  // URI carrying a query or fragment produces something that is not a scope at
  // all - "https://vpn.example/x?foo=bar/.default". Reject the input rather
  // than sending that to the token endpoint.
  if (url.username || url.password) {
    throw new ProfileError(`<${field}> must not contain credentials: ${raw}`);
  }
  if (url.search) {
    throw new ProfileError(`<${field}> must not contain a query string: ${raw}`, {
      hint: 'The OAuth scope is this URI with "/.default" appended, so it must be a bare URI.',
    });
  }
  if (url.hash) {
    throw new ProfileError(`<${field}> must not contain a fragment: ${raw}`, {
      hint: 'The OAuth scope is this URI with "/.default" appended, so it must be a bare URI.',
    });
  }

  const trimmed = raw.replace(/\/+$/, '');
  // An app ID URI may embed the client GUID, as in api://<guid>.
  const embedded = trimmed.split('/').pop() ?? '';

  return {
    value: trimmed,
    kind: 'uri',
    scope: `${trimmed}/.default`,
    clientId: GUID.test(embedded) ? embedded.toLowerCase() : undefined,
  };
}

/**
 * A DNS suffix from <dnssuffixes>.
 *
 * These become systemd-resolved routing domains, so the same injection
 * concerns apply as for the gateway hostname. Azure writes them with or
 * without a leading dot; both normalise to the bare suffix.
 */
export function validateDnsSuffix(value: string, field = 'dnssuffix'): string {
  const suffix = value.trim().replace(/^\.+/, '').replace(/\.+$/, '');
  if (suffix.length === 0) {
    throw new ProfileError(`<${field}> is empty`);
  }
  return validateHostname(suffix, field, { allowSingleLabel: true });
}

/**
 * Validate a certificate thumbprint from <servervalidation><Cert><hash>.
 *
 * Azure writes a SHA-1 digest: 40 hex characters, sometimes colon-separated.
 * It is normalised and recorded for diagnostics only - see the note on
 * AzureVpnProfile.certificateThumbprint for why it is not used as a trust
 * anchor.
 */
export function validateCertificateThumbprint(value: string, field = 'hash'): string {
  const hash = value.trim().replace(/[:\s]/g, '').toLowerCase();

  if (!/^[0-9a-f]+$/.test(hash)) {
    throw new ProfileError(`<${field}> is not a hexadecimal certificate thumbprint`);
  }
  // SHA-1 (40) is what Azure emits; accept SHA-256 (64) too rather than
  // rejecting a profile that happens to use a better digest.
  if (hash.length !== 40 && hash.length !== 64) {
    throw new ProfileError(
      `<${field}> is ${hash.length} hex characters; expected 40 (SHA-1) or 64 (SHA-256)`,
    );
  }
  return hash;
}
