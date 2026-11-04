import { AuthError } from '../errors.ts';

export const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';

/**
 * Azure VPN uses ASCII TLV fields, not a groups claim in the VPN JWT.
 * The Windows client 4.0.5.0 sends a prefix, then type 00 (VPN) and
 * type 01 (Microsoft Graph), each with an eight-digit hexadecimal length.
 * The gateway uses the Graph credential to resolve membership itself.
 */
export function groupCredential(vpnToken: string, graphToken: string): string {
  const field = (type: string, token: string): string => {
    // Tokens are opaque. Accept the ASCII bearer-token alphabet, excluding
    // line breaks and separators that could escape management framing.
    if (!/^[A-Za-z0-9._~+/-]+=*$/.test(token) || token.length > 0xffffffff) {
      throw new AuthError('Entra returned an invalid token for group authentication');
    }
    return type + token.length.toString(16).padStart(8, '0') + token;
  };
  return 'TlvToken:' + field('00', vpnToken) + field('01', graphToken);
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Whether Entra's tenant id agrees with the tenant the profile names.
 *
 * A profile may name its tenant by verified domain, or by a GUID in any case,
 * while Entra reports a lowercase GUID. Only a GUID can be compared. A domain
 * is not a mismatch: sign-in already went to that tenant's authority, and the
 * Graph token is still held to the VPN token's tenant.
 */
export function isProfileTenant(profileTenant: string, tenantId: string): boolean {
  return !GUID.test(profileTenant) || profileTenant.toLowerCase() === tenantId.toLowerCase();
}

/** What a user needs to hear when the profile's group token could not be used. */
export function groupTokenWarning(reason: string): string {
  return (
    'no Microsoft Graph token is available, so this connection uses the VPN token alone ' +
    `and the gateway may assign its default address pool (${reason}). The application ` +
    'needs Microsoft Graph consent in your tenant; your VPN administrator can check this'
  );
}
