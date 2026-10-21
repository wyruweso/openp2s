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
