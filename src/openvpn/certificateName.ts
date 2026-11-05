/**
 * The certificate name a gateway must present.
 *
 * Chain validation shows that a certificate came from a trusted CA, not that
 * it belongs to an Azure gateway: a certificate bought for any other domain
 * can chain to the same roots. Anyone who also holds the profile's shared
 * tls-auth key, and can get between a user and the gateway, could otherwise
 * pose as the gateway and collect the credential.
 *
 * OpenVPN compares the CN exactly and takes a single value, so the name has to
 * be known before connecting. For the hostnames below it can be worked out, so
 * nobody has to supply it:
 *
 *     azuregateway-<guid>-<hash>.vpn.azure.com      <guid>.vpn.azure.com
 *     azuregateway-<guid>-<hash>.ln.vpn.azure.com   <guid>.ln.vpn.azure.com
 *     <name>.vpn.azure.com                          *.vpn.azure.com
 *
 * The first was reported from a real gateway in issue #32. The other two come
 * from Certificate Transparency logs in November 2026, and those logs show that
 * the wildcard certificates exist, not which hosts present them. So a gateway
 * with the first form could still present the wildcard. If one does, the
 * connection stops and reports the name, as below.
 *
 * Only hosts under vpn.azure.com qualify. Only Microsoft can get a certificate
 * for that domain, so a modified profile cannot make OpenP2S accept a
 * certificate of its own by naming a host it controls.
 *
 * Virtual WAN shares the .ln host form but presents
 * wan.<id>.ln.vpn.azure.com, and <id> is not in the hostname. The rule then
 * expects the wrong name, which stops the connection and reports the
 * certificate presented. A wrong guess fails safely, and --verify-name fixes it.
 */

import { OpenP2SError } from '../errors.ts';

const GUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const PER_GATEWAY_HOST = new RegExp(
  `^azuregateway-(${GUID})-[0-9a-z]+\\.((?:ln\\.)?vpn\\.azure\\.com)$`,
);
const WILDCARD_HOST = /^[a-z0-9-]+\.vpn\.azure\.com$/;

/** The name a gateway at this host should present, when that can be worked out. */
export function expectedCertificateName(host: string): string | undefined {
  // Hostnames are case-insensitive, but OpenVPN's comparison is not, and the
  // names on these certificates are lowercase.
  const name = host.toLowerCase();
  const perGateway = PER_GATEWAY_HOST.exec(name);
  if (perGateway) return `${perGateway[1]}.${perGateway[2]}`;
  return WILDCARD_HOST.test(name) ? '*.vpn.azure.com' : undefined;
}

/**
 * The name to require: the one the user gave, or the one every gateway agrees on.
 *
 * An empty override falls through to the rule rather than meaning "no check",
 * so `--verify-name ""` cannot become an off switch. Gateways that disagree
 * give no answer, because OpenVPN can only hold one name.
 */
export function resolveCertificateName(
  gateways: readonly string[],
  override?: string,
): string | undefined {
  if (override) return override;
  const names = new Set(gateways.map(expectedCertificateName));
  return names.size === 1 ? [...names][0] : undefined;
}

/**
 * The same, for a command that is about to send a real credential.
 *
 * Refusing here happens before any sign-in. Connecting anyway would hand the
 * credential to whichever certificate turned up.
 */
export function requireCertificateName(
  profile: { readonly gateway: string; readonly gateways: readonly string[] },
  override?: string,
): string {
  const name = resolveCertificateName(profile.gateways, override);
  if (name) return name;
  throw new OpenP2SError(`cannot work out the certificate name for ${profile.gateway}`, {
    hint:
      'OpenP2S checks the name on the gateway certificate, and can only work it\n' +
      'out for standard Azure gateway hostnames under vpn.azure.com.\n\n' +
      'Run: openp2s probe <profile>\n' +
      'It reports the name the gateway presents. Confirm that name with your VPN\n' +
      'administrator, then pass it with --verify-name.',
  });
}
