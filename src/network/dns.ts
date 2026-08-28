/**
 * DNS configuration, behind a platform-neutral interface.
 *
 * A tunnel can come up perfectly and still leave Azure Virtual Desktop failing
 * with "Access is forbidden from this network" - because corporate DNS
 * resolves the AVD name to a private address reachable through the tunnel,
 * while public DNS returns the public endpoint, which is then refused.
 */

/**
 * The route-only domain matching everything.
 *
 * Not used by default: we know the exact suffixes from the profile, and
 * sending every query to the corporate resolver would leak the user's whole
 * browsing history to their employer. Available on request.
 */
export const ALL_DOMAINS = '~.';

export interface DnsPlan {
  readonly interfaceName: string;
  readonly servers: readonly string[];
  readonly domains: readonly string[];
  /** Always false for split DNS. */
  readonly defaultRoute: boolean;
}

export interface DnsConfigureOptions {
  /**
   * Route *all* DNS through the VPN (`~.`).
   *
   * Only ever set from an explicit user request or an explicit profile
   * instruction - never inferred from the mere presence of a DNS server.
   */
  readonly allDomains?: boolean;
}

export interface DnsConfigurator {
  /**
   * Point `interfaceName` at the given servers, for the given domains only.
   *
   * Implementations must configure *split* DNS: the VPN's resolvers handle
   * the listed domains and nothing else.
   */
  configure(
    interfaceName: string,
    dnsServers: readonly string[],
    domains: readonly string[],
    options?: DnsConfigureOptions,
  ): Promise<void>;

  /** Undo everything configure() did for this interface. */
  revert(interfaceName: string): Promise<void>;
}

/**
 * Convert an Azure DNS suffix into a systemd-resolved routing domain.
 *
 *   wvd.microsoft.com   ->  ~wvd.microsoft.com
 *   .wvd.microsoft.com  ->  ~wvd.microsoft.com
 *
 * The `~` prefix is what makes the domain *route-only*: queries for names
 * under it go to this link's servers, but the link does not become a
 * candidate for anything else. Without the tilde, systemd-resolved treats the
 * entry as a search domain and the split-DNS property is lost.
 */
export function toRoutingDomain(suffix: string): string {
  const trimmed = suffix
    .trim()
    .replace(/^[.~]+/, '')
    .replace(/\.+$/, '');
  return `~${trimmed}`;
}

export function toRoutingDomains(suffixes: readonly string[]): string[] {
  const domains: string[] = [];
  for (const suffix of suffixes) {
    const domain = toRoutingDomain(suffix);
    if (domain !== '~' && !domains.includes(domain)) {
      domains.push(domain);
    }
  }
  return domains;
}

/**
 * Reject an interface name that is not a plausible kernel interface.
 *
 * The name comes from our own OpenVPN process, but it becomes an argument to
 * a privileged command, so it is checked rather than trusted. IFNAMSIZ caps
 * this at 15 characters.
 */
export function isValidInterfaceName(name: string): boolean {
  return /^[A-Za-z0-9_.-]{1,15}$/.test(name) && name !== '.' && name !== '..';
}

/**
 * Warn when DNS servers are configured with nothing routed to them.
 *
 * This is the Private Link failure mode: the tunnel is healthy, the corporate
 * resolver is attached to the link, and queries still go to public DNS
 * because no routing domain sends them anywhere else. The public answer wins,
 * the browser gets the public endpoint, and the service refuses with
 * "Access is forbidden from this network".
 *
 * Diagnosed by the oal/microsoft-azure-vpn-ubuntu-26.04-lts-fix project.
 */
export function privateLinkWarning(
  servers: readonly string[],
  domains: readonly string[],
  allDomains: boolean,
): string | undefined {
  if (servers.length === 0 || allDomains || domains.length > 0) {
    return undefined;
  }
  return (
    'the profile supplies DNS servers but no DNS suffixes, so nothing is routed ' +
    'to them. Private Link names may still resolve through your public DNS and ' +
    'return public addresses. Pass --dns-domain <suffix> to route specific names, ' +
    'or --dns-all to send every query over the VPN.'
  );
}
