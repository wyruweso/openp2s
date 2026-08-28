/**
 * Azure VPN Client XML profile parser.
 *
 * Parsed with a real XML parser, never regular expressions, and every
 * extracted value pushed through the validators in validate.ts before it
 * reaches the normalised model.
 *
 * The schema this targets is the one Azure actually exports today:
 *
 *   <AzVpnProfile xmlns="http://schemas.datacontract.org/2004/07/">
 *     <name>                                   display name
 *     <serverlist><ServerEntry><fqdn>          gateway (may repeat)
 *     <clientauth><type>aad</type>
 *                 <aad><tenant><audience><issuer>
 *     <servervalidation><serversecret>         tls-auth key
 *                       <Cert><hash>           certificate thumbprint
 *                       <usepinnedroot>
 *     <clientconfig><dnsservers><dnsserver>
 *                   <dnssuffixes><dnssuffix>
 *                   <includeroutes>
 *     <protocolconfig><sslprotocolConfig><transportprotocol>
 *
 * Note how deeply nested the important fields are, and that <issuer> and
 * <type> each appear twice with different meanings. Lookups therefore go
 * through xmlTree.ts, which resolves an exact path first and only then falls
 * back to a *scoped* search - so a flat or older profile still parses without
 * a document-wide search picking up the wrong <issuer>.
 */

import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { basename, extname } from 'node:path';
import { ProfileError } from '../errors.ts';
import { validateServerSecret } from './serversecret.ts';
import { routeFromPrefix, type AzureVpnProfile, type AzureVpnRoute } from './types.ts';
import {
  validateAudience,
  validateCertificateThumbprint,
  validateDnsSuffix,
  validateHostname,
  validateIpAddress,
  validatePrefix,
  validateTenantUrl,
} from './validate.ts';
import {
  atPath,
  child,
  childNode,
  findFirst,
  findFirstText,
  parseBoolean,
  text,
  textAtPath,
  toArray,
  type XmlNode,
} from './xmlTree.ts';

/** Azure gateways listen for OpenVPN on 443. */
const DEFAULT_PORT = 443;

/** Guard against a profile file large enough to be a denial of service. */
const MAX_PROFILE_BYTES = 1024 * 1024;

export interface ParseOptions {
  /** Display name override; otherwise <name>, otherwise the file name. */
  readonly name?: string;
}

/**
 * Locate the profile root.
 *
 * Azure names it <AzVpnProfile>, but rather than requiring that, take the
 * first top-level element that actually looks like a profile.
 */
function findProfileRoot(document: XmlNode): XmlNode {
  const candidates: XmlNode[] = [];

  for (const [key, value] of Object.entries(document)) {
    if (key.startsWith('?') || key === '#text' || key.startsWith('@_')) continue;
    for (const entry of toArray(value)) {
      if (typeof entry === 'object' && entry !== null && !Array.isArray(entry)) {
        candidates.push(entry as XmlNode);
      }
    }
  }

  const looksLikeProfile = (node: XmlNode): boolean =>
    findFirst(node, 'fqdn', 4) !== undefined || findFirst(node, 'serversecret', 4) !== undefined;

  const found = candidates.find(looksLikeProfile);
  if (found) return found;

  if (looksLikeProfile(document)) return document;

  if (candidates.length === 0) {
    throw new ProfileError('profile contains no XML elements');
  }
  throw new ProfileError('profile is missing required element <fqdn>', {
    hint: 'This does not look like an Azure VPN Client profile.',
  });
}

/**
 * Read every gateway in <serverlist>.
 *
 * Azure profiles can list more than one gateway entry. All are kept: the
 * first becomes the primary and the rest become additional `remote` lines, so
 * OpenVPN can fail over the way the official client does.
 */
function parseGateways(root: XmlNode): string[] {
  const gateways: string[] = [];

  const serverList = childNode(root, 'serverlist');
  for (const entry of toArray(child(serverList, 'ServerEntry'))) {
    if (typeof entry !== 'object' || entry === null) continue;
    const fqdn = text(child(entry as XmlNode, 'fqdn'));
    if (fqdn) {
      const host = validateHostname(fqdn, 'fqdn');
      if (!gateways.includes(host)) gateways.push(host);
    }
  }

  if (gateways.length === 0) {
    // Older/flat profiles put <fqdn> at the top level.
    const flat = findFirstText(root, 'fqdn', 4);
    if (flat) gateways.push(validateHostname(flat, 'fqdn'));
  }

  if (gateways.length === 0) {
    throw new ProfileError('profile is missing required element <fqdn>', {
      hint: 'Export the profile again from the Azure portal (azurevpnconfig.xml).',
    });
  }

  return gateways;
}

function requireText(value: string | undefined, element: string): string {
  if (value === undefined) {
    throw new ProfileError(`profile is missing required element <${element}>`, {
      hint: 'Export the profile again from the Azure portal (azurevpnconfig.xml).',
    });
  }
  return value;
}

/** Convert a dotted netmask such as 255.255.0.0 to a prefix length. */
function netmaskToPrefixLength(mask: string): number {
  const octets = mask.split('.');
  if (octets.length !== 4) {
    throw new ProfileError(`<mask> is not a valid netmask: ${mask}`);
  }

  let bits = '';
  for (const octet of octets) {
    if (!/^[0-9]{1,3}$/.test(octet) || Number(octet) > 255) {
      throw new ProfileError(`<mask> is not a valid netmask: ${mask}`);
    }
    bits += Number(octet).toString(2).padStart(8, '0');
  }

  if (!/^1*0*$/.test(bits)) {
    throw new ProfileError(`<mask> is not a contiguous netmask: ${mask}`);
  }
  return bits.replace(/0+$/, '').length;
}

/**
 * Read <includeroutes>, tolerating the shapes seen in the wild.
 *
 * Either repeated <route><destination>/<mask></route> children, or flat
 * <includeroute> text elements. Both normalise to CIDR.
 */
function parseIncludeRoutes(clientConfig: XmlNode | undefined): AzureVpnRoute[] {
  const container = childNode(clientConfig, 'includeroutes');
  if (!container) return [];

  const routes: AzureVpnRoute[] = [];
  const seen = new Set<string>();

  const push = (raw: string, field: string): void => {
    const prefix = validatePrefix(raw, field);
    if (seen.has(prefix.cidr)) return;
    seen.add(prefix.cidr);
    routes.push(routeFromPrefix(prefix));
  };

  for (const entry of toArray(child(container, 'route'))) {
    if (typeof entry !== 'object' || entry === null) {
      const value = text(entry);
      if (value) push(value, 'route');
      continue;
    }
    const node = entry as XmlNode;
    const destination = text(child(node, 'destination')) ?? text(child(node, 'address'));
    if (!destination) {
      throw new ProfileError('<route> is missing <destination>');
    }
    const mask = text(child(node, 'mask')) ?? text(child(node, 'prefixlength'));
    if (mask === undefined) {
      push(destination, 'route');
    } else if (/^[0-9]{1,3}$/.test(mask)) {
      push(`${destination}/${mask}`, 'route');
    } else {
      push(`${destination}/${netmaskToPrefixLength(mask)}`, 'route');
    }
  }

  for (const entry of toArray(child(container, 'includeroute'))) {
    const value = text(entry);
    if (value) push(value, 'includeroute');
  }

  return routes;
}

function parseDnsServers(clientConfig: XmlNode | undefined): string[] {
  const container = childNode(clientConfig, 'dnsservers');
  if (!container) return [];

  const servers: string[] = [];
  for (const entry of toArray(child(container, 'dnsserver'))) {
    const value = text(entry);
    if (!value) continue;
    const address = validateIpAddress(value, 'dnsserver');
    if (!servers.includes(address)) servers.push(address);
  }
  return servers;
}

function parseDnsSuffixes(clientConfig: XmlNode | undefined): string[] {
  const container = childNode(clientConfig, 'dnssuffixes');
  if (!container) return [];

  const suffixes: string[] = [];
  for (const entry of toArray(child(container, 'dnssuffix'))) {
    const value = text(entry);
    if (!value) continue;
    const suffix = validateDnsSuffix(value);
    if (!suffixes.includes(suffix)) suffixes.push(suffix);
  }
  return suffixes;
}

export class AzureProfileParser {
  private readonly parser: XMLParser;

  constructor() {
    this.parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      // Keep every value a string. Type coercion would turn an all-digit
      // serversecret into a float and silently destroy it.
      parseTagValue: false,
      parseAttributeValue: false,
      trimValues: true,
      // Namespace prefixes are stripped when matching local names instead, so
      // both default-namespace and prefixed documents work.
      removeNSPrefix: false,
      // An Azure profile has no legitimate use for custom entities, and
      // processing them invites XXE and billion-laughs. fast-xml-parser does
      // not resolve external entities at all; this closes the internal path.
      processEntities: false,
    });
  }

  parse(xml: string, options: ParseOptions = {}): AzureVpnProfile {
    if (xml.length > MAX_PROFILE_BYTES) {
      throw new ProfileError(
        `profile is larger than ${MAX_PROFILE_BYTES} bytes; refusing to parse`,
      );
    }

    const validation = XMLValidator.validate(xml, { allowBooleanAttributes: true });
    if (validation !== true) {
      const { line, col, msg } = validation.err;
      throw new ProfileError(`profile is not well-formed XML at line ${line}:${col}: ${msg}`);
    }

    let document: XmlNode;
    try {
      document = this.parser.parse(xml) as XmlNode;
    } catch (error) {
      throw new ProfileError('could not parse profile XML', { cause: error });
    }

    const root = findProfileRoot(document);

    // ---- gateway -------------------------------------------------------
    const gateways = parseGateways(root);
    const gateway = gateways[0] as string;

    // ---- authentication ------------------------------------------------
    // Scope the search to <clientauth> so the <issuer> under <Cert> in
    // <servervalidation> can never be mistaken for the Entra issuer.
    const clientAuth = childNode(root, 'clientauth');
    const aad = childNode(clientAuth, 'aad');

    const authType = textAtPath(root, ['clientauth', 'type'])?.toLowerCase();
    if (authType !== undefined && authType !== 'aad') {
      throw new ProfileError(
        `profile uses "${authType}" authentication, which OpenP2S does not support`,
        {
          hint: 'OpenP2S supports Microsoft Entra ID (aad) authentication only.',
        },
      );
    }

    const tenantText = requireText(
      text(child(aad, 'tenant')) ?? findFirstText(root, 'tenant', 3),
      'tenant',
    );
    const audienceText = requireText(
      text(child(aad, 'audience')) ?? findFirstText(root, 'audience', 3),
      'audience',
    );

    const tenant = validateTenantUrl(tenantText);
    const audience = validateAudience(audienceText);
    const issuer = text(child(aad, 'issuer'));

    const explicitClientId = text(child(aad, 'clientid')) ?? text(child(root, 'clientid'));
    const clientId = explicitClientId ?? audience.clientId;
    if (!clientId) {
      throw new ProfileError(
        `profile <audience> is a URI (${audience.value}) and does not imply a client id`,
        { hint: 'Pass --client-id with the application id registered for this VPN gateway.' },
      );
    }

    // ---- server validation ---------------------------------------------
    const serverValidation = childNode(root, 'servervalidation');
    const serverSecret = validateServerSecret(
      requireText(
        text(child(serverValidation, 'serversecret')) ?? findFirstText(root, 'serversecret', 3),
        'serversecret',
      ),
    );

    const certHash = text(atPath(root, ['servervalidation', 'Cert', 'hash']));
    const thumbprint = certHash ? validateCertificateThumbprint(certHash) : undefined;
    const usePinnedRoot = parseBoolean(text(child(serverValidation, 'usepinnedroot'))) ?? false;

    // ---- transport -------------------------------------------------------
    const transport = textAtPath(root, [
      'protocolconfig',
      'sslprotocolConfig',
      'transportprotocol',
    ])?.toLowerCase();

    if (transport !== undefined && transport !== 'tcp') {
      // Azure Entra P2S runs OpenVPN over TCP 443, and --experimental-azure-compat asserts
      // TCPv4_CLIENT in the OCC string. Refuse rather than advertise a lie.
      throw new ProfileError(
        `profile requests "${transport}" transport, but Azure Entra P2S requires tcp`,
      );
    }

    // ---- client config ---------------------------------------------------
    const clientConfig = childNode(root, 'clientconfig');

    const displayName = text(child(root, 'name'));

    return {
      name: options.name ?? displayName ?? 'profile',
      gateway,
      gateways,
      port: DEFAULT_PORT,
      auth: {
        authority: tenant.authority,
        tenantId: tenant.tenantId,
        audience: audience.value,
        scope: audience.scope,
        clientId,
        ...(issuer ? { issuer } : {}),
      },
      serverSecret,
      ...(thumbprint ? { certificateThumbprint: thumbprint } : {}),
      usePinnedRoot,
      dnsServers: parseDnsServers(clientConfig),
      dnsSuffixes: parseDnsSuffixes(clientConfig),
      includeRoutes: parseIncludeRoutes(clientConfig),
    };
  }

  /** Parse from a file; the profile's own <name> wins over the file name. */
  parseFile(path: string, contents: string): AzureVpnProfile {
    const profile = this.parse(contents);
    if (profile.name !== 'profile') return profile;
    return { ...profile, name: basename(path, extname(path)) };
  }
}
