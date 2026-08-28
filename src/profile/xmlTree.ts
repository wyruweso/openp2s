/**
 * A small navigation layer over the parsed XML document.
 *
 * Real Azure profiles nest things several levels deep and in places that are
 * not obvious from the field names:
 *
 *   <serverlist><ServerEntry><fqdn>          the gateway
 *   <clientauth><aad><tenant>                the Entra authority
 *   <servervalidation><serversecret>         the tls-auth key
 *   <servervalidation><Cert><hash>           a certificate thumbprint
 *
 * Older and hand-written profiles put some of these at the top level instead,
 * so every lookup here tries an exact path first and then falls back to a
 * scoped search. Searching is deliberately *scoped* rather than global,
 * because several element names are reused at different depths with different
 * meanings - <issuer> appears under both <aad> and <Cert>, and <type> appears
 * under both <clientauth> and <servervalidation>. A naive document-wide
 * search for those would silently pick the wrong one.
 */

export type XmlNode = Record<string, unknown>;

/** Strip any namespace prefix: "azvpn:fqdn" -> "fqdn". */
export function localName(key: string): string {
  const colon = key.indexOf(':');
  return colon === -1 ? key : key.slice(colon + 1);
}

function isElement(value: unknown): value is XmlNode {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Wrap a value that may be absent, single, or repeated into an array. */
export function toArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * Coerce a leaf to a trimmed string.
 *
 * An element written as <fqdn/> parses to an empty object rather than a
 * string, and an element with attributes keeps its text under "#text".
 */
export function text(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (isElement(value) && '#text' in value) {
    return text(value['#text']);
  }
  return undefined;
}

/** Direct child by local name, case-insensitive. Azure mixes casing. */
export function child(node: XmlNode | undefined, name: string): unknown {
  if (!node) return undefined;
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(node)) {
    if (key.startsWith('@_') || key === '#text') continue;
    if (localName(key).toLowerCase() === wanted) {
      return value;
    }
  }
  return undefined;
}

/** Direct child element (not a leaf). */
export function childNode(node: XmlNode | undefined, name: string): XmlNode | undefined {
  const value = child(node, name);
  if (Array.isArray(value)) {
    const first = value.find(isElement);
    return first;
  }
  return isElement(value) ? value : undefined;
}

/**
 * Follow an exact path of local names.
 *
 * Returns the node at the end of the path, or undefined if any step is
 * missing. Used for the lookups where we know exactly where the value should
 * live in a current Azure export.
 */
export function atPath(root: XmlNode | undefined, path: readonly string[]): unknown {
  let current: unknown = root;
  for (const step of path) {
    if (!isElement(current)) return undefined;
    current = child(current, step);
    if (Array.isArray(current)) {
      current = current.find((entry) => entry !== undefined);
    }
  }
  return current;
}

/** Text at an exact path. */
export function textAtPath(root: XmlNode | undefined, path: readonly string[]): string | undefined {
  return text(atPath(root, path));
}

/**
 * Breadth-first search for the first element with this local name.
 *
 * Bounded in depth so a pathological document cannot make this expensive, and
 * only ever called with a scope node, never the whole document, for names
 * that are reused at different depths.
 */
export function findFirst(root: XmlNode | undefined, name: string, maxDepth = 6): unknown {
  if (!root) return undefined;

  let frontier: XmlNode[] = [root];
  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth += 1) {
    const next: XmlNode[] = [];

    for (const node of frontier) {
      const direct = child(node, name);
      if (direct !== undefined) {
        return Array.isArray(direct) ? direct.find((entry) => entry !== undefined) : direct;
      }
      for (const [key, value] of Object.entries(node)) {
        if (key.startsWith('@_') || key === '#text') continue;
        for (const entry of toArray(value)) {
          if (isElement(entry)) next.push(entry);
        }
      }
    }
    frontier = next;
  }
  return undefined;
}

/** Text of the first element with this local name, searched from `root`. */
export function findFirstText(
  root: XmlNode | undefined,
  name: string,
  maxDepth = 6,
): string | undefined {
  return text(findFirst(root, name, maxDepth));
}

/**
 * Resolve a value that may be at a known path or, in older profiles, higher up.
 *
 * The exact path always wins. The fallback search is rooted at `fallbackScope`
 * (defaulting to the document root) so it stays scoped.
 */
export function resolveText(
  root: XmlNode,
  path: readonly string[],
  fallbackName: string,
  fallbackScope?: XmlNode,
): string | undefined {
  return textAtPath(root, path) ?? findFirstText(fallbackScope ?? root, fallbackName);
}

/** Parse an Azure boolean-ish element ("true"/"false"/"1"/"0"). */
export function parseBoolean(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  const normalised = value.trim().toLowerCase();
  if (normalised === 'true' || normalised === '1') return true;
  if (normalised === 'false' || normalised === '0') return false;
  return undefined;
}
