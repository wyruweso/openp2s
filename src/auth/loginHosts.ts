/**
 * The Microsoft login endpoints OpenP2S will talk to.
 *
 * One list, because two would drift: the profile parser decides where an
 * authority may point and the browser opener what may reach the desktop's URL
 * handler, and those have to be the same set for a profile that imports to be
 * one that can sign in.
 */
const ENTRA_LOGIN_HOSTS: ReadonlySet<string> = new Set([
  'login.microsoftonline.com',
  'login.microsoftonline.us',
  'login.partner.microsoftonline.cn',
  // Azure Germany P2S profiles name login-us; the rest are older forms, still
  // found in profiles issued before the sovereign clouds were renamed.
  'login-us.microsoftonline.de',
  'login.microsoftonline.de',
  'login.usgovcloudapi.net',
  'login.chinacloudapi.cn',
]);

export function isEntraLoginHost(hostname: string): boolean {
  return ENTRA_LOGIN_HOSTS.has(hostname.toLowerCase());
}

export function entraLoginHosts(): string[] {
  return [...ENTRA_LOGIN_HOSTS];
}
