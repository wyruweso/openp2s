/**
 * Handing a URL to the user's browser.
 *
 * Separate from the authenticator on purpose: nothing in src/auth/entra.ts may
 * spawn a process, so a test reaching the browser flow cannot open real tabs
 * on whoever is running the suite.
 */

import { spawn } from 'node:child_process';
import { AuthError } from '../errors.ts';
import { entraLoginHosts, isEntraLoginHost } from './loginHosts.ts';

/**
 * The URL comes from MSAL, not from the profile, so this is defence in depth -
 * but it is about to reach whatever the desktop registered for https.
 */
export function validateAuthenticationUrl(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AuthError('refusing to open a malformed authentication URL');
  }

  if (parsed.protocol !== 'https:') {
    throw new AuthError(`refusing to open a non-https authentication URL: ${parsed.protocol}//`);
  }
  // Browsers have historically displayed user:password@host in ways that hide
  // where the request is going.
  if (parsed.username || parsed.password) {
    throw new AuthError('refusing to open an authentication URL carrying credentials');
  }
  // WHATWG URL erases :443, so anything left is non-standard - something other
  // than Entra on a name that parses as Microsoft's.
  if (parsed.port !== '') {
    throw new AuthError(`refusing to open an authentication URL on port ${parsed.port}`);
  }
  if (!isEntraLoginHost(parsed.hostname)) {
    throw new AuthError(`refusing to open an unexpected authentication host: ${parsed.hostname}`, {
      hint: `OpenP2S opens sign-in only at: ${entraLoginHosts().join(', ')}`,
    });
  }

  return parsed;
}

/** xdg-open covers any freedesktop desktop; the rest are for those without. */
const OPENERS: ReadonlyArray<{
  readonly command: string;
  readonly args: (url: string) => string[];
}> = [
  { command: 'xdg-open', args: (url) => [url] },
  { command: 'gio', args: (url) => ['open', url] },
  { command: 'x-www-browser', args: (url) => [url] },
  { command: 'sensible-browser', args: (url) => [url] },
];

/** The slice of a spawned child used here, so tests can supply one. */
export interface OpenerProcess {
  once(event: 'error', listener: () => void): unknown;
  once(event: 'spawn', listener: () => void): unknown;
  once(event: 'exit', listener: (code: number | null) => void): unknown;
  unref(): void;
}

export type Spawner = (command: string, args: string[]) => OpenerProcess;

const spawnOpener: Spawner = (command, args) =>
  // Detached with stdio discarded: the browser outlives this process, and
  // anything it writes to stdout would corrupt `--json` output.
  spawn(command, args, { stdio: 'ignore', detached: true });

/**
 * How long an opener gets to fail before it is believed.
 *
 * Starting is not opening: on a headless machine xdg-open is usually present,
 * spawns cleanly, and only then exits non-zero for want of a handler. Waiting
 * for that exit is what separates it from one that worked.
 */
export const OPENER_SETTLE_MS = 400;

export interface OpenOptions {
  readonly spawner?: Spawner;
  readonly settleMs?: number;
}

/** False - try the next candidate - if it is absent, fails to start, or exits non-zero. */
function tryOpener(
  spawner: Spawner,
  command: string,
  args: string[],
  settleMs: number,
): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const done = (ok: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(ok);
    };

    try {
      const child = spawner(command, args);
      // A missing command surfaces as an 'error' event, not a throw.
      child.once('error', () => done(false));
      // xdg-open hands the URL over and exits 0; anything else could not.
      child.once('exit', (code) => done(code === 0));
      child.once('spawn', () => {
        child.unref();
        // Still running: an opener that execs the browser in place.
        timer = setTimeout(() => done(true), settleMs);
      });
    } catch {
      done(false);
    }
  });
}

/**
 * Open `url` in a browser on this machine, or fail.
 *
 * Failing is the point: the redirect goes to a listener on 127.0.0.1 here, so
 * a browser elsewhere can never deliver the code, and printing the URL would
 * hang until the sign-in expired with nothing to say why.
 *
 * Success here still is not a signed-in user - the real signal is MSAL
 * receiving the callback - only that waiting for one is worthwhile.
 */
export async function openInBrowser(url: string, options: OpenOptions = {}): Promise<void> {
  const validated = validateAuthenticationUrl(url);
  const spawner = options.spawner ?? spawnOpener;
  const settleMs = options.settleMs ?? OPENER_SETTLE_MS;

  for (const opener of OPENERS) {
    if (await tryOpener(spawner, opener.command, opener.args(validated.href), settleMs)) return;
  }

  throw new AuthError('could not open a browser on this machine', {
    hint:
      'Browser sign-in needs a browser here: the reply goes to a listener on\n' +
      '127.0.0.1, so opening the link elsewhere cannot complete it.\n' +
      'On a headless machine, run again with --auth device-code.',
  });
}
