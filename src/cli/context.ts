/**
 * Shared command wiring.
 *
 * Every command needs the same handful of collaborators - paths, a command
 * runner, an elevator, a cache store - and building them in one place keeps
 * the command modules about their own logic rather than about construction.
 */

import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FileTokenCacheStore } from '../auth/cache/fileStore.ts';
import type { TokenCacheStore } from '../auth/cache/store.ts';
import { openInBrowser } from '../auth/browser.ts';
import type { InteractiveFlow } from '../auth/entra.ts';
import { EntraAuthenticator } from '../auth/entra.ts';
import { ProfileError } from '../errors.ts';
import { SystemdResolvedConfigurator } from '../network/systemdResolved.ts';
import { AzureProfileParser } from '../profile/parser.ts';
import type { AzureVpnProfile, EntraAuthConfig } from '../profile/types.ts';
import { SystemCommandRunner, type CommandRunner } from '../platform/exec.ts';
import { ensurePrivateDir, resolvePaths, type OpenP2SPaths } from '../platform/paths.ts';
import { Elevator } from '../platform/privilege.ts';
import { SessionStore } from '../platform/session.ts';
import { Ui } from './ui.ts';

/**
 * Repository root, found relative to this file rather than the cwd.
 *
 * Undefined in the single-executable build: there is no checkout to resolve
 * against, and `import.meta.url` is meaningless once the source has been
 * bundled into the binary. Callers fall back to the installed locations - see
 * src/openvpn/binary.ts.
 */
export function repoRoot(): string | undefined {
  try {
    const url = import.meta.url;
    if (!url) return undefined;
    return resolve(dirname(fileURLToPath(url)), '..', '..');
  } catch {
    return undefined;
  }
}

export interface GlobalOptions {
  readonly verbose?: boolean;
  readonly quiet?: boolean;
}

export interface CommandContext {
  readonly ui: Ui;
  readonly paths: OpenP2SPaths;
  readonly runner: CommandRunner;
  readonly elevator: Elevator;
  readonly session: SessionStore;
  readonly repoRoot: string | undefined;
}

export function createContext(options: GlobalOptions = {}): CommandContext {
  const ui = new Ui({
    ...(options.quiet !== undefined ? { quiet: options.quiet } : {}),
    ...(options.verbose !== undefined ? { verbose: options.verbose } : {}),
  });
  const paths = resolvePaths();

  return {
    ui,
    paths,
    runner: new SystemCommandRunner(),
    elevator: new Elevator(),
    session: new SessionStore(paths.sessionFile),
    repoRoot: repoRoot(),
  };
}

export function createDnsConfigurator(context: CommandContext): SystemdResolvedConfigurator {
  return new SystemdResolvedConfigurator({
    runner: context.runner,
    elevator: context.elevator,
  });
}

export function createCacheStore(context: CommandContext): TokenCacheStore {
  ensurePrivateDir(context.paths.stateDir);
  ensurePrivateDir(context.paths.cacheDir);
  return new FileTokenCacheStore({ directory: context.paths.cacheDir });
}

export interface AuthOverrides {
  /** Which interactive flow to use. Omitted means DEFAULT_FLOW ('browser'). */
  readonly flow?: InteractiveFlow;
  readonly clientId?: string | undefined;
  readonly scope?: string | undefined;
}

/**
 * Work out which Entra identity a command is talking about.
 *
 * Every command that touches the token cache must derive this the same way,
 * because the cache key is (authority, audience, clientId). If `login` applied
 * a `--client-id` override and `status` did not, they would compute different
 * keys and `status` would report no session for one that exists - and `clear`
 * would fail to delete it. One function, used by login, status, clear and
 * connect, makes that impossible.
 */
export function resolveAuthIdentity(
  profile: AzureVpnProfile,
  overrides: AuthOverrides = {},
): EntraAuthConfig {
  return {
    ...profile.auth,
    ...(overrides.clientId ? { clientId: overrides.clientId } : {}),
    ...(overrides.scope ? { scope: overrides.scope } : {}),
  };
}

export function createAuthenticator(
  context: CommandContext,
  profile: AzureVpnProfile,
  overrides: AuthOverrides = {},
): EntraAuthenticator {
  return new EntraAuthenticator({
    auth: resolveAuthIdentity(profile, overrides),
    store: createCacheStore(context),
    ...(overrides.flow ? { flow: overrides.flow } : {}),
    onDeviceCode: (prompt) => context.ui.deviceCode(prompt.verificationUri, prompt.userCode),
    onDebug: (message) => context.ui.debug(message),
    // Open first, announce second: openInBrowser() throws when nothing here
    // can open a URL, and "continue in your browser" would be a lie.
    openBrowser: async (url) => {
      await openInBrowser(url);
      context.ui.browserPrompt();
    },
  });
}

/** Read and parse a profile, with a readable error when the file is missing. */
export async function loadProfile(path: string): Promise<AzureVpnProfile> {
  let contents: string;
  try {
    contents = await readFile(path, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    throw new ProfileError(
      code === 'ENOENT' ? `profile not found: ${path}` : `could not read profile: ${path}`,
      {
        cause: error,
        ...(code === 'ENOENT'
          ? {
              hint: 'Download azurevpnconfig.xml from the Azure portal (VPN gateway > Point-to-site configuration).',
            }
          : {}),
      },
    );
  }

  return new AzureProfileParser().parseFile(path, contents);
}
