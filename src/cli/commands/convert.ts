/**
 * `openp2s convert <profile.xml> [-o out.ovpn]`
 *
 * Turn an Azure profile into a standalone OpenVPN config, without connecting.
 * The same rendering `connect` uses, so every connection exercises it:
 *
 *   inspect  = parse + show the safe fields
 *   convert  = parse + render
 *   connect  = parse + render + authenticate + run + configure the network
 *
 * The output is secret - it embeds the serversecret as the inline tls-auth key
 * - so it is written 0600 via an atomic rename and never overwrites without
 * --force. It names no credential source: the token is short-lived and must
 * not be stored. `--credentials <path>` opts into a runnable config, but
 * OpenP2S still never writes that file.
 */

import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { open, readFile, rename, stat, unlink } from 'node:fs/promises';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { OpenP2SError } from '../../errors.ts';
import { resolveCaPath } from '../../openvpn/ca.ts';
import { AZURE_USERNAME } from '../../openvpn/azureCompat.ts';
import { renderOpenVpnConfig, type CredentialDelivery } from '../../openvpn/config.ts';
import { createContext, loadProfile, type GlobalOptions } from '../context.ts';

export interface ConvertOptions extends GlobalOptions {
  /** Where to write. Defaults to <profile-name>.ovpn beside the profile. */
  readonly output?: string;
  /** Write to stdout instead of a file. Prints key material; opt-in only. */
  readonly stdout?: boolean;
  readonly force?: boolean;
  readonly ca?: string;
  /**
   * Emit `auth-user-pass <path>` so the config is runnable by hand.
   *
   * Off by default: portable output names no credential source, because
   * baking a runtime path into a file meant to be read and copied is exactly
   * the kind of environment-specific detail that makes a config non-portable.
   */
  readonly credentials?: string;
  /** Emit the Azure OCC string and peer-info. Normally unnecessary. */
  readonly azureCompat?: boolean;
  readonly verb?: number;
  readonly verifyName?: string;
  /** Embed the CA certificate, so the config does not reference a host path. */
  readonly inlineCa?: boolean;
}

/**
 * Quote a value for a shell command we print for the user to copy.
 *
 * We never execute these, but a path containing a space would produce a
 * command that silently does the wrong thing, and a security-oriented tool
 * should not hand out copy-pasteable commands that are only safe by luck.
 */
function shellQuote(value: string): string {
  if (/^[A-Za-z0-9._/:@%+=-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * Write a file that no one else can read, replacing any existing one.
 *
 * Always through a private temporary file and a rename, never by opening the
 * destination:
 *
 *   - `rename()` replaces a symlink at the destination rather than following
 *     it, so `-o link-to-something-else --force` overwrites the link, not its
 *     target. Opening the path for writing would follow it.
 *   - the rename is atomic, so a crash mid-write cannot leave a truncated
 *     config that looks complete.
 *
 * The temporary file is created O_EXCL at 0600 in the destination directory,
 * so it is never briefly readable and the rename never crosses a filesystem.
 */
async function writePrivateAtomic(outputPath: string, contents: string): Promise<void> {
  const temporary = join(
    dirname(outputPath),
    `.${basename(outputPath)}.${randomBytes(6).toString('hex')}.tmp`,
  );

  let handle;
  try {
    handle = await open(
      temporary,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
  } catch (error) {
    throw new OpenP2SError(`could not create a temporary file next to ${outputPath}`, {
      cause: error,
    });
  }

  try {
    await handle.write(contents);
    await handle.chmod(0o600);
    await handle.close();
    await rename(temporary, outputPath);
  } catch (error) {
    await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw new OpenP2SError(`could not write ${outputPath}`, { cause: error });
  }
}

/** Default output path: the profile's name with an .ovpn extension. */
function defaultOutputPath(profilePath: string, profileName: string): string {
  const directory = dirname(resolve(profilePath));
  const stem =
    profileName.trim().length > 0
      ? profileName
          .trim()
          .replace(/[^A-Za-z0-9._-]+/g, '-')
          .replace(/^-+|-+$/g, '')
      : basename(profilePath, extname(profilePath));
  return join(directory, `${stem || 'profile'}.ovpn`);
}

export async function convertCommand(
  profilePath: string,
  options: ConvertOptions = {},
): Promise<number> {
  const context = createContext(options);
  const { ui } = context;

  // Options that contradict each other are a mistake, not a preference.
  if (options.stdout && options.output) {
    throw new OpenP2SError('--stdout cannot be combined with --output');
  }
  if (options.stdout && options.force) {
    throw new OpenP2SError('--force applies only when writing a file');
  }

  const profile = await loadProfile(profilePath);
  const ca = resolveCaPath(options.ca);

  // Inlining makes the config self-contained. A whole system bundle is large,
  // so say what is being embedded.
  let inlineCa: string | undefined;
  if (options.inlineCa) {
    try {
      inlineCa = await readFile(ca.path, 'utf8');
    } catch (error) {
      throw new OpenP2SError(`could not read the CA certificate at ${ca.path}`, { cause: error });
    }
    if (!ca.pinned) {
      ui.warn(
        `inlining the whole system CA bundle (${ca.path}); pass --ca with a single ` +
          'root certificate for a smaller, more specific config',
      );
    }
  }

  // Default is `external`: no credential directive at all. `--credentials`
  // opts into a runnable config that names a file the caller creates.
  const credentials: CredentialDelivery = options.credentials
    ? { kind: 'file', path: options.credentials }
    : { kind: 'external' };

  const config = renderOpenVpnConfig({
    profile,
    credentials,
    caPath: ca.path,
    standalone: true,
    ...(inlineCa ? { inlineCa } : {}),
    ...(options.verb !== undefined ? { verb: options.verb } : {}),
    ...(options.verifyName ? { verifyName: options.verifyName } : {}),
    ...(options.azureCompat ? { azureCompat: true } : {}),
  });

  // ---- stdout -----------------------------------------------------------
  if (options.stdout) {
    // stdout carries the artifact and nothing else, so `convert --stdout >
    // profile.ovpn` produces a valid file. Everything else goes to stderr;
    // ui.warn already writes there.
    //
    // The key ends up wherever this output does: terminal scrollback, a
    // recorded session, CI logs, a screen share.
    ui.warn(
      'this config contains the profile serversecret as an inline tls-auth key, ' +
        'and stdout may be captured by scrollback, session recordings or CI logs',
    );
    process.stdout.write(config);
    return 0;
  }

  // ---- file -------------------------------------------------------------
  const outputPath = options.output ?? defaultOutputPath(profilePath, profile.name);

  let exists = false;
  try {
    await stat(outputPath);
    exists = true;
  } catch (error) {
    // Only "not there" means it is safe to proceed. EACCES or ENOTDIR are
    // real problems and must not be reported as "the file does not exist".
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw new OpenP2SError(`cannot inspect ${outputPath}`, { cause: error });
    }
  }

  if (exists && !options.force) {
    throw new OpenP2SError(`refusing to overwrite ${outputPath}`, {
      hint: 'Pass --force to replace it, or -o to choose another path.',
    });
  }

  await writePrivateAtomic(outputPath, config);

  ui.ok(`Wrote ${outputPath}`);
  ui.line();
  ui.fields([
    ['Gateway', `${profile.gateway}:${profile.port}`],
    ['Mode', 'standalone OpenVPN config'],
    [
      'CA',
      inlineCa
        ? `embedded (${ca.pinned ? 'single root' : 'system bundle'})`
        : `${ca.path} (host-specific; use --inline-ca to embed it)`,
    ],
    [
      'Credentials',
      credentials.kind === 'file'
        ? `${credentials.path} (you create it)`
        : 'supplied by OpenP2S at runtime (not named in the config)',
    ],
    ['Permissions', '0600 (embeds the serversecret as inline tls-auth)'],
    [
      'Azure compat',
      options.azureCompat
        ? 'experimental-azure-compat (requires an OpenP2S OpenVPN build)'
        : 'not needed (default)',
    ],
  ]);

  ui.line();
  if (credentials.kind === 'file') {
    // In a packaged build there is no checkout, so name the binary generically.
    const openvpnPath = context.repoRoot
      ? join(context.repoRoot, 'build/openvpn/sbin/openvpn')
      : 'openvpn-openp2s';
    const quotedCredentials = shellQuote(credentials.path);

    ui.line('To run it by hand:');
    ui.line();
    // umask first: a plain redirect would be briefly world-readable.
    ui.line('  (umask 077 && \\');
    ui.line(`     printf '${AZURE_USERNAME}\\n<entra-access-token>\\n' > ${quotedCredentials})`);
    ui.line(`  sudo ${shellQuote(openvpnPath)} --config ${shellQuote(outputPath)}`);
    ui.line(`  rm -f ${quotedCredentials}   # as soon as OpenVPN exits`);
    ui.line();
    ui.line("The token must come from this profile's tenant and audience, and is");
    ui.line('short-lived. Prefer a path under $XDG_RUNTIME_DIR so it cannot outlive the');
    ui.line('session, and delete it as soon as OpenVPN has read it.');
  } else {
    ui.line('This config names no credential source, so it carries nothing');
    ui.line('runtime-specific. `openp2s connect` normally supplies the token in');
    ui.line('memory over the OpenVPN management socket; only an OpenVPN older than');
    ui.line('2.7.2 falls back to a temporary 0600 runtime file.');
    ui.line();
    ui.line('For a config you can run by hand, add --credentials <path>.');
  }

  if (options.azureCompat) {
    ui.line();
    ui.warn(
      'this config uses experimental-azure-compat, so it is no longer a generic ' +
        'OpenVPN config: it needs the OpenP2S OpenVPN, which carries that patch',
    );
  }

  if (profile.dnsServers.length > 0) {
    ui.line();
    ui.warn(
      "this config carries no DNS settings: OpenVPN cannot apply the profile's " +
        'split DNS itself. Private names may resolve through your public resolver. ' +
        '`openp2s connect` handles that part.',
    );
  }

  return 0;
}
