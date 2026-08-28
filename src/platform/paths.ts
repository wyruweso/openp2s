/**
 * Where OpenP2S keeps its files, and who owns them.
 *
 * Two storage tiers, with a deliberate split:
 *
 *   runtime  /run/user/$UID/openp2s   0700, tmpfs
 *            The Entra access token, the generated OpenVPN config (which
 *            embeds the serversecret), and the session record. tmpfs means
 *            these vanish on logout and reboot without us having to be
 *            careful, and never touch a disk that could be imaged later.
 *
 *   state    ~/.local/state/openp2s   0700, persistent
 *            The MSAL token cache only. Survives reboot so that `connect`
 *            can reuse a login, and nothing else lives here.
 *
 * ## OpenP2S does not run as root
 *
 * `sudo openp2s` is refused. Serving another user's directories as root means
 * creating and inspecting paths that user controls, and a controlled path can
 * be a symlink to one they do not own - which a chown would then hand them.
 * There is no chown here, because root never touches a user's directory.
 *
 * Running genuinely as root, with no sudo involved, is allowed; those are then
 * root's own directories.
 */

import { constants, lstatSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { OpenP2SError } from '../errors.ts';

export interface UserIdentity {
  readonly uid: number;
  readonly gid: number;
  readonly username: string;
  readonly home: string;
}

interface PasswdEntry {
  readonly username: string;
  readonly uid: number;
  readonly gid: number;
  readonly home: string;
}

/** Node has no getpwuid binding, and a native dependency is not worth it. */
function lookupPasswd(uid: number): PasswdEntry | undefined {
  let contents: string;
  try {
    contents = readFileSync('/etc/passwd', 'utf8');
  } catch {
    return undefined;
  }

  for (const line of contents.split('\n')) {
    const fields = line.split(':');
    if (fields.length < 6) continue;
    if (Number(fields[2]) !== uid) continue;
    return {
      username: fields[0] ?? String(uid),
      uid,
      gid: Number(fields[3] ?? uid),
      home: fields[5] ?? '/',
    };
  }
  return undefined;
}

/** Always our own user. SUDO_UID is read only to recognise sudo and refuse it. */
export interface IdentityOverrides {
  /** Effective uid. Injectable so the sudo branch is testable unprivileged. */
  readonly euid?: number;
  readonly egid?: number;
}

export function resolveUserIdentity(
  env: NodeJS.ProcessEnv = process.env,
  overrides: IdentityOverrides = {},
): UserIdentity {
  const euid = overrides.euid ?? (typeof process.geteuid === 'function' ? process.geteuid() : 0);
  const sudoUid = env['SUDO_UID'] ? Number(env['SUDO_UID']) : Number.NaN;

  // See the note at the top of this file.
  if (euid === 0 && Number.isInteger(sudoUid) && sudoUid > 0) {
    const entry = lookupPasswd(sudoUid);
    throw new OpenP2SError('do not run openp2s under sudo', {
      hint:
        `Run it as ${entry?.username ?? 'yourself'}:\n\n` +
        '  openp2s connect <profile>.xml\n\n' +
        'OpenP2S asks for elevation only where it is needed - starting openvpn\n' +
        'and configuring systemd-resolved - and keeps your token cache and\n' +
        'runtime files under your own account.',
    });
  }

  const uid = euid;
  const gid = overrides.egid ?? (typeof process.getegid === 'function' ? process.getegid() : 0);
  const entry = lookupPasswd(uid);
  return {
    uid,
    gid,
    username: entry?.username ?? env['USER'] ?? String(uid),
    home: entry?.home ?? homedir(),
  };
}

export interface OpenP2SPaths {
  readonly user: UserIdentity;
  /** tmpfs, 0700: tokens, generated config, session record. */
  readonly runtimeDir: string;
  /** Persistent, 0700: MSAL token cache only. */
  readonly stateDir: string;
  readonly cacheDir: string;
  readonly sessionFile: string;
  /** Exclusive lock: one OpenP2S connection per machine. */
  readonly lockFile: string;
  readonly credentialsFile: string;
  readonly managementSocket: string;
  readonly configFile: string;
  readonly logFile: string;
}

export function resolvePaths(
  env: NodeJS.ProcessEnv = process.env,
  overrides: IdentityOverrides = {},
): OpenP2SPaths {
  const user = resolveUserIdentity(env, overrides);

  // XDG defines these as absolute; a relative value would follow the cwd.
  const absolute = (value: string | undefined): string | undefined =>
    value && isAbsolute(value) ? value : undefined;

  const runtimeBase = absolute(env['XDG_RUNTIME_DIR']) ?? `/run/user/${user.uid}`;
  const stateBase = absolute(env['XDG_STATE_HOME']) ?? join(user.home, '.local', 'state');

  const runtimeDir = join(runtimeBase, 'openp2s');
  const stateDir = join(stateBase, 'openp2s');

  return {
    user,
    runtimeDir,
    stateDir,
    cacheDir: join(stateDir, 'cache'),
    sessionFile: join(runtimeDir, 'session.json'),
    lockFile: join(runtimeDir, 'connect.lock'),
    credentialsFile: join(runtimeDir, 'credentials'),
    managementSocket: join(runtimeDir, 'mgmt.sock'),
    configFile: join(runtimeDir, 'openvpn.conf'),
    logFile: join(runtimeDir, 'openvpn.log'),
  };
}

/**
 * Create a directory 0700, owned by the real user.
 *
 * mkdir's mode argument is masked by umask, so the mode is asserted after the
 * fact instead of assumed. If a directory already exists with looser
 * permissions we refuse rather than silently trusting it - a world-readable
 * runtime directory would expose the access token.
 */
export function ensurePrivateDir(path: string): void {
  try {
    mkdirSync(path, { recursive: true, mode: 0o700 });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // /run/user/$UID is created by pam_systemd at login. On a headless or
    // minimal system, or under a service account, it may simply not exist,
    // and mkdir then fails on the root-owned parent. Say so, rather than
    // surfacing a bare EACCES.
    if (code === 'EACCES' || code === 'ENOENT' || code === 'EROFS') {
      throw new OpenP2SError(`cannot create the runtime directory ${path}`, {
        cause: error,
        hint:
          'OpenP2S keeps the generated OpenVPN config and its management\n' +
          'socket there, and expects a private, tmpfs-backed directory.\n' +
          'If /run/user/$UID does not exist (common on headless systems or\n' +
          'under a service account), start a proper login session, or set\n' +
          'XDG_RUNTIME_DIR to a directory you own with mode 0700.',
      });
    }
    throw error;
  }

  // lstat, not stat: validate the path itself, not what it points at.
  let stats;
  try {
    stats = lstatSync(path);
  } catch (error) {
    throw new OpenP2SError(`cannot stat ${path}`, { cause: error });
  }

  if (stats.isSymbolicLink()) {
    throw new OpenP2SError(`${path} is a symbolic link`, {
      hint:
        'OpenP2S keeps credentials here and will not follow a link to somewhere\n' +
        'else. Remove it, or point XDG_RUNTIME_DIR at a real directory you own.',
    });
  }

  const mode = stats.mode & 0o777;
  if (mode & (constants.S_IRWXG | constants.S_IRWXO)) {
    throw new OpenP2SError(
      `${path} is group- or world-accessible (mode ${mode.toString(8).padStart(4, '0')})`,
      {
        hint: `OpenP2S stores credentials here. Fix it with: chmod 700 ${path}`,
      },
    );
  }

  // No chown: we only ever create directories for ourselves, and chown()
  // follows symlinks.
}

/**
 * A throwaway namespace for one probe run, so a probe never contends with a
 * live connect - or its cleanup deletes a running tunnel's artifacts.
 *
 * The token cache is deliberately not redirected. The directory name is short
 * because the management socket lives inside it and sun_path is 108 bytes.
 */
export function probePaths(base: OpenP2SPaths, id: string): OpenP2SPaths {
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(id)) {
    throw new OpenP2SError(`invalid probe id ${JSON.stringify(id)}`);
  }
  const dir = join(base.runtimeDir, 'probe', id);
  return {
    ...base,
    runtimeDir: dir,
    // Written to only if something goes wrong with the invariants below; a
    // probe never records a session.
    sessionFile: join(dir, 'session.json'),
    lockFile: join(dir, 'probe.lock'),
    credentialsFile: join(dir, 'credentials'),
    managementSocket: join(dir, 'm.sock'),
    configFile: join(dir, 'openvpn.conf'),
    logFile: join(dir, 'openvpn.log'),
  };
}
