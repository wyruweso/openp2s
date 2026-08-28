/**
 * Privilege escalation for the two operations that genuinely need root:
 * running openvpn (creates the tun device, installs routes) and running
 * resolvectl (rewrites per-link DNS).
 *
 * OpenP2S runs unprivileged; `sudo openp2s` is refused (see paths.ts). Keeping
 * the XML parser in particular out of a root process is worth the plumbing.
 *
 * Commands are resolved to absolute paths first, so what runs with elevation
 * is what this process located rather than whatever sudo's PATH finds.
 *
 * Nothing crosses the boundary in the environment. That also keeps sudo seeing
 * the real binary, so a restricted sudoers rule naming it can match.
 */

import { accessSync, constants as fsConstants } from 'node:fs';
import { delimiter, isAbsolute, join } from 'node:path';
import { OpenP2SError } from '../errors.ts';

export interface ElevationPlan {
  /** Absolute path to the executable, or the escalation helper. */
  readonly command: string;
  readonly args: string[];
  readonly elevated: boolean;
}

export interface ElevatorOptions {
  readonly euid?: number;
  /** Path or name of the escalation helper. */
  readonly sudoPath?: string;
  /**
   * Never escalate. Does **not** drop privileges already held, so probe mode
   * does not rely on it - its guarantee is in the generated config.
   */
  readonly disabled?: boolean;
  /** PATH used to resolve executables. Injectable for tests. */
  readonly path?: string;
}

export class Elevator {
  private readonly euid: number;
  private readonly sudoPath: string;
  private readonly searchPath: string;
  private readonly disabled: boolean;

  constructor(options: ElevatorOptions = {}) {
    this.disabled = options.disabled ?? false;
    this.euid = options.euid ?? (typeof process.geteuid === 'function' ? process.geteuid() : 0);
    this.sudoPath = options.sudoPath ?? 'sudo';
    this.searchPath = options.path ?? process.env['PATH'] ?? '/usr/sbin:/usr/bin:/sbin:/bin';
  }

  /** Fails closed rather than letting sudo resolve the name itself. */
  private resolveExecutable(command: string): string {
    if (command.includes('/')) {
      if (!isAbsolute(command)) {
        throw new OpenP2SError(`refusing to run a relative path with elevation: ${command}`);
      }
      return command;
    }

    for (const dir of this.searchPath.split(delimiter)) {
      if (!dir) continue;
      const candidate = join(dir, command);
      try {
        accessSync(candidate, fsConstants.X_OK);
        return candidate;
      } catch {
        // Keep looking.
      }
    }

    throw new OpenP2SError(`${command} was not found on PATH`, {
      hint: `Searched: ${this.searchPath}`,
    });
  }

  get isRoot(): boolean {
    return this.euid === 0;
  }

  /** Build the (command, argv) pair to spawn. */
  plan(command: string, args: readonly string[]): ElevationPlan {
    const resolved = this.resolveExecutable(command);

    if (this.isRoot || this.disabled) {
      return { command: resolved, args: [...args], elevated: false };
    }

    return {
      command: this.sudoPath,
      // `--` stops sudo parsing anything after it as its own option, so a
      // hostname that happens to start with a dash cannot become a flag.
      args: ['--', resolved, ...args],
      elevated: true,
    };
  }

  /** One-line description for the CLI to explain why a password is wanted. */
  describe(): string {
    if (this.disabled) return 'running unprivileged (probe mode)';
    return this.isRoot
      ? 'running as root'
      : `escalating via ${this.sudoPath} (openvpn and resolvectl need root)`;
  }
}
