/**
 * Command execution behind a narrow, mockable interface.
 *
 * Two rules hold everywhere in OpenP2S:
 *
 *   1. No shell. Ever. Commands are (executable, argv[]) pairs passed straight
 *      to execve. Values that originate in the Azure XML profile - gateway
 *      hostnames, DNS server addresses, search domains - are attacker-
 *      influenced input, and the only durable defence against injection is
 *      never to build a command string in the first place.
 *   2. Everything goes through `CommandRunner`, so tests can assert on the
 *      exact argv a component would have executed without running anything.
 */

import { spawn } from 'node:child_process';
import { OpenP2SError } from '../errors.ts';

export interface CommandResult {
  readonly code: number;
  /** `code` is -1 for every signal, so the signal itself is reported too. */
  readonly signal?: NodeJS.Signals | undefined;
  readonly stdout: string;
  readonly stderr: string;
}

export interface RunOptions {
  /** Milliseconds before the child is killed. A timeout always rejects. */
  readonly timeoutMs?: number;
  /** Layered over the fully inherited environment; nothing is filtered. */
  readonly env?: Readonly<Record<string, string>>;
  /** Reject on a non-zero exit code. Exit codes only - never a timeout. */
  readonly check?: boolean;
}

export interface CommandRunner {
  run(command: string, args: readonly string[], options?: RunOptions): Promise<CommandResult>;
}

/**
 * Reject arguments that cannot be passed through execve intact.
 *
 * A NUL byte would silently truncate an argument, which is exactly the kind
 * of quiet mismatch between "what we validated" and "what ran" that turns a
 * parser bug into a security bug.
 */
function assertExecSafe(value: string, what: string): void {
  if (value.includes('\0')) {
    throw new OpenP2SError(`refusing to execute: ${what} contains a NUL byte`);
  }
}

/** Runs commands for real, via execve with no shell involved. */
export class SystemCommandRunner implements CommandRunner {
  async run(
    command: string,
    args: readonly string[],
    options: RunOptions = {},
  ): Promise<CommandResult> {
    assertExecSafe(command, 'command');
    for (const arg of args) {
      assertExecSafe(arg, 'argument');
    }

    const timeoutMs = options.timeoutMs ?? 15_000;
    // setTimeout treats NaN and negatives as 0; Infinity disables it.
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new OpenP2SError(
        `refusing to execute ${command}: timeout must be a positive finite number of milliseconds`,
      );
    }

    return await new Promise<CommandResult>((resolve, reject) => {
      const child = spawn(command, [...args], {
        // Explicitly false. This is the single most important line in the file.
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, ...options.env },
      });

      let stdout = '';
      let stderr = '';
      let settled = false;
      let timedOut = false;

      const timer = setTimeout(() => {
        if (!settled) {
          timedOut = true;
          child.kill('SIGKILL');
        }
      }, timeoutMs);
      timer.unref?.();

      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => {
        stdout += chunk;
      });
      child.stderr.on('data', (chunk: string) => {
        stderr += chunk;
      });

      child.on('error', (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const notFound = (error as NodeJS.ErrnoException).code === 'ENOENT';
        reject(
          new OpenP2SError(`failed to execute ${command}`, {
            cause: error,
            ...(notFound ? { hint: `${command} was not found on PATH` } : {}),
          }),
        );
      });

      child.on('close', (code, signal) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const result: CommandResult = {
          code: code ?? -1,
          signal: signal ?? undefined,
          stdout,
          stderr,
        };

        // A timeout is a failure of the operation, not a result of it.
        // `check` governs exit codes and has no say here.
        if (timedOut) {
          reject(
            new OpenP2SError(`${command} timed out after ${timeoutMs} ms and was killed`, {
              hint: stderr.trim() ? `Last stderr: ${stderr.trim()}` : undefined,
            }),
          );
          return;
        }

        if (options.check && result.code !== 0) {
          const how = result.signal
            ? `was terminated by ${result.signal}`
            : `exited with code ${result.code}`;
          reject(
            new OpenP2SError(`${command} ${how}` + (stderr.trim() ? `: ${stderr.trim()}` : '')),
          );
          return;
        }
        resolve(result);
      });
    });
  }
}

/**
 * Records invocations instead of running them. Used by the DNS and lifecycle
 * tests to assert on exact argv without touching the host's network state.
 */
export type CommandResponder = (command: string, args: readonly string[]) => CommandResult | Error;

export class RecordingCommandRunner implements CommandRunner {
  readonly calls: Array<{ command: string; args: string[]; options: RunOptions }> = [];
  private readonly responder: CommandResponder;

  constructor(responder: CommandResponder = () => ({ code: 0, stdout: '', stderr: '' })) {
    this.responder = responder;
  }

  // Not `async`: this records rather than executes, so there is nothing to
  // await. The interface is still honoured by returning a promise.
  run(command: string, args: readonly string[], options: RunOptions = {}): Promise<CommandResult> {
    this.calls.push({ command, args: [...args], options });
    const outcome = this.responder(command, args);
    if (outcome instanceof Error) {
      return Promise.reject(outcome);
    }
    if (options.check && outcome.code !== 0) {
      return Promise.reject(new OpenP2SError(`${command} exited with code ${outcome.code}`));
    }
    return Promise.resolve(outcome);
  }

  /** Flattened "command arg arg" strings, for readable test assertions. */
  get commandLines(): string[] {
    return this.calls.map((call) => [call.command, ...call.args].join(' '));
  }
}
