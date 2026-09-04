/**
 * Terminal output.
 *
 * All user-facing writing goes through here so that redaction, colour
 * handling and quiet mode are decided once. Nothing in OpenP2S calls
 * console.log directly.
 */

import { redact } from '../errors.ts';

const isTty = process.stdout.isTTY === true;

/**
 * Respect NO_COLOR and a non-tty stdout.
 *
 * Colour is decoration; if output is being piped into a file or a log
 * collector, escape codes are just noise.
 */
const useColour = isTty && !process.env['NO_COLOR'] && process.env['TERM'] !== 'dumb';

const style = {
  reset: useColour ? '\x1b[0m' : '',
  bold: useColour ? '\x1b[1m' : '',
  dim: useColour ? '\x1b[2m' : '',
  green: useColour ? '\x1b[32m' : '',
  yellow: useColour ? '\x1b[33m' : '',
  red: useColour ? '\x1b[31m' : '',
  cyan: useColour ? '\x1b[36m' : '',
};

export interface UiOptions {
  readonly quiet?: boolean;
  readonly verbose?: boolean;
}

export class Ui {
  private readonly quiet: boolean;
  private readonly verboseMode: boolean;

  constructor(options: UiOptions = {}) {
    this.quiet = options.quiet ?? false;
    this.verboseMode = options.verbose ?? false;
  }

  get isVerbose(): boolean {
    return this.verboseMode;
  }

  /** Plain line to stdout. Redacted, always. */
  line(text = ''): void {
    if (this.quiet) return;
    process.stdout.write(`${redact(text)}\n`);
  }

  /** A completed step. */
  ok(text: string): void {
    if (this.quiet) return;
    process.stdout.write(`${style.green}✓${style.reset} ${redact(text)}\n`);
  }

  /** Something worth knowing that did not stop the operation. */
  warn(text: string): void {
    process.stderr.write(`${style.yellow}warning:${style.reset} ${redact(text)}\n`);
  }

  /** A failure. Written to stderr so it survives stdout redirection. */
  error(text: string): void {
    process.stderr.write(`${style.red}error:${style.reset} ${redact(text)}\n`);
  }

  /** Remediation advice printed under an error. */
  hint(text: string): void {
    process.stderr.write(`${style.dim}${redact(text)}${style.reset}\n`);
  }

  /** Diagnostics, shown only with --verbose. */
  debug(text: string): void {
    if (!this.verboseMode || this.quiet) return;
    process.stderr.write(`${style.dim}${redact(text)}${style.reset}\n`);
  }

  heading(text: string): void {
    if (this.quiet) return;
    process.stdout.write(`${style.bold}${redact(text)}${style.reset}\n`);
  }

  /**
   * Aligned "Label: value" rows, as used by inspect and status.
   *
   * Undefined values are skipped rather than printed as "undefined"; empty
   * arrays render as an explicit "(none)" so the reader can tell the
   * difference between "not configured" and "we forgot to look".
   */
  fields(rows: ReadonlyArray<readonly [string, string | readonly string[] | undefined]>): void {
    if (this.quiet) return;

    const visible = rows.filter(([, value]) => value !== undefined);
    const width = Math.max(0, ...visible.map(([label]) => label.length));

    for (const [label, value] of visible) {
      const padded = `${label}:`.padEnd(width + 2);

      if (Array.isArray(value)) {
        if (value.length === 0) {
          process.stdout.write(`${padded}${style.dim}(none)${style.reset}\n`);
          continue;
        }
        process.stdout.write(`${padded}${redact(String(value[0]))}\n`);
        for (const extra of value.slice(1)) {
          process.stdout.write(`${' '.repeat(width + 2)}${redact(String(extra))}\n`);
        }
      } else {
        process.stdout.write(`${padded}${redact(String(value))}\n`);
      }
    }
  }

  /**
   * The browser sign-in prompt.
   *
   * The authorization URL is not printed: the browser is already open, and the
   * reply can only reach the listener on this machine, so it would be live
   * OAuth parameters in a log for no gain.
   *
   * stderr, like deviceCode() below: commands with a `--json` mode promise
   * stdout carries exactly one document, and a cold cache must not break that.
   */
  browserPrompt(): void {
    const out = (text: string): void => {
      process.stderr.write(text);
    };
    out('\n');
    out(`${style.bold}Continue the sign-in in your browser.${style.reset}\n\n`);
    out(`${style.dim}Waiting for sign-in...${style.reset}\n`);
  }

  /**
   * The device code prompt.
   *
   * Given its own block with blank lines around it because the user has to
   * read a code off the screen and type it somewhere else, often on a phone.
   *
   * Written to stderr, not stdout. It is an interactive prompt, and commands
   * with a `--json` mode promise that stdout carries exactly one document;
   * a cold token cache must not be able to break `openp2s probe --json | jq`.
   */
  deviceCode(verificationUri: string, userCode: string): void {
    const out = (text: string): void => {
      process.stderr.write(text);
    };
    out('\n');
    out(`${style.bold}Authentication required.${style.reset}\n\n`);
    out('Open:\n');
    out(`  ${style.cyan}${verificationUri}${style.reset}\n\n`);
    out('Code:\n');
    out(`  ${style.bold}${userCode}${style.reset}\n\n`);
    out(`${style.dim}Waiting for authentication...${style.reset}\n`);
  }
}
