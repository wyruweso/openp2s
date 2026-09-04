#!/usr/bin/env node
/**
 * OpenP2S command line entry point.
 *
 * Argument parsing, and a single place where errors become exit codes. The
 * commands themselves return a number and throw OpenP2SError rather than
 * exiting; the one exception is the signal handler in `connect`, which must
 * terminate the process itself once teardown has finished.
 */

import { Command, CommanderError } from 'commander';
import type { InteractiveFlow } from '../auth/entra.ts';
import { describeError, OpenP2SError } from '../errors.ts';
import { authClearCommand, authLoginCommand, authStatusCommand } from './commands/auth.ts';
import { connectCommand } from './commands/connect.ts';
import { disconnectCommand } from './commands/disconnect.ts';
import { inspectCommand } from './commands/inspect.ts';
import { convertCommand } from './commands/convert.ts';
import { doctorCommand } from './commands/doctor.ts';
import { probeCommand } from './commands/probe.ts';
import { statusCommand } from './commands/status.ts';
import { Ui } from './ui.ts';

const VERSION = '0.1.2';

/** Options every command accepts. */
interface RootOptions {
  readonly verbose?: boolean;
  readonly quiet?: boolean;
}

function rootOptions(command: Command): RootOptions {
  // Commander puts global options on the root program, not on subcommands.
  const opts: RootOptions = command.optsWithGlobals();
  return {
    ...(opts.verbose !== undefined ? { verbose: opts.verbose } : {}),
    ...(opts.quiet !== undefined ? { quiet: opts.quiet } : {}),
  };
}

/**
 * Read a numeric option.
 *
 * Commander hands options back as `unknown`, so narrow rather than coercing:
 * String() on an unexpected object would silently produce "[object Object]"
 * and then fail with a confusing message.
 */
/**
 * Validate --auth. A typo must be an error, not a silent fall back to the
 * default: the two flows differ in what a tenant permits.
 */
function parseAuthFlow(value: string): InteractiveFlow {
  if (value === 'browser' || value === 'device-code') return value;
  throw new OpenP2SError(`--auth must be "browser" or "device-code", got ${JSON.stringify(value)}`);
}

function parsePositiveInt(value: unknown, what: string, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== 'string' && typeof value !== 'number') {
    throw new OpenP2SError(`${what} must be a number`);
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new OpenP2SError(`${what} must be a positive whole number, got: ${String(value)}`);
  }
  return parsed;
}

export function buildProgram(): Command {
  const program = new Command();

  program
    .name('openp2s')
    .description(
      'Native Linux client for Azure Point-to-Site VPN with Microsoft Entra ID authentication',
    )
    .version(VERSION, '-V, --version')
    .option('-v, --verbose', 'show OpenVPN output and diagnostics')
    .option('-q, --quiet', 'suppress progress output')
    .showHelpAfterError();

  program
    .command('connect')
    .description('connect to the VPN using an Azure profile')
    .argument('<profile>', 'path to azurevpnconfig.xml')
    .option('--ca <path>', 'CA certificate to validate the gateway against')
    .option('--client-id <id>', 'override the Entra application id')
    .option(
      '--auth <flow>',
      'sign-in flow: browser (loopback + PKCE, default) or device-code for a headless machine',
    )
    .option('--scope <scope>', 'override the OAuth scope')
    .option('--openvpn-binary <path>', 'override the OpenP2S OpenVPN binary')
    .option(
      '--allow-unsupported-openvpn',
      'use an OpenVPN whose capabilities cannot be established',
    )
    .option('--timeout <seconds>', 'how long to wait for the tunnel', '90')
    .option(
      '--allow-system-trust-store',
      'connect a pinned-root profile using the system CA store (a weaker policy)',
    )
    .option(
      '--experimental-azure-compat',
      'send the Azure OCC string and peer-info; only if a gateway rejects the session',
    )
    .option('--no-dns', 'do not apply the profile DNS settings')
    .option('--dns-all', 'route every DNS query over the VPN (~.), not just profile suffixes')
    .option('--dns-domain <suffix...>', 'extra DNS suffixes to route over the VPN')
    .option(
      '--verify-name <name>',
      'require this certificate name, e.g. "*.vpn.azure.com" (see docs/SECURITY.md)',
    )
    .action(async (profile: string, options: Record<string, unknown>, command: Command) => {
      const code = await connectCommand(profile, {
        ...rootOptions(command),
        ...(typeof options['ca'] === 'string' ? { ca: options['ca'] } : {}),
        ...(typeof options['clientId'] === 'string' ? { clientId: options['clientId'] } : {}),
        ...(typeof options['auth'] === 'string'
          ? { authFlow: parseAuthFlow(options['auth']) }
          : {}),
        ...(typeof options['scope'] === 'string' ? { scope: options['scope'] } : {}),
        ...(typeof options['openvpnBinary'] === 'string'
          ? { openvpnBinary: options['openvpnBinary'] }
          : {}),
        ...(options['allowUnsupportedOpenvpn'] === true ? { allowUnsupportedOpenvpn: true } : {}),
        ...(options['allowSystemTrustStore'] === true ? { allowSystemTrustStore: true } : {}),
        ...(typeof options['verifyName'] === 'string' ? { verifyName: options['verifyName'] } : {}),
        // commander's --no-dns sets dns:false.
        ...(options['experimentalAzureCompat'] === true ? { azureCompat: true } : {}),
        ...(options['dns'] === false ? { noDns: true } : {}),
        ...(options['dnsAll'] === true ? { dnsAll: true } : {}),
        ...(Array.isArray(options['dnsDomain'])
          ? { dnsDomains: options['dnsDomain'] as string[] }
          : {}),
        timeout: parsePositiveInt(options['timeout'], '--timeout', 90),
      });
      process.exitCode = code;
    });

  program
    .command('disconnect')
    .description('disconnect the VPN and clean up')
    .option('--grace <seconds>', 'how long to wait before SIGKILL', '5')
    .action(async (options: Record<string, unknown>, command: Command) => {
      process.exitCode = await disconnectCommand({
        ...rootOptions(command),
        graceSeconds: parsePositiveInt(options['grace'], '--grace', 5),
      });
    });

  program
    .command('status')
    .description('show the current connection')
    .option('--json', 'machine-readable output')
    .action(async (options: Record<string, unknown>, command: Command) => {
      process.exitCode = await statusCommand({
        ...rootOptions(command),
        ...(options['json'] === true ? { json: true } : {}),
      });
    });

  program
    .command('inspect')
    .description('show what OpenP2S reads from a profile, without connecting')
    .argument('<profile>', 'path to azurevpnconfig.xml')
    .option('--ca <path>', 'CA certificate to report on')
    .option('--compat', 'also show Azure compatibility support and OpenVPN build provenance')
    .option('--openvpn-binary <path>', 'describe this binary rather than the default one')
    .action(async (profile: string, options: Record<string, unknown>, command: Command) => {
      process.exitCode = await inspectCommand(profile, {
        ...rootOptions(command),
        ...(typeof options['ca'] === 'string' ? { ca: options['ca'] } : {}),
        ...(options['compat'] === true ? { showCompat: true } : {}),
        ...(typeof options['openvpnBinary'] === 'string'
          ? { openvpnBinary: options['openvpnBinary'], showCompat: true }
          : {}),
      });
    });

  program
    .command('convert')
    .description('convert an Azure profile into a standalone OpenVPN config')
    .argument('<profile>', 'path to azurevpnconfig.xml')
    .option('-o, --output <path>', 'where to write (default: <name>.ovpn beside the profile)')
    .option('--stdout', 'write to stdout instead; prints the tls-auth key')
    .option('--force', 'overwrite an existing file')
    .option('--ca <path>', 'CA certificate to reference')
    .option('--inline-ca', 'embed the CA certificate so the config is self-contained')
    .option('--credentials <path>', 'emit auth-user-pass <path> so the config is runnable by hand')
    .option('--experimental-azure-compat', 'also emit the Azure OCC string and peer-info')
    .option('--verify-name <name>', 'require this certificate name')
    .option('--verb <n>', 'OpenVPN verbosity')
    .action(async (profile: string, options: Record<string, unknown>, command: Command) => {
      process.exitCode = await convertCommand(profile, {
        ...rootOptions(command),
        ...(typeof options['output'] === 'string' ? { output: options['output'] } : {}),
        ...(options['stdout'] === true ? { stdout: true } : {}),
        ...(options['force'] === true ? { force: true } : {}),
        ...(typeof options['ca'] === 'string' ? { ca: options['ca'] } : {}),
        ...(typeof options['credentials'] === 'string'
          ? { credentials: options['credentials'] }
          : {}),
        ...(options['inlineCa'] === true ? { inlineCa: true } : {}),
        ...(options['experimentalAzureCompat'] === true ? { azureCompat: true } : {}),
        ...(typeof options['verifyName'] === 'string' ? { verifyName: options['verifyName'] } : {}),
        ...(options['verb'] !== undefined
          ? { verb: parsePositiveInt(options['verb'], '--verb', 3) }
          : {}),
      });
    });

  program
    .command('doctor')
    .description('check the environment, the profile, and a live connection')
    .argument('[profile]', 'path to azurevpnconfig.xml')
    .option('--ca <path>', 'CA certificate to check for')
    .option(
      '--dns-probe <hostname>',
      'check that this hostname resolves to a private address through the VPN',
    )
    .action(
      async (profile: string | undefined, options: Record<string, unknown>, command: Command) => {
        process.exitCode = await doctorCommand(profile, {
          ...rootOptions(command),
          ...(typeof options['ca'] === 'string' ? { ca: options['ca'] } : {}),
          ...(typeof options['dnsProbe'] === 'string' ? { dnsProbe: options['dnsProbe'] } : {}),
        });
      },
    );

  program
    .command('probe')
    .description('test the gateway exchange without creating a tunnel or changing DNS')
    .argument('<profile>', 'path to azurevpnconfig.xml')
    .option(
      '--experimental-azure-compat',
      'also send the Azure OCC string and peer-info (measured unnecessary; escape hatch)',
    )
    .option('--ca <path>', 'CA certificate to validate the gateway against')
    .option('--client-id <id>', 'override the Entra application id')
    .option(
      '--auth <flow>',
      'sign-in flow: browser (loopback + PKCE, default) or device-code for a headless machine',
    )
    .option('--scope <scope>', 'override the Entra scope')
    .option('--openvpn-binary <path>', 'override the OpenP2S OpenVPN binary')
    .option('--timeout <seconds>', 'how long to wait', '45')
    .option('--label <name>', 'label for this variant in the output')
    .option('--json', 'machine-readable output')
    .action(async (profile: string, options: Record<string, unknown>, command: Command) => {
      process.exitCode = await probeCommand(profile, {
        ...rootOptions(command),
        ...(options['experimentalAzureCompat'] === true ? { azureCompat: true } : {}),
        ...(typeof options['ca'] === 'string' ? { ca: options['ca'] } : {}),
        ...(typeof options['clientId'] === 'string' ? { clientId: options['clientId'] } : {}),
        ...(typeof options['auth'] === 'string'
          ? { authFlow: parseAuthFlow(options['auth']) }
          : {}),
        ...(typeof options['scope'] === 'string' ? { scope: options['scope'] } : {}),
        ...(typeof options['openvpnBinary'] === 'string'
          ? { openvpnBinary: options['openvpnBinary'] }
          : {}),
        ...(typeof options['label'] === 'string' ? { label: options['label'] } : {}),
        ...(options['json'] === true ? { json: true } : {}),
        timeout: parsePositiveInt(options['timeout'], '--timeout', 45),
      });
    });

  const auth = program.command('auth').description('manage the cached Entra session');

  auth
    .command('login')
    .description('sign in and cache the Entra session, without connecting')
    .argument('<profile>', 'path to azurevpnconfig.xml')
    .option('--force', 'ignore the cached session and sign in again')
    .option('--client-id <id>', 'override the Entra application id')
    .option(
      '--auth <flow>',
      'sign-in flow: browser (loopback + PKCE, default) or device-code for a headless machine',
    )
    .option('--scope <scope>', 'override the OAuth scope')
    .action(async (profile: string, options: Record<string, unknown>, command: Command) => {
      process.exitCode = await authLoginCommand(profile, {
        ...rootOptions(command),
        ...(options['force'] === true ? { force: true } : {}),
        ...(typeof options['clientId'] === 'string' ? { clientId: options['clientId'] } : {}),
        ...(typeof options['auth'] === 'string'
          ? { authFlow: parseAuthFlow(options['auth']) }
          : {}),
        ...(typeof options['scope'] === 'string' ? { scope: options['scope'] } : {}),
      });
    });

  auth
    .command('status')
    .description('show cached Entra sessions')
    .argument('[profile]', 'limit the report to this profile')
    // The same overrides as login, so both compute the same cache key.
    .option('--client-id <id>', 'the Entra application id the session was created with')
    .option('--scope <scope>', 'the OAuth scope the session was created with')
    .action(
      async (profile: string | undefined, options: Record<string, unknown>, command: Command) => {
        process.exitCode = await authStatusCommand({
          ...rootOptions(command),
          ...(profile ? { profile } : {}),
          ...(typeof options['clientId'] === 'string' ? { clientId: options['clientId'] } : {}),
          ...(typeof options['scope'] === 'string' ? { scope: options['scope'] } : {}),
        });
      },
    );

  auth
    .command('clear')
    .description('forget a cached Entra session')
    .argument('[profile]', 'the profile whose session to clear')
    .option('--all', 'clear every cached session')
    .option('--client-id <id>', 'the Entra application id the session was created with')
    .option('--scope <scope>', 'the OAuth scope the session was created with')
    .action(
      async (profile: string | undefined, options: Record<string, unknown>, command: Command) => {
        process.exitCode = await authClearCommand({
          ...rootOptions(command),
          ...(profile ? { profile } : {}),
          ...(options['all'] === true ? { all: true } : {}),
          ...(typeof options['clientId'] === 'string' ? { clientId: options['clientId'] } : {}),
          ...(typeof options['scope'] === 'string' ? { scope: options['scope'] } : {}),
        });
      },
    );

  return program;
}

export async function main(argv: readonly string[] = process.argv): Promise<number> {
  const ui = new Ui();

  try {
    await buildProgram().parseAsync([...argv]);
    return typeof process.exitCode === 'number' ? process.exitCode : 0;
  } catch (error) {
    // commander throws for --help and --version too; those are not failures.
    if (error instanceof CommanderError) {
      return error.exitCode;
    }

    if (error instanceof OpenP2SError) {
      ui.error(error.message);
      if (error.hint) {
        ui.hint(error.hint);
      }
      return error.exitCode;
    }

    ui.error(describeError(error));
    return 1;
  }
}
