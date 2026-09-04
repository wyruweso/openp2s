/**
 * `openp2s probe <profile.xml>`
 *
 * Runs the protocol exchange against the real gateway and reports how far it
 * got. "Fails at TLS handshake" and "fails at key-method-2" are completely
 * different problems, and knowing which is most of the diagnosis.
 *
 * It cannot touch the host because of what its *config* says - `dev null`,
 * `route-noexec`, `ifconfig-noexec` - not because of the uid it runs as;
 * `sudo openp2s probe` is something a user can type. Everything worth
 * measuring happens on the control channel and is unaffected.
 *
 * It does write a config and socket into a private throwaway directory, and
 * may update the cached Entra session. Runtime paths are never shared with
 * `connect`: a probe's cleanup must not delete a live tunnel's socket.
 */

import type { InteractiveFlow } from '../../auth/entra.ts';
import { randomBytes } from 'node:crypto';
import { rm } from 'node:fs/promises';
import { describeError, OpenP2SError, redact } from '../../errors.ts';
import { locateOpenVpnBinary, type OpenVpnBinary } from '../../openvpn/binary.ts';
import { resolveCaPath } from '../../openvpn/ca.ts';
import { CONNECTION_STAGES, stageRank, type ConnectionStage } from '../../openvpn/process.ts';
import type { DnsConfigurator } from '../../network/dns.ts';
import { ensurePrivateDir, probePaths } from '../../platform/paths.ts';
import { Elevator } from '../../platform/privilege.ts';
import { Connection } from '../connection.ts';
import { createAuthenticator, createContext, loadProfile, type GlobalOptions } from '../context.ts';

/** A rejecting implementation, so a regression fails loudly rather than
 * silently reconfiguring the resolver. */
const NO_DNS: DnsConfigurator = {
  configure(): Promise<void> {
    return Promise.reject(new OpenP2SError('probe mode must never configure DNS'));
  },
  revert(): Promise<void> {
    return Promise.resolve();
  },
};

export interface ProbeOptions extends GlobalOptions {
  readonly ca?: string;
  readonly clientId?: string;
  /** Which interactive sign-in flow to use. */
  readonly authFlow?: InteractiveFlow;
  /** So a probe diagnoses the same auth configuration `connect` uses. */
  readonly scope?: string;
  readonly openvpnBinary?: string;
  readonly timeout?: number;
  /** Send the Azure OCC string and peer-info. Off by default. */
  readonly azureCompat?: boolean;
  /** Machine-readable output, for scripting. */
  readonly json?: boolean;
  readonly label?: string;
}

const STAGE_LABELS: Record<ConnectionStage, string> = {
  start: 'nothing (process did not start)',
  tcp: 'TCP connection established',
  tls: 'TLS handshake completed',
  cert: 'gateway certificate verified',
  // Not "token accepted": the credential was sent, but the gateway can still
  // answer AUTH_FAILED immediately afterwards.
  auth: 'key-method-2 credential exchange completed',
  push: 'PUSH_REPLY received',
  tun: 'tun device opened',
  complete: 'initialization sequence completed',
};

/** Anything longer is a mistake, not a preference. */
const MAX_TIMEOUT_SECONDS = 600;

/** The stable shape of `probe --json`. */
interface ProbeReport {
  readonly variant: string;
  readonly azureCompat: boolean;
  readonly stage: ConnectionStage;
  readonly stageRank: number;
  /** The credential was sent. Not the same as being authenticated. */
  readonly credentialExchangeCompleted: boolean;
  /** PUSH_REPLY arrived - the only observable proof the token was accepted. */
  readonly authenticated: boolean;
  readonly tlsCipher: string | null;
  readonly failureReason: string | null;
  readonly error: string | null;
  /** What produced this result. No filesystem path, so it can be pasted. */
  readonly openvpn: {
    readonly version: string | null;
    readonly commit: string | null;
    readonly patchStack: string | null;
    readonly patchSha256: string | null;
    readonly binarySha256: string | null;
    readonly userPassLen: number;
    readonly provenanceKnown: boolean;
  } | null;
  readonly ca: { readonly pinned: boolean } | null;
}

function provenanceOf(binary: OpenVpnBinary): ProbeReport['openvpn'] {
  return {
    version: binary.upstreamVersion ?? null,
    commit: binary.upstreamCommit ?? null,
    patchStack: binary.patchStack ?? null,
    patchSha256: binary.patchSha256 ?? null,
    binarySha256: binary.binarySha256 ?? null,
    userPassLen: binary.userPassLen,
    provenanceKnown: binary.provenanceKnown,
  };
}

export async function probeCommand(
  profilePath: string,
  options: ProbeOptions = {},
): Promise<number> {
  const context = createContext(options);

  // Everything before the run can fail too - a missing profile, no binary, no
  // CA. In JSON mode those must still be a JSON document on stdout, or
  // `openp2s probe x --json | jq .` breaks exactly when something is wrong,
  // which is the moment a script most needs the output.
  let binary: OpenVpnBinary | undefined;
  let caPinned: boolean | undefined;
  try {
    return await runProbe(context, options, profilePath, (b, pinned) => {
      binary = b;
      caPinned = pinned;
    });
  } catch (caught) {
    if (!options.json) throw caught;

    emitJson({
      variant: options.label ?? (options.azureCompat ? 'azure-compat' : 'default'),
      azureCompat: options.azureCompat ?? false,
      stage: 'start',
      stageRank: stageRank('start'),
      credentialExchangeCompleted: false,
      authenticated: false,
      tlsCipher: null,
      failureReason: null,
      error: describeError(caught),
      openvpn: binary ? provenanceOf(binary) : null,
      ca: caPinned === undefined ? null : { pinned: caPinned },
    });
    return 1;
  }
}

function emitJson(report: ProbeReport): void {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

async function runProbe(
  context: ReturnType<typeof createContext>,
  options: ProbeOptions,
  profilePath: string,
  observe: (binary: OpenVpnBinary, caPinned: boolean) => void,
): Promise<number> {
  const { ui } = context;

  const timeoutSeconds = options.timeout ?? 45;
  if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
    throw new OpenP2SError('--timeout must be a positive number of seconds');
  }
  if (timeoutSeconds > MAX_TIMEOUT_SECONDS) {
    throw new OpenP2SError(`--timeout must not exceed ${MAX_TIMEOUT_SECONDS} seconds`);
  }

  const profile = await loadProfile(profilePath);
  const binary = locateOpenVpnBinary({
    repoRoot: context.repoRoot,
    ...(options.openvpnBinary ? { override: options.openvpnBinary } : {}),
  });
  const ca = resolveCaPath(options.ca);
  observe(binary, ca.pinned);

  if (!binary.provenanceKnown && !options.json) {
    // A probe is a diagnostic: trying an unknown binary is a legitimate thing
    // to want. Say what is unknown rather than refusing. The assumed value is
    // whatever locateOpenVpnBinary() resolved, so the message and the
    // behaviour cannot disagree.
    ui.warn(
      `no BUILDINFO beside ${binary.path}; its USER_PASS_LEN is unknown and ` +
        `assumed to be ${binary.userPassLen}, so a larger token will be reported as too long`,
    );
  }

  const azureCompat = options.azureCompat ?? false;

  // Should not happen with the shipped binary, which carries the patch. See
  // the hint below.
  if (azureCompat && !binary.azureCompatAvailable) {
    // The shipped binary always carries the patch, so this should be
    // unreachable in a normal install. It stays because --openvpn-binary can
    // point at anything, and "unknown option" from OpenVPN is a worse message.
    throw new OpenP2SError('--experimental-azure-compat needs an OpenVPN built with that support', {
      hint:
        'The OpenVPN shipped with OpenP2S carries it. This binary does not,\n' +
        'so it was built elsewhere or is an older OpenP2S build.\n\n' +
        'Rebuild with: scripts/build-openvpn.sh',
    });
  }

  const variant = options.label ?? (azureCompat ? 'azure-compat' : 'default');

  if (!options.json) {
    ui.heading(`Probe: ${variant}`);
    ui.fields([
      ['Gateway', profile.gateway],
      ['azure-compat', azureCompat ? 'on (OCC string + peer-info)' : 'off (default)'],
      ['Host changes', 'none: no tun, no routes, no DNS (enforced by the config)'],
    ]);
    ui.line();
  }

  const authenticator = createAuthenticator(context, profile, {
    ...(options.clientId ? { clientId: options.clientId } : {}),
    ...(options.authFlow ? { flow: options.authFlow } : {}),
    ...(options.scope ? { scope: options.scope } : {}),
  });

  // A namespace of this probe's own, so it can never contend with a live
  // connect - or with another probe - over the management socket, the
  // generated config or the credentials file.
  const paths = probePaths(context.paths, `p${process.pid}-${randomBytes(4).toString('hex')}`);
  ensurePrivateDir(paths.runtimeDir);

  const connection = new Connection({
    profile,
    paths,
    binary,
    caPath: ca.path,
    authenticator,
    dns: NO_DNS,
    // Second layer only: the config is what makes the run non-mutating.
    // Refusing to escalate additionally means a probe never prompts for a
    // password.
    elevator: new Elevator({ disabled: true }),
    probe: true,
    skipDns: true,
    azureCompat,
    connectTimeoutMs: timeoutSeconds * 1000,
    stopGracePeriodMs: 2_000,
    // D_SHOW_OCC is LOGLEV(7), so verb 7 is what prints the local and
    // expected OCC options strings - exactly what you want when checking
    // whether --experimental-azure-compat changed anything on the wire.
    // Noisy, but --verbose on a probe is an explicit request for detail.
    verb: ui.isVerbose ? 7 : 4,
    credentialLimits: { userPassLen: binary.userPassLen },
    events: {
      onAuthenticated: (outcome) => {
        if (!options.json) {
          ui.ok(outcome.fromCache ? 'Authenticated from cache' : 'Authenticated');
        }
      },
      // Redacted here as well as in ui.debug(): verb 7 prints a great deal,
      // and this should not depend on one function staying correct.
      onLogLine: (line) => ui.debug(redact(line)),
      onWarning: (message) => {
        if (!options.json) ui.warn(message);
      },
    },
  });

  let error: string | undefined;
  try {
    await connection.connect();
  } catch (caught) {
    // describeError walks the cause chain and redacts; a raw exception message
    // must not reach stdout in JSON mode or a terminal in verbose mode.
    error = describeError(caught);
  } finally {
    await connection.cleanup();
    // Remove the whole ephemeral namespace, not just the files the connection
    // knows about.
    await rm(paths.runtimeDir, { recursive: true, force: true }).catch(() => undefined);
  }

  const stage = connection.stage;
  const credentialExchangeCompleted = stageRank(stage) >= stageRank('auth');
  const authenticated = stageRank(stage) >= stageRank('push');
  const failureReason = connection.failureReason;

  if (options.json) {
    emitJson({
      variant,
      azureCompat,
      stage,
      stageRank: stageRank(stage),
      credentialExchangeCompleted,
      authenticated,
      tlsCipher: connection.tlsCipher ?? null,
      failureReason: failureReason === undefined ? null : redact(failureReason),
      error: error ?? null,
      openvpn: provenanceOf(binary),
      ca: { pinned: ca.pinned },
    });
    return authenticated ? 0 : 1;
  }

  ui.line();
  ui.heading('Result');
  ui.fields([
    ['Stage reached', `${stage} (${STAGE_LABELS[stage]})`],
    [
      'Progress',
      CONNECTION_STAGES.map((s) => (stageRank(s) <= stageRank(stage) ? s : `(${s})`)).join(' -> '),
    ],
    ['TLS', connection.tlsCipher ?? 'not negotiated'],
    // Two separate facts. The credential fitting through the control channel
    // is what the patch fixes; the gateway accepting it is a different
    // question, and PUSH_REPLY is the only evidence of it.
    ['Credential exchange', credentialExchangeCompleted ? 'completed' : 'did not complete'],
    [
      'Authentication',
      authenticated
        ? 'accepted (PUSH_REPLY received)'
        : credentialExchangeCompleted
          ? 'not accepted (no PUSH_REPLY)'
          : 'not attempted',
    ],
    ['Note', failureReason],
  ]);

  ui.line();
  if (authenticated) {
    ui.ok('This variant works: the gateway completed the exchange.');
    return 0;
  }
  ui.error(`This variant fails at "${stage}".`);
  if (error) ui.hint(error);
  return 1;
}
