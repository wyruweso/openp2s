/**
 * `openp2s disconnect`
 *
 * Runs from any terminal, using the session record to find the tunnel.
 *
 * The teardown itself is `teardownConnection()`, shared with the foreground
 * `connect` path so there is one ordering and one set of rules rather than two
 * that drift apart.
 *
 * What is specific here is the recovery behaviour: the session record is
 * cleared **only** when the teardown reports itself complete. It is the only
 * thing that records where the tunnel and its artifacts are, so deleting it
 * after a partial failure would destroy exactly the information needed to
 * finish the job - and a later `openp2s disconnect` would cheerfully answer
 * "Not connected" while OpenVPN was still running and a credentials file was
 * still on disk.
 */

import { describeError, OpenP2SError } from '../../errors.ts';
import { teardownConnection, type TeardownTargets } from '../teardown.ts';
import { createContext, createDnsConfigurator, type GlobalOptions } from '../context.ts';

export interface DisconnectOptions extends GlobalOptions {
  /** Wait this long for openvpn to exit before SIGKILL. */
  readonly graceSeconds?: number;
}

/** Anything longer is a mistake, not a preference. */
const MAX_GRACE_SECONDS = 60;

export async function disconnectCommand(options: DisconnectOptions = {}): Promise<number> {
  const context = createContext(options);
  const { ui, paths } = context;

  const grace = options.graceSeconds ?? 5;
  if (!Number.isFinite(grace) || grace < 0 || grace > MAX_GRACE_SECONDS) {
    throw new OpenP2SError(`--grace must be between 0 and ${MAX_GRACE_SECONDS} seconds`);
  }

  const record = await context.session.read();
  if (!record) {
    ui.line('Not connected.');
    return 0;
  }

  // Record the intent before signalling anything, so a foreground `connect`
  // watching the process reports a requested shutdown rather than a failure.
  // Failing to write it must not prevent the disconnect: a confusing message
  // is better than a tunnel that stays up.
  try {
    await context.session.write({ ...record, disconnectRequestedAt: new Date().toISOString() });
  } catch (error) {
    ui.warn(`could not record the disconnect request: ${describeError(error)}`);
  }

  const targets: TeardownTargets = {
    openvpnPid: record.openvpnPid,
    openvpnStartTime: record.openvpnStartTime,
    interfaceName: record.interfaceName,
    dnsConfigured: record.dnsServers.length > 0,
    artifacts: [
      // Prefer the paths in the record, so a session written by an older
      // version is still cleaned up correctly.
      { label: 'credentials', path: record.credentialsPath || paths.credentialsFile },
      { label: 'generated config', path: record.configPath || paths.configFile },
      { label: 'management socket', path: record.managementSocket || paths.managementSocket },
      // The lock itself is a kernel-held socket name that vanished with the
      // owning process; this is only the file describing who held it.
      { label: 'lock record', path: paths.lockFile },
    ].filter((artifact) => artifact.path.length > 0),
  };

  const result = await teardownConnection(targets, {
    dns: createDnsConfigurator(context),
    graceMs: grace * 1000,
    signal: (pid, signal) => sendSignal(context, pid, signal),
    onProgress: (message) => ui.ok(message),
    onWarning: (message) => ui.warn(message),
  });

  if (result.complete) {
    await context.session.clear();
    ui.ok('Disconnected');
    return 0;
  }

  // Keep the record so a later attempt knows what is still outstanding.
  ui.line();
  ui.warn(
    `disconnected with ${result.problems.length} problem${result.problems.length === 1 ? '' : 's'}; ` +
      'the session record is kept so the cleanup can be retried',
  );
  ui.hint('Run `openp2s disconnect` again, or `openp2s status` to see what remains.');
  return 5;
}

/**
 * Send a signal, elevating when we are not root.
 *
 * `kill` is invoked with an argv array like every other command. The pid comes
 * from our own session record, but it is still passed as its own argument
 * rather than interpolated into a string.
 */
async function sendSignal(
  context: ReturnType<typeof createContext>,
  pid: number,
  signal: 'SIGTERM' | 'SIGKILL',
): Promise<void> {
  if (context.elevator.isRoot) {
    process.kill(pid, signal);
    return;
  }
  const plan = context.elevator.plan('kill', [`-${signal.replace('SIG', '')}`, String(pid)]);
  await context.runner.run(plan.command, plan.args, { timeoutMs: 10_000 });
}
