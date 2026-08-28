/**
 * Azure-specific OpenVPN directives.
 *
 * Emits nothing by default: measurement against a live gateway showed only the
 * patch's buffer sizes are load-bearing, and no Azure-specific directive is
 * needed. `--experimental-azure-compat` is the escape hatch for a gateway that
 * behaves differently.
 *
 * Attribution: the OCC string and peer-info values come from the
 * cveld/azure-vpn-client-headless-container project. See the README.
 */

/** The OpenVPN username Azure expects; the password is the Entra token. */
export const AZURE_USERNAME = 'AzureAD';

export interface AzureCompatOptions {
  /** Send the Azure OCC options string and peer-info. Off by default. */
  readonly compat?: boolean;
}

/** Returns an empty list unless compat mode was asked for. */
export function azureCompatDirectives(options: AzureCompatOptions = {}): string[] {
  const lines: string[] = [];

  if (options.compat) {
    // The patched OpenVPN validates the config against what this advertises
    // and refuses to start on a mismatch.
    lines.push('experimental-azure-compat');
  }

  return lines;
}

/**
 * What this build supports, as label/value rows for `inspect --compat`.
 *
 * Phrased as capabilities, not as settings to choose between: no
 * Azure-specific directive is needed against a gateway that works.
 */
export function describeAzureCompat(binary?: {
  readonly azureCompatAvailable: boolean;
}): ReadonlyArray<readonly [string, string]> {
  return [
    ['Default', 'disabled: no Azure-specific directives are emitted'],
    [
      'experimental-azure-compat',
      binary === undefined
        ? 'compiled into the shipped OpenVPN; off unless --experimental-azure-compat'
        : binary.azureCompatAvailable
          ? 'compiled in, off unless --experimental-azure-compat is passed'
          : 'NOT in this binary; the shipped OpenVPN carries it',
    ],
    ['Cannot be enabled by', 'the server, or the environment'],
    ['TLS ClientHello shaping', 'not shipped: unpatched OpenVPN completes the handshake'],
    ['Measured Azure Public gateway', 'no Azure-specific directives required'],
  ];
}
