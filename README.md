# OpenP2S

OpenP2S is a Linux client for Azure Point-to-Site VPNs that use Microsoft
Entra ID authentication.

Use it when you have an Azure P2S `azurevpnconfig.xml` profile and need to
connect from Linux. Microsoft has announced the retirement of the official
Azure VPN Client for Linux on 31 August 2026; the gateways themselves are
unaffected. OpenP2S handles Entra sign-in, the Azure-compatible
OpenVPN connection, split DNS, and cleanup on disconnect.

```bash
openp2s connect azurevpnconfig.xml
```

## Quick start

**1. Get your profile.** In the Azure portal: **VPN gateway → Point-to-site
configuration → Download VPN client**. Unpack it and find
`azurevpnconfig.xml`.

**2. Install OpenP2S** (see [Installation](#installation)):

```bash
sudo apt install ./openp2s_0.1.0_amd64.deb
```

**3. Connect:**

```console
$ openp2s connect azurevpnconfig.xml
✓ Signed in with Microsoft Entra ID
✓ VPN connected
✓ Configured split DNS

Connected
Interface: tun0

Press Ctrl+C to disconnect.
```

The first connection signs you in with a Microsoft Entra device code: OpenP2S
prints a URL and a short code to enter in a browser. Later connections reuse
the cached session.

## Installation

### Debian / Ubuntu

Download `openp2s_<version>_amd64.deb` from the
[releases page](https://github.com/wyruweso/openp2s/releases), then:

```bash
sha256sum --check SHA256SUMS
sudo apt install ./openp2s_*_amd64.deb
```

This installs `openp2s`, its OpenVPN build, and a man page.

### Portable bundle

For manual installation, or to run without installing a package:

```bash
tar xf openp2s-*-linux-amd64.tar.gz
cd openp2s-*-linux-amd64
./openp2s connect ~/azurevpnconfig.xml
```

The bundle works in place — the CLI finds the OpenVPN that shipped beside it.
To install it system-wide instead:

```bash
sudo install -D -m 0755 openp2s          /usr/local/bin/openp2s
sudo install -D -m 0755 openvpn-openp2s  /usr/local/lib/openp2s/openvpn
sudo install -D -m 0644 BUILDINFO        /usr/local/lib/openp2s/BUILDINFO
```

## Commands

| Command      | What it does                                         |
| ------------ | ---------------------------------------------------- |
| `connect`    | Connect to the VPN. Runs in the foreground.          |
| `status`     | Show the current connection (`--json` for scripting) |
| `disconnect` | Disconnect and clean up                              |
| `inspect`    | Show what OpenP2S reads from a profile               |
| `doctor`     | Check local requirements and configuration           |
| `probe`      | Test the gateway without creating a tunnel           |
| `convert`    | Write a standalone OpenVPN config                    |
| `auth`       | Manage the cached Entra session                      |

Run `openp2s <command> --help` for options, or `man openp2s`.

## Requirements

- Linux
- systemd-resolved (`resolvectl`) for split DNS
- `sudo`, for OpenVPN and DNS changes only
- An Azure P2S gateway configured for Microsoft Entra ID authentication

OpenP2S runs as your normal user. `sudo openp2s ...` is refused — it elevates
only the two operations that need root.

## How it works

1. Parses your Azure VPN profile.
2. Signs you in with Microsoft Entra ID.
3. Runs its own OpenVPN build against the gateway.
4. Applies the profile's split DNS to the VPN interface.
5. Stops OpenVPN, reverts DNS, and removes temporary runtime files.

## Authentication

OpenP2S uses Microsoft Entra device-code authentication. On the first
connection it shows a URL and a code; later connections reuse the cached
session when possible. MFA and Conditional Access apply normally.

```bash
openp2s auth login azurevpnconfig.xml   # sign in without connecting
openp2s auth status                     # show cached sessions
openp2s auth clear azurevpnconfig.xml   # forget this profile's session
openp2s auth clear --all                # forget every cached session
```

## Split DNS

Azure P2S profiles may specify private DNS servers and search domains. OpenP2S
applies them **only to the VPN interface and only for those domains**, so your
ordinary browsing does not go through your employer's resolver.

This matters for Azure Virtual Desktop and Private Link, where public DNS
returns an endpoint that is then refused — a failure that looks like a broken
service even though the VPN is connected.

- `--no-dns` — leave DNS alone entirely
- `--dns-all` — route _every_ DNS query over the VPN

## Troubleshooting

Start here:

```bash
openp2s doctor azurevpnconfig.xml    # check the environment and the profile
openp2s inspect azurevpnconfig.xml   # see what OpenP2S read from the profile
openp2s probe azurevpnconfig.xml     # test the gateway, no tunnel created
```

`probe` reports how far the exchange got — TCP, TLS, certificate,
credentials, `PUSH_REPLY` — which usually identifies the problem on its own.

Add `--verbose` for detail. If `probe` shows the gateway rejecting the session
after credentials are sent, try:

```bash
openp2s connect azurevpnconfig.xml --experimental-azure-compat
```

If the tunnel is up but a private name still resolves to a public address —
the Azure Virtual Desktop and Private Link failure described above — give
`doctor` a hostname to check:

```bash
openp2s doctor azurevpnconfig.xml --dns-probe myhost.privatelink.example
```

`doctor` resolves that name through the VPN interface only and reports whether
the result is a private address. The hostname must be supplied explicitly
because the VPN profile does not contain one.

## Why does OpenP2S bundle OpenVPN?

Azure Entra access tokens are larger than two fixed limits in stock OpenVPN:
the token is sent as the OpenVPN password, and it does not fit. OpenP2S ships
a pinned OpenVPN build with those limits raised.

That build also contains an experimental Azure compatibility mode, **disabled
by default**. The gateways tested so far do not need it; if `probe` suggests
otherwise, `--experimental-azure-compat` turns it on.

OpenP2S never falls back to your system OpenVPN binary. A stock build
truncates the token and the gateway rejects it, which looks like a server
fault rather than a client one.

Each release publishes `BUILDINFO`, `SHA256SUMS`, and the complete
corresponding source for the OpenVPN it ships.

## Security

- OpenP2S runs as your normal user and elevates only OpenVPN and DNS changes.
- Access tokens never appear in a command line or an environment variable.
- Runtime files are private to your Unix user; a compatibility fallback may
  use a temporary `0600` credential file.
- VPN certificate verification is always enabled and cannot be turned off.

See [docs/SECURITY.md](docs/SECURITY.md) for details and known limitations.

## Current limitations

- Tested end-to-end against **Azure Public** only.
- Requires **systemd-resolved**; other resolvers are not supported.
- **Entra ID authentication only** — not certificate or RADIUS profiles.
- Command line only; no NetworkManager integration or GUI.
- **x86-64 (amd64) only** — releases are published for amd64. The build
  tooling also supports arm64, but that is not yet a tested or supported
  release target.
- Certificate-name pinning is opt-in (`--verify-name`); see `docs/SECURITY.md`.

## Prior work

OpenP2S builds on several pieces of prior investigation:

- **[`cveld/azure-vpn-client-headless-container`](https://github.com/cveld/azure-vpn-client-headless-container)**
  — reverse engineering of Azure/OpenVPN wire compatibility. The Azure OCC
  string and the `IV_VER=AzMac` peer-info it established are reproduced
  verbatim by the optional compatibility mode, where only an exact match is of
  any use.
- **[Luca Boccassi's OpenVPN patch series](https://gerrit.openvpn.net/q/owner:luca.boccassi@gmail.com)**
  — demonstrated Azure Entra authentication with OpenVPN and addressed the same
  two credential-size limits OpenP2S raises: the management interface's
  multi-line password support
  ([Gerrit 1593](https://gerrit.openvpn.net/c/openvpn/+/1593), merged for
  2.7.2, which OpenP2S relies on to keep the token off disk) and the
  key-method-2 control-channel buffer
  ([Gerrit 1622](https://gerrit.openvpn.net/c/openvpn/+/1622), still open).
  OpenP2S validates its own equivalent against its pinned OpenVPN release.
- **[`oal/microsoft-azure-vpn-ubuntu-26.04-lts-fix`](https://github.com/oal/microsoft-azure-vpn-ubuntu-26.04-lts-fix)**
  — analysis of the systemd-resolved routing-domain failure mode that can break
  Azure Private Link and Azure Virtual Desktop even when the tunnel itself is
  healthy.

## Disclaimer

OpenP2S is an independent project and is not affiliated with, endorsed by, or
supported by Microsoft. Azure, Microsoft Entra ID, and Azure Virtual Desktop
are trademarks of Microsoft Corporation.

## License

GPL-2.0-only. See [LICENSE](LICENSE).

The bundled OpenVPN is upstream OpenVPN with the patches described above,
under its own GPL-2.0 terms with linking exceptions; see `openvpn-COPYING` in
any release.
