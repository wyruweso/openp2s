# Security

What OpenP2S stores, what it protects, and what it does not.

## Sensitive data

| Material                        | Where                                 | Permissions            | Survives reboot |
| ------------------------------- | ------------------------------------- | ---------------------- | --------------- |
| Entra access token              | process memory                        | —                      | no              |
| Credential file (fallback only) | `/run/user/$UID/openp2s/credentials`  | `0600` in a `0700` dir | no (tmpfs)      |
| Generated OpenVPN config        | `/run/user/$UID/openp2s/openvpn.conf` | `0600` in a `0700` dir | no (tmpfs)      |
| Entra token cache               | `~/.local/state/openp2s/cache/`       | `0600` in a `0700` dir | **yes**         |

The access token is normally delivered to OpenVPN over a private Unix socket
and is never written to disk. If the OpenVPN in use does not support that
mechanism, OpenP2S falls back to the temporary credential file above. That
file exists for the lifetime of the connection, because OpenVPN may re-read
it, and is removed when the connection is torn down. It lives on tmpfs, so it
also disappears at reboot whether or not any cleanup ran.

On either path the token never appears in a command line or in an environment
variable, so it is not exposed to other processes through `/proc`.

The generated OpenVPN config embeds the profile's `serversecret` as the
tls-auth key. Treat that file, and any config written by `openp2s convert`,
as key material.

The token cache holds a refresh token and is the one item that survives a
reboot. Remove it with `openp2s auth clear`.

When the profile enables group authentication, the same protections apply to
both the VPN access token and the Microsoft Graph access token. MSAL caches
them in the existing private cache; their combined TLV credential is assembled
in memory and sent only to a VPN gateway whose certificate name is checked.
Graph acquisition is bound to the same account and tenant. A missing or
mismatched Graph token is not sent: OpenP2S warns and connects with the VPN
token alone.

A reconnect keeps the account and the kind of credential the session started
with. If it can't renew those without signing in, OpenVPN stops and you connect
again, so a live session never changes identity or address pool unnoticed.

## Sign-in

OpenP2S uses the browser authorization-code flow with PKCE. The authorization
code is bound to a one-time verifier generated inside OpenP2S and is delivered
to a listener on 127.0.0.1 that exists only for the duration of the sign-in, so
an intercepted code cannot be redeemed without the verifier.

The browser must be on this machine, and OpenP2S fails with a clear message
when none can be opened. The sign-in ends in a redirect to 127.0.0.1, which
resolves to whichever machine the browser is running on, so a URL opened
elsewhere would deliver the code to that machine rather than to OpenP2S.

`--auth device-code` prints a code for you to enter on another device. It is
the only flow that works with no local browser, and it is **opt-in**: the
device-code flow is susceptible to phishing, because an attacker can start the
flow and persuade you to approve their sign-in. Organisations can block it by
Conditional Access.

OpenP2S never falls back from one flow to the other. A refusal you should see —
a Conditional Access denial, or an application that does not permit the
loopback redirect — would otherwise be hidden by a silent retry on the flow
your organisation was trying to prevent.

Sessions are cached per flow. A session obtained by device code is not reused
for a browser sign-in, because Entra records how a session was established and
carries that through refreshes.

## Privileges

OpenP2S runs as you. Two operations are elevated through `sudo`.

OpenVPN does not keep root. `sudo` starts `setpriv`, which runs OpenVPN as you
with only `CAP_NET_ADMIN`, for its whole life. That is enough to open the tun
device and install routes, including after a reconnect, and it limits what a bad
config or an OpenVPN bug can reach. It is still network administration: do not
add a passwordless `sudo` rule, because a rule for `setpriv` is a rule for root.

Per-link DNS is set with `resolvectl` through `sudo`.

`sudo openp2s ...` is refused. Running the whole client as root would mean a
root process creating and inspecting files inside directories you control,
which is a category of risk with nothing to gain — the two commands that need
root still get it.

## VPN server verification

Certificate verification is always on. There is no option to disable it.

For a gateway under `vpn.azure.com`, the certificate must chain to one of the
two roots Azure gateways use, which ship with OpenP2S: DigiCert Global Root G2
and DigiCert Global Root CA. For any other host it is validated against your
system trust store. `--ca` replaces either. The peer must also present a
certificate marked for TLS server use. **No CA is ever read from the profile**,
so a modified profile cannot introduce a trust anchor.

The roots ship with OpenP2S because system stores follow browser policy.
DigiCert Global Root CA left browser trust in April 2026 and distributions are
dropping it, while Azure gateways still use it. This has two costs: a
distribution update cannot withdraw these roots, only an OpenP2S release can.
And if Azure moves to another root, connecting fails until OpenP2S is updated or
you pass `--ca`.

OpenP2S also checks the certificate's name, because a trusted chain alone does
not show that a certificate belongs to an Azure gateway. There is no option to
turn this off. The check is an exact match against the certificate's X.509 name
(the CN), not browser-style hostname or SAN matching. OpenP2S works out the
expected name from the gateway hostname:

| Gateway hostname                              | Expected name             |
| --------------------------------------------- | ------------------------- |
| `azuregateway-<guid>-<hash>.vpn.azure.com`    | `<guid>.vpn.azure.com`    |
| `<name>.vpn.azure.com`                        | `*.vpn.azure.com`         |
| `azuregateway-<guid>-<hash>.ln.vpn.azure.com` | `<guid>.ln.vpn.azure.com` |

Only Microsoft can get a certificate for names under `vpn.azure.com`, so a
modified profile cannot use this to make OpenP2S accept a certificate of its
own. `*.vpn.azure.com` is shared by the gateways that use it, so in that case
the check shows the peer is an Azure gateway, not which one.

`--verify-name` replaces the expected name. It must be the CN exactly as the
gateway presents it:

```bash
openp2s connect profile.xml --verify-name '<certificate-cn>'
```

A mismatch stops the connection rather than retrying, and reports the
certificate presented. Virtual WAN gateways reach this on first use, because
their name cannot be worked out from the hostname. A name that does not end in
`.vpn.azure.com` may mean the peer is not your gateway.

For any other hostname, such as another cloud or a test gateway, `connect`
refuses until you supply a name. `openp2s probe` reports the CN the gateway
presents. With no name to check, a probe accepts any trusted certificate and
sends it your Entra token, so check that name before trusting it.

## Local security assumptions

The protection boundary is the Unix user. Runtime files are `0600` inside a
`0700` directory, and OpenP2S verifies those permissions rather than assuming
them: it refuses to start if the runtime directory is group- or
world-accessible, and deletes a token cache that has become readable by others
instead of using it.

OpenP2S does not treat processes running under the same Unix account as a
security boundary. Depending on your system's protections, such a process may
be able to read these files, the token cache, or OpenP2S's own memory. OpenP2S
does not defend against code already running as you.

The token cache is a `0600` file, not a desktop keyring. It is not encrypted
at rest, so it is readable by anything that can read your home directory —
including a backup of it.

## Reporting vulnerabilities

Please report security issues privately, rather than opening a public issue:

<https://github.com/wyruweso/openp2s/security/advisories/new>

That is GitHub's private vulnerability reporting for this repository, which is
enabled: a report is visible only to the maintainer until an advisory is
published. Include the OpenP2S version from `openp2s --version` and the
OpenVPN provenance from `openp2s status --verbose`.

### In scope

The classes of issue this project most wants to hear about:

- exposure or persistence of an Entra access or refresh token;
- command or configuration injection, particularly anything reaching the
  generated OpenVPN config, which is read by a process running as root;
- privilege escalation across the `sudo` boundary described above;
- unsafe handling of a hostile VPN profile;
- anything that would let the OpenVPN tarball, patch, or binary verification
  in `scripts/verify-provenance.sh` be bypassed or weakened.

The local security assumptions above are deliberate rather than oversights.
In particular, OpenP2S does not defend against code already running as your
own user, and says so.

### Response

I will acknowledge a report as soon as practical and aim to give an initial
assessment within 7 days. OpenP2S is maintained by one person, so please allow
time for a fix to be prepared and released before disclosing publicly.
