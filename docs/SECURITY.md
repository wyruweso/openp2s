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

## Privileges

OpenP2S runs as you. Only operations that require root are elevated, through
`sudo`: the OpenVPN process lifecycle, and per-link DNS configuration.

`sudo openp2s ...` is refused. Running the whole client as root would mean a
root process creating and inspecting files inside directories you control,
which is a category of risk with nothing to gain — the two commands that need
root still get it.

## VPN server verification

Certificate verification is always on. There is no option to disable it.

The gateway certificate is validated against your system trust store, and the
peer must present a certificate marked for TLS server use. **No CA is ever
read from the profile**, so a modified profile cannot introduce a trust anchor.

**Known limitation:** by default OpenP2S does not check _which_ certificate
the gateway presents, only that it is valid and trusted. Any certificate
issued under a trusted root is accepted, including one for a different Azure
gateway.

`--verify-name` adds that check. It is an exact match against the
certificate's X.509 name (the CN), not browser-style hostname or SAN matching,
so the value must be the CN exactly as the gateway presents it:

```bash
openp2s connect profile.xml --verify-name '<certificate-cn>'
```

Run `openp2s connect --verbose` once to see the CN the gateway presents. This
is not the default because that name varies between clouds and gateway
generations, and a wrong value fails the connection outright.

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
