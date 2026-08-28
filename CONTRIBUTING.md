# Contributing

Thanks for taking an interest in OpenP2S.

OpenP2S is intentionally small in scope, but it handles VPN credentials, root
operations, DNS configuration, and a patched OpenVPN build. Changes in those
areas deserve a little extra care.

## Before you start

For bugs and feature requests, open an issue.

For security vulnerabilities, **do not open a public issue or pull request**.
Please use GitHub Security Advisories instead. See
[docs/SECURITY.md](docs/SECURITY.md).

Never attach a real `azurevpnconfig.xml` to an issue or PR. It contains the
gateway's `serversecret` and should be treated as key material.

Useful diagnostics are:

```bash
openp2s --version
openp2s doctor <profile>.xml
openp2s inspect <profile>.xml
openp2s probe <profile>.xml
```

Please still review output before posting it publicly.

## Development setup

Node is pinned in `.node-version`.

```bash
npm ci
npm run check
```

`npm run check` runs formatting, linting, type checking, and tests.

The test suite should not require root, network access, a real VPN profile, or
changes to system DNS. Use the helpers and fakes under `tests/` instead.

To build the release artifacts:

```bash
npm run build:openvpn
npm run build:cli
npm run build:release
npm run build:deb
npm run smoke:package
```

The individual provenance and policy checks are also available through the
scripts in `scripts/`.

## A few important invariants

Please keep these true:

- OpenP2S never falls back to the system OpenVPN binary.
- Access tokens must not appear in argv, environment variables, or logs.
- `sudo openp2s ...` is not supported; only the operations that need root are
  elevated.
- Certificate verification cannot be disabled.
- Real Azure profiles and built binaries must never be committed.
- The normal OpenVPN behaviour change is deliberately minimal. Experimental
  Azure compatibility behaviour stays opt-in.
- Teardown must preserve enough state to recover if OpenVPN or DNS cleanup
  fails.

The test and build scripts enforce many of these. If a policy check fails,
please understand why before relaxing it.

## Pull requests

Keep PRs focused where practical.

Before submitting:

```bash
npm run check
```

Please also:

- add or update tests for behaviour changes;
- update `README.md`, `docs/SECURITY.md`, or the man page when relevant;
- explain non-obvious decisions in comments rather than narrating the code;
- mention how changes to authentication, privileges, DNS, or OpenVPN behaviour
  were verified.

Some VPN behaviour can only be confirmed against a real Azure gateway. If your
change depends on that, include the result of an appropriate `openp2s probe`
or manual test in the PR description.

## OpenVPN changes

The pinned OpenVPN release and patch hashes live in `patches/manifest`.

When updating OpenVPN or its patches, keep the change separate and run the
OpenVPN build, provenance, patch-policy, and binary-policy checks before
submitting it.

## Scope

OpenP2S currently targets:

- Linux on amd64;
- Microsoft Entra ID authentication;
- Azure Public;
- `systemd-resolved`;
- command-line use.

Release artifacts are currently published for amd64 only. The build tooling
also supports arm64, but it is not yet a supported or tested release target.

Other authentication methods, DNS resolvers, architectures, NetworkManager
integration, and a GUI may be reasonable future work, but please open an issue
before starting a large change in one of those areas.

## Licence

OpenP2S is GPL-2.0-only. Contributions are accepted under the same licence.
There is no CLA.
