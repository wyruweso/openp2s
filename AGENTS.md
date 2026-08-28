# Notes for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) first — it is written for humans but
everything in it applies here. This file is the short version, plus the
mistakes that are easy to make quickly.

## What this is

A Linux CLI that connects to Azure Point-to-Site VPNs using Microsoft Entra ID.
TypeScript on Node (no build step for development — `.ts` runs directly), plus
a pinned, patched OpenVPN built from source by shell scripts under `scripts/`.

```
src/          the CLI. cli/ commands, auth/ Entra + token cache,
              openvpn/ config and process, network/ split DNS,
              profile/ Azure XML, platform/ exec, paths, privilege
scripts/      build and policy checks. read the header comment first
patches/      the OpenVPN patches; patches/manifest is the source of truth
packaging/    man page and audited licence copies
tests/        node:test. no network, no root, no system DNS
```

## Before you finish

```bash
npm run check   # format:check, lint, typecheck, test
```

Anything touching `scripts/`, `patches/` or packaging also needs the build
checks listed in CONTRIBUTING.md. Do not report a change as done on a
typecheck alone.

## Rules that are not style preferences

Each has an automated check behind it. If one fails, fix the change — do not
relax the check, add an inline disable, or edit the fixture it compares to.

1. **`patches/2.7.6/long-credentials.patch` changes two constants.** That is
   the project's central claim, asserted line by line by
   `scripts/check-patch-policy.sh`. Never extend it. New OpenVPN behaviour
   goes in the experimental patch or, preferably, in TypeScript.
2. **Never commit a binary, a built artifact, or anything from `build/`.**
3. **Never commit a real Azure profile or a real token.** Fixtures in
   `tests/fixtures/` are synthetic; generate credential-shaped test input with
   `tests/helpers/syntheticToken.ts`.
4. **Credentials never reach argv, the environment, or a log.** Everything
   user-facing goes through `redact()` in `src/errors.ts`. Redaction must also
   not eat legitimate output — hashes, thumbprints, PEM blocks are asserted
   readable in `tests/redaction.test.ts`.
5. **Certificate verification is never optional, and the client never runs as
   root.** Only the OpenVPN lifecycle and per-link DNS are elevated.
6. **The executable stays byte-reproducible** across build paths
   (`scripts/check-cli-reproducible.sh`). This constrains anything embedded at
   build time — no timestamps, no absolute paths, no build host details.
7. **Adding a runtime dependency is a decision, not a detail.** There are three.
   Each one carries a `THIRD_PARTY_NOTICES` obligation enforced at release.
8. **The man page documents guarantees, not the option list.** `--help` is the
   option reference; `packaging/openp2s.1` describes the commands, the files,
   the privilege boundary and the exit codes, and names an option only where it
   carries a claim. So edit it when a change touches one of those — a new exit
   code, a different privilege, an option that weakens or strengthens a stated
   guarantee — and leave it alone for an ordinary flag.
   `tests/manpage.test.ts` holds those claims to the implementation.

## House style

Comments explain **why**, not what — the reason a limit exists, why a fallback
is there, why a rule is stricter than it looks. Match that; the existing
comments are the specification for a lot of this behaviour, so read the ones
near your change before altering the code under them.

Prose in the README, the man page and `docs/` is plain and unhyped. Keep it.
