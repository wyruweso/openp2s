#!/usr/bin/env bash
#
# Drive an *installed* OpenP2S through its real entry points.
#
# The unit tests cover the renderers; they cannot cover the installed layout,
# where there is no source checkout to find the OpenVPN binary or man page in.
#
# Every command below - inspect, convert, doctor, status - runs fine with no
# OpenVPN present at all, so the first thing asserted is the resolution itself:
# the installed CLI must report the installed OpenVPN, at the packaged path,
# with its provenance intact. Everything after that is secondary.
#
# Usage: scripts/smoke-package.sh [--profile <file>] [--prefix <dir>]
#
#   --prefix  where the package installed itself: /usr for the .deb (default),
#             /usr/local for a manual install from the portable bundle.

set -euo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="$REPO_ROOT/tests/fixtures/azure-schema.xml"
PREFIX="/usr"

die() { printf '\n  smoke test failed: %s\n\n' "$1" >&2; exit 1; }
ok()  { printf '  ok  %s\n' "$1"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --profile) PROFILE="${2:?--profile needs a path}"; shift 2 ;;
        --prefix) PREFIX="${2:?--prefix needs a path}"; shift 2 ;;
        -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

# By absolute path: a different binary earlier on PATH would prove nothing.
OPENP2S="$PREFIX/bin/openp2s"
EXPECTED_OPENVPN="$PREFIX/lib/openp2s/openvpn"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf '\n==> installed package smoke test\n'
printf '    cli:     %s\n' "$OPENP2S"
printf '    openvpn: %s (expected)\n\n' "$EXPECTED_OPENVPN"

[ -x "$OPENP2S" ] || die "$OPENP2S is not installed or not executable"

# ---- the resolution the package exists to get right -----------------------
[ -x "$EXPECTED_OPENVPN" ] \
    || die "the package did not install an executable OpenVPN at $EXPECTED_OPENVPN"

"$OPENP2S" inspect "$PROFILE" --compat > "$WORK/compat.out" 2>&1 \
    || { cat "$WORK/compat.out" >&2; die "inspect --compat failed"; }

RESOLVED="$(sed -n 's/^[[:space:]]*Path:[[:space:]]*//p' "$WORK/compat.out" | head -1)"
[ -n "$RESOLVED" ] || { cat "$WORK/compat.out" >&2; die "the CLI reported no OpenVPN binary path"; }
[ "$RESOLVED" = "$EXPECTED_OPENVPN" ] || die \
"the installed CLI resolved a different OpenVPN
  resolved: $RESOLVED
  expected: $EXPECTED_OPENVPN
The package installed one binary and the CLI is using another. If the resolved
path is inside a source checkout, the installed layout is not actually being
exercised."
ok "the installed CLI resolves the installed OpenVPN"

# Without BUILDINFO beside it this reads "unknown" and `connect` refuses.
grep -qE '^[[:space:]]*USER_PASS_LEN:[[:space:]]*4096$' "$WORK/compat.out" || die \
"the installed OpenVPN does not report USER_PASS_LEN 4096.
Its BUILDINFO is missing or does not describe it, so OpenP2S treats its
provenance as unknown and connect will refuse to use it."
# Both patches, so the compat flag is available without a rebuild.
grep -qE '^[[:space:]]*Patch stack:[[:space:]]*long-credentials experimental-azure-compat$' \
    "$WORK/compat.out" \
    || die "the installed OpenVPN does not report the two shipped patches"

grep -qE '^[[:space:]]*experimental-azure-compat:[[:space:]]*compiled in' "$WORK/compat.out" \
    || die "the installed CLI does not report the compat option as available"
ok "its provenance is intact (USER_PASS_LEN 4096, both shipped patches)"

# ---- the ordinary commands ------------------------------------------------
"$OPENP2S" --version >/dev/null || die "openp2s --version failed"
ok "reports its version"

"$OPENP2S" inspect "$PROFILE" > "$WORK/inspect.out" || die "inspect failed"
grep -q 'Gateway' "$WORK/inspect.out" || die "inspect printed no gateway"
grep -q 'Local environment' "$WORK/inspect.out" || die "inspect printed no local section"
ok "inspects a profile"

# ---- convert --------------------------------------------------------------
"$OPENP2S" convert "$PROFILE" -o "$WORK/out.ovpn" || die "convert failed"

[ "$(stat -c %a "$WORK/out.ovpn")" = "600" ] \
  || die "the converted config is not 0600; it embeds the tls-auth key"
ok "writes the converted config 0600"

# With or without an argument: `auth-user-pass` alone is a valid directive.
! grep -qE '^auth-user-pass([[:space:]]|$)' "$WORK/out.ovpn" \
  || die "portable output names a credential source"
! grep -qE '^management([[:space:]]|$)' "$WORK/out.ovpn" \
  || die "portable output names a management socket"
! grep -q '/run/user/' "$WORK/out.ovpn" \
  || die "portable output contains a runtime path"
ok "names no credential delivery directive and no runtime path"

grep -qE '^remote ' "$WORK/out.ovpn" || die "no remote directive"
grep -q '<tls-auth>' "$WORK/out.ovpn" || die "no inline tls-auth key"
grep -qE '^dev tun$' "$WORK/out.ovpn" || die "no tun device"
ok "carries a remote, a tun device and the inline tls-auth key"

# ---- doctor ---------------------------------------------------------------
#
# A CI runner has no /dev/net/tun and no systemd-resolved, so findings are
# expected. What must hold is that the command ran, parsed the profile and
# rendered its sections - not that it found nothing.
set +e
"$OPENP2S" doctor "$PROFILE" > "$WORK/doctor.out" 2>&1
doctor_rc=$?
set -e

case "$doctor_rc" in
  0|1) ;;
  *) cat "$WORK/doctor.out" >&2; die "doctor exited $doctor_rc, expected 0 or 1" ;;
esac
grep -q 'Profile:' "$WORK/doctor.out" \
  || { cat "$WORK/doctor.out" >&2; die "doctor did not reach the profile section"; }
# It must also see the installed OpenVPN, not merely fail gracefully without it.
grep -q 'OpenP2S OpenVPN binary is built' "$WORK/doctor.out" \
  || { cat "$WORK/doctor.out" >&2; die "doctor did not find the installed OpenVPN"; }
ok "runs its checks, finds the OpenVPN and reports on the profile (exit $doctor_rc)"

# ---- status ---------------------------------------------------------------
#
# Nothing is connected here, so this asserts the disconnected contract and,
# more usefully, that --json really is one JSON document on stdout.
set +e
"$OPENP2S" status --json > "$WORK/status.json" 2> "$WORK/status.err"
status_rc=$?
set -e
[ "$status_rc" = "1" ] || die "status exited $status_rc when disconnected, expected 1"

# node, not python3: the package implies no Python dependency.
node -e '
  const fs = require("node:fs");
  const doc = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (doc.state !== "disconnected") throw new Error("state is " + doc.state);
  if (doc.connected !== false) throw new Error("connected is " + doc.connected);
' "$WORK/status.json" || die "status --json is not the documented disconnected document"
ok "status --json is one JSON document on stdout"

# ---- man page -------------------------------------------------------------
if [ "$PREFIX" = "/usr" ]; then
    man -w openp2s >/dev/null || die "no man page installed"
    ok "installs a man page"
fi

printf '\n==> installed package smoke test passed\n\n'
