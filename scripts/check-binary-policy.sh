#!/usr/bin/env bash
#
# What the shipped OpenVPN must and must not be.
#
# One binary, carrying both patches: long-credentials (always active) and
# experimental-azure-compat (compiled in, inert unless a config asks for it).
# TLS ClientHello shaping and key logging do not ship at all; the option list
# below is what asserts that.
#
# ## What this can and cannot prove
#
# Two checks read the binary: the options it understands, and whether PKCS11 is
# compiled in. The rest are properties of how it was built - USER_PASS_LEN is a
# compile-time constant with no runtime expression - and come from the
# provenance chain:
#
#     patches/manifest  pins the tarball and patches by sha256
#     build-openvpn.sh  verifies both, and asserts the patched source
#     BUILDINFO         records the sha256 of the resulting binary
#     this script       checks the binary is that one, then trusts BUILDINFO
#
# The hash check is what makes the last step mean anything: without it,
# "BUILDINFO says 4096" is a statement about a note sitting near a file. It
# also catches a binary modified after its hash was recorded.
#
# Usage: scripts/check-binary-policy.sh [--binary <path>] [--buildinfo <path>]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BINARY="build/openvpn/sbin/openvpn"
BUILDINFO=""

die() { printf '\n  policy violation: %s\n\n' "$1" >&2; exit 1; }
ok()  { printf '  ok  %s\n' "$1"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BINARY="${2:?--binary needs a path}"; shift 2 ;;
        --buildinfo) BUILDINFO="${2:?--buildinfo needs a path}"; shift 2 ;;
        -h|--help) sed -n '2,36p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -x "$BINARY" ] || die "no executable OpenVPN at $BINARY"

# The build tree keeps BUILDINFO above sbin/; every install keeps it beside
# the binary. Try both.
if [ -z "$BUILDINFO" ]; then
    for candidate in "$(dirname "$BINARY")/BUILDINFO" "$(dirname "$BINARY")/../BUILDINFO"; do
        [ -f "$candidate" ] && { BUILDINFO="$candidate"; break; }
    done
fi
[ -n "$BUILDINFO" ] && [ -f "$BUILDINFO" ] \
    || die "no BUILDINFO found for $BINARY; its provenance is unknown. Pass --buildinfo."

# Fail closed on a missing or duplicated key, and never inside a pipeline whose
# exit status set -e would act on before the message could be printed.
buildinfo() {
    local key="$1" value count
    count="$(awk -F= -v k="$key" '$1 == k { n++ } END { print n + 0 }' "$BUILDINFO")"
    [ "$count" = "1" ] || die "BUILDINFO has $count entries for '$key', expected exactly 1"
    value="$(awk -F= -v k="$key" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$BUILDINFO")"
    [ -n "$value" ] || die "BUILDINFO has an empty '$key'"
    printf '%s' "$value"
}

printf '\n==> binary policy for %s\n' "$BINARY"
printf '    provenance from %s\n\n' "$BUILDINFO"

# ---- 1. is this BUILDINFO actually about this binary? --------------------
# Everything below depends on the answer.
ACTUAL_SHA="$(sha256sum "$BINARY" | cut -d' ' -f1)"
RECORDED_SHA="$(buildinfo binary_sha256)"
[ "$ACTUAL_SHA" = "$RECORDED_SHA" ] || die \
"the binary does not match the BUILDINFO beside it
  binary:    $ACTUAL_SHA
  BUILDINFO: $RECORDED_SHA
Either the binary was modified after it was built (stripping does this), or
this BUILDINFO describes a different build. Nothing it says applies here."
ok "binary matches its BUILDINFO ($ACTUAL_SHA)"

# ---- 2. what the binary itself says --------------------------------------
#
# Read once: `--version | head -1 | grep -q` lets a SIGPIPE decide the answer
# under pipefail, which here would pass a forbidden PKCS11 build.
VERSION_OUTPUT="$("$BINARY" --version 2>&1)" || die "$BINARY --version failed"
[ -n "$VERSION_OUTPUT" ] || die "$BINARY --version produced nothing"
VERSION_LINE="${VERSION_OUTPUT%%$'\n'*}"

# OpenVPN exits non-zero for --help, so the status is not a usable signal;
# emptiness is, and is checked below.
HELP_OUTPUT="$("$BINARY" --help 2>&1 || true)"
[ -n "$HELP_OUTPUT" ] || die "$BINARY --help produced nothing"

# Exhaustive rather than current: an option removed from the tree but left in
# a stale build directory is what this catches.
#
# --experimental-azure-compat is not here: it ships, inert. What keeps that
# safe is its OPT_P_GENERAL permission mask, asserted by check-patch-policy.sh.
FORBIDDEN_OPTIONS="
azure-tls-sni
azure-tls-alpn
azure-tls-pha
azure-tls-shape
azure-keylog
keylog
tls-keylog
"

# A here-string, not a pipeline. `grep -q` exits on the first match and closes
# the pipe while the producer is still writing, and under `set -o pipefail` the
# producer's EPIPE then becomes the pipeline's status - so a *successful* match
# can be reported as a failure. Measured at roughly 1 run in 100 against this
# 34 KB help text, which is exactly the kind of flake that wastes an afternoon.
for opt in $FORBIDDEN_OPTIONS; do
    # Whole token, so --azure-compat does not match --azure-compat-other.
    if grep -Eq -- "(^|[[:space:]])--${opt}([=,[:space:]]|\$)" <<<"$HELP_OUTPUT"; then
        die "the default build understands --$opt; it must be an opt-in build only"
    fi
done
ok "understands none of the TLS-shaping or key-logging research options"

# The one capability the binary must have, so the flag does not die with
# "unknown option" on a gateway that needs it.
if ! grep -Eq -- '(^|[[:space:]])--experimental-azure-compat([=,[:space:]]|$)' <<<"$HELP_OUTPUT"; then
    die "the binary does not understand --experimental-azure-compat; there is one build and it must carry the patch"
fi
ok "understands --experimental-azure-compat (compiled in, off by default)"

# misc.h already defines USER_PASS_LEN as 4096 under #ifdef ENABLE_PKCS11, so
# an autodetected pkcs11-helper would make the patch inert while every other
# check still passed.
if grep -q '\[PKCS11\]' <<<"$VERSION_LINE"; then
    die "the build has PKCS11 support, so upstream's PKCS11 USER_PASS_LEN branch is active and the patch is inert"
fi
ok "PKCS11 support is absent, so upstream's 4096 branch is not what is active"

# ---- 3. what it was built from -------------------------------------------
PATCH_STACK="$(buildinfo patch_stack)"
EXPECTED_STACK="long-credentials experimental-azure-compat"
[ "$PATCH_STACK" = "$EXPECTED_STACK" ] || die \
"the patch stack is '$PATCH_STACK', expected exactly '$EXPECTED_STACK'.
There is one binary and it carries exactly these two patches: neither a build
missing the compat patch nor one carrying anything else."
ok "patch stack is exactly the two shipped patches"

COMPAT="$(buildinfo azure_compat_available)"
[ "$COMPAT" = "1" ] || die \
"BUILDINFO reports azure_compat_available=$COMPAT, expected 1.
The shipped binary carries the compat patch; a build without it cannot serve
--experimental-azure-compat."
ok "BUILDINFO agrees the compat patch is compiled in"

USER_PASS_LEN="$(buildinfo user_pass_len)"
[ "$USER_PASS_LEN" = "4096" ] || die "BUILDINFO reports USER_PASS_LEN=$USER_PASS_LEN, expected 4096"
ok "USER_PASS_LEN is 4096"

# ---- 4. does that provenance hold up against the manifest? ---------------
# What turns "BUILDINFO says 4096" into something worth believing. Run here so
# this gate fails closed on its own rather than trusting the caller.
printf '\n'
scripts/verify-provenance.sh --binary "$BINARY" --buildinfo "$BUILDINFO" >/dev/null 2>&1 \
    || die "provenance verification failed; run: scripts/verify-provenance.sh --binary $BINARY --buildinfo $BUILDINFO"
ok "provenance verified against patches/manifest"

printf '\n==> binary policy satisfied\n\n'
