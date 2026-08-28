#!/usr/bin/env bash
#
# Assemble a portable release bundle and the tarball that ships it.
#
#   openp2s-<version>-linux-<arch>.tar.gz
#     openp2s-<version>-linux-<arch>/
#       openp2s                 the CLI, one self-contained executable
#       openvpn-openp2s         OpenVPN + patches/<version>/long-credentials.patch
#       BUILDINFO               provenance for both binaries
#       SHA256SUMS              hashes of everything beside it
#       LICENSE                 OpenP2S's own licence
#       NODE_LICENSE            the exact Node runtime inside the executable
#       THIRD_PARTY_NOTICES     generated from what is actually bundled
#       README.md
#   openvpn-<version>-openp2s-source.tar.gz   GPL corresponding source
#
# Extract it and run ./openp2s: the CLI finds openvpn-openp2s beside itself,
# so the bundle works in place with nothing installed.
#
# What is built from source: OpenVPN, from the pinned upstream tarball. The
# CLI is bundled from this repository's TypeScript into the build machine's
# Node runtime, which is a prebuilt distribution - its version and sha256 are
# in BUILDINFO. No prebuilt OpenP2S or patched OpenVPN is ever downloaded.
#
# Usage: scripts/build-release.sh [--out <dir>] [--skip-build]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_OUT="$REPO_ROOT/build/release"
OUT="$DEFAULT_OUT"
SKIP_BUILD=0

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="${2:?--out needs a path}"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help) sed -n '2,28p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

VERSION="$(grep -E '^\s*"version"' "$REPO_ROOT/package.json" | head -1 | cut -d'"' -f4)"
[ -n "$VERSION" ] || die "could not read the version from package.json"

case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
esac
BUNDLE_NAME="openp2s-$VERSION-linux-$ARCH"

if [ "$SKIP_BUILD" -eq 0 ]; then
    log "building the patched OpenVPN"
    "$REPO_ROOT/scripts/build-openvpn.sh" >/dev/null || die "OpenVPN build failed"
    log "building the CLI executable"
    "$REPO_ROOT/scripts/build-cli.sh" >/dev/null || die "CLI build failed"
fi

CLI="$REPO_ROOT/build/cli/openp2s"
OPENVPN="$REPO_ROOT/build/openvpn/sbin/openvpn"
BUILDINFO="$REPO_ROOT/build/openvpn/BUILDINFO"
CLI_BUILDINFO="$REPO_ROOT/build/cli/CLI-BUILDINFO"
NODE_LICENSE="$REPO_ROOT/build/cli/NODE_LICENSE"
METAFILE="$REPO_ROOT/build/cli/esbuild-meta.json"

# ------------------------------------------------------------ preflight ----
#
# --skip-build means "do not compile again", never "trust whatever is in
# build/": a release is the one artifact where a stale input is unrecoverable.
log "verifying inputs"

[ -x "$CLI" ]           || die "missing $CLI (run scripts/build-cli.sh)"
[ -x "$OPENVPN" ]       || die "missing $OPENVPN (run scripts/build-openvpn.sh)"
[ -f "$BUILDINFO" ]     || die "missing $BUILDINFO (run scripts/build-openvpn.sh)"
[ -f "$CLI_BUILDINFO" ] || die "missing $CLI_BUILDINFO (run scripts/build-cli.sh)"
[ -f "$NODE_LICENSE" ]  || die "missing $NODE_LICENSE (run scripts/build-cli.sh)"
[ -f "$METAFILE" ]      || die "missing $METAFILE (run scripts/build-cli.sh)"

# The bundled CLI must be the version on the tin.
CLI_VERSION="$("$CLI" --version 2>/dev/null)" || die "$CLI does not run"
[ "$CLI_VERSION" = "$VERSION" ] || die \
    "the built CLI reports $CLI_VERSION but package.json says $VERSION; rerun scripts/build-cli.sh"
"$CLI" --help 2>&1 | grep 'openp2s' >/dev/null || die "$CLI does not print OpenP2S help"

# Fail closed: a release builder that leaves this as a suggestion will
# eventually publish something unverified.
log "verifying OpenVPN provenance"
"$REPO_ROOT/scripts/verify-provenance.sh" >/dev/null \
    || die "OpenVPN provenance verification failed; run scripts/verify-provenance.sh"

# A rebuilt binary with a stale BUILDINFO would ship and then be refused at
# runtime.
check_sha() {
    local file="$1" declared="$2" what="$3" actual
    actual="$(sha256sum "$file" | cut -d' ' -f1)"
    [ -n "$declared" ] || die "$what has no recorded sha256"
    [ "$actual" = "$declared" ] || die \
"$what does not match its provenance record
  file:      $actual
  recorded:  $declared
Rebuild so the two agree."
}
check_sha "$OPENVPN" "$(grep '^binary_sha256=' "$BUILDINFO" | cut -d= -f2)" "the OpenVPN binary"
check_sha "$CLI" "$(grep '^cli_binary_sha256=' "$CLI_BUILDINFO" | cut -d= -f2)" "the CLI executable"

# Exactly the two shipped patches. Anything else is not what
# THIRD_PARTY_NOTICES and the package description say.
EXPECTED_STACK="long-credentials experimental-azure-compat"
PATCH_STACK="$(grep '^patch_stack=' "$BUILDINFO" | cut -d= -f2)"
[ "$PATCH_STACK" = "$EXPECTED_STACK" ] || die \
"this OpenVPN was built with the patch stack '$PATCH_STACK', not '$EXPECTED_STACK'.
Rebuild with scripts/build-openvpn.sh."
[ "$(grep '^azure_compat_available=' "$BUILDINFO" | cut -d= -f2)" = "1" ] \
    || die "this OpenVPN does not carry the compat patch; there is one build and it must"

# ------------------------------------------------------------- staging ----
#
# Assembled under a temporary name and moved into place. `rm -rf` on a
# caller-supplied --out is not something this script does - `--out "$HOME"`
# must not delete a home directory. Only the default location is managed.
STAGE_ROOT="$(mktemp -d)"
trap 'rm -rf "$STAGE_ROOT"' EXIT
STAGE="$STAGE_ROOT/$BUNDLE_NAME"
mkdir -p "$STAGE"

log "assembling $BUNDLE_NAME"

install -m 0755 "$CLI" "$STAGE/openp2s"
install -m 0755 "$OPENVPN" "$STAGE/openvpn-openp2s"
install -m 0644 "$REPO_ROOT/LICENSE" "$STAGE/LICENSE"
install -m 0644 "$REPO_ROOT/README.md" "$STAGE/README.md"
install -m 0644 "$NODE_LICENSE" "$STAGE/NODE_LICENSE"

# Both halves. The executable is a copy of a specific Node binary, so "which
# Node" is as much its identity as "which OpenVPN commit" is the other's.
{
    cat "$BUILDINFO"
    printf '\n'
    grep -v '^#' "$CLI_BUILDINFO"
} > "$STAGE/BUILDINFO"
chmod 0644 "$STAGE/BUILDINFO"

# Verbatim: it carries the OpenSSL linking exception this build depends on.
OPENVPN_VERSION="$(grep '^openvpn_version=' "$BUILDINFO" | cut -d= -f2)"
TARBALL="$REPO_ROOT/build/openvpn-src/openvpn-$OPENVPN_VERSION.tar.gz"
[ -f "$TARBALL" ] || die "missing $TARBALL, needed for the OpenVPN licence text"
tar -xzOf "$TARBALL" "openvpn-$OPENVPN_VERSION/COPYING" > "$STAGE/openvpn-COPYING" \
    || die "could not extract COPYING from $TARBALL"
chmod 0644 "$STAGE/openvpn-COPYING"

# Assembled before the notices, which name it and whose generator checks it
# exists. Distributing a modified GPLv2 binary is an obligation to supply the
# source; pointing at a build script does not discharge it.
log "assembling the corresponding source"
"$REPO_ROOT/scripts/build-source-tarball.sh" --out "$STAGE_ROOT" >/dev/null \
    || die "could not assemble the corresponding source tarball"
OUT_SOURCE_TARBALL="$(printf '%s\n' "$STAGE_ROOT"/openvpn-*-openp2s-source.tar.gz)"
[ -f "$OUT_SOURCE_TARBALL" ] || die "the corresponding source tarball was not produced"

# ------------------------------------------------- third party notices ----
#
# From esbuild's metafile - every module actually compiled in - rather than a
# hand-maintained list.
# Last: it names the other files and the generator checks they exist.
log "generating third-party notices from the bundle"
( cd "$REPO_ROOT" && node scripts/generate-notices.ts \
    "$METAFILE" "$BUILDINFO" "$CLI_BUILDINFO" \
    "$STAGE/openvpn-COPYING" "$STAGE/NODE_LICENSE" \
    "$OUT_SOURCE_TARBALL" ) > "$STAGE/THIRD_PARTY_NOTICES" \
    || die "could not generate THIRD_PARTY_NOTICES"
chmod 0644 "$STAGE/THIRD_PARTY_NOTICES"

# ------------------------------------------------------------ checksums ---
log "writing SHA256SUMS"
( cd "$STAGE" && sha256sum -- * > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS )
chmod 0644 "$STAGE/SHA256SUMS"

# --------------------------------------------------------------- verify ---
log "verifying the bundle"
( cd "$STAGE" && sha256sum --quiet --check SHA256SUMS ) || die "checksum verification failed"

# The full policy gate against the binary that is actually in the bundle.
"$REPO_ROOT/scripts/check-binary-policy.sh" \
    --binary "$STAGE/openvpn-openp2s" --buildinfo "$STAGE/BUILDINFO" >/dev/null \
    || die "the bundled OpenVPN does not satisfy the binary policy"

BUNDLED_VERSION="$("$STAGE/openp2s" --version 2>&1)" || die "the bundled CLI does not run"
[ "$BUNDLED_VERSION" = "$VERSION" ] \
    || die "the bundled CLI reports $BUNDLED_VERSION, expected $VERSION"
"$STAGE/openvpn-openp2s" --version >/dev/null || die "the bundled OpenVPN does not run"

# The bundle must work in place. Asserted, not assumed: `inspect` alone
# tolerates a missing OpenVPN, so require --compat to name the one here.
LOCATED="$( cd "$STAGE" && ./openp2s inspect \
    "$REPO_ROOT/tests/fixtures/azure-schema.xml" --compat 2>&1 )" \
    || die "the bundled CLI cannot inspect a profile"
grep -q "openvpn-openp2s" <<<"$LOCATED" || die \
"the bundled CLI did not find openvpn-openp2s beside itself.
The portable bundle is meant to work in place; without sibling discovery it
cannot. See locateOpenVpnBinary in src/openvpn/binary.ts."
grep -q "USER_PASS_LEN: *4096" <<<"$LOCATED" \
    || die "the bundled CLI does not report USER_PASS_LEN 4096 for its OpenVPN"

# ---------------------------------------------------------- publication ---
if [ "$OUT" = "$DEFAULT_OUT" ]; then
    rm -rf "$OUT"
else
    # A caller-supplied destination is never removed, only created.
    [ ! -e "$OUT" ] || die "$OUT already exists; remove it yourself or choose another --out"
fi
mkdir -p "$OUT"

cp -a "$STAGE/." "$OUT/"
install -m 0644 "$OUT_SOURCE_TARBALL" "$OUT/$(basename "$OUT_SOURCE_TARBALL")"

TAR_ARGS=(--owner=0 --group=0 --numeric-owner --sort=name)
[ -n "${SOURCE_DATE_EPOCH:-}" ] && TAR_ARGS+=(--mtime="@$SOURCE_DATE_EPOCH")
( cd "$STAGE_ROOT" && tar "${TAR_ARGS[@]}" -cf - "$BUNDLE_NAME" ) \
    | gzip -9n > "$OUT/$BUNDLE_NAME.tar.gz"
chmod 0644 "$OUT/$BUNDLE_NAME.tar.gz"


printf '\n'
log "release bundle ready"
printf '\n'
printf '    %s\n\n' "$OUT"
( cd "$OUT" && ls -la | tail -n +2 | awk 'NF>=9 {printf "    %-11s %10s  %s\n", $1, $5, $NF}' )
printf '\n'
printf '    Run it in place:\n'
printf '      tar xf %s.tar.gz && cd %s && ./openp2s status\n' "$BUNDLE_NAME" "$BUNDLE_NAME"
printf '\n'
printf '    Or install manually under /usr/local (the .deb owns /usr):\n'
printf '      sudo install -D -m 0755 openp2s          /usr/local/bin/openp2s\n'
printf '      sudo install -D -m 0755 openvpn-openp2s  /usr/local/lib/openp2s/openvpn\n'
printf '      sudo install -D -m 0644 BUILDINFO        /usr/local/lib/openp2s/BUILDINFO\n'
printf '      sudo install -D -m 0644 LICENSE          /usr/local/share/doc/openp2s/LICENSE\n'
printf '      sudo install -D -m 0644 NODE_LICENSE     /usr/local/share/doc/openp2s/NODE_LICENSE\n'
printf '      sudo install -D -m 0644 openvpn-COPYING  /usr/local/share/doc/openp2s/openvpn-COPYING\n'
printf '      sudo install -D -m 0644 THIRD_PARTY_NOTICES /usr/local/share/doc/openp2s/THIRD_PARTY_NOTICES\n'
printf '\n'
