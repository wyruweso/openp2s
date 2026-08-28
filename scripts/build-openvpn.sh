#!/usr/bin/env bash
#
# Build the OpenP2S OpenVPN binary:
#
#     upstream OpenVPN release tarball  (pinned by sha256)
#   + patches/<version>/long-credentials.patch          (pinned by sha256)
#   + patches/<version>/experimental-azure-compat.patch (pinned by sha256)
#   = build/openvpn/sbin/openvpn
#
# The pins live in patches/manifest, which is the single source of truth.
# Nothing here reads a mutable branch.
#
# One binary, carrying both shipped patches:
#
#   long-credentials.patch          always active; the only reason a stock
#                                   OpenVPN cannot authenticate
#   experimental-azure-compat.patch compiled in, inert unless the config
#                                   contains --experimental-azure-compat
#
# The second is off by default because measurement showed it is not required,
# and only the local config can reach it: OPT_P_GENERAL means a server cannot
# push it, and nothing shipped reads the environment. Both are asserted by
# scripts/check-patch-policy.sh.
#
#   --openvpn-version X   Build a different pinned release (default: manifest)
#   --jobs N              Parallel make jobs
#   --keep-build          Leave the unpacked source tree in place

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/patches/manifest"
BUILD_ROOT="$REPO_ROOT/build/openvpn"
SRC_ROOT="$REPO_ROOT/build/openvpn-src"

JOBS="$(nproc 2>/dev/null || echo 4)"
KEEP_BUILD=0
VERSION=""

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --jobs) JOBS="${2:?--jobs needs a value}"; shift 2 ;;
        --jobs=*) JOBS="${1#*=}"; shift ;;
        --openvpn-version) VERSION="${2:?--openvpn-version needs a value}"; shift 2 ;;
        --keep-build) KEEP_BUILD=1; shift ;;
        # Accepted and ignored: there is one binary now.
        --with-azure-compat)
            printf 'note: --with-azure-compat is the default now; there is one binary\n' >&2
            shift ;;
        -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -f "$MANIFEST" ] || die "missing build manifest: $MANIFEST"

# One reader for patches/manifest, shared with the policy gates. Independent
# parsers are how a build and its verifier end up disagreeing about which file
# they are checking. See scripts/lib/manifest.sh.
# shellcheck source=scripts/lib/manifest.sh
. "$REPO_ROOT/scripts/lib/manifest.sh"
manifest() { manifest_get "$1"; }

[ -n "$VERSION" ] || VERSION="$(manifest DEFAULT_VERSION)"
[ -n "$VERSION" ] || die "no OPENVPN version selected and no DEFAULT_VERSION in the manifest"

TARBALL_NAME="$(manifest "$VERSION.tarball")"
TARBALL_URL="$(manifest "$VERSION.url")"
TARBALL_SHA="$(manifest "$VERSION.tarball_sha256")"
OPENVPN_TAG="$(manifest "$VERSION.tag")"
OPENVPN_COMMIT="$(manifest "$VERSION.commit")"
USER_PASS_LEN="$(manifest "$VERSION.user_pass_len")"
TLS_CHANNEL_BUF_SIZE="$(manifest "$VERSION.tls_channel_buf_size")"

[ -n "$TARBALL_URL" ] || die "OpenVPN $VERSION is not in patches/manifest.
Supported versions: $(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.url' "$MANIFEST" | sed 's/\.url$//' | sort -u | tr '\n' ' ')
A version is added only after it passes the probe/test matrix."

# Mandatory: an empty sha256 would give a BUILDINFO stating a pin nothing
# verified, which looks like assurance.
[ -n "$TARBALL_SHA" ] || die "manifest has no tarball_sha256 for OpenVPN $VERSION"
[ -n "$USER_PASS_LEN" ] || die "manifest has no user_pass_len for OpenVPN $VERSION"
[ -n "$TLS_CHANNEL_BUF_SIZE" ] || die "manifest has no tls_channel_buf_size for OpenVPN $VERSION"

# --------------------------------------------------------- patch stack ----
PATCH_NAMES=(); PATCH_FILES=(); PATCH_HASHES=()

add_patch() {
    local label="$1" key="$2"
    local file; file="$(manifest "$VERSION.patch.$key")"
    local hash; hash="$(manifest "$VERSION.patch.${key}_sha256")"
    [ -n "$file" ] || die "manifest has no patch '$key' for OpenVPN $VERSION"

    [ -n "$hash" ] || die "manifest has no sha256 for patch '$key' (OpenVPN $VERSION)"
    [ -f "$REPO_ROOT/$file" ] || die "missing patch: $REPO_ROOT/$file"
    PATCH_NAMES+=("$label"); PATCH_FILES+=("$REPO_ROOT/$file"); PATCH_HASHES+=("$hash")
}

# Both, always. long-credentials must apply to pristine upstream sources.
add_patch long-credentials long_credentials
add_patch experimental-azure-compat experimental_azure_compat

# ------------------------------------------------------- prerequisites ----
missing=()
for tool in curl tar patch make cc sha256sum pkg-config; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
[ ${#missing[@]} -eq 0 ] || die "missing build tools: ${missing[*]}
On Debian/Ubuntu: sudo apt install build-essential curl tar patch pkg-config"

if ! pkg-config --exists openssl 2>/dev/null && [ ! -f /usr/include/openssl/ssl.h ]; then
    die "OpenSSL development headers not found.
On Debian/Ubuntu: sudo apt install libssl-dev"
fi

# ------------------------------------------------------------ download ----
mkdir -p "$SRC_ROOT"
TARBALL="$SRC_ROOT/${TARBALL_NAME:-openvpn-$VERSION.tar.gz}"

verify_tarball() {
    [ -f "$TARBALL" ] || return 1
    [ "$(sha256sum "$TARBALL" | cut -d' ' -f1)" = "$TARBALL_SHA" ]
}

if verify_tarball; then
    log "using cached $(basename "$TARBALL") (sha256 verified)"
else
    [ -f "$TARBALL" ] && { log "cached tarball failed its hash check, re-downloading"; rm -f "$TARBALL"; }
    log "downloading OpenVPN $VERSION"
    curl -fSL --proto '=https' --tlsv1.2 -o "$TARBALL" "$TARBALL_URL" \
        || die "download failed: $TARBALL_URL"
    verify_tarball || die "sha256 mismatch for $(basename "$TARBALL")
  expected: $TARBALL_SHA
  actual:   $(sha256sum "$TARBALL" | cut -d' ' -f1)
Refusing to build from an unverified source tarball."
    log "sha256 verified: $TARBALL_SHA"
fi

# -------------------------------------------------------- verify patches --
PATCH_STACK=""
for i in "${!PATCH_FILES[@]}"; do
    actual="$(sha256sum "${PATCH_FILES[$i]}" | cut -d' ' -f1)"
    expected="${PATCH_HASHES[$i]}"
    if [ "$actual" != "$expected" ]; then
        die "patch sha256 mismatch for ${PATCH_NAMES[$i]}
  expected: $expected
  actual:   $actual
$(basename "${PATCH_FILES[$i]}") changed without updating patches/manifest."
    fi
    log "patch verified: ${PATCH_NAMES[$i]} (${actual:0:16}...)"
    PATCH_STACK="$PATCH_STACK ${PATCH_NAMES[$i]}"
done

# --------------------------------------------------------- extract+patch --
WORK="$SRC_ROOT/openvpn-$VERSION"
rm -rf "$WORK"
log "extracting"
tar xzf "$TARBALL" -C "$SRC_ROOT"
[ -d "$WORK" ] || die "expected $WORK after extracting the tarball"

for i in "${!PATCH_FILES[@]}"; do
    log "applying patch: ${PATCH_NAMES[$i]}"
    # --dry-run first so a rejected hunk never leaves a half-patched tree.
    # --fuzz=0: the tarball is pinned, so an inexact hunk means divergence.
    # --no-backup-if-mismatch so nothing litters .orig files.
    patch -p1 -d "$WORK" --dry-run --silent --fuzz=0 --no-backup-if-mismatch < "${PATCH_FILES[$i]}" \
        || die "${PATCH_NAMES[$i]} does not apply cleanly to OpenVPN $VERSION"
    patch -p1 -d "$WORK" --silent --fuzz=0 --no-backup-if-mismatch < "${PATCH_FILES[$i]}"
done

# ------------------------------------------------- verify the patched source --
#
# The hashes above prove the inputs; this proves the result. A patch that
# applied cleanly but landed somewhere harmless would otherwise still yield a
# binary BUILDINFO calls patched. Read from the tree about to be compiled.
assert_define() {
    local file="$1" name="$2" want="$3" got
    got="$(grep -E "^#define[[:space:]]+$name[[:space:]]+[0-9]+" "$WORK/$file" \
        | tail -1 | awk '{print $3}')"
    [ -n "$got" ] || die "could not find $name in $file after patching"
    [ "$got" = "$want" ] || die \
"$name is $got in the patched source, expected $want
The patch applied but did not produce the expected result. $file may have been
restructured upstream; regenerate patches/$VERSION/long-credentials.patch."
    log "patched source verified: $name = $got"
}

assert_define src/openvpn/misc.h USER_PASS_LEN "$USER_PASS_LEN"
assert_define src/openvpn/common.h TLS_CHANNEL_BUF_SIZE "$TLS_CHANNEL_BUF_SIZE"

# ---------------------------------------------------------------- build ---
log "configuring"
# Optional features that affect the dependency set or protocol behaviour are
# selected explicitly, so no library silently changes the feature set because
# it happened to be installed on the build machine.
#
# --disable-pkcs11 is load-bearing rather than tidy. misc.h defines
# USER_PASS_LEN as 4096 under #ifdef ENABLE_PKCS11 and 128 in the #else that
# long-credentials.patch replaces, so an autodetected pkcs11-helper would make
# the patch silently inert while every check still passed.
CONFIGURE_FLAGS=(
    --prefix="$BUILD_ROOT"
    --with-crypto-library=openssl
    # Not needed by an Azure P2S client, and each one is a dependency that
    # could otherwise appear or disappear with the build environment.
    --disable-lzo
    --disable-lz4
    --disable-comp-stub
    --disable-pkcs11
    --disable-plugins
    --disable-plugin-auth-pam
    --disable-plugin-down-root
    --disable-systemd
    --disable-selinux
    --disable-port-share
    --disable-async-push
    --disable-ntlm
    --disable-unit-tests
    # DCO is off: never part of the fix, and it costs a libnl-genl dependency
    # in the build and the package for a data path we need not optimise.
    --disable-dco
    # The management interface is how the token reaches OpenVPN in memory.
    --enable-fragment
    --enable-management
    # NOT --disable-debug: that compiles out dmsg() and every verb 7+ message,
    # including D_SHOW_OCC, which `openp2s probe --verbose` exists to show.
    # Normal runs use verb 3-4 and are unaffected.
    --enable-debug
)

( cd "$WORK" && CFLAGS="${CFLAGS:--O2}" ./configure "${CONFIGURE_FLAGS[@]}" ) \
    > "$SRC_ROOT/configure.log" 2>&1 \
    || die "configure failed, see $SRC_ROOT/configure.log
Missing development headers are the usual cause. On Debian/Ubuntu:
  sudo apt install build-essential libssl-dev libnl-genl-3-dev libcap-ng-dev"

log "compiling (-j$JOBS)"
( cd "$WORK" && make -j"$JOBS" ) > "$SRC_ROOT/build.log" 2>&1 \
    || die "build failed, see $SRC_ROOT/build.log"

BUILT="$WORK/src/openvpn/openvpn"
[ -x "$BUILT" ] || die "build reported success but $BUILT is missing"

mkdir -p "$BUILD_ROOT/sbin"
install -m 0755 "$BUILT" "$BUILD_ROOT/sbin/openvpn"

# ------------------------------------------------------------ buildinfo ---
BINARY_SHA="$(sha256sum "$BUILD_ROOT/sbin/openvpn" | cut -d' ' -f1)"

# The compiler and its flags decide the bytes as much as the source does.
# Recorded rather than normalised: CC and CFLAGS are still honoured from the
# environment, and this makes that visible.
CC_BIN="${CC:-cc}"
CC_VERSION="$("$CC_BIN" --version 2>/dev/null | head -1)"
OPENSSL_VERSION="$(pkg-config --modversion openssl 2>/dev/null || printf 'unknown')"
CONFIGURE_FLAGS_RECORD="$(printf '%s ' "${CONFIGURE_FLAGS[@]}" | sed "s|--prefix=[^ ]* ||")"

cat > "$BUILD_ROOT/BUILDINFO" <<EOF
# Generated by scripts/build-openvpn.sh. Not checked in.
#
# openvpn_tag and openvpn_commit are release metadata read from
# patches/manifest. The cryptographic anchor for what was actually built is
# openvpn_tarball_sha256: this binary came from that tarball, not from a git
# checkout of that commit.
openvpn_version=$VERSION
openvpn_tag=${OPENVPN_TAG:-}
openvpn_commit=${OPENVPN_COMMIT:-}
openvpn_tarball_sha256=$TARBALL_SHA
patch_stack=$(printf '%s' "${PATCH_NAMES[*]}")
long_credentials_sha256=${PATCH_HASHES[0]}
experimental_azure_compat_sha256=${PATCH_HASHES[1]}
binary_sha256=$BINARY_SHA
user_pass_len=$USER_PASS_LEN
tls_channel_buf_size=$TLS_CHANNEL_BUF_SIZE
azure_compat_available=1
built_on=$(uname -srm)
build_cc=$CC_VERSION
build_cflags=${CFLAGS:--O2}
build_openssl=$OPENSSL_VERSION
build_configure_flags=$CONFIGURE_FLAGS_RECORD
EOF
cp "$BUILD_ROOT/BUILDINFO" "$BUILD_ROOT/sbin/BUILDINFO"

[ "$KEEP_BUILD" -eq 0 ] && rm -rf "$WORK"

printf '\n'
log "OpenP2S OpenVPN binary ready"
printf '\n'
printf '    upstream:  OpenVPN %s (%s, commit %s)\n' \
    "$VERSION" "${OPENVPN_TAG:-}" "${OPENVPN_COMMIT:0:12}"
printf '    patches:  %s\n' "$PATCH_STACK"
printf '    binary:    %s\n' "$BUILD_ROOT/sbin/openvpn"
printf '    sha256:    %s\n' "$BINARY_SHA"
printf '\n'
