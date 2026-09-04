#!/usr/bin/env bash
#
# Build a Debian/Ubuntu package.
#
#   /usr/bin/openp2s                    the CLI, one self-contained executable
#   /usr/lib/openp2s/openvpn            OpenVPN + long-credentials.patch
#   /usr/lib/openp2s/BUILDINFO          upstream version, commit, hashes
#   /usr/share/doc/openp2s/…            copyright, licences, notices, changelog
#
# The patched OpenVPN goes to a private path so it can never shadow the
# distribution's /usr/sbin/openvpn: a stock build cannot authenticate, and the
# failure looks like a server fault. The package does not provide, conflict
# with, or replace `openvpn`.
#
# Dependencies are computed from the binaries on *this* machine, so the package
# targets the distribution it was built on. Recorded in the description; a
# wider claim needs a build matrix.
#
# Usage: scripts/build-deb.sh [--out <dir>] [--skip-build]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/build/deb"
SKIP_BUILD=0

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="${2:?--out needs a path}"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help) sed -n '2,23p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ "$(uname -s)" = "Linux" ] || die "OpenP2S is a Linux client"
command -v dpkg-deb >/dev/null || die "dpkg-deb is required (apt install dpkg-dev)"

# Not optional: without it the package would install onto a machine missing
# the libraries OpenVPN links against and fail at first use.
command -v dpkg-shlibdeps >/dev/null \
    || die "dpkg-shlibdeps is required to compute library dependencies (apt install dpkg-dev)"

VERSION="$(grep -E '^\s*"version"' "$REPO_ROOT/package.json" | head -1 | cut -d'"' -f4)"
[ -n "$VERSION" ] || die "could not read the version from package.json"
ARCH="$(dpkg --print-architecture)"

if [ "$SKIP_BUILD" -eq 0 ]; then
    log "building the patched OpenVPN"
    "$REPO_ROOT/scripts/build-openvpn.sh" >/dev/null || die "OpenVPN build failed"
    log "building the CLI executable"
    "$REPO_ROOT/scripts/build-cli.sh" >/dev/null || die "CLI build failed"
    log "assembling third-party notices"
    "$REPO_ROOT/scripts/build-release.sh" --skip-build >/dev/null || die "release bundle failed"
fi

CLI="$REPO_ROOT/build/cli/openp2s"
OPENVPN="$REPO_ROOT/build/openvpn/sbin/openvpn"
BUILDINFO="$REPO_ROOT/build/openvpn/BUILDINFO"
NOTICES="$REPO_ROOT/build/release/THIRD_PARTY_NOTICES"
NODE_LICENSE="$REPO_ROOT/build/cli/NODE_LICENSE"

# ------------------------------------------------------------ preflight ----
#
# --skip-build means "do not compile again", not "package whatever is lying in
# build/": a stale tree would give openp2s_0.2.0 containing yesterday's 0.1.0.
[ -x "$CLI" ]       || die "missing $CLI (run scripts/build-cli.sh)"
[ -x "$OPENVPN" ]   || die "missing $OPENVPN (run scripts/build-openvpn.sh)"
[ -f "$BUILDINFO" ] || die "missing $BUILDINFO (run scripts/build-openvpn.sh)"

# The copyright file cites it.
[ -f "$NOTICES" ] \
    || die "missing $NOTICES (run scripts/build-release.sh --skip-build)"

# A copy of the node binary is distributed, so its licence is required.
[ -f "$NODE_LICENSE" ] \
    || die "missing $NODE_LICENSE (run scripts/build-cli.sh); the executable embeds the Node runtime"

log "verifying the staged artifacts"

CLI_VERSION="$("$CLI" --version 2>/dev/null)" || die "$CLI does not run"
[ "$CLI_VERSION" = "$VERSION" ] || die \
    "the built CLI reports $CLI_VERSION but the package version is $VERSION; rebuild with scripts/build-cli.sh"

"$REPO_ROOT/scripts/verify-provenance.sh" >/dev/null \
    || die "OpenVPN provenance verification failed; see scripts/verify-provenance.sh"

# The binaries came from build/ and need not have been built here.
check_arch() {
    local file="$1" want="$2" got
    got="$(readelf -h "$file" 2>/dev/null | sed -n 's/^ *Machine: *//p')"
    [ -n "$got" ] || die "$file is not an ELF binary"
    case "$want:$got" in
        amd64:*X86-64*|arm64:*AArch64*|armhf:*ARM*|i386:*Intel*80386*) ;;
        *) die "$file is $got, but the package architecture is $want" ;;
    esac
}
if command -v readelf >/dev/null; then
    check_arch "$CLI" "$ARCH"
    check_arch "$OPENVPN" "$ARCH"
fi

OPENVPN_VERSION="$(grep '^openvpn_version=' "$BUILDINFO" | cut -d= -f2)"
[ -n "$OPENVPN_VERSION" ] || die "BUILDINFO has no openvpn_version"

# ------------------------------------------------------------- staging ----
STAGE="$OUT/openp2s_${VERSION}_${ARCH}"
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/bin" \
         "$STAGE/usr/lib/openp2s" \
         "$STAGE/usr/share/doc/openp2s" \
         "$STAGE/usr/share/man/man1"

# Neither binary is stripped, deliberately.
#
# BUILDINFO records the OpenVPN's sha256 and OpenP2S checks it at runtime; a
# mismatch means `connect` refuses to start. Stripping would change the binary
# after that hash was computed, for 92 KB out of 31 MB. The openp2s executable
# cannot be stripped either: it would disturb the injected SEA blob.
install -m 0755 "$CLI" "$STAGE/usr/bin/openp2s"
install -m 0755 "$OPENVPN" "$STAGE/usr/lib/openp2s/openvpn"
install -m 0644 "$BUILDINFO" "$STAGE/usr/lib/openp2s/BUILDINFO"
install -m 0644 "$REPO_ROOT/README.md" "$STAGE/usr/share/doc/openp2s/README.md"
install -m 0644 "$NOTICES" "$STAGE/usr/share/doc/openp2s/THIRD_PARTY_NOTICES"

# ---- licences, shipped verbatim ------------------------------------------
#
# Upstream texts rather than summaries. OpenVPN's COPYING carries linking
# exceptions for OpenSSL and for Apache-2.0 libraries - and this build *is*
# linked against OpenSSL - while Node's LICENSE enumerates the terms of every
# component bundled inside the node binary that the CLI is a copy of. Neither
# is safe to compress into one SPDX identifier.
OPENVPN_COPYING="$REPO_ROOT/build/openvpn-src/openvpn-$OPENVPN_VERSION/COPYING"
if [ ! -f "$OPENVPN_COPYING" ]; then
    # The source tree is gone unless --keep-build; use the verified tarball.
    TARBALL="$REPO_ROOT/build/openvpn-src/openvpn-$OPENVPN_VERSION.tar.gz"
    [ -f "$TARBALL" ] || die "cannot find OpenVPN COPYING: no source tree and no $TARBALL"
    tar -xzOf "$TARBALL" "openvpn-$OPENVPN_VERSION/COPYING" \
        > "$STAGE/usr/share/doc/openp2s/openvpn-COPYING" \
        || die "could not extract COPYING from $TARBALL"
else
    install -m 0644 "$OPENVPN_COPYING" "$STAGE/usr/share/doc/openp2s/openvpn-COPYING"
fi
chmod 0644 "$STAGE/usr/share/doc/openp2s/openvpn-COPYING"

install -m 0644 "$NODE_LICENSE" "$STAGE/usr/share/doc/openp2s/NODE_LICENSE"

# ---- lintian overrides ---------------------------------------------------
#
# Deliberate properties, declared with reasons rather than silenced by
# discarding lintian's output, so a *new* error still fails the build.
mkdir -p "$STAGE/usr/share/lintian/overrides"
cat > "$STAGE/usr/share/lintian/overrides/openp2s" <<'OVERRIDES'
# The openp2s executable is a Node.js single executable application: a copy of
# the node binary with an application blob appended. Stripping it would disturb
# the injected blob and produce something that does not run.
openp2s: unstripped-binary-or-object [usr/bin/openp2s]

# The bundled OpenVPN is deliberately not stripped either. BUILDINFO beside it
# records its sha256, and OpenP2S verifies that at runtime before using the
# binary; stripping would change the file after the hash was computed, so the
# package would ship an OpenVPN its own provenance record disowns and which
# OpenP2S would then refuse to run.
openp2s: unstripped-binary-or-object [usr/lib/openp2s/openvpn]

# The Node.js runtime inside the executable bundles zlib. That is inherent to
# a single executable application; there is no shared-library form of it.
openp2s: embedded-library zlib [usr/bin/openp2s]
OVERRIDES
chmod 0644 "$STAGE/usr/share/lintian/overrides/openp2s"

gzip -9nc "$REPO_ROOT/packaging/openp2s.1" > "$STAGE/usr/share/man/man1/openp2s.1.gz"
chmod 0644 "$STAGE/usr/share/man/man1/openp2s.1.gz"

# ----------------------------------------------------------- copyright ----
cat > "$STAGE/usr/share/doc/openp2s/copyright" <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: openp2s
Source: https://github.com/wyruweso/openp2s

Files: *
Copyright: 2026 OpenP2S contributors
License: GPL-2.0-only

Files: usr/lib/openp2s/openvpn
Copyright: OpenVPN Inc. and contributors
License: GPL-2.0-with-exceptions
 This is OpenVPN $OPENVPN_VERSION, built from the official release tarball with
 two patches applied, both in the OpenP2S source under
 patches/$OPENVPN_VERSION/: long-credentials.patch, which changes two buffer
 sizes and nothing else, and experimental-azure-compat.patch, which adds one
 OpenVPN option that is inert unless a configuration asks for it.
 .
 OpenVPN is under the GNU General Public License version 2 with linking
 exceptions, including one for OpenSSL, against which this build is linked.
 The complete upstream terms are in openvpn-COPYING in this directory. That
 file is authoritative; nothing here restates or narrows it.
 .
 The complete corresponding source is published with each release as
 openvpn-$OPENVPN_VERSION-openp2s-source.tar.gz, containing the unmodified
 upstream release, the patch applied to it, and the configure flags used.
 It can also be regenerated with scripts/build-source-tarball.sh from the
 OpenP2S repository.

Files: usr/bin/openp2s
Copyright: OpenP2S contributors; Node.js contributors and others; Microsoft Corporation
License: GPL-2.0-only and MIT and others
 OpenP2S's own code is GPL-2.0-only.
 .
 The executable is a Node.js single executable application: it is a copy of
 the node binary with an application blob appended. It therefore contains the
 Node.js runtime and every component bundled inside it, which are covered by a
 range of licences beyond Node's own MIT terms. The full text as published
 with the exact Node release used is in NODE_LICENSE in this directory.
 .
 It also embeds the @azure/msal-node, commander and fast-xml-parser libraries
 (MIT). See THIRD_PARTY_NOTICES.

License: GPL-2.0-only
 On Debian systems the full text of the GNU General Public License version 2
 can be found in /usr/share/common-licenses/GPL-2.
EOF
chmod 0644 "$STAGE/usr/share/doc/openp2s/copyright"

# The changelog timestamp is the one thing here that varies between otherwise
# identical builds, so honour SOURCE_DATE_EPOCH when the caller sets it.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    CHANGELOG_DATE="$(date -R -u -d "@$SOURCE_DATE_EPOCH")"
else
    CHANGELOG_DATE="$(date -R)"
fi
printf 'openp2s (%s) unstable; urgency=medium\n\n  * Release %s.\n\n -- Wyruweso <tseluiko.m@gmail.com>  %s\n' \
    "$VERSION" "$VERSION" "$CHANGELOG_DATE" \
    | gzip -9n > "$STAGE/usr/share/doc/openp2s/changelog.gz"
chmod 0644 "$STAGE/usr/share/doc/openp2s/changelog.gz"

# ------------------------------------------------------------- control ----
# Computed, not hardcoded: names and ABI versions differ between releases.
# Fail-closed - an under-declared dependency installs and then does not work.
log "computing library dependencies"
mkdir -p "$STAGE/debian"
printf 'Source: openp2s\n' > "$STAGE/debian/control"
( cd "$STAGE" && dpkg-shlibdeps -O --ignore-missing-info \
        usr/lib/openp2s/openvpn usr/bin/openp2s ) > "$OUT/shlibdeps.txt" 2>"$OUT/shlibdeps.err" \
    || { cat "$OUT/shlibdeps.err" >&2; die "could not compute shared-library dependencies"; }
rm -rf "$STAGE/debian"

SHLIB="$(sed -n 's/^shlibs:Depends=//p' "$OUT/shlibdeps.txt")"
[ -n "$SHLIB" ] || die "dpkg-shlibdeps produced no dependencies, which cannot be right"

# ca-certificates is hard: there is no bundled root, so without it every
# connection fails verification. sensible-utils is hard because the browser
# sign-in invokes sensible-browser by name.
#
# sudo and xdg-utils are only recommended: running as root directly provides
# the first, and a headless machine wants neither - it uses --auth device-code.
DEPENDS="$SHLIB, systemd, ca-certificates, sensible-utils"

# The build umask can leave directories 0775, which lintian flags.
find "$STAGE" -type d -exec chmod 0755 {} +

INSTALLED_KB="$(du -sk "$STAGE" | cut -f1)"
BUILT_ON="$( (. /etc/os-release 2>/dev/null && printf '%s' "$PRETTY_NAME") || printf 'unknown' )"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: openp2s
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: $DEPENDS
Recommends: sudo, xdg-utils
Installed-Size: $INSTALLED_KB
Maintainer: wyruweso <tseluiko.m@gmail.com>
Homepage: https://github.com/wyruweso/openp2s
Description: Azure Point-to-Site VPN client with Microsoft Entra ID auth
 OpenP2S connects to an Azure Point-to-Site VPN gateway that uses Microsoft
 Entra ID authentication, from Linux, using standard OpenVPN with the
 smallest currently necessary compatibility patch.
 .
 Stock OpenVPN $OPENVPN_VERSION cannot carry an Entra access token, because two
 independent limits are too small for it. USER_PASS_LEN truncates the password
 the token is sent as, and TLS_CHANNEL_BUF_SIZE limits the key-method-2 control
 channel message that carries it. Measurement against a live gateway showed
 that raising both, and nothing else, is sufficient. This package ships its own
 OpenVPN built that way, installed privately at /usr/lib/openp2s/openvpn so it
 never shadows the system openvpn.
 .
 That OpenVPN also carries an opt-in Azure compatibility option, off by
 default and reachable only from the local configuration, for gateways that
 turn out to require the Azure options string.
 .
 OpenP2S also handles the Entra sign-in - through the browser by default, or
 with a device code on a machine that has none - along with token caching and
 the systemd-resolved split DNS that Azure Private Link names require.
 .
 Built on $BUILT_ON. Library dependencies are resolved against that release;
 installing on an older distribution is not supported.
EOF

# ---------------------------------------------------------------- build ---
log "building the package"
DEB="$OUT/openp2s_${VERSION}_${ARCH}.deb"
# --root-owner-group gives root:root without needing root or fakeroot.
dpkg-deb --build --root-owner-group "$STAGE" "$DEB" >/dev/null
[ -f "$DEB" ] || die "dpkg-deb produced no package"

# --------------------------------------------------------------- verify ---
log "verifying"
dpkg-deb --info "$DEB" >/dev/null || die "the package is not readable"

# Read the contents once: piping dpkg-deb into `grep -q` makes grep exit
# early and dpkg-deb die on SIGPIPE.
CONTENTS="$(dpkg-deb --contents "$DEB")"
for path in ./usr/bin/openp2s \
            ./usr/lib/openp2s/openvpn \
            ./usr/lib/openp2s/BUILDINFO \
            ./usr/share/doc/openp2s/copyright \
            ./usr/share/doc/openp2s/openvpn-COPYING \
            ./usr/share/doc/openp2s/NODE_LICENSE \
            ./usr/share/doc/openp2s/THIRD_PARTY_NOTICES; do
    grep -q " $path\$" <<<"$CONTENTS" || die "missing from the package: $path"
done

# The packaged OpenVPN must be the one its own BUILDINFO describes. This is the
# regression guard for the strip that used to happen above: without it, the
# package installs an OpenVPN that OpenP2S itself refuses to run.
PKG_DIR="$(mktemp -d)"
trap 'rm -rf "$PKG_DIR"' EXIT
dpkg-deb -x "$DEB" "$PKG_DIR"
# The same gate CI runs on the build tree, against the bytes a user installs.
"$REPO_ROOT/scripts/check-binary-policy.sh" \
    --binary "$PKG_DIR/usr/lib/openp2s/openvpn" \
    --buildinfo "$PKG_DIR/usr/lib/openp2s/BUILDINFO" \
    | sed 's/^/    /' \
    || die "the packaged OpenVPN does not satisfy the binary policy"


PKG_CLI_VERSION="$("$PKG_DIR/usr/bin/openp2s" --version 2>/dev/null)" \
    || die "the packaged CLI does not run"
[ "$PKG_CLI_VERSION" = "$VERSION" ] \
    || die "the packaged CLI reports $PKG_CLI_VERSION, expected $VERSION"

# The package must not claim to provide the system openvpn.
FIELDS="$(dpkg-deb --field "$DEB" Provides Conflicts Replaces)" \
    || die "could not read the package control fields"
if grep -qw openvpn <<<"$FIELDS"; then
    die "the package must not provide, conflict with or replace openvpn"
fi

# Errors fail the build; warnings are shown. A linter whose findings are all
# discarded is decoration.
if command -v lintian >/dev/null; then
    LINTIAN_OUT="$OUT/lintian.txt"
    lintian --tag-display-limit 0 "$DEB" > "$LINTIAN_OUT" 2>&1 || true
    sed 's/^/    /' "$LINTIAN_OUT"
    if grep -q '^E: ' "$LINTIAN_OUT"; then
        die "lintian reported errors (see above)"
    fi
fi

printf '\n'
log "package ready"
printf '\n'
printf '    %s\n' "$DEB"
printf '    size:    %s\n' "$(du -h "$DEB" | cut -f1)"
printf '    sha256:  %s\n' "$(sha256sum "$DEB" | cut -d' ' -f1)"
printf '    built on: %s\n' "$BUILT_ON"
printf '    depends: %s\n' "$DEPENDS"
printf '\n'
printf '    sudo apt install ./%s\n' "$(basename "$DEB")"
printf '\n'
