#!/usr/bin/env bash
#
# The corresponding source for the OpenVPN binary we distribute.
#
# OpenP2S ships a modified GPLv2 binary. "Reproducible with our build script"
# describes a process, not an offer of source, and depends on an upstream
# tarball staying downloadable. So the release carries the source:
#
#     openvpn-<version>-openp2s-source.tar.gz
#       openvpn-<version>/          upstream release, unmodified
#       patches/                    the patch that was applied, byte for byte
#       BUILDINFO                   which binary this corresponds to
#       README                      how to rebuild it
#
# Extract, apply the patch, run configure with the flags recorded in the
# README, and you have the binary.
#
# Usage: scripts/build-source-tarball.sh [--out <dir>]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/build/release"
MANIFEST="$REPO_ROOT/patches/manifest"
BUILDINFO="$REPO_ROOT/build/openvpn/BUILDINFO"

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="${2:?--out needs a path}"; shift 2 ;;
        -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -f "$BUILDINFO" ] || die "missing $BUILDINFO (run scripts/build-openvpn.sh)"

VERSION="$(grep '^openvpn_version=' "$BUILDINFO" | cut -d= -f2)"
[ -n "$VERSION" ] || die "BUILDINFO has no openvpn_version"

TARBALL="$REPO_ROOT/build/openvpn-src/openvpn-$VERSION.tar.gz"
[ -f "$TARBALL" ] || die "missing the upstream tarball $TARBALL (run scripts/build-openvpn.sh)"

# If this disagrees, the tarball on disk is not what the binary came from.
WANT_SHA="$(grep '^openvpn_tarball_sha256=' "$BUILDINFO" | cut -d= -f2)"
GOT_SHA="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
[ "$WANT_SHA" = "$GOT_SHA" ] \
    || die "the upstream tarball does not match BUILDINFO ($GOT_SHA != $WANT_SHA)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

STAGE="$WORK/openvpn-$VERSION-openp2s-source"
mkdir -p "$STAGE/patches"

log "assembling corresponding source for OpenVPN $VERSION"

tar -xzf "$TARBALL" -C "$STAGE"
cp "$REPO_ROOT"/patches/"$VERSION"/*.patch "$STAGE/patches/"
cp "$MANIFEST" "$STAGE/patches/manifest"
cp "$BUILDINFO" "$STAGE/BUILDINFO"
cp "$REPO_ROOT/scripts/build-openvpn.sh" "$STAGE/build-openvpn.sh"

# Taken from the build script rather than retyped, so it cannot drift.
# --prefix is dropped: it names a directory in the build tree, not a property
# of the build.
CONFIGURE_FLAGS="$(sed -n '/^CONFIGURE_FLAGS=(/,/^)/p' "$REPO_ROOT/scripts/build-openvpn.sh" \
    | grep -oE '^\s+--[a-z0-9=_-]+' | tr -d ' ' | grep -v '^--prefix' | tr '\n' ' ')"

cat > "$STAGE/README" <<INFO
Corresponding source for the OpenP2S build of OpenVPN $VERSION
==============================================================

This is the complete source for the \`openvpn-openp2s\` binary distributed
with OpenP2S $(grep -E '^\s*"version"' "$REPO_ROOT/package.json" | head -1 | cut -d'"' -f4),
provided to satisfy the GNU General Public License version 2.

Contents
--------

  openvpn-$VERSION/     the upstream OpenVPN release, unmodified
  patches/              the patches applied, byte for byte
  patches/manifest      the pins: tarball sha256, commit, patch sha256s
  BUILDINFO             identifies the binary this source corresponds to
  build-openvpn.sh      the script that produced it

Upstream
--------

  version:  $VERSION
  commit:   $(grep '^openvpn_commit=' "$BUILDINFO" | cut -d= -f2)
  tarball:  sha256 $WANT_SHA

Obtained from https://swupdate.openvpn.org/community/releases/

What was changed
----------------

  $(grep '^patch_stack=' "$BUILDINFO" | cut -d= -f2)

long-credentials.patch changes two constants and nothing else:

  USER_PASS_LEN         128  -> 4096   (src/openvpn/misc.h)
  TLS_CHANNEL_BUF_SIZE  2048 -> 8192   (src/openvpn/common.h)

Every line it touches is asserted by scripts/check-patch-policy.sh in the
OpenP2S repository.

experimental-azure-compat.patch adds one OpenVPN option,
--experimental-azure-compat, which sends an Azure-specific options string and
peer-info. It is compiled in but inert: nothing happens unless a configuration
contains the option. It carries OPT_P_GENERAL, so a server cannot push it, and
it reads no environment variable. OpenP2S does not pass it by default, because
measurement against a live gateway showed it is not required.

Rebuilding
----------

    cd openvpn-$VERSION
    patch -p1 < ../patches/long-credentials.patch
    ./configure $CONFIGURE_FLAGS
    make

The resulting src/openvpn/openvpn should match:

  sha256 $(grep '^binary_sha256=' "$BUILDINFO" | cut -d= -f2)

built with the toolchain recorded in BUILDINFO. A different compiler or libc
will produce different bytes from identical source.

Licence
-------

OpenVPN is distributed under the GNU General Public License version 2, with
linking exceptions for OpenSSL and for Apache-2.0 licensed libraries. The
complete upstream terms are in openvpn-$VERSION/COPYING, which is the
authoritative text; nothing here restates or summarises it.
INFO

mkdir -p "$OUT"
ARCHIVE="$OUT/openvpn-$VERSION-openp2s-source.tar.gz"

# Deterministic: fixed ownership, sorted entries, optional SOURCE_DATE_EPOCH.
TAR_ARGS=(--owner=0 --group=0 --numeric-owner --sort=name)
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    TAR_ARGS+=(--mtime="@$SOURCE_DATE_EPOCH")
fi

( cd "$WORK" && tar "${TAR_ARGS[@]}" -cf - "openvpn-$VERSION-openp2s-source" ) \
    | gzip -9n > "$ARCHIVE"

printf '\n'
log "corresponding source ready"
printf '\n'
printf '    %s\n' "$ARCHIVE"
printf '    size:    %s\n' "$(du -h "$ARCHIVE" | cut -f1)"
printf '    sha256:  %s\n' "$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
printf '\n'
