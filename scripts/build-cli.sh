#!/usr/bin/env bash
#
# Build a single-file `openp2s` executable that needs no Node installed.
#
#   src/**.ts  --esbuild-->  one CommonJS bundle
#              --node sea-->  a blob
#              --postject-->  injected into a copy of the node binary
#
# The result is one file. Note what it does NOT contain: the patched OpenVPN
# binary. That is a separate native artifact built by build-openvpn.sh, and
# OpenP2S looks for it at runtime (see src/openvpn/binary.ts). A distributable
# package ships both.
#
# The executable is a copy of the node binary with the SEA blob injected, so
# the Node release is part of the artifact: two builds from identical source
# but different Node patch releases produce different bytes. Pinned in
# .node-version and recorded in build/cli/CLI-BUILDINFO.
#
# Linux only, deliberately. OpenP2S depends on systemd-resolved for split DNS,
# /run/user/$UID for runtime state, and sudo for privilege escalation; a
# binary for another platform would build and then not work.
#
# Usage: scripts/build-cli.sh [--out <path>] [--build-dir <path>]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/cli"
OUT=""
OUT_EXPLICIT=0

die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
log() { printf '==> %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="${2:?--out needs a path}"; OUT_EXPLICIT=1; shift 2 ;;
        # Intermediates go here: the bundle, the SEA blob, the config and
        # CLI-BUILDINFO. Separable so two builds can be genuinely independent
        # rather than sharing one directory and overwriting each other - which
        # is what a reproducibility check needs, and what lets two builds run
        # at once without colliding.
        --build-dir) BUILD_DIR="${2:?--build-dir needs a path}"; shift 2 ;;
        -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ "$OUT_EXPLICIT" -eq 1 ] || OUT="$BUILD_DIR/openp2s"

# type -P, not command -v: an alias or shell function cannot be copied.
NODE_BIN="$(type -P node)" || die "node is required to build (not to run) the executable"
[ "$(uname -s)" = "Linux" ] || die "OpenP2S is a Linux client"

# From the lockfile, never the network: `npx --yes` would silently fetch a
# toolchain npm ci never pinned.
ESBUILD="$REPO_ROOT/node_modules/.bin/esbuild"
POSTJECT="$REPO_ROOT/node_modules/.bin/postject"
[ -x "$ESBUILD" ] || die "esbuild is not installed; run: npm ci"
[ -x "$POSTJECT" ] || die "postject is not installed; run: npm ci"

# The syntax target is the runtime it will run on: this exact node binary.
NODE_VERSION="$("$NODE_BIN" --version)"          # v24.13.0
NODE_MAJOR="${NODE_VERSION#v}"; NODE_MAJOR="${NODE_MAJOR%%.*}"

PINNED_VERSION=""
if [ -f "$REPO_ROOT/.node-version" ]; then
    PINNED_VERSION="v$(tr -d '[:space:]' < "$REPO_ROOT/.node-version")"
    if [ "$NODE_VERSION" != "$PINNED_VERSION" ]; then
        # Not fatal: a developer build with a different Node is fine.
        printf 'warning: building with %s, but .node-version pins %s;\n' \
            "$NODE_VERSION" "$PINNED_VERSION" >&2
        printf '         the resulting executable will not match a release build byte for byte\n\n' >&2
    fi
fi

mkdir -p "$BUILD_DIR"
mkdir -p "$(dirname "$OUT")"

# Assembled under a temporary name and renamed once verified, so the file's
# existence is the guarantee that it works - an interrupted build cannot leave
# a plain node binary called openp2s. The rename also replaces a symlink at
# $OUT rather than writing through it.
TMP_OUT="$(mktemp "$(dirname "$OUT")/.openp2s.XXXXXXXX")"
cleanup() { rm -f "$TMP_OUT"; }
trap cleanup EXIT

# ---------------------------------------------------------------- bundle ---
log "bundling with esbuild"
"$ESBUILD" "$REPO_ROOT/src/cli/sea-entry.ts" \
    --bundle \
    --platform=node \
    --target="node$NODE_MAJOR" \
    --format=cjs \
    --minify \
    --legal-comments=none \
    --outfile="$BUILD_DIR/openp2s.cjs" \
    --log-level=warning \
    --metafile="$BUILD_DIR/esbuild-meta.json" \
    || die "esbuild failed"

printf '    bundle: %s bytes\n' "$(wc -c < "$BUILD_DIR/openp2s.cjs")"

# ------------------------------------------------------------------- sea ---
# useCodeCache is off deliberately: the V8 code cache is not deterministic, and
# is the only source of nondeterminism in this pipeline. Reproducibility is
# worth more than the ~6ms of startup it buys, on a command whose real work is
# a network handshake and an interactive login.
# Relative paths, and node runs from the build directory: Node stores the main
# script's path inside the blob, so an absolute one would embed the build
# directory in the shipped executable and make it path-dependent.
cat > "$BUILD_DIR/sea-config.json" <<JSON
{
  "main": "openp2s.cjs",
  "output": "openp2s.blob",
  "disableExperimentalSEAWarning": true,
  "useSnapshot": false,
  "useCodeCache": false
}
JSON

log "generating the SEA blob"
( cd "$BUILD_DIR" && "$NODE_BIN" --experimental-sea-config sea-config.json ) >/dev/null 2>&1 \
    || die "sea blob generation failed"

# --------------------------------------------------------------- inject ---
log "injecting into a copy of node"
cp "$NODE_BIN" "$TMP_OUT"
chmod u+w "$TMP_OUT"

"$POSTJECT" "$TMP_OUT" NODE_SEA_BLOB "$BUILD_DIR/openp2s.blob" \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
    || die "postject failed"

chmod 0755 "$TMP_OUT"

# --------------------------------------------------------------- verify ---
#
# The output is a copy of the node binary, so a failed injection would still
# answer `--version` - with Node's version. Every check below asserts
# something only OpenP2S would say.
log "verifying"

EXPECTED_VERSION="$("$NODE_BIN" -p "require('$REPO_ROOT/package.json').version")"
ACTUAL_VERSION="$("$TMP_OUT" --version 2>&1)" || die "the built executable does not run"

[ "$ACTUAL_VERSION" = "$EXPECTED_VERSION" ] || die \
"the built executable reports '$ACTUAL_VERSION', expected '$EXPECTED_VERSION'.
If that looks like a Node version, the SEA blob was not injected and the
output is a plain copy of node."

"$TMP_OUT" --help 2>&1 | grep -q 'openp2s' \
    || die "the built executable does not print OpenP2S help"

# One real command end to end: the parser and wiring survived minification.
"$TMP_OUT" inspect "$REPO_ROOT/tests/fixtures/azure-schema.xml" >/dev/null 2>&1 \
    || die "the built executable cannot inspect a profile"

# A release binary must not carry the build machine's directory layout.
for leaked in "$REPO_ROOT" "$BUILD_DIR"; do
    if strings -a "$TMP_OUT" 2>/dev/null | grep -qF "$leaked"; then
        die "the executable embeds the build path $leaked, so it is not reproducible elsewhere"
    fi
done

mv "$TMP_OUT" "$OUT"
trap - EXIT

# ----------------------------------------------------------- provenance ---
#
# The node binary is half the artifact. Folded into BUILDINFO by
# build-release.sh.
NODE_SHA="$(sha256sum "$NODE_BIN" | cut -d' ' -f1)"

# The licence of the exact Node that went in. Node bundles many components
# under their own terms, and its LICENSE enumerates them; taking it from beside
# the binary keeps the notices describing what actually shipped.
NODE_LICENSE="$(dirname "$NODE_BIN")/../LICENSE"
if [ -f "$NODE_LICENSE" ]; then
    install -m 0644 "$NODE_LICENSE" "$BUILD_DIR/NODE_LICENSE"
else
    printf 'warning: no LICENSE beside %s; NODE_LICENSE will be missing\n' "$NODE_BIN" >&2
    rm -f "$BUILD_DIR/NODE_LICENSE"
fi
cat > "$BUILD_DIR/CLI-BUILDINFO" <<INFO
# Generated by scripts/build-cli.sh. Not checked in.
openp2s_version=$EXPECTED_VERSION
cli_node_version=${NODE_VERSION#v}
cli_node_pinned=${PINNED_VERSION#v}
cli_node_sha256=$NODE_SHA
cli_esbuild_version=$("$ESBUILD" --version)
cli_postject_version=$(node -p "require('$REPO_ROOT/node_modules/postject/package.json').version" 2>/dev/null || printf 'unknown')
cli_platform=linux
cli_arch=$(uname -m)
cli_binary_sha256=$(sha256sum "$OUT" | cut -d' ' -f1)
INFO

printf '\n'
log "openp2s executable ready"
printf '\n'
printf '    path:    %s\n' "$OUT"
printf '    size:    %s\n' "$(du -h "$OUT" | cut -f1)"
printf '    version: %s\n' "$ACTUAL_VERSION"
printf '    node:    %s\n' "${NODE_VERSION#v}"
printf '    sha256:  %s\n' "$(sha256sum "$OUT" | cut -d' ' -f1)"
printf '\n'
printf '    It still needs the patched OpenVPN binary at runtime. Either:\n'
printf '      scripts/build-openvpn.sh, or install the openp2s package,\n'
printf '      or pass --openvpn-binary <path> to connect/probe/inspect.\n'
printf '\n'
