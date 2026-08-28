#!/usr/bin/env bash
#
# Is the openp2s executable byte-reproducible?
#
# Scope: the CLI executable only. openvpn-openp2s, the .deb and the tarball are
# not compared - that needs a normalised compiler, libc and archive metadata.
#
# The claim is relative to the toolchain in CLI-BUILDINFO. A different Node
# release will NOT produce the same bytes, and cannot: the executable is a copy
# of the node binary.
#
# The two builds use different build directories, at different absolute paths.
# Separate directories keep them independent; different paths matter because
# Node stores the main script's path inside the SEA blob, so a same-path check
# would pass while the executable stayed unreproducible elsewhere.
#
# Usage: scripts/check-cli-reproducible.sh

set -euo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

die() { printf '\n  not reproducible: %s\n\n' "$1" >&2; exit 1; }
ok()  { printf '  ok  %s\n' "$1"; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Different lengths too: that is what shifts offsets when a path leaks in.
DIR_A="$WORK/a"
DIR_B="$WORK/b-with-a-deliberately-longer-name"

printf '\n==> CLI reproducibility check\n\n'
printf '    build A: %s\n' "$DIR_A"
printf '    build B: %s\n\n' "$DIR_B"

# Irrelevant host state is varied so environment leakage shows up rather than
# cancelling out. NODE_OPTIONS is cleared, not varied: it changes behaviour.
build() {
    local dir="$1" out="$2" tmp="$3" tz="$4"
    mkdir -p "$dir" "$tmp"
    ( unset NODE_OPTIONS
      export TMPDIR="$tmp" TZ="$tz"
      scripts/build-cli.sh --build-dir "$dir" --out "$out" ) > "$dir/build.log" 2>&1 \
        || { cat "$dir/build.log" >&2; die "the build in $dir failed"; }
}

build "$DIR_A" "$WORK/openp2s-a" "$WORK/tmp-a" "UTC"
build "$DIR_B" "$WORK/openp2s-b" "$WORK/tmp-b" "Pacific/Kiritimati"

# Stage by stage, because the failures mean different things: bundle is
# esbuild, blob is the SEA step, executable is injection.
compare() {
    local what="$1" a="$2" b="$3" hint="${4:-}"
    local sha_a sha_b
    sha_a="$(sha256sum "$a" | cut -d' ' -f1)"
    sha_b="$(sha256sum "$b" | cut -d' ' -f1)"
    [ "$sha_a" = "$sha_b" ] || die "the $what differs between builds
  A: $sha_a
  B: $sha_b${hint:+
$hint}"
    ok "$what is byte-identical"
}

compare "esbuild bundle" "$DIR_A/openp2s.cjs" "$DIR_B/openp2s.cjs"

compare "SEA blob" "$DIR_A/openp2s.blob" "$DIR_B/openp2s.blob" \
"Two known causes: useCodeCache, which bakes a non-deterministic V8 code cache
into the blob; and an absolute path in sea-config.json, which Node stores in
the blob and which then differs with the build directory. See build-cli.sh."

# Metadata too, or the executable matches while its BUILDINFO does not.
compare "CLI-BUILDINFO" "$DIR_A/CLI-BUILDINFO" "$DIR_B/CLI-BUILDINFO" \
"CLI-BUILDINFO must record only the toolchain, never a timestamp or a build path."

compare "executable" "$WORK/openp2s-a" "$WORK/openp2s-b"

# Even with matching hashes, an embedded path means the next build differs.
# One scan into a file, then plain greps: no pipeline to lose a match in, and
# a failing `strings` is an error rather than a silent pass.
strings -a "$WORK/openp2s-a" > "$WORK/strings-a" \
    || die "could not inspect the executable with strings"

for path in "$DIR_A" "$DIR_B" "$WORK"; do
    if grep -Fq "$path" "$WORK/strings-a"; then
        die "the executable embeds the build path $path"
    fi
done
ok "no build path is embedded in the executable"

printf '\n==> the CLI build is reproducible with the pinned toolchain\n\n'
