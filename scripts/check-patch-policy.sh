#!/usr/bin/env bash
#
# Policy checks on the shipped patches.
#
# The claim is that OpenP2S is upstream OpenVPN plus a patch changing two
# constants. Counting files does not establish that, so this asserts it as a
# property of the diff: every removed line, and every added line of *code*,
# must be one of the constants, with the expected multiplicity.
#
# "Line of code" means what the compiler sees. Comments are stripped by
# tracking /* */ spans (scripts/lib/diff.sh), not by testing line prefixes -
# `* explanation */ int backdoor = 1;` starts with '*' and declares a variable.
#
# experimental-azure-compat is not held to the two-constants rule; it adds an
# option. Section 6 asserts instead that only the local config can reach it.
#
# Run by ci.yml and release.yml, so a release passes the same checks as a PR.
#
# Usage: scripts/check-patch-policy.sh [version]

set -euo pipefail

# Deterministic comparisons regardless of the caller's locale.
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MANIFEST="$REPO_ROOT/patches/manifest"

die() { printf '\n  policy violation: %s\n\n' "$1" >&2; exit 1; }
ok()  { printf '  ok  %s\n' "$1"; }

# shellcheck source=scripts/lib/manifest.sh
. "$REPO_ROOT/scripts/lib/manifest.sh"
# shellcheck source=scripts/lib/diff.sh
. "$REPO_ROOT/scripts/lib/diff.sh"

[ -f "$MANIFEST" ] || die "missing $MANIFEST"

VERSION="${1:-$(manifest_require DEFAULT_VERSION)}"
manifest_get "$VERSION.url" >/dev/null
[ -n "$(manifest_get "$VERSION.url")" ] || die \
    "OpenVPN $VERSION is not in patches/manifest (known: $(manifest_versions | tr '\n' ' '))"

# The manifest decides which file this is, exactly as build-openvpn.sh does.
PATCH_REL="$(manifest_require "$VERSION.patch.long_credentials")"
PATCH="$REPO_ROOT/$PATCH_REL"
[ -f "$PATCH" ] || die "the manifest names $PATCH_REL as the production patch, but it does not exist"

printf '\n==> patch policy for OpenVPN %s\n' "$VERSION"
printf '    production patch: %s\n\n' "$PATCH_REL"

# ---- 1. it is the patch the manifest pins --------------------------------
PINNED_SHA="$(manifest_require "$VERSION.patch.long_credentials_sha256")"
ACTUAL_SHA="$(sha256sum "$PATCH" | cut -d' ' -f1)"
[ "$ACTUAL_SHA" = "$PINNED_SHA" ] || die \
"$PATCH_REL does not match its pin
  pinned: $PINNED_SHA
  actual: $ACTUAL_SHA"
ok "production patch matches its manifest pin"

# ---- 2. which files it may touch -----------------------------------------
ALLOWED_FILES="src/openvpn/common.h
src/openvpn/misc.h"

touched="$(diff_touched_files "$PATCH")"
if [ "$touched" != "$ALLOWED_FILES" ]; then
    printf 'expected exactly:\n%s\n\ngot:\n%s\n' "$ALLOWED_FILES" "$touched" >&2
    die "the production patch touches files outside the allowlist"
fi
ok "touches exactly 2 files, both allowed"

# ---- 3. what it may remove -----------------------------------------------
#
# Sorted, NOT deduplicated: `sort -u` would let a constant added three times
# collapse to the expected text. Multiplicity is part of the claim.
# The "after" values come from the manifest so the build and this check cannot
# disagree. The "before" values are upstream's.
WANT_USER_PASS_LEN="$(manifest_require "$VERSION.user_pass_len")"
WANT_TLS_BUF="$(manifest_require "$VERSION.tls_channel_buf_size")"

ALLOWED_REMOVALS="#define TLS_CHANNEL_BUF_SIZE 2048
#define USER_PASS_LEN 128"

removed="$(diff_removed_lines "$PATCH" | sed 's/[[:space:]]*$//' | grep -v '^$' | sort)"
if [ "$removed" != "$ALLOWED_REMOVALS" ]; then
    printf 'expected exactly:\n%s\n\ngot:\n%s\n' "$ALLOWED_REMOVALS" "$removed" >&2
    die "the production patch removes upstream code beyond the two constants"
fi
ok "removes exactly the 2 upstream constants, once each"

# ---- 4. what it may add --------------------------------------------------
#
# Comments are allowed - the patch explains itself to an upstream reviewer -
# but are identified by stripping /* */ spans, not by how a line starts.
ALLOWED_ADDITIONS="$(printf '#define TLS_CHANNEL_BUF_SIZE %s\n#define USER_PASS_LEN %s' \
    "$WANT_TLS_BUF" "$WANT_USER_PASS_LEN" | sort)"

added_code="$(diff_added_code "$PATCH" | sort)"
if [ "$added_code" != "$ALLOWED_ADDITIONS" ]; then
    printf 'expected exactly:\n%s\n\ngot:\n%s\n' "$ALLOWED_ADDITIONS" "$added_code" >&2
    die "the production patch adds code beyond the two constants"
fi
ok "adds exactly the 2 replacement constants, once each (plus comments)"

# ---- 5. no getenv() opt-in ------------------------------------------------
#
# Narrower than "no behaviour from the environment", which cannot be proved
# here: only that no patch reintroduces a getenv()-based opt-in.
# Captured first, so a failure of the parser is an error rather than an empty
# result that reads as "clean".
GETENV_RE='(^|[^_[:alnum:]])(secure_)?getenv[[:space:]]*\('
for patch_file in patches/*/*.patch; do
    added="$(diff_added_lines "$patch_file")" \
        || die "could not read the added lines of $patch_file"
    if grep -Eq "$GETENV_RE" <<<"$added"; then
        grep -nE "$GETENV_RE" <<<"$added" >&2
        die "$patch_file adds a getenv() call; the environment-variable opt-in is not shippable"
    fi
done
ok "no shipped patch adds a getenv() call"

# ---- 6. the compat patch is reachable only from the local config ---------
#
# The compat code is always in the shipped binary, so "cannot be enabled by
# accident" is a property of the patch, not of the build. Two things must hold:
# the option must be an ordinary OpenVPN option, visible in the config, and it
# must carry a permission mask a pushed option cannot satisfy.
EAC="$REPO_ROOT/$(manifest_require "$VERSION.patch.experimental_azure_compat")"

grep -q 'streq(p\[0\], "experimental-azure-compat")' "$EAC" \
    || die "the compat patch does not add --experimental-azure-compat as an OpenVPN option"
ok "compat mode is an ordinary --experimental-azure-compat option"

# OPT_P_GENERAL is not pushable, so a server's copy is rejected.
grep -q 'VERIFY_PERMISSION(OPT_P_GENERAL);' "$EAC" \
    || die "the compat option's permission mask would allow a server to push it"
ok "a server cannot push --experimental-azure-compat"


grep -q 'options_postprocess_verify_azure_compat' "$EAC" \
    || die "the compat patch does not validate the config before advertising its OCC string"
ok "compat mode validates the config before advertising its OCC string"

# ---- 6. the manifest and the patch directory agree -----------------------
#
# Both directions, and structurally: a substring search could be satisfied by
# accident and said nothing about entries pointing at missing files.
declared=""
for key in $(manifest_patch_keys "$VERSION"); do
    rel="$(manifest_require "$VERSION.patch.$key")"
    [ -f "$REPO_ROOT/$rel" ] || die "manifest declares $key at $rel, which does not exist"

    pinned="$(manifest_require "$VERSION.patch.${key}_sha256")"
    actual="$(sha256sum "$REPO_ROOT/$rel" | cut -d' ' -f1)"
    [ "$actual" = "$pinned" ] || die \
"$rel does not match its manifest pin
  pinned: $pinned
  actual: $actual"

    declared="$declared$rel
"
done

on_disk="$(printf '%s\n' patches/"$VERSION"/*.patch | sort)"
declared_sorted="$(printf '%s' "$declared" | grep -v '^$' | sort)"
if [ "$on_disk" != "$declared_sorted" ]; then
    printf 'on disk:\n%s\n\ndeclared in the manifest:\n%s\n' "$on_disk" "$declared_sorted" >&2
    die "patches/$VERSION and patches/manifest describe different sets of patches"
fi
ok "every patch on disk is declared and pinned, and every declared patch exists"

printf '\n==> patch policy satisfied\n\n'
