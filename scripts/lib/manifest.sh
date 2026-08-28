#!/usr/bin/env bash
#
# One reader for patches/manifest, so a build and its policy gate cannot end up
# checking different files.
#
# Source this, do not execute it:
#
#     . "$REPO_ROOT/scripts/lib/manifest.sh"
#     version="$(manifest_require DEFAULT_VERSION)"

# Parsed, never sourced: it should not be able to execute anything.
# awk rather than grep|cut, so a missing key is empty rather than a non-zero
# exit that `set -e` acts on first.
manifest_get() {
    local key="$1" file="${2:-$MANIFEST}"
    [ -f "$file" ] || return 0
    awk -F= -v k="$key" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

# Fatal on a missing value. For anything a build or policy decision needs.
manifest_require() {
    local key="$1" value
    value="$(manifest_get "$key")"
    [ -n "$value" ] || die "patches/manifest has no '$key'"
    printf '%s' "$value"
}

# Every version the manifest describes.
manifest_versions() {
    awk -F. '/^[0-9]+\.[0-9]+\.[0-9]+\.url=/ { print $1 "." $2 "." $3 }' "$MANIFEST" | sort -u
}

# The patch keys declared for a version, in manifest order.
manifest_patch_keys() {
    local version="$1"
    awk -F= -v prefix="$version.patch." '
        index($1, prefix) == 1 && $1 !~ /_sha256$/ {
            print substr($1, length(prefix) + 1)
        }
    ' "$MANIFEST"
}
