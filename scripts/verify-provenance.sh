#!/usr/bin/env bash
#
# Is this artifact internally consistent with the sources it claims to come
# from?
#
# Answers one question about a binary produced by the OpenP2S build pipeline:
#
#     does its BUILDINFO describe *this* file, do the pins it records match
#     patches/manifest, and is the patch stack the shipped one?
#
# ## What this cannot do
#
# It cannot tell you a binary someone handed you was built from these sources.
# BUILDINFO is an unsigned assertion beside a file: anyone supplying the binary
# can supply a matching BUILDINFO, and every check here would pass.
#
# Origin is established by the release SHA256SUMS, `gh attestation verify`, or
# rebuilding from the published source. This is the consistency check that runs
# inside a pipeline you already trust, and catches a binary modified after its
# hash was recorded.
#
# Usage:
#   scripts/verify-provenance.sh [--binary <path>] [--buildinfo <path>]
#                                [--expect-stack <stack>]
#
# With no arguments it checks the build tree. Point it at an installed or
# extracted binary to check that instead:
#
#   scripts/verify-provenance.sh --binary /usr/lib/openp2s/openvpn
#
# --expect-stack overrides the expected patch stack, for verifying a build made
# with a different set of patches deliberately.

set -euo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/patches/manifest"
BUILD_ROOT="$REPO_ROOT/build/openvpn"

BINARY=""
BUILDINFO=""
EXPECT_STACK="long-credentials experimental-azure-compat"

pass=0
fail=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail+1)); }
info() { printf '        %s\n' "$*"; }
die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) BINARY="${2:?--binary needs a path}"; shift 2 ;;
        --buildinfo) BUILDINFO="${2:?--buildinfo needs a path}"; shift 2 ;;
        --expect-stack) EXPECT_STACK="${2:?--expect-stack needs a value}"; shift 2 ;;
        -h|--help) sed -n '2,36p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

# What the caller asked for decides, so `--binary` on a machine with a
# checkout cannot silently verify against the checkout's BUILDINFO.
if [ -n "$BUILDINFO" ]; then
    :                                          # explicit wins
elif [ -n "$BINARY" ]; then
    # An installed or extracted layout keeps BUILDINFO beside the binary.
    BUILDINFO="$(dirname "$BINARY")/BUILDINFO"
else
    # The build tree, where it sits one level above sbin/.
    BUILDINFO="$BUILD_ROOT/BUILDINFO"
fi
[ -n "$BINARY" ] || BINARY="$BUILD_ROOT/sbin/openvpn"

# shellcheck source=scripts/lib/manifest.sh
. "$REPO_ROOT/scripts/lib/manifest.sh"
manifest() { manifest_get "$1"; }

# Fail closed on a missing or duplicated key rather than returning empty and
# letting a comparison silently succeed against another empty value.
buildinfo() {
    local key="$1" count
    count="$(awk -F= -v k="$key" '$1 == k { n++ } END { print n + 0 }' "$BUILDINFO")"
    [ "$count" = "1" ] || { printf 'BUILDINFO-ERROR(%s entries)' "$count"; return 0; }
    awk -F= -v k="$key" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$BUILDINFO"
}

printf '\nOpenP2S OpenVPN provenance check\n\n'
[ -f "$MANIFEST" ] || die "missing $MANIFEST"

# From the artifact, not DEFAULT_VERSION: a --openvpn-version build is a
# legitimate thing to check.
if [ -f "$BUILDINFO" ]; then
    VERSION="$(buildinfo openvpn_version)"
    [ -n "$(manifest "$VERSION.url")" ] \
        || die "BUILDINFO reports OpenVPN $VERSION, which patches/manifest does not pin"
else
    VERSION="$(manifest DEFAULT_VERSION)"
fi
info "verifying against OpenVPN $VERSION"
info "binary:    $BINARY"
info "buildinfo: $BUILDINFO"
printf '\n'

# ---- 1. every pinned patch matches its hash -----------------------------
for key in long_credentials experimental_azure_compat; do
    file="$(manifest "$VERSION.patch.$key")"
    pinned="$(manifest "$VERSION.patch.${key}_sha256")"
    [ -n "$file" ] || { bad "manifest has no patch '$key'"; continue; }
    if [ ! -f "$REPO_ROOT/$file" ]; then
        bad "$key patch is missing: $file"
        continue
    fi
    actual="$(sha256sum "$REPO_ROOT/$file" | cut -d' ' -f1)"
    if [ "$actual" = "$pinned" ]; then
        ok "$key matches its pin"
    else
        bad "$key changed since the pin was recorded"
        info "pinned: $pinned"
        info "actual: $actual"
    fi
done

# ---- 2. the production patch really is minimal --------------------------
#
# Delegated, not reimplemented: two implementations of one policy drift, and
# the weaker one is what lets something through.
if "$REPO_ROOT/scripts/check-patch-policy.sh" "$VERSION" >/dev/null 2>&1; then
    ok "production patch satisfies the patch policy"
else
    bad "production patch violates the patch policy"
    info "run: scripts/check-patch-policy.sh $VERSION"
fi

if grep -qE '^\+.*\b(system|popen|exec[lv]|/bin/sh)\s*\(' "$REPO_ROOT"/patches/*/*.patch; then
    bad "a patch introduces a process-execution call"
else
    ok "no patch introduces a process-execution call"
fi

# ---- 3. Azure behaviour is opt-in and cannot be pushed ------------------
#
# Syntactic: the option exists, carries a mask a server cannot satisfy, and
# has a validator - not that the lifecycle is correct.
EAC="$REPO_ROOT/$(manifest "$VERSION.patch.experimental_azure_compat")"
if grep -q 'streq(p\[0\], "experimental-azure-compat")' "$EAC"; then
    ok "Azure mode is an explicit --experimental-azure-compat option"
else
    bad "no --experimental-azure-compat option in the opt-in patch"
fi
if grep -q 'VERIFY_PERMISSION(OPT_P_GENERAL);' "$EAC"; then
    ok "--experimental-azure-compat cannot be enabled by a pushed option"
else
    bad "--experimental-azure-compat permission mask allows pushed options"
fi
if grep -q 'options_postprocess_verify_azure_compat' "$EAC"; then
    ok "Azure mode validates the config before advertising its OCC string"
else
    bad "no configuration validation for --experimental-azure-compat"
fi

# ---- 4. the build, if there is one --------------------------------------
if [ ! -f "$BUILDINFO" ]; then
    info ''
    info "no BUILDINFO at $BUILDINFO"
    info 'run scripts/build-openvpn.sh to produce a build'
else
    BUILT_VERSION="$(buildinfo openvpn_version)"
    BUILT_STACK="$(buildinfo patch_stack)"

    [ "$BUILT_VERSION" = "$VERSION" ] \
        && ok "built from OpenVPN $BUILT_VERSION" \
        || bad "BUILDINFO version $BUILT_VERSION does not match $VERSION"

    [ "$(buildinfo openvpn_commit)" = "$(manifest "$VERSION.commit")" ] \
        && ok "upstream commit matches the pin" \
        || bad "upstream commit does not match the pin"

    [ "$(buildinfo openvpn_tarball_sha256)" = "$(manifest "$VERSION.tarball_sha256")" ] \
        && ok "source tarball hash matches the pin" \
        || bad "source tarball hash does not match the pin"

    LC="$REPO_ROOT/$(manifest "$VERSION.patch.long_credentials")"
    [ "$(buildinfo long_credentials_sha256)" = "$(sha256sum "$LC" | cut -d' ' -f1)" ] \
        && ok "binary was built from the current long-credentials patch" \
        || bad "binary was built from a different long-credentials patch; rebuild"

    # Asserted, not merely printed. This script's summary states the binary is
    # upstream plus long-credentials and nothing else; a research build was
    # passing all fifteen checks and getting that summary printed over it.
    if [ "$BUILT_STACK" = "$EXPECT_STACK" ]; then
        ok "patch stack is exactly '$EXPECT_STACK'"
    else
        bad "patch stack is '$BUILT_STACK', expected '$EXPECT_STACK'"
        info 'pass --expect-stack to verify a differently-patched build deliberately'
    fi

    # Compiled in but inert; the permission mask is what keeps that safe.
    COMPAT="$(buildinfo azure_compat_available)"
    if [ "$EXPECT_STACK" = "long-credentials experimental-azure-compat" ]; then
        [ "$COMPAT" = "1" ] \
            && ok "compat patch compiled in, as the single shipped build requires" \
            || bad "azure_compat_available=$COMPAT; the shipped build must carry the compat patch"
    else
        info "azure_compat_available: $COMPAT"
    fi


    EAC_REL="$(manifest "$VERSION.patch.experimental_azure_compat")"
    EAC_BUILT="$(buildinfo experimental_azure_compat_sha256)"
    if [ "$EAC_BUILT" = "$(sha256sum "$REPO_ROOT/$EAC_REL" | cut -d' ' -f1)" ]; then
        ok "binary was built from the current experimental-azure-compat patch"
    else
        bad "binary was built from a different experimental-azure-compat patch; rebuild"
    fi

    if [ -x "$BINARY" ]; then
        [ "$(sha256sum "$BINARY" | cut -d' ' -f1)" = "$(buildinfo binary_sha256)" ] \
            && ok "binary is unmodified since it was built" \
            || bad "binary has changed since the build recorded its hash"

        # Read once: under pipefail a SIGPIPE from head could decide this.
        version_output="$("$BINARY" --version 2>&1 || true)"
        first_line="$(printf '%s\n' "$version_output" | sed -n '1p')"
        if printf '%s\n' "$first_line" | grep -Fq "OpenVPN $VERSION"; then
            ok "binary reports OpenVPN $VERSION"
        else
            bad "binary does not report OpenVPN $VERSION"
            info "reported: $first_line"
        fi
    else
        bad "no binary at $BINARY"
    fi
fi

printf '\n'
if [ "$fail" -eq 0 ]; then
    printf '\033[32m%d check(s) passed.\033[0m\n\n' "$pass"
    printf '    OpenVPN %s (commit %s)\n' "$VERSION" "$(manifest "$VERSION.commit" | cut -c1-12)"
    printf '  + %s\n' "$(manifest "$VERSION.patch.long_credentials")"
    printf '  + %s (compiled in, off by default)\n' \
        "$(manifest "$VERSION.patch.experimental_azure_compat")"
    printf '  = an artifact consistent with its recorded provenance\n\n'
    exit 0
fi

printf '\033[31m%d check(s) failed\033[0m, %d passed.\n\n' "$fail" "$pass"
exit 1
