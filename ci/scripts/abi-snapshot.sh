#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-snapshot.sh — capture / verify the LibreSCRS public C++ ABI surface.
#
# LibreMiddleware ships as a set of static archives (libLibreSCRS_*.a) plus
# the public PKCS#11 shared object (librescrs-pkcs11.so). The ABI surface
# that consumer SDK builds depend on is the demangled set of T-binding
# (global text, default-visible) symbols exported from each public archive,
# plus the dynamic-symbols list from the SO.
#
# This script generates a stable, sorted, human-readable text artefact
# checked into the tree at:
#   ci/abi/5.x-baseline.txt
#
# Use --check to compare a fresh build against the baseline; the script
# fails non-zero on any difference. Use --update to regenerate the baseline.
#
# Why text not abigail/abicompat: LibreSCRS-specific. The bulk of the API
# is plain C++20 value types + factories + builders — header-only or
# trivially inlined. abidiff against XML is overkill and obscures cosmetic
# diffs (typedef churn, unsigned-int vs size_t under different toolchains).
# A demangled T-symbol diff catches the cases that matter — function added
# / removed / signature changed — with a one-line review per change.
#
# Usage:
#   abi-snapshot.sh [--check|--update] [BUILD_DIR]
#
# Default action: --check. Default BUILD_DIR: build.

set -euo pipefail

# Force a deterministic, locale-independent sort so the baseline lines
# up byte-for-byte across developer machines and CI runners. Without
# LC_ALL=C, glibc's default UTF-8 collation interleaves alphabetic and
# punctuation differently than ASCII (e.g. en_US.UTF-8 sorts
# `…CancelSource const&)` before `…CancelSource&&)` while sr_RS sorts
# the other way), and any diff against the baseline is pure noise.
export LC_ALL=C

# Tools before anything else. Every pipeline below is `nm | awk | c++filt |
# sort`, and with c++filt absent the "command not found" used to go to
# /dev/null: the pipeline came back empty, each section printed its header and
# no symbols, and `--update` wrote a baseline of comments over a real one. The
# sibling repository's snapshot already refuses an empty section for exactly
# this reason; a missing tool is "I cannot measure", never a pass.
for tool in nm c++filt; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool not found on PATH -- cannot measure the ABI surface" >&2; exit 2; }
done

ACTION="check"
BUILD_DIR="build"

# What the scan actually saw. A section that exists but yields nothing is a
# broken artefact; no section at all is an unbuilt tree. Both are exit 2.
artefacts_scanned=0
total_symbols=0

# emit_symbols <label> <dynamic|static> <file>
#
# Writes the section's symbols on stdout and refuses an empty one. `|| true`
# on the pipeline because `set -o pipefail` would otherwise turn nm's own
# failure into exit 1 -- "ABI drift" -- where the truth is "I could not read
# this file".
# The binding classes this snapshot deliberately does NOT record, and why.
#
# The policy defines the public API as what users can reach under the LibreSCRS
# namespaces through the public targets. It says in as many words that anything
# else is implementation detail and may change in any release. Vague-linkage
# entries are not API under that definition: they are how the object model
# emits a vtable, a typeinfo, an inline member or a template instantiation, and
# the compiler decides which of them exist. Measured on this tree: 543 T, 102 W,
# 62 V, 4 u and 7 A over the seven shared libraries. Recording the 168 W/V/u
# entries would put inlining decisions into the ABI contract, so one -O level or
# one new use of an exported type would rewrite the baseline -- a gate measuring
# a proxy rather than the property. `A` is the version-definition entry, not code.
#
# The filter is declared here rather than left implicit in an awk clause,
# because a filter nobody can see is an exemption nobody can audit. It is also
# falsifiable: a binding class that is NOT in this list appearing in the export
# table stops the snapshot rather than being dropped in silence. That matters for
# exactly one shape this tree does not have today -- an exported DATA symbol
# (`D`, `B`, `R`, `G`, `S`), which IS part of a C++ ABI contract and which the
# old T-only clause would have thrown away without a word.
#
# What this filter does NOT answer: whether an implementation-detail symbol
# should be in the export table at all. Sixteen of the W/V entries name
# LibreSCRS::*::Internal:: types. That is a visibility question and it belongs to
# check-impl-visibility.sh, which records it.
NOT_RECORDED_BINDINGS="W V u A"

# emit_symbols <label> <dynamic|static> <file>
#
# Writes the section's symbols on stdout and refuses an empty one. `|| true`
# on the pipeline because `set -o pipefail` would otherwise turn nm's own
# failure into exit 1 -- "ABI drift" -- where the truth is "I could not read
# this file".
emit_symbols() {
    local label="$1" mode="$2" file="$3" syms n raw unexpected
    if [[ "$mode" == dynamic ]]; then
        raw="$(nm -D -U "$file" 2>/dev/null || true)"
    else
        raw="$(nm -U "$file" 2>/dev/null || true)"
    fi

    # Every binding class in the table that is neither recorded (T) nor declared
    # as not recorded. A new one is "I cannot judge what this is": deciding for
    # it silently is how a data symbol would leave the contract unnoticed.
    unexpected="$(printf '%s\n' "$raw" \
        | awk 'NF >= 3 { print $2 }' \
        | sort -u \
        | grep -vxF -e T $(printf -- '-e %s ' $NOT_RECORDED_BINDINGS) || true)"
    if [[ -n "$unexpected" ]]; then
        echo "FATAL: section '$label' exports binding class(es) this snapshot has no" >&2
        echo "       rule for: $(printf '%s' "$unexpected" | tr '\n' ' ')" >&2
        echo "       T is recorded; $NOT_RECORDED_BINDINGS are deliberately not (see the" >&2
        echo "       note above emit_symbols). A data symbol is part of the ABI and must" >&2
        echo "       be recorded; decide, and say which in the same change." >&2
        exit 2
    fi

    syms="$(printf '%s\n' "$raw" | awk '$2 == "T" { print $3 }' | c++filt | sort -u || true)"
    n=0
    [[ -n "$syms" ]] && n="$(printf '%s\n' "$syms" | wc -l)"
    if [[ "$n" -eq 0 ]]; then
        echo "FATAL: section '$label' yielded no T-binding symbols from '$file'" >&2
        echo "       (broken artefact, or nm/c++filt produced nothing)." >&2
        echo "       Refusing to emit an empty snapshot for this section." >&2
        exit 2
    fi
    printf '%s\n' "$syms"
    artefacts_scanned=$((artefacts_scanned + 1))
    total_symbols=$((total_symbols + n))
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) ACTION="check"; shift ;;
        --update) ACTION="update"; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) BUILD_DIR="$1"; shift ;;
    esac
done

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "ERROR: build dir '$BUILD_DIR' not found" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BASELINE="${REPO_ROOT}/ci/abi/5.x-baseline.txt"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

snapshot="${SCRATCH}/snapshot.txt"

{
    echo "# LibreSCRS public ABI snapshot"
    echo "# Generated by ci/scripts/abi-snapshot.sh"
    echo "# Format: one demangled T-binding symbol per line, sorted; one"
    echo "# section per public archive / SO, header line '== <basename> =='."
    echo "# Re-generate with: ci/scripts/abi-snapshot.sh --update <build_dir>"
    echo "# Diff a fresh build against this baseline with: ci/scripts/abi-snapshot.sh --check"
    echo "#"
    echo "# Scans whichever LibreSCRS_* surface is present in <build_dir>:"
    echo "#   * SHARED build → libLibreSCRS_*.so.<MAJOR>.<MINOR>.<PATCH> dynamic"
    echo "#     T-binding symbols (the distro-installable ABI surface)."
    echo "#   * STATIC build → libLibreSCRS_*.a archive T-binding symbols (the"
    echo "#     monolithic SDK ABI surface; useful only when"
    echo "#     LIBREMIDDLEWARE_BUILD_PLUGINS=OFF — see the FATAL_ERROR guard"
    echo "#     in the root CMakeLists.txt)."
    echo "# Both paths funnel through the same 'nm | c++filt | awk T | sort -u'"
    echo "# pipeline so a single baseline applies to whichever mode CI runs."

    # Prefer the SHARED .so surface when present (the distro-installable
    # ABI). Fall back to STATIC .a archives only when no SHARED .so files
    # exist (monolithic SDK build).
    so_count=$(find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 -name 'libLibreSCRS_*.so.[0-9]*.[0-9]*.[0-9]*' 2>/dev/null | wc -l)
    if [[ "$so_count" -gt 0 ]]; then
        while IFS= read -r so; do
            name="$(basename "$so")"
            # Strip the trailing `.X.Y.Z` so the baseline carries the
            # stable soname (libLibreSCRS_<Module>.so) rather than the
            # patch-version filename — keeps the baseline insensitive to
            # 4.x point releases.
            stable_name="${name%.*.*.*}"
            echo
            echo "== $stable_name =="
            emit_symbols "$stable_name" dynamic "$so"
        done < <(find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 -name 'libLibreSCRS_*.so.[0-9]*.[0-9]*.[0-9]*' | sort)
    else
        while IFS= read -r archive; do
            name="$(basename "$archive")"
            echo
            echo "== $name =="
            emit_symbols "$name" static "$archive"
        done < <(find "$BUILD_DIR" -name 'libLibreSCRS_*.a' | sort)
    fi

    # PKCS#11 shared object — dynamic symbols (T-binding) only.
    # PKCS#11 has a fixed C ABI (the C_* function table); we still
    # snapshot any C++ symbols that leak (should be zero — verified
    # by the SOVERSION'd .so's own visibility settings).
    while IFS= read -r so; do
        name="$(basename "$so")"
        echo
        echo "== $name =="
        # `--defined-only` is GNU-only; `-U` is portable.
        emit_symbols "$name" dynamic "$so"
    done < <(find "$BUILD_DIR" -path "*/lib/pkcs11/librescrs-pkcs11.so.[0-9]*" -not -name "*.[0-9]" | sort | head -1)

} > "$snapshot"

# A header-only snapshot is a measurement that did not happen, and writing one
# over the baseline disarms every later --check against the same empty tree.
if [[ "$artefacts_scanned" -eq 0 ]]; then
    echo "FATAL: no libLibreSCRS_* archive or shared object under '$BUILD_DIR'" >&2
    echo "       -- build first. Refusing to emit a header-only snapshot." >&2
    exit 2
fi
if [[ "$total_symbols" -eq 0 ]]; then
    echo "FATAL: scanned $artefacts_scanned artefact(s) under '$BUILD_DIR' and read" >&2
    echo "       0 symbols. Refusing to emit an empty snapshot." >&2
    exit 2
fi

case "$ACTION" in
    update)
        mkdir -p "$(dirname "$BASELINE")"
        cp "$snapshot" "$BASELINE"
        echo "Wrote ABI baseline: $BASELINE"
        wc -l "$BASELINE"
        ;;
    check)
        if [[ ! -f "$BASELINE" ]]; then
            echo "ERROR: baseline not found at $BASELINE" >&2
            echo "       Run 'ci/scripts/abi-snapshot.sh --update <build_dir>' to capture." >&2
            exit 2
        fi
        if diff -u "$BASELINE" "$snapshot" > "${SCRATCH}/abi-diff.txt"; then
            echo "ABI snapshot matches baseline ($(wc -l < "$BASELINE") lines)."
            exit 0
        else
            echo "ABI DRIFT detected vs $BASELINE:" >&2
            cat "${SCRATCH}/abi-diff.txt" >&2
            echo >&2
            echo "If this drift is intentional (a new public API addition or" >&2
            echo "an explicit breaking change for a major bump):" >&2
            echo "   ci/scripts/abi-snapshot.sh --update $BUILD_DIR" >&2
            exit 1
        fi
        ;;
esac
