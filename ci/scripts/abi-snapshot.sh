#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-snapshot.sh — capture / verify the LibreSCRS public C++ ABI surface.
#
# LibreMiddleware ships as a set of libLibreSCRS_* shared libraries. The ABI
# surface that consumer SDK builds depend on is the demangled set of T-binding
# (global text, default-visible) symbols exported from each public library.
#
# This script generates a stable, sorted, human-readable text artefact
# checked into the tree at:
#   ci/abi/5.x-baseline.txt
#
# Use --check to compare a fresh build against the baseline; the script
# fails non-zero on any difference. Use --update to regenerate the baseline.
# Both refuse a tree in which one function is exported by two libraries, and
# a tree that exports a LibreSCRS entity the installed headers do not declare
# (see "Only public entities" below).
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
#
# Needs clang (CXX, default clang++) and python3 besides nm and c++filt: the
# public surface is read from clang's AST of the installed headers.

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
for tool in nm c++filt python3; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool not found on PATH -- cannot measure the ABI surface" >&2; exit 2; }
done

ACTION="check"
BUILD_DIR="build"

# What the scan actually saw. A section that exists but yields nothing is a
# broken artefact; no section at all is an unbuilt tree. Both are exit 2.
artefacts_scanned=0
total_symbols=0

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
# should be in the export table at all. That is judged over EVERY binding class,
# not recorded, by the public-entity rule below.
NOT_RECORDED_BINDINGS="W V u A"

# ── Only public entities ──────────────────────────────────────────────────
# Every exported symbol, whatever its binding class, must name an entity that
# the installed headers declare as a consumer compiles them -- without
# LIBRESCRS_INTERNAL_BUILD, friend declarations not counted -- and nothing in
# an Internal or detail scope (abi-public-surface.py says how it is measured).
#
# This replaced a rule that dropped every T symbol whose own name contained
# ::Internal:: or ::detail:: before recording the rest. That rule made the
# baseline fall from 44 internal lines to 5 while the libraries still exported
# 82 internal symbols, and it recorded 35 secure-channel members, declared only
# in headers that are never installed, as public 5.x ABI.
#
# No internal symbol is exported, none is listed as an exception. The same
# pass reads what the shipped images -- a card plugin, a sibling LibreSCRS
# library, the installed test archive -- import (an import of a hidden or
# internal symbol fails) and what inline bodies of the installed headers call,
# and fails an installed header that opens a condition on
# LIBRESCRS_INTERNAL_BUILD.

# emit_symbols <label> <file>
#
# Writes the section's symbols on stdout and refuses an empty one. `|| true`
# on the pipeline because `set -o pipefail` would otherwise turn nm's own
# failure into exit 1 -- "ABI drift" -- where the truth is "I could not read
# this file".
emit_symbols() {
    local label="$1" file="$2" syms n raw unexpected
    raw="$(nm -D -U "$file" 2>/dev/null || true)"

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

    # Every exported function, under the library that exports it, for the
    # one-owner check after the scan.
    printf '%s\n' "$raw" | awk -v lib="$label" '$2 == "T" { print $3 "\t" lib }' >> "$OWNERS"

    # Every export of every binding class, for the public-entity rule.
    printf '%s\n' "$raw" | awk -v lib="$label" 'NF >= 3 && $2 != "A" { print lib "\t" $2 "\t" $3 }' >> "$EXPORTS"

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
SURFACE="${REPO_ROOT}/ci/scripts/abi-public-surface.py"
INCLUDE_ROOT="${REPO_ROOT}/include"
CXX="${CXX:-clang++}"
[[ -f "$SURFACE" ]] || { echo "FATAL: required file '$SURFACE' not found" >&2; exit 2; }
if ! "$CXX" --version 2>/dev/null | grep -q clang; then
    echo "FATAL: '$CXX' is not clang -- the public surface is read from clang's AST" >&2
    exit 2
fi
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

snapshot="${SCRATCH}/snapshot.txt"
OWNERS="${SCRATCH}/owners.txt"
EXPORTS="${SCRATCH}/exports.tsv"
: > "$OWNERS"
: > "$EXPORTS"

{
    echo "# LibreSCRS public ABI snapshot"
    echo "# Generated by ci/scripts/abi-snapshot.sh"
    echo "# Format: one demangled T-binding symbol per line, sorted; one"
    echo "# section per public shared library, header line '== <soname> =='."
    echo "# Re-generate with: ci/scripts/abi-snapshot.sh --update <build_dir>"
    echo "# Diff a fresh build against this baseline with: ci/scripts/abi-snapshot.sh --check"
    echo "#"
    echo "# Scans the dynamic T-binding symbols of every"
    echo "# libLibreSCRS_*.so.<MAJOR>.<MINOR>.<PATCH> in <build_dir>."

    while IFS= read -r so; do
        name="$(basename "$so")"
        # Strip the trailing `.X.Y.Z` so the baseline carries the
        # stable soname (libLibreSCRS_<Module>.so) rather than the
        # patch-version filename — keeps the baseline insensitive to
        # point releases.
        stable_name="${name%.*.*.*}"
        echo
        echo "== $stable_name =="
        emit_symbols "$stable_name" "$so"
    done < <(find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 -name 'libLibreSCRS_*.so.[0-9]*.[0-9]*.[0-9]*' 2>/dev/null | sort)

} > "$snapshot"

# A header-only snapshot is a measurement that did not happen, and writing one
# over the baseline disarms every later --check against the same empty tree.
if [[ "$artefacts_scanned" -eq 0 ]]; then
    echo "FATAL: no libLibreSCRS_* shared library under '$BUILD_DIR/lib/LibreSCRS'" >&2
    echo "       -- build first. Refusing to emit a header-only snapshot." >&2
    exit 2
fi
if [[ "$total_symbols" -eq 0 ]]; then
    echo "FATAL: scanned $artefacts_scanned artefact(s) under '$BUILD_DIR' and read" >&2
    echo "       0 symbols. Refusing to emit an empty snapshot." >&2
    exit 2
fi

# One owner per exported function. A library that absorbs another library's
# implementation (an OBJECT or static archive linked into two shared targets)
# exports the same functions twice, and the snapshot would record both copies
# as two separate promises: the second library could then never drop them
# within the major version. Which copy a process runs depends on load order.
# Vague-linkage entries (V, W) legitimately appear in every library that uses
# a type, so this judges T only -- the bindings the snapshot records.
# Refused for --update as well, so the
# duplicate cannot be written into the baseline.
dup_owners="$(awk -F'\t' '{ n[$1]++; libs[$1] = libs[$1] " " $2 }
    END { for (s in n) if (n[s] > 1) print s "\t" libs[s] }' "$OWNERS" | sort)"
if [[ -n "$dup_owners" ]]; then
    # Arithmetic expansion drops the padding BSD wc puts before the count.
    dup_count=$(($(printf '%s\n' "$dup_owners" | wc -l)))
    echo "FATAL: ${dup_count} function(s) exported by more than one library:" >&2
    printf '%s\n' "$dup_owners" | while IFS=$'\t' read -r sym libs; do
        printf '  %s  --%s\n' "$(printf '%s\n' "$sym" | c++filt)" "$libs" >&2
    done
    echo "       Each exported function has one owning library. Link the owner" >&2
    echo "       instead of absorbing its implementation into a second library." >&2
    exit 1
fi

# What the shipped images import: the core libraries (sibling imports), every
# card plugin, and the installed test archive (minus what its own members
# define). Test executables are not shipped and are not read.
IMPORTS="${SCRATCH}/imports.tsv"
: > "$IMPORTS"
plugin_count=0
while IFS= read -r image; do
    [[ -n "$image" ]] || continue
    case "$image" in */plugins/*) plugin_count=$((plugin_count + 1)) ;; esac
    nm -D -u "$image" 2>/dev/null | awk -v img="$(basename "$image")" '{ print img "\t" $NF }' >> "$IMPORTS"
done < <({
    find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 -name 'libLibreSCRS_*.so.[0-9]*.[0-9]*.[0-9]*'
    find "$BUILD_DIR/plugins" -maxdepth 2 -name '*.so' 2>/dev/null
} | sort)
if [[ "$plugin_count" -eq 0 ]]; then
    echo "FATAL: no card plugin under '$BUILD_DIR/plugins' -- cannot judge what shipped images import" >&2
    exit 2
fi
while IFS= read -r archive; do
    [[ -n "$archive" ]] || continue
    nm -U "$archive" 2>/dev/null | awk 'NF >= 3 { print $3 }' | sort -u > "$SCRATCH/archive-defined"
    nm -u "$archive" 2>/dev/null | awk 'NF >= 2 { print $NF }' | sort -u \
        | comm -23 - "$SCRATCH/archive-defined" \
        | awk -v img="$(basename "$archive")" '{ print img "\t" $0 }' >> "$IMPORTS"
done < <(find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 -name 'libLibreSCRSTesting_*.a' | sort)

# Refused for --update as well, so an internal export cannot be written into
# the baseline as public ABI.
surface_rc=0
python3 "$SURFACE" --clang "$CXX" --include-root "$INCLUDE_ROOT" --exports "$EXPORTS" \
    --imports "$IMPORTS" || surface_rc=$?
if [[ "$surface_rc" -ne 0 ]]; then
    exit "$surface_rc"
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
