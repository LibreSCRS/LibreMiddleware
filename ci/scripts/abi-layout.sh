#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-layout.sh — record and verify the SHAPE of the public LibreSCRS ABI.
#
# The symbol snapshot beside this one (ci/scripts/abi-snapshot.sh) lists the
# exported, demangled symbols. A type's size, a member's byte offset and a
# virtual's slot index are none of those, so a change to any of them passes a
# clean symbol diff untouched — while a program linked against the previous
# release reads a wrong element size out of a value returned by reference and
# dies. Inline members emit no symbol at all, so adding, removing or reordering
# one is entirely invisible to a symbol list.
#
# This script therefore records, from the public headers alone:
#   * one line per public type      — sizeof / align (and 'polymorphic')
#   * one line per top-level member — its byte offset
#   * the full vtable slot order of every polymorphic public class
#   * the plugin ABI sentinel
#
# It needs a compiler and no build, so it costs seconds and can run even when
# the build is broken.
#
# ADDITIVE     = every baseline line still present, byte-identical. Appending a
#                member after the last one, or a virtual after the last slot,
#                only adds lines.
# NON-ADDITIVE = a baseline line disappeared: a size moved, an offset shifted,
#                a slot changed occupant, a type went away. This requires the
#                SONAME integer (LIBRESCRS_ABI_SOVERSION, in the top-level
#                CMakeLists.txt) to move, and --update refuses to record such a
#                difference until it has.
#
# Canonical configuration: Linux / x86_64 / libstdc++ — the same leg that runs
# abi-snapshot.sh. Member offsets are facts about one toolchain and one
# standard library, so exactly one configuration may record them. --update is
# refused outright on Darwin.
#
# Usage:
#   abi-layout.sh --check  <build_dir>    compare tree against baseline
#   abi-layout.sh --update <build_dir>    rewrite baseline from the tree
#   abi-layout.sh --print  <build_dir>    write the snapshot to stdout
#
# <build_dir> is mandatory and has no default: --check and --print always also
# write the snapshot to <build_dir>/abi-layout-snapshot.txt, so a failing CI run
# can upload the file the runner actually saw. They write nothing else there.
#
# Environment:
#   LIBRESCRS_ABI_LAYOUT_INCLUDE_ROOT   override the header root. For a one-off
#       recording from a historical header tree and for the selftest only;
#       never in CI.
#
# Exit codes:
#   0  layout matches the baseline (or --print / --update succeeded)
#   1  non-additive difference, or --update refused
#   2  the tool could not produce a usable snapshot, or was misused
#      — deliberately a different code from a difference, so a broken tool is
#      never read as an ABI finding.

set -euo pipefail
export LC_ALL=C

ACTION=""
BUILD_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) ACTION="check"; shift ;;
        --update) ACTION="update"; shift ;;
        --print) ACTION="print"; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        -*) echo "ERROR: unknown option '$1'" >&2; exit 2 ;;
        *) BUILD_DIR="$1"; shift ;;
    esac
done

[[ -n "$ACTION" ]] || ACTION="check"

if [[ -z "$BUILD_DIR" ]]; then
    echo "ERROR: build dir '' not found" >&2
    exit 2
fi
if [[ ! -d "$BUILD_DIR" ]]; then
    echo "ERROR: build dir '$BUILD_DIR' not found" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INCLUDE_ROOT="${LIBRESCRS_ABI_LAYOUT_INCLUDE_ROOT:-${REPO_ROOT}/include}"
PROBE="${REPO_ROOT}/ci/abi/vtable-probe.cpp"
BASELINE="${REPO_ROOT}/ci/abi/layout-baseline.txt"
CLASSIFY="${REPO_ROOT}/ci/scripts/abi-layout-classify.py"

for f in "$PROBE" "$CLASSIFY"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: required file '$f' not found" >&2
        exit 2
    fi
done
if [[ ! -d "$INCLUDE_ROOT" ]]; then
    echo "ERROR: include root '$INCLUDE_ROOT' not found" >&2
    exit 2
fi

# The SONAME integer is read out of the tree, never guessed. A default value
# here would let the check run against a tree that has no such declaration and
# report a difference that means nothing.
TREE_SOVERSION="$(grep -oP 'set\(LIBRESCRS_ABI_SOVERSION\s+\K[0-9]+' \
                  "${REPO_ROOT}/CMakeLists.txt" || true)"
if [[ -z "$TREE_SOVERSION" ]]; then
    echo "ERROR: LIBRESCRS_ABI_SOVERSION not found in ${REPO_ROOT}/CMakeLists.txt" >&2
    exit 2
fi

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

CXX="${CXX:-clang++}"
if ! command -v "$CXX" >/dev/null 2>&1; then
    echo "ERROR: '$CXX' not found; the layout snapshot needs clang" >&2
    exit 2
fi

CLANG_VERSION="$("$CXX" --version | head -1)"
GLIBCXX_RELEASE="$(echo '#include <version>' \
    | "$CXX" -std=c++23 -x c++ -E -dM - 2>/dev/null \
    | sed -n 's/^#define _GLIBCXX_RELEASE \(.*\)$/\1/p' | head -1)"
[[ -n "$GLIBCXX_RELEASE" ]] || GLIBCXX_RELEASE="unknown"

# ---------------------------------------------------------------------------
# Produce the snapshot.
# ---------------------------------------------------------------------------

# The umbrella TU is generated by finding every public header, so a brand-new
# public header is covered by the gate without anyone listing it.
( cd "$INCLUDE_ROOT" && find LibreSCRS -name '*.h' -not -path '*/detail/*' | sort \
    | sed 's|^|#include <|; s|$|>|' ) > "${SCRATCH}/all.cpp"

if [[ ! -s "${SCRATCH}/all.cpp" ]]; then
    echo "ERROR: layout snapshot is not usable: no public headers under ${INCLUDE_ROOT}/LibreSCRS" >&2
    exit 2
fi

# The prototype swallowed clang's stderr and its exit code. It must not: a
# failed compile yields an empty dump, an empty dump is "every line vanished",
# and a tool failure would be read as a tidy NON-ADDITIVE ABI finding.
set +e
"$CXX" -std=c++23 -w -I"$INCLUDE_ROOT" -fsyntax-only \
       -Xclang -fdump-record-layouts-complete "${SCRATCH}/all.cpp" \
       > "${SCRATCH}/rl.txt" 2> "${SCRATCH}/rl.err"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
    echo "ERROR: layout snapshot is not usable: record-layout dump failed (rc=$rc)" >&2
    sed -n '1,40p' "${SCRATCH}/rl.err" >&2
    exit 2
fi

set +e
"$CXX" -std=c++23 -w -I"$INCLUDE_ROOT" -c -o /dev/null \
       -Xclang -fdump-vtable-layouts "$PROBE" \
       > "${SCRATCH}/vt.txt" 2> "${SCRATCH}/vt.err"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
    echo "ERROR: layout snapshot is not usable: vtable dump failed (rc=$rc)" >&2
    sed -n '1,40p' "${SCRATCH}/vt.err" >&2
    exit 2
fi

snapshot="${SCRATCH}/snapshot.txt"

{
    echo "# LibreSCRS public ABI LAYOUT snapshot"
    echo "# soversion: ${TREE_SOVERSION}"
    echo "# clang: ${CLANG_VERSION}"
    echo "# libstdc++: _GLIBCXX_RELEASE ${GLIBCXX_RELEASE}"
    echo "# host: linux-x86_64"
    echo "#"
    echo "# One line per public type (sizeof/align), one per top-level data member"
    echo "# (byte offset), and the full vtable slot order of every polymorphic public"
    echo "# class. Regenerate with: ci/scripts/abi-layout.sh --update <build_dir>"
    echo "#"
    echo "# Canonical configuration: Linux / x86_64 / libstdc++ — the same leg that"
    echo "# runs abi-snapshot.sh. Offsets are toolchain-ABI-specific; never"
    echo "# regenerate on macOS."
    echo ""
    echo "== record layouts =="

    python3 - "${SCRATCH}/rl.txt" <<'PY'
import re, sys
out = []
name = None; members = []; poly = False
for line in open(sys.argv[1], encoding='utf-8', errors='replace'):
    if line.startswith('*** Dumping AST Record Layout'):
        name = None; members = []; poly = False; continue
    m = re.match(r'^ *0 \| (?:class|struct|union) (LibreSCRS::\S+)\s*$', line)
    if m and name is None:
        name = m.group(1); continue
    if name is None:
        continue
    if '[sizeof=' in line:
        sz = re.search(r'sizeof=(\d+)', line).group(1)
        al = re.search(r'align=(\d+)', line).group(1)
        if '::detail::' not in name:
            out.append(f"{name}\tsizeof={sz} align={al}{' polymorphic' if poly else ''}")
            out.extend(f"{name}\t  +{off:<5} {what}" for off, what in members)
        name = None; continue
    m = re.match(r'^ *(\d+) \|   (\S.*)$', line)
    if m:
        what = m.group(2).rstrip()
        if 'vtable pointer' in what: poly = True; continue
        if what.endswith('(base)') or what.endswith('(base) (empty)'): continue
        members.append((int(m.group(1)), what))
for l in sorted(set(out)):
    print(l)
PY

    echo ""
    echo "== vtable slot order =="
    # The dump's own header carries the entry count ("(27 entries)."), so every
    # legitimate append would read as a removal without stripping it.
    awk '/^Vtable for /{p=($0 ~ /VtProbe/); if(p) print; next} p && /^ *[0-9]+ \|/ {print} p && /^$/ {p=0}' \
        "${SCRATCH}/vt.txt" \
        | sed 's/(anonymous namespace):://g; s/ ([0-9]* entries)\.$//; s/  *$//'

    echo ""
    echo "== plugin ABI sentinel =="
    grep -h "kCardPluginAbiVersion = " "${INCLUDE_ROOT}/LibreSCRS/Plugin/PluginTypes.h" | sed 's/^ *//'
} > "$snapshot"

# ---------------------------------------------------------------------------
# Sanity: an unusable snapshot must never reach the classifier.
# ---------------------------------------------------------------------------

section_lines() {
    awk -v want="$1" '
        /^== /   { inside = ($0 == want); next }
        inside && NF { n++ }
        END { print n + 0 }
    ' "$snapshot"
}

rl_lines="$(section_lines '== record layouts ==')"
vt_lines="$(section_lines '== vtable slot order ==')"

if [[ "$rl_lines" -lt 150 ]]; then
    echo "ERROR: layout snapshot is not usable: '== record layouts ==' has ${rl_lines} lines (< 150)" >&2
    exit 2
fi
if [[ "$vt_lines" -lt 20 ]]; then
    echo "ERROR: layout snapshot is not usable: '== vtable slot order ==' has ${vt_lines} lines (< 20)" >&2
    exit 2
fi
if ! grep -q $'^LibreSCRS::Plugin::CardPlugin\tsizeof=.* polymorphic$' "$snapshot"; then
    echo "ERROR: layout snapshot is not usable: LibreSCRS::Plugin::CardPlugin is missing or not polymorphic" >&2
    exit 2
fi

# Every polymorphic public class must be instantiated by the probe, or its
# vtable never reaches the snapshot and the gate silently stops covering it.
uncovered="$(awk -F'\t' '/\tsizeof=.* polymorphic$/ {print $1}' "$snapshot" | sort -u \
             | while read -r cls; do
                 short="${cls##*::}"
                 grep -q -- "$short" "$PROBE" || echo "$cls"
               done)"
if [[ -n "$uncovered" ]]; then
    while read -r cls; do
        [[ -n "$cls" ]] || continue
        echo "ERROR: polymorphic class ${cls} is not covered by ci/abi/vtable-probe.cpp" >&2
    done <<< "$uncovered"
    exit 2
fi

snapshot_lines="$(wc -l < "$snapshot")"

# ---------------------------------------------------------------------------
# Act.
# ---------------------------------------------------------------------------

case "$ACTION" in
print)
    cp -- "$snapshot" "${BUILD_DIR}/abi-layout-snapshot.txt"
    cat "$snapshot"
    exit 0
    ;;

check)
    cp -- "$snapshot" "${BUILD_DIR}/abi-layout-snapshot.txt"
    if [[ ! -f "$BASELINE" ]]; then
        echo "ERROR: baseline '${BASELINE}' not found; record it with --update" >&2
        exit 2
    fi
    base_soversion="$(sed -n 's/^# soversion: \([0-9]*\)$/\1/p' "$BASELINE" | head -1)"
    [[ -n "$base_soversion" ]] || base_soversion="unknown"

    set +e
    python3 "$CLASSIFY" "$BASELINE" "$snapshot" > "${SCRATCH}/verdict.txt" 2>&1
    rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
        # --check judges SHAPE only. The soversions are reported, never
        # decisive: between the SONAME bump and the one permitted baseline
        # rewrite the tree deliberately says one number and the baseline
        # another, and that on its own is not a failure.
        echo "NON-ADDITIVE ABI change (tree soversion=${TREE_SOVERSION}, baseline soversion=${base_soversion}):"
        sed '1d' "${SCRATCH}/verdict.txt"
        exit 1
    fi
    echo "ABI layout snapshot matches baseline (${snapshot_lines} lines, soversion ${TREE_SOVERSION})."
    exit 0
    ;;

update)
    if [[ "$(uname -s)" == "Darwin" ]]; then
        echo "ERROR: --update is refused on Darwin; member offsets are facts about one toolchain" >&2
        exit 1
    fi
    if [[ -f "$BASELINE" ]]; then
        base_soversion="$(sed -n 's/^# soversion: \([0-9]*\)$/\1/p' "$BASELINE" | head -1)"
        [[ -n "$base_soversion" ]] || base_soversion="unknown"
        set +e
        python3 "$CLASSIFY" "$BASELINE" "$snapshot" > "${SCRATCH}/verdict.txt" 2>&1
        rc=$?
        set -e
        if [[ $rc -ne 0 && "$TREE_SOVERSION" == "$base_soversion" ]]; then
            echo "ERROR: refusing to record a non-additive change while the SONAME integer stands still (tree=${TREE_SOVERSION} baseline=${base_soversion})" >&2
            sed '1d' "${SCRATCH}/verdict.txt" >&2
            exit 1
        fi
    fi
    cp -- "$snapshot" "${BUILD_DIR}/abi-layout-snapshot.txt"
    cp -- "$snapshot" "$BASELINE"
    echo "ABI layout baseline recorded (${snapshot_lines} lines, soversion ${TREE_SOVERSION})."
    exit 0
    ;;
esac
