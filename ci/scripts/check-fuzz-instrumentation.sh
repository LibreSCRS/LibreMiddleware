#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-fuzz-instrumentation.sh [build-dir]   (default: build-fuzz)
#
# A harness that only LINKS the library it is meant to fuzz fuzzes
# uninstrumented code.
#
# The sanitizer flags in fuzz/CMakeLists.txt are PRIVATE on each executable, so
# they reach that executable's own translation units and stop there. The
# libraries are compiled without them. For such a harness the
# undefined-behaviour checks never run at all, and the address checks see only
# what their interceptors see -- so a scalar read one past the end of a
# heap buffer, which is exactly what a length-driven walker does on hostile
# bytes, is not reported. Nothing failed; nothing was measured.
#
# fuzz/instrumented-sources.txt is the single declaration of which harness
# compiles which source, and which harness deliberately does not. CMake reads
# it and this check reads it, the way cmake/EmrtdCryptoPrivateIncludes.cmake is
# read twice -- that file exists because two hand-kept copies of one list
# drifted and three harnesses stopped compiling their source with nobody
# noticing.
#
# What is asserted, per row:
#   * a harness the build produced but the list does not mention -> failure.
#     Otherwise a new harness is silently LINK_ONLY, which is the state this
#     check exists to end.
#   * a named source whose object is not in the harness's object set ->
#     failure. The list would otherwise describe a build that does not exist.
#   * a named source whose object carries no sanitizer references -> failure.
#     This is the only assertion that measures instrumentation rather than
#     bookkeeping: an object can be in the target and still be compiled with
#     the checks off.
#   * a LINK_ONLY row with no written reason -> failure. "Temporary" with no
#     owner is how six of ten harnesses got here.
#
# Exit: 0 every declared source is compiled in and instrumented
#       1 a declaration and the build disagree, or an object is not instrumented
#       2 cannot measure (no build directory, no list, no nm) -- never a pass.
set -uo pipefail
shopt -s globstar nullglob   # without globstar, ** is ONE level and every
                             # object lookup silently finds nothing

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD="${1:-$repo/build-fuzz}"
[ -d "$BUILD" ] || { echo "FATAL: build directory '$BUILD' not found -- cannot measure" >&2; exit 2; }
LIST="$repo/fuzz/instrumented-sources.txt"
[ -f "$LIST" ] || { echo "FATAL: $LIST not found -- cannot measure" >&2; exit 2; }
command -v nm >/dev/null 2>&1 || { echo "FATAL: nm(1) is not on PATH -- cannot measure" >&2; exit 2; }

rc=0
fail() { echo "FAIL: $*" >&2; rc=1; }

declared="$(mktemp)"; trap 'rm -f "$declared"' EXIT

built=()
for d in "$BUILD"/fuzz/CMakeFiles/fuzz_*.dir; do
    built+=("$(basename "${d%.dir}")")
done
if [ "${#built[@]}" -eq 0 ]; then
    echo "FATAL: no fuzz target object directories under $BUILD/fuzz -- cannot measure" >&2
    exit 2
fi

while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue;; esac
    harness="${line%%:*}"
    rest="${line#*:}"
    [ "$harness" = "$line" ] && { fail "$(basename "$LIST"): unparseable row: $line"; continue; }
    harness="${harness// /}"
    printf '%s\n' "$harness" >> "$declared"

    dir="$BUILD/fuzz/CMakeFiles/$harness.dir"
    if [ ! -d "$dir" ]; then
        fail "the list names $harness, which this build did not produce"
        continue
    fi

    body="${rest%%#*}"
    reason="${rest#"$body"}"
    body="$(printf '%s' "$body" | tr -d '[:space:]')"

    if [ "$body" = "LINK_ONLY" ]; then
        if [ -z "$reason" ]; then
            fail "$harness is LINK_ONLY with no written reason -- say why, and write 'due YYYY-MM-DD'"
            continue
        fi
        # The date is read, not merely present. A reason ending in "due <date>"
        # was the whole difference between a deferral and a permanent state, and
        # nothing parsed it: three harnesses would have passed their date in
        # silence, which is how six of ten got here in the first place.
        due="$(printf '%s' "$reason" | grep -oE 'due [0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -1 | cut -d' ' -f2)"
        if [ -z "$due" ]; then
            fail "$harness is LINK_ONLY with no due date -- write 'due YYYY-MM-DD' so the deferral can end"
        elif ! due_epoch="$(date -u -d "$due" +%s 2>/dev/null)" || [ -z "$due_epoch" ]; then
            fail "$harness: '$due' is not a date this can be judged by"
        elif [ "$due_epoch" -lt "$(date -u +%s)" ]; then
            fail "$harness has been LINK_ONLY past its own date of $due -- either instrument it or move the date deliberately"
        fi
        continue
    fi

    src="$body"
    # Matched on the declared PATH, not its basename. CMake mirrors an
    # out-of-tree source's path under the target's object directory, so the
    # object for lib/emrtd/src/data_group.cpp ends with exactly that path --
    # while a basename match would be satisfied by any data_group.cpp.o from
    # anywhere, and the declaration would then describe a file it never saw.
    objs=("$dir"/**/"$src".o)
    if [ "${#objs[@]}" -eq 0 ]; then
        fail "$harness does not compile $src -- the list says it does"
        continue
    fi
    for obj in "${objs[@]}"; do
        n=$(nm -u "$obj" 2>/dev/null | grep -c '__asan_report\|__ubsan_handle')
        if [ "$n" -eq 0 ]; then
            fail "$harness: $src is in the target but its object carries no sanitizer references -- it is compiled with the checks off"
        fi
    done
done < "$LIST"

for h in "${built[@]}"; do
    grep -qxF "$h" "$declared" 2>/dev/null \
        || fail "$h is built but not in $(basename "$LIST") -- a harness nobody declared is a harness nobody noticed was link-only"
done

if [ "$rc" = 0 ]; then
    echo "check-fuzz-instrumentation: ${#built[@]} harness(es) declared and measured under $BUILD"
fi
exit "$rc"
