#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-fuzz-instrumentation.selftest.sh -- prove the instrumentation check can
# fail, including on the one thing it is actually for.
#
# Three of the four cases below measure BOOKKEEPING: a harness missing from the
# list, a list naming a source the target does not compile, a missing build
# directory. A check whose measuring branch is dead -- one whose object lookup
# quietly finds nothing, so its `grep -c` is compared against an empty string,
# or one that greps a file that is always there -- passes all three. The fourth
# case is the one that separates them: the source IS compiled into the target,
# and is compiled with `-fno-sanitize=all`. Only a check that reads the object
# back fails that.
#
# Each case builds a real two-file libFuzzer target with clang, because the
# property under test is a property of an object file and cannot be faked with
# a text fixture. Without clang the selftest exits 2 -- it has not passed.
#
# Cases (all four are perturbations, all four must go non-zero):
#   link_only_undeclared    harness built, absent from the list  -> 1, names it
#   source_not_in_target    list names a source not compiled     -> 1, names it
#   no_build_dir            no build directory                   -> 2 (never 0)
#   uninstrumented_object   source in target, sanitizers off     -> 1, names it
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-fuzz-instrumentation.sh"
CLANG="${CLANGXX:-}"
if [ -z "$CLANG" ]; then
    for c in clang++-21 clang++; do command -v "$c" >/dev/null 2>&1 && { CLANG="$c"; break; }; done
fi
[ -n "$CLANG" ] || { echo "FATAL: no clang++ on PATH -- cannot measure" >&2; exit 2; }
command -v cmake >/dev/null 2>&1 || { echo "FATAL: no cmake on PATH -- cannot measure" >&2; exit 2; }

WORK="$(mktemp -d /var/tmp/fuzzinstr-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fail=0
FIXTURE_ROOT=""

# fixture <name> -> sets FIXTURE_ROOT. Always builds the PRISTINE shape and
# asserts it green; a CMake-side perturbation is applied afterwards by
# perturb_cmake, so that "it was green first" is measured and not assumed.
# A minimal repository shaped like this one: ci/scripts/<check>, fuzz/, and a
# build tree beside it. The harness compiles one library source into itself,
# exactly the shape fuzz/CMakeLists.txt uses for the walkers.
fixture() {
    local name="$1" extra=""
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/fuzz" "$root/lib"
    cp "$CHECK" "$root/ci/scripts/$(basename "$CHECK")"
    chmod +x "$root/ci/scripts/$(basename "$CHECK")"

    cat > "$root/lib/walker.cpp" <<'SRC'
#include <cstddef>
#include <cstdint>
// A length-driven walk over caller-supplied bytes: the shape whose
// out-of-bounds read only a sanitizer that is actually compiled in reports.
int walk(const uint8_t* data, size_t len)
{
    int total = 0;
    for (size_t i = 0; i + 1 < len;) {
        size_t n = data[i + 1];
        for (size_t k = 0; k < n && i + 2 + k < len; ++k) {
            total += data[i + 2 + k];
        }
        i += 2 + n;
    }
    return total;
}
SRC
    cat > "$root/fuzz/harness.cpp" <<'SRC'
#include <cstddef>
#include <cstdint>
int walk(const uint8_t* data, size_t len);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    return walk(data, size) == 0x7fffffff ? 1 : 0;
}
SRC
    # The target lives in a fuzz/ subdirectory, because that is where the check
    # looks for object directories -- <build>/fuzz/CMakeFiles/<harness>.dir.
    # A fixture that put it anywhere else would only ever exercise the
    # cannot-measure branch, which is how the first draft of this selftest
    # reported three red cases it had not actually driven.
    cat > "$root/CMakeLists.txt" <<'CM'
cmake_minimum_required(VERSION 3.28)
project(fuzzinstr CXX)
set(CMAKE_CXX_STANDARD 17)
add_subdirectory(fuzz)
CM
    cat > "$root/fuzz/CMakeLists.txt" <<CM
add_executable(fuzz_walker
    \${CMAKE_CURRENT_SOURCE_DIR}/harness.cpp
    \${PROJECT_SOURCE_DIR}/lib/walker.cpp)
target_compile_options(fuzz_walker PRIVATE -fsanitize=fuzzer,address,undefined -g)
target_link_options(fuzz_walker PRIVATE -fsanitize=fuzzer,address,undefined -g)
$extra
CM
    printf 'fuzz_walker: lib/walker.cpp\n' > "$root/fuzz/instrumented-sources.txt"

    if ! ( cd "$root" && cmake -B build-fuzz -S . -DCMAKE_CXX_COMPILER="$CLANG" \
             -DCMAKE_BUILD_TYPE=RelWithDebInfo > "$root/cmake.log" 2>&1 \
           && cmake --build build-fuzz -j2 >> "$root/cmake.log" 2>&1 ); then
        echo "case $name: FAIL -- fixture would not build"
        tail -15 "$root/cmake.log" | sed 's/^/    /'
        fail=$((fail + 1))
    fi

    # A perturbation of an already-red tree proves nothing.
    local out grc
    out="$(bash "$root/ci/scripts/$(basename "$CHECK")" "$root/build-fuzz" 2>&1)"; grc=$?
    if [ "$grc" != 0 ]; then
        echo "case $name: FAIL -- fixture is not green before perturbation (rc=$grc)"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1))
    fi
    FIXTURE_ROOT="$root"
}

# perturb_cmake <root> <cmake-line>: append a line to the fixture's fuzz/
# CMakeLists.txt and rebuild. Restores nothing -- each fixture is its own tree.
perturb_cmake() {
    local root="$1" line="$2"
    printf '%s\n' "$line" >> "$root/fuzz/CMakeLists.txt"
    if ! ( cd "$root" && cmake -B build-fuzz -S . -DCMAKE_CXX_COMPILER="$CLANG" \
             -DCMAKE_BUILD_TYPE=RelWithDebInfo >> "$root/cmake.log" 2>&1 \
           && cmake --build build-fuzz -j2 >> "$root/cmake.log" 2>&1 ); then
        echo "FAIL -- perturbed fixture would not build"
        tail -15 "$root/cmake.log" | sed 's/^/    /'
        fail=$((fail + 1))
    fi
}

# expect <name> <want-rc> <root> <build-dir> [<substring>...]
expect() {
    local name="$1" want="$2" root="$3" bld="$4"; shift 4
    local out grc
    cases=$((cases + 1))
    out="$(bash "$root/ci/scripts/$(basename "$CHECK")" "$bld" 2>&1)"; grc=$?
    if [ "$grc" = "$want" ]; then
        echo "case $name: OK   -- exit $grc"
        [ "$want" != 0 ] && red=$((red + 1))
    else
        echo "case $name: FAIL -- expected exit $want, got $grc"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1))
        return
    fi
    local want_s
    for want_s in "$@"; do
        case "$out" in
            *"$want_s"*) ;;
            *) echo "  case $name: FAIL -- the output does not name '$want_s'"
               echo "$out" | sed 's/^/    /'
               fail=$((fail + 1)) ;;
        esac
    done
}

# 1. The state this check exists to end: a harness that links and nobody said so.
fixture link_only_undeclared; r="$FIXTURE_ROOT"
: > "$r/fuzz/instrumented-sources.txt"
expect link_only_undeclared 1 "$r" "$r/build-fuzz" 'fuzz_walker' 'not in instrumented-sources.txt'

# 2. A list that describes a build which does not exist.
fixture source_not_in_target; r="$FIXTURE_ROOT"
printf 'fuzz_walker: lib/absent.cpp\n' > "$r/fuzz/instrumented-sources.txt"
expect source_not_in_target 1 "$r" "$r/build-fuzz" 'fuzz_walker' 'lib/absent.cpp'

# 3. Nothing to measure is not a pass.
fixture no_build_dir; r="$FIXTURE_ROOT"
expect no_build_dir 2 "$r" "$r/build-fuzz-absent"

# 4. The measuring branch. The source is in the target; the checks are off.
fixture uninstrumented_object
r="$FIXTURE_ROOT"
perturb_cmake "$r" \
    'set_source_files_properties(${PROJECT_SOURCE_DIR}/lib/walker.cpp PROPERTIES COMPILE_OPTIONS -fno-sanitize=all)'

expect uninstrumented_object 1 "$r" "$r/build-fuzz" 'fuzz_walker' 'lib/walker.cpp' 'checks off'

echo "selftest: $cases cases, $red red-proved"
[ "$fail" = 0 ] && [ "$red" = "$cases" ]
