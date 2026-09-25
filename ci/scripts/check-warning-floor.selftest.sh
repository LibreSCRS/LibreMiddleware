#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-warning-floor.selftest.sh -- each case asserts rc AND the message.
# Perturbs the baseline, the graph and the compiler that configured the tree
# independently, because a gate that fails for the wrong reason is not a gate.
#
# Run against the check as it was before it asked warning-gate.py for the
# section, eleven of these thirteen cases fall (all but 5 and 6): it read the
# floor from the top of the file, which the gate's own --update stopped
# writing, so every build it judged was "no min_compile_units", and it never
# looked at which compiler configured the tree.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d "${TMPDIR:-/var/tmp}/cwf-selftest.XXXXXX")"
trap 'rm -rf "$T"' EXIT
fails=0
cases=0
red=0
# say <status> <label> <gate-rc>: <gate-rc> is what the gate was expected to
# return for this case, and a non-zero one is a case that proved the gate red.
say() {
  cases=$((cases + 1))
  if [ "${3:-0}" != 0 ]; then red=$((red + 1)); fi
  if [ "$1" = 0 ]; then printf 'PASS  %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; fails=1; fi
}

# fixture <name> <floor> <n-edges> [compiler-version] [baseline-json]
# The tree is configured by GCC <compiler-version> (default 13.2.0); the
# baseline, unless given whole, is the layout warning-gate.py --update writes:
# the floor inside that compiler's own section.
fixture() {
  local d="$T/$1"; rm -rf "$d"; mkdir -p "$d/ci/scripts" "$d/b/CMakeFiles/3.28.3"
  cp "$HERE/check-warning-floor.sh" "$HERE/warning-gate.py" "$d/ci/scripts/"
  chmod +x "$d/ci/scripts/check-warning-floor.sh"
  local ver="${4:-13.2.0}"
  : > "$d/b/CMakeCache.txt"
  printf 'set(CMAKE_CXX_COMPILER_ID "GNU")\nset(CMAKE_CXX_COMPILER_VERSION "%s")\n' "$ver" \
    > "$d/b/CMakeFiles/3.28.3/CMakeCXXCompiler.cmake"
  if [ -n "${5:-}" ]; then printf '%s\n' "$5" > "$d/ci/warning-baseline.json"
  elif [ "$2" != NONE ]; then
    printf '{\n  "GNU-%s": {"min_compile_units": %s, "project": {}, "system": {}, "system_reasons": {}}\n}\n' \
      "${ver%%.*}" "$2" > "$d/ci/warning-baseline.json"
  fi
  if [ "$3" != NONE ]; then
    : > "$d/b/build.ninja"
    local i=0; while [ "$i" -lt "$3" ]; do
      printf 'build x%d.o: CXX_COMPILER__t_unscanned ../s%d.cpp\n' "$i" "$i" >> "$d/b/build.ninja"; i=$((i+1)); done
    printf 'build all: phony x0.o\n' >> "$d/b/build.ninja"
  fi
  printf '%s' "$d"
}
run() { bash "$1/ci/scripts/check-warning-floor.sh" "$1/b" >"$T/out" 2>&1; echo $?; }

d=$(fixture a 100 111); rc=$(run "$d")
[ "$rc" = 0 ] && grep -q 'floor is 11 low' "$T/out"; say $? "1 floor below the graph is reachable, and the slack is named" 0

d=$(fixture b 111 111); rc=$(run "$d")
[ "$rc" = 0 ] && grep -q 'GNU-13 min_compile_units=111 is reachable' "$T/out"; say $? "2 floor equal to the graph is green" 0

d=$(fixture c 122 111); rc=$(run "$d")
[ "$rc" = 1 ] && grep -q 'min_compile_units=122' "$T/out" && grep -q 'only 111 compile edges' "$T/out"
say $? "3 PERTURBATION: floor above the graph is red and names both numbers" 1

d=$(fixture d 0 111); rc=$(run "$d")
[ "$rc" = 1 ] && grep -q 'anti-vacuum rule is disarmed' "$T/out"; say $? "4 a zero floor is refused, not passed" 1

d=$(fixture e NONE 111); rc=$(run "$d")
[ "$rc" = 2 ] && grep -q 'no baseline' "$T/out"; say $? "5 a missing baseline is 'cannot measure' (2), not pass" 2

d=$(fixture f 111 NONE); rc=$(run "$d")
[ "$rc" = 2 ] && grep -q 'no .*build.ninja' "$T/out"; say $? "6 a missing build.ninja is 'cannot measure' (2), not pass" 2

d=$(fixture g 111 0); rc=$(run "$d")
[ "$rc" = 2 ] && grep -q 'no compile edges' "$T/out"; say $? "7 a graph with no compile edges is 'cannot measure' (2), not pass" 2

# 8: the layout the gate itself writes -- the floor only inside the compiler's
# section, nothing at the top. This is exactly the file CI failed on.
d=$(fixture h 111 111); rc=$(run "$d")
[ "$rc" = 0 ] && grep -q 'GNU-13 min_compile_units=111 is reachable' "$T/out"
say $? "8 the per-compiler layout warning-gate.py --update writes is read" 0

# 9: two compilers, and only the one that configured the tree is judged. The
# other one's floor is unreachable on purpose, so reading it would be red.
two='{"GNU-13": {"min_compile_units": 100, "project": {}, "system": {}, "system_reasons": {}},
 "GNU-16": {"min_compile_units": 400, "project": {}, "system": {}, "system_reasons": {}}}'
d=$(fixture i X 111 13.2.0 "$two"); rc=$(run "$d")
[ "$rc" = 0 ] && grep -q 'GNU-13 min_compile_units=100 is reachable' "$T/out"
say $? "9 a GCC 13 tree is judged by the GNU-13 section, not the GNU-16 one" 0
d=$(fixture j X 111 16.1.1 "$two"); rc=$(run "$d")
[ "$rc" = 1 ] && grep -q 'GNU-16 min_compile_units=400' "$T/out" && grep -q 'only 111 compile edges' "$T/out"
say $? "10 PERTURBATION: a GCC 16 tree over the same file is red on the GNU-16 floor" 1

# 11: a compiler the baseline has no section for cannot be judged.
d=$(fixture k X 111 14.2.0 '{"GNU-13": {"min_compile_units": 100}}'); rc=$(run "$d")
[ "$rc" = 2 ] && grep -q 'no section for GNU-14' "$T/out"
say $? "11 a compiler with no section is 'cannot measure' (2), not pass" 2

# 12: the older layout -- flat categories under the key, floor at the top --
# is still read, the same way warning-gate.py reads it.
d=$(fixture l X 111 13.2.0 '{"GNU-13": {"-Wcomment": 3}, "min_compile_units": 122}'); rc=$(run "$d")
[ "$rc" = 1 ] && grep -q 'GNU-13 min_compile_units=122' "$T/out"
say $? "12 PERTURBATION: the older top-level floor is still read, and red when unreachable" 1

# 13: a tree nothing configured names no compiler.
d=$(fixture m 111 111); rm -f "$d/b/CMakeCache.txt"; rc=$(run "$d")
[ "$rc" = 2 ] && grep -q 'not a configured build tree' "$T/out"
say $? "13 an unconfigured tree is 'cannot measure' (2), not pass" 2

[ "$fails" -eq 0 ] || echo "selftest: FAILED"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit "$fails"
