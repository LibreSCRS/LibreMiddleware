#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-warning-floor.selftest.sh -- seven cases; each asserts rc AND the
# message. Perturbs the baseline and the graph independently, because a gate
# that fails for the wrong reason is not a gate.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d "${TMPDIR:-/var/tmp}/cwf-selftest.XXXXXX")"
trap 'rm -rf "$T"' EXIT
fails=0
say() { if [ "$1" = 0 ]; then printf 'PASS  %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; fails=1; fi; }

fixture() {  # fixture <name> <floor-json-line> <n-edges>
  local d="$T/$1"; rm -rf "$d"; mkdir -p "$d/ci/scripts" "$d/b"
  cp "$HERE/check-warning-floor.sh" "$d/ci/scripts/"; chmod +x "$d/ci/scripts/check-warning-floor.sh"
  [ "$2" = NONE ] || printf '{\n  "GNU-16": {},\n  "min_compile_units": %s\n}\n' "$2" > "$d/ci/warning-baseline.json"
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
[ "$rc" = 0 ] && grep -q 'floor is 11 low' "$T/out"; say $? "1 floor below the graph is reachable, and the slack is named"

d=$(fixture b 111 111); rc=$(run "$d")
[ "$rc" = 0 ] && grep -q 'min_compile_units=111 is reachable' "$T/out"; say $? "2 floor equal to the graph is green"

d=$(fixture c 122 111); rc=$(run "$d")
[ "$rc" = 1 ] && grep -q 'min_compile_units=122' "$T/out" && grep -q 'only 111 compile edges' "$T/out"
say $? "3 PERTURBATION: floor above the graph is red and names both numbers"

d=$(fixture d 0 111); rc=$(run "$d")
[ "$rc" = 1 ] && grep -q 'anti-vacuum rule is disarmed' "$T/out"; say $? "4 a zero floor is refused, not passed"

d=$(fixture e NONE 111); rc=$(run "$d")
[ "$rc" = 2 ] && grep -q 'no baseline' "$T/out"; say $? "5 a missing baseline is 'cannot measure' (2), not pass"

d=$(fixture f 111 NONE); rc=$(run "$d")
[ "$rc" = 2 ] && grep -q 'no .*build.ninja' "$T/out"; say $? "6 a missing build.ninja is 'cannot measure' (2), not pass"

d=$(fixture g 111 0); rc=$(run "$d")
[ "$rc" = 2 ] && grep -q 'no compile edges' "$T/out"; say $? "7 a graph with no compile edges is 'cannot measure' (2), not pass"

[ "$fails" -eq 0 ] && echo "selftest: 7/7 OK" || echo "selftest: FAILED"
exit "$fails"
