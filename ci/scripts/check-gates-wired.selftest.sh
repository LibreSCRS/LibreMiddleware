#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-gates-wired.selftest.sh — perturbs the gate, never just runs it.
# Nine cases; each asserts rc AND the message, because a gate that fails for the
# wrong reason is not a gate. Fixture is a throw-away git checkout under
# ${TMPDIR:-/var/tmp}; nothing in the real tree is touched.
set -uo pipefail
GATE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-gates-wired.sh"
[ -x "$GATE" ] || { echo "FATAL: gate not executable at $GATE" >&2; exit 2; }
T="$(mktemp -d "${TMPDIR:-/var/tmp}/cgw-selftest.XXXXXX")"
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

mkfixture() {  # mkfixture <dir>
  local d="$1"
  rm -rf "$d"; mkdir -p "$d/ci/scripts" "$d/tools" "$d/.github/workflows"
  printf '#!/bin/sh\nexit 0\n' > "$d/ci/scripts/wired.sh"
  printf '#!/bin/sh\nexit 0\n' > "$d/tools/hop.sh"
  printf 'jobs:\n  lint:\n    steps:\n      - run: ci/scripts/wired.sh\n      - run: ci/scripts/check-gates-wired.sh\n' > "$d/.github/workflows/ci.yml"
  printf 'cmake_minimum_required(VERSION 3.24)\n' > "$d/CMakeLists.txt"
  cp "$GATE" "$d/ci/scripts/check-gates-wired.sh"; chmod +x "$d/ci/scripts/check-gates-wired.sh"
  git -C "$d" init -q
  git -C "$d" add -A
  git -C "$d" -c user.email=s@e -c user.name=s commit -qm f
}
run() { bash "$1/ci/scripts/check-gates-wired.sh" >"$T/out" 2>&1; echo $?; }

# 1. wired script + a script the wired one names (one hop) -> green
mkfixture "$T/a"
printf '#!/bin/sh\ntools/hop.sh\n' > "$T/a/ci/scripts/wired.sh"
git -C "$T/a" add -A; git -C "$T/a" -c user.email=s@e -c user.name=s commit -qm h
rc=$(run "$T/a")
[ "$rc" = 0 ] && grep -q 'OK: every shipped gate is wired' "$T/out"; say $? "1 green: wired + one hop" 0

# 2. PERTURBATION: drop the mention from the workflow -> red, and it names the file
mkfixture "$T/b"
printf 'jobs:\n  lint:\n    steps:\n      - run: ci/scripts/check-gates-wired.sh\n' > "$T/b/.github/workflows/ci.yml"
git -C "$T/b" add -A; git -C "$T/b" -c user.email=s@e -c user.name=s commit -qm p
rc=$(run "$T/b")
[ "$rc" = 1 ] && grep -q 'FAIL: ci/scripts/wired.sh is shipped' "$T/out"; say $? "2 red when nothing names the script" 1

# 3. ANTI-CHEAT: the only mention is a YAML comment -> still red
mkfixture "$T/c"
printf 'jobs:\n  lint:\n    steps:\n      # ci/scripts/wired.sh used to run here\n      - run: ci/scripts/check-gates-wired.sh\n' \
  > "$T/c/.github/workflows/ci.yml"
git -C "$T/c" add -A; git -C "$T/c" -c user.email=s@e -c user.name=s commit -qm c
rc=$(run "$T/c")
[ "$rc" = 1 ] && grep -q 'FAIL: ci/scripts/wired.sh is shipped' "$T/out"; say $? "3 a comment does not count as wiring" 1

# 4. allowlist entry without a reason -> red, and it says so
mkfixture "$T/d"
printf 'jobs:\n  lint:\n    steps:\n      - run: ci/scripts/check-gates-wired.sh\n' > "$T/d/.github/workflows/ci.yml"
printf 'ci/scripts/wired.sh\n' > "$T/d/ci/gate-wiring-exceptions.txt"
git -C "$T/d" add -A; git -C "$T/d" -c user.email=s@e -c user.name=s commit -qm d
rc=$(run "$T/d")
[ "$rc" = 1 ] && grep -q "carries no reason" "$T/out"; say $? "4 allowlist without a reason is refused" 1

# 5. allowlist with a reason -> green, and the skip is printed
mkfixture "$T/e"
printf 'jobs:\n  lint:\n    steps:\n      - run: ci/scripts/check-gates-wired.sh\n' > "$T/e/.github/workflows/ci.yml"
printf 'ci/scripts/wired.sh  run by hand at release time, see docs/RELEASE.md\ntools/hop.sh  same\n' \
  > "$T/e/ci/gate-wiring-exceptions.txt"
git -C "$T/e" add -A; git -C "$T/e" -c user.email=s@e -c user.name=s commit -qm e
rc=$(run "$T/e")
[ "$rc" = 0 ] && grep -q 'SKIP: ci/scripts/wired.sh' "$T/out"; say $? "5 allowlist with a reason is honoured" 0

# 6. stale allowlist entry (path no longer tracked) -> red
mkfixture "$T/f"
printf 'jobs:\n  lint:\n    steps:\n      - run: ci/scripts/wired.sh\n      - run: ci/scripts/check-gates-wired.sh\n' > "$T/f/.github/workflows/ci.yml"
printf 'ci/scripts/gone.sh  deleted last cycle\n' > "$T/f/ci/gate-wiring-exceptions.txt"
printf '#!/bin/sh\nexit 0\n' > "$T/f/tools/hop.sh"
printf '#!/bin/sh\ntools/hop.sh\n' > "$T/f/ci/scripts/wired.sh"
git -C "$T/f" add -A; git -C "$T/f" -c user.email=s@e -c user.name=s commit -qm f2
rc=$(run "$T/f")
[ "$rc" = 1 ] && grep -q 'stale entry' "$T/out"; say $? "6 stale allowlist entry is refused" 1

# 7. no candidates at all -> 2 (cannot judge), never 0
mkfixture "$T/g"
git -C "$T/g" rm -q -r --cached tools >/dev/null
git -C "$T/g" rm -q --cached ci/scripts/wired.sh >/dev/null
rm -rf "$T/g/tools" "$T/g/ci/scripts/wired.sh"
git -C "$T/g" add -A; git -C "$T/g" -c user.email=s@e -c user.name=s commit -qm g
git -C "$T/g" rm -q --cached ci/scripts/check-gates-wired.sh >/dev/null
git -C "$T/g" -c user.email=s@e -c user.name=s commit -qm g2
rc=$(bash "$T/g/ci/scripts/check-gates-wired.sh" >"$T/out" 2>&1; echo $?)
[ "$rc" = 2 ] && grep -q 'no candidate scripts found' "$T/out"; say $? "7 an empty candidate set is 'cannot judge' (2), not pass" 2

# 8. an exception is a ROOT, not a pardon: what it calls is covered too
mkfixture "$T/h"
printf 'jobs:\n  lint:\n    steps:\n      - run: ci/scripts/check-gates-wired.sh\n' > "$T/h/.github/workflows/ci.yml"
printf '#!/bin/sh\ntools/hop.sh\n' > "$T/h/ci/scripts/wired.sh"
printf 'ci/scripts/wired.sh  invoked as ci/scripts/$stage.sh by the release job\n' \
  > "$T/h/ci/gate-wiring-exceptions.txt"
git -C "$T/h" add -A; git -C "$T/h" -c user.email=s@e -c user.name=s commit -qm h8
rc=$(run "$T/h")
[ "$rc" = 0 ] && grep -q 'SKIP: ci/scripts/wired.sh' "$T/out" && ! grep -q 'tools/hop.sh is shipped' "$T/out"
say $? "8 an exception seeds reachability for what it calls" 0

# 9. a packaging recipe that nothing names -> red. This case exists because the
# candidate pathspec is data the gate cannot check about itself: one sibling
# copy lost 'packaging/arch/*' from it and went green over a whole directory of
# shipped scripts, which no comparison of the six copies' contents would have
# explained on its own. The fixture makes the pathspec observable.
mkfixture "$T/i"
printf '#!/bin/sh\ntools/hop.sh\n' > "$T/i/ci/scripts/wired.sh"
mkdir -p "$T/i/packaging/arch"
printf '#!/bin/sh\nexit 0\n' > "$T/i/packaging/arch/check-recipe.sh"
git -C "$T/i" add -A; git -C "$T/i" -c user.email=s@e -c user.name=s commit -qm i9
rc=$(run "$T/i")
[ "$rc" = 1 ] && grep -q 'FAIL: packaging/arch/check-recipe.sh is shipped' "$T/out"
say $? "9 a packaging recipe that nothing names is red" 1

[ "$fails" -eq 0 ] && echo "selftest: 9/9 OK" || echo "selftest: FAILED"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit "$fails"
