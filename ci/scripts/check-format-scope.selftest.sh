#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-format-scope.selftest.sh — prove the scope check can fail.
#
# In four of the six repositories here the check passes on the day it lands,
# because nothing is outside the formatted roots yet. Its whole value is the
# moment a new shared directory appears, so in those repositories this selftest
# is the only thing that demonstrates the gate works at all.
#
# Every case runs against a throwaway git repository under /var/tmp (never
# /tmp, which is a RAM filesystem here).
#
# Cases:
#   1  everything under a listed root            -> 0
#   2  one file outside every root               -> 1, and it is named
#   3  that same file excluded by pattern        -> 0
#   4  a root in the list that does not exist    -> 2
#   5  an empty ci/format-dirs.txt               -> 2
#   6  no ci/format-dirs.txt at all              -> 2
#   7  an untracked file outside every root      -> 0 (only git ls-files counts)
#   8  a .mm file outside every root             -> 1 (Objective-C++ counts)
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-format-scope.sh"
WORK="$(mktemp -d /var/tmp/fmtscope-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
cases=0
red=0

make_repo() {
    local name="$1"; shift
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/lib" "$root/test" "$root/tools"
    cp "$CHECK" "$root/ci/scripts/check-format-scope.sh"
    chmod +x "$root/ci/scripts/check-format-scope.sh"
    echo 'int a;' > "$root/lib/a.cpp"
    echo 'int b;' > "$root/test/b.cpp"
    git -C "$root" init -q
    git -C "$root" config user.email t@t
    git -C "$root" config user.name t
    echo "$root"
}

commit_all() { git -C "$1" add -A && git -C "$1" -c commit.gpgsign=false commit -qm x; }

check() {
    local label="$1" expected="$2" actual="$3"
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$expected" != 0 ]; then red=$((red + 1)); fi
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   — exit $actual"; pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"; fail=$((fail + 1))
    fi
}

# --- case 1
r="$(make_repo c1)"; printf 'lib\ntest\n' > "$r/ci/format-dirs.txt"; commit_all "$r"
out="$(bash "$r/ci/scripts/check-format-scope.sh" 2>&1)"; rc=$?
check 1 0 $rc

# --- case 2
r="$(make_repo c2)"; printf 'lib\ntest\n' > "$r/ci/format-dirs.txt"
echo 'int c;' > "$r/tools/stray.cpp"; commit_all "$r"
out="$(bash "$r/ci/scripts/check-format-scope.sh" 2>&1)"; rc=$?
check 2 1 $rc
case "$out" in *"tools/stray.cpp"*) ;; *) echo "  case 2: FAIL — the output does not name tools/stray.cpp"; fail=$((fail + 1)) ;; esac
case "$out" in *"1 tracked source file(s) are outside"*) ;; *) echo "  case 2: FAIL — wrong summary"; fail=$((fail + 1)) ;; esac

# --- case 3: same tree, the stray file excluded by an explicit pattern
r="$(make_repo c3)"; printf 'lib\ntest\n' > "$r/ci/format-dirs.txt"
printf '# fed to the compiler verbatim as a probe\n^tools/stray\\.cpp$\n' > "$r/ci/format-exclude.txt"
echo 'int c;' > "$r/tools/stray.cpp"; commit_all "$r"
out="$(bash "$r/ci/scripts/check-format-scope.sh" 2>&1)"; rc=$?
check 3 0 $rc

# --- case 4: a listed root that is not on disk
r="$(make_repo c4)"; printf 'lib\ntest\nnowhere\n' > "$r/ci/format-dirs.txt"; commit_all "$r"
out="$(bash "$r/ci/scripts/check-format-scope.sh" 2>&1)"; rc=$?
check 4 2 $rc
case "$out" in *"nowhere"*) ;; *) echo "  case 4: FAIL — message does not name the stale root"; fail=$((fail + 1)) ;; esac

# --- case 5: an empty list
r="$(make_repo c5)"; printf '# only a comment\n' > "$r/ci/format-dirs.txt"; commit_all "$r"
out="$(bash "$r/ci/scripts/check-format-scope.sh" 2>&1)"; rc=$?
check 5 2 $rc

# --- case 6: no list at all
r="$(make_repo c6)"; commit_all "$r"
out="$(bash "$r/ci/scripts/check-format-scope.sh" 2>&1)"; rc=$?
check 6 2 $rc

# --- case 7: an untracked stray does not fail the gate
r="$(make_repo c7)"; printf 'lib\ntest\n' > "$r/ci/format-dirs.txt"; commit_all "$r"
echo 'int c;' > "$r/tools/untracked.cpp"
out="$(bash "$r/ci/scripts/check-format-scope.sh" 2>&1)"; rc=$?
check 7 0 $rc

# --- case 8: Objective-C++ counts
r="$(make_repo c8)"; printf 'lib\ntest\n' > "$r/ci/format-dirs.txt"
echo 'int d;' > "$r/tools/bridge.mm"; commit_all "$r"
out="$(bash "$r/ci/scripts/check-format-scope.sh" 2>&1)"; rc=$?
check 8 1 $rc
case "$out" in *"tools/bridge.mm"*) ;; *) echo "  case 8: FAIL — .mm not counted"; fail=$((fail + 1)) ;; esac

echo "selftest: $pass passed, $fail failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
