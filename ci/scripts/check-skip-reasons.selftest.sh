#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-skip-reasons.selftest.sh — prove the skip-reason check can fail, and
# prove it does not read a broken scanner as a clean repository.
#
# Cases:
#   1  bare GTEST_SKIP();                      -> 1
#   2  GTEST_SKIP() << "";                     -> 1
#   3  GTEST_SKIP() << "   ";                  -> 1
#   4  GTEST_SKIP() << "no card";              -> 0
#   5  GTEST_SKIP() << env.skipReason;         -> 0  (a run-time reason is a reason)
#   6  the reason on the next line             -> 0  (the argument list spans lines)
#   7  a doc comment mentioning GTEST_SKIP()   -> 0  (comments are not code)
#   8  an untracked file with a bare skip      -> 0  (only git ls-files counts)
#   9  QSKIP("")                               -> 1
#  10  a repository with no tracked sources    -> 2  (nothing scanned is not clean)
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-skip-reasons.sh"
WORK="$(mktemp -d /var/tmp/skipreasons-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

make_repo() {
    local name="$1" body="$2"
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/test"
    cp "$CHECK" "$root/ci/scripts/check-skip-reasons.sh"
    chmod +x "$root/ci/scripts/check-skip-reasons.sh"
    printf '%s\n' "$body" > "$root/test/a_test.cpp"
    git -C "$root" init -q
    git -C "$root" config user.email t@t
    git -C "$root" config user.name t
    git -C "$root" add -A
    git -C "$root" -c commit.gpgsign=false commit -qm x
    echo "$root"
}

check() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   — exit $actual"; pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"; fail=$((fail + 1))
    fi
}

run() { bash "$1/ci/scripts/check-skip-reasons.sh" 2>&1; }

r="$(make_repo c1 'TEST(S, T) { GTEST_SKIP(); }')"
out="$(run "$r")"; rc=$?; check 1 1 $rc
case "$out" in *"test/a_test.cpp:1"*) ;; *) echo "  case 1: FAIL — did not name file:line"; fail=$((fail + 1)) ;; esac

r="$(make_repo c2 'TEST(S, T) { GTEST_SKIP() << ""; }')"
out="$(run "$r")"; rc=$?; check 2 1 $rc

r="$(make_repo c3 'TEST(S, T) { GTEST_SKIP() << "   "; }')"
out="$(run "$r")"; rc=$?; check 3 1 $rc

r="$(make_repo c4 'TEST(S, T) { GTEST_SKIP() << "no card present"; }')"
out="$(run "$r")"; rc=$?; check 4 0 $rc

r="$(make_repo c5 'TEST(S, T) { GTEST_SKIP() << env.skipReason; }')"
out="$(run "$r")"; rc=$?; check 5 0 $rc

r="$(make_repo c6 "$(printf 'TEST(S, T)\n{\n    GTEST_SKIP()\n        << "reader is absent";\n}\n')")"
out="$(run "$r")"; rc=$?; check 6 0 $rc

r="$(make_repo c7 "$(printf '/// Callers GTEST_SKIP() on nullopt.\n// see GTEST_SKIP() above\nTEST(S, T) { EXPECT_TRUE(true); }\n')")"
out="$(run "$r")"; rc=$?; check 7 0 $rc

r="$(make_repo c8 'TEST(S, T) { EXPECT_TRUE(true); }')"
printf 'TEST(U, V) { GTEST_SKIP(); }\n' > "$r/test/untracked_test.cpp"
out="$(run "$r")"; rc=$?; check 8 0 $rc

r="$(make_repo c9 'void t() { QSKIP(""); }')"
out="$(run "$r")"; rc=$?; check 9 1 $rc

# case 10: a repository with no tracked C/C++ source at all. Nothing scanned
# must read as "cannot judge", not as "clean": a filter that matches nothing is
# the shape that makes a gate vacuous.
r="$WORK/c10"; mkdir -p "$r/ci/scripts"
cp "$CHECK" "$r/ci/scripts/check-skip-reasons.sh"; chmod +x "$r/ci/scripts/check-skip-reasons.sh"
echo readme > "$r/README.md"
git -C "$r" init -q; git -C "$r" config user.email t@t; git -C "$r" config user.name t
git -C "$r" add README.md; git -C "$r" -c commit.gpgsign=false commit -qm x
out="$(run "$r")"; rc=$?; check 10 2 $rc

echo "selftest: $pass passed, $fail failed"
[ "$fail" = 0 ]
