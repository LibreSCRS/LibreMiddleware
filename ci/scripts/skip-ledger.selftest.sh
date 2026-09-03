#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# skip-ledger.selftest.sh — prove the ledger fails in both directions, and
# prove it refuses to record a book from a run that was never provisioned.
#
# Cases:
#   1  empty book, nothing skipped, nothing disabled     -> 0
#   2  a skipped test with no line in the book           -> 1
#   3  a book line that matched nothing skipped          -> 1 (a stale entry)
#   4  a count that moved                                -> 1
#   5  an unknown category                               -> 2
#   6  a DISABLED_ case in the sources but not in the book -> 1
#   7  no book at all                                    -> 2
#   8  no ctest log at all                               -> 2
#   9  --update refused when ci/skip-ledger-env.txt names an unset variable,
#      and the book is left untouched
#  10  --update accepted once that variable is set
set -uo pipefail

TOOL="$(cd "$(dirname "$0")" && pwd)/skip-ledger.sh"
WORK="$(mktemp -d /var/tmp/skipledger-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

# A ctest log whose "did not run" block lists the names it is given.
make_log() {
    local f="$1"; shift
    {
        echo "100% tests passed, 0 tests failed out of 10"
        echo ""
        echo "The following tests did not run:"
        local i=1
        for n in "$@"; do printf '\t%3d - %s (Skipped)\n' "$i" "$n"; i=$((i + 1)); done
    } > "$f"
}

make_repo() {
    local name="$1" src="${2:-}"
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/test"
    cp "$TOOL" "$root/ci/scripts/skip-ledger.sh"; chmod +x "$root/ci/scripts/skip-ledger.sh"
    printf '%s\n' "${src:-TEST(S, Ordinary) { }}" > "$root/test/a_test.cpp"
    git -C "$root" init -q
    git -C "$root" config user.email t@t
    git -C "$root" config user.name t
    git -C "$root" add -A
    git -C "$root" -c commit.gpgsign=false commit -qm x
    echo "$root"
}

check() {
    local label="$1" expected="$2" actual="$3" extra="${4:-1}"
    if [ "$expected" = "$actual" ] && [ "$extra" = 1 ]; then
        echo "case $label: OK   — exit $actual"; pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"; fail=$((fail + 1))
    fi
}

run() { ( cd "$1" && bash ci/scripts/skip-ledger.sh "${@:2}" 2>&1 ); }

# --- case 1
r="$(make_repo c1)"; make_log "$r/ctest.log"
printf '# empty book\n' > "$r/ci/skipped-tests.linux.txt"
out="$(run "$r" --check ctest.log linux)"; rc=$?; check 1 0 $rc

# --- case 2
r="$(make_repo c2)"; make_log "$r/ctest.log" "Card.NeedsReader"
printf '# empty book\n' > "$r/ci/skipped-tests.linux.txt"
out="$(run "$r" --check ctest.log linux)"; rc=$?
ok=0; case "$out" in *"Card.NeedsReader"*) case "$out" in *"unrecorded"*) ok=1 ;; esac ;; esac
check 2 1 $rc $ok

# --- case 3: a line that has rotted against the test it names
r="$(make_repo c3)"; make_log "$r/ctest.log" "Card.NeedsReader"
printf 'CARD      Card.NeedsReader     1\nNETWORK   Gone.Renamed         1\n' > "$r/ci/skipped-tests.linux.txt"
out="$(run "$r" --check ctest.log linux)"; rc=$?
ok=0; case "$out" in *"stale entry: Gone.Renamed"*) ok=1 ;; esac
check 3 1 $rc $ok

# --- case 4: the count moved
r="$(make_repo c4)"; make_log "$r/ctest.log" "Card.A" "Card.B"
printf 'CARD      Card.*     1\n' > "$r/ci/skipped-tests.linux.txt"
out="$(run "$r" --check ctest.log linux)"; rc=$?
ok=0; case "$out" in *"count moved"*) ok=1 ;; esac
check 4 1 $rc $ok

# --- case 5: a category outside the closed vocabulary
r="$(make_repo c5)"; make_log "$r/ctest.log" "Card.A"
printf 'FLAKY     Card.*     1\n' > "$r/ci/skipped-tests.linux.txt"
out="$(run "$r" --check ctest.log linux)"; rc=$?
ok=0; case "$out" in *"unknown category"*) ok=1 ;; esac
check 5 2 $rc $ok

# --- case 6: a DISABLED_ case ctest never mentions
r="$(make_repo c6 'TEST(Suite, DISABLED_NotYet) { }')"; make_log "$r/ctest.log"
printf '# empty book\n' > "$r/ci/skipped-tests.linux.txt"
out="$(run "$r" --check ctest.log linux)"; rc=$?
ok=0; case "$out" in *"Suite.DISABLED_NotYet"*) ok=1 ;; esac
check 6 1 $rc $ok

# --- case 7 / 8: nothing to judge
r="$(make_repo c7)"; make_log "$r/ctest.log"
out="$(run "$r" --check ctest.log linux)"; rc=$?
ok=0; case "$out" in *"no skip ledger"*) ok=1 ;; esac
check 7 2 $rc $ok
r="$(make_repo c8)"; printf '# book\n' > "$r/ci/skipped-tests.linux.txt"
out="$(run "$r" --check nosuch.log linux)"; rc=$?
ok=0; case "$out" in *"no ctest log"*) ok=1 ;; esac
check 8 2 $rc $ok

# --- case 9: an unprovisioned --update is refused, and changes nothing
r="$(make_repo c9)"; make_log "$r/ctest.log" "SoftHSM.Signs" "SoftHSM.Verifies"
printf 'SELFTEST_TOKEN_CONF\n' > "$r/ci/skip-ledger-env.txt"
printf 'CARD      Card.*     1\n' > "$r/ci/skipped-tests.linux.txt"
before="$(sha256sum "$r/ci/skipped-tests.linux.txt" | cut -d' ' -f1)"
out="$( cd "$r" && env -u SELFTEST_TOKEN_CONF bash ci/scripts/skip-ledger.sh --update ctest.log linux 2>&1 )"; rc=$?
after="$(sha256sum "$r/ci/skipped-tests.linux.txt" | cut -d' ' -f1)"
ok=0; case "$out" in *"SELFTEST_TOKEN_CONF"*) [ "$before" = "$after" ] && ok=1 ;; esac
check 9 2 $rc $ok

# --- case 10: the same call with the variable set records the draft
out="$( cd "$r" && SELFTEST_TOKEN_CONF=/somewhere bash ci/scripts/skip-ledger.sh --update ctest.log linux 2>&1 )"; rc=$?
ok=0; case "$(cat "$r/ci/skipped-tests.linux.txt")" in *"SoftHSM.*"*) ok=1 ;; esac
check 10 0 $rc $ok

echo "selftest: $pass passed, $fail failed"
[ "$fail" = 0 ]
