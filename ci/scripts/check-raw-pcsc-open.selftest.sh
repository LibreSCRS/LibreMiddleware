#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Selftest for check-raw-pcsc-open.sh.
#
# Five cases: one per exit code the check can return, three of them proving a
# red, and one that states a blind spot rather than closing it. The reason this exists is the case that shipped: the check printed OK for
# a tree with no sources in it at all, because a recursive grep that finds
# nothing looks the same whether the tree is clean or empty. A check that has
# never failed is not a check.
#
# Each case is a small tree with the subject copied into its own ci/scripts/,
# because the subject resolves the repository root from its own location.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
subject="$here/check-raw-pcsc-open.sh"
[[ -f "$subject" ]] || { echo "missing subject: $subject" >&2; exit 2; }
repo="$(cd "$here/../.." && pwd)"

work="$(mktemp -d /var/tmp/check-raw-pcsc-open-selftest.XXXXXX)"
trap 'rm -rf "$work"' EXIT

fails=0
reds=0
cases=0

# make_tree <name> -- a tree with the subject and the two declaring files.
make_tree() {
    local dir="$work/$1"
    mkdir -p "$dir/ci/scripts" "$dir/lib/smartcard/src"
    cat "$subject" > "$dir/ci/scripts/check-raw-pcsc-open.sh"
    cat "$repo/lib/smartcard/src/pcsc_connection.h" > "$dir/lib/smartcard/src/pcsc_connection.h"
    cat "$repo/lib/smartcard/src/pcsc_connection.cpp" > "$dir/lib/smartcard/src/pcsc_connection.cpp"
    printf '%s\n' "$dir"
}

run() { # run <name> <expected-rc> <tree> [red]
    local name="$1" want="$2" dir="$3" red="${4:-}" got
    cases=$((cases + 1))
    ( cd "$dir" && bash ci/scripts/check-raw-pcsc-open.sh ) > "$work/out" 2>&1
    got=$?
    if [[ "$got" -eq "$want" ]]; then
        printf '  ok    %-56s rc=%s\n' "$name" "$got"
        [[ -n "$red" ]] && reds=$((reds + 1))
    else
        printf '  FAIL  %-56s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# case_1 -- an honest production caller under lib/ must be reported.
d="$(make_tree case_1)"
mkdir -p "$d/lib/smartcard/src"
printf '%s\n' '#include "pcsc_connection.h"' \
    'void f(const std::string& r) { (void)PCSCConnection::openRawDiagnostic(r); }' \
    > "$d/lib/smartcard/src/rogue.cpp"
run "case_1 a production caller under lib/ is reported" 1 "$d" red

# case_2 -- the case that shipped: nothing to scan is not a clean scan.
d="$work/case_2"
mkdir -p "$d/ci/scripts" "$d/lib"
cat "$subject" > "$d/ci/scripts/check-raw-pcsc-open.sh"
run "case_2 an empty tree cannot be measured" 2 "$d" red

# case_3 -- the header stopped declaring the factory, so there is nothing left
# for this gate to confine and it must say so rather than pass.
d="$(make_tree case_3)"
grep -v 'openRawDiagnostic' "$d/lib/smartcard/src/pcsc_connection.h" > "$d/h.tmp"
cat "$d/h.tmp" > "$d/lib/smartcard/src/pcsc_connection.h"
rm -f "$d/h.tmp"
run "case_3 a header without the factory cannot be measured" 2 "$d" red

# case_4 -- the happy path, so a check that fails everything cannot pass this.
d="$(make_tree case_4)"
run "case_4 a clean tree passes" 0 "$d"

# case_5 -- the gate's OTHER blind spot, stated so nobody has to rediscover it:
# a caller inside the defining .cpp passes, exactly as one inside the declaring
# header does. That file is production code under lib/, so this is not a corner.
# Documented rather than fixed: closing it means linker separation, not a grep.
d="$(make_tree case_5)"
printf '%s\n' 'void blindSpot(const std::string& r) { (void)openRawDiagnostic(r); }' \
    >> "$d/lib/smartcard/src/pcsc_connection.cpp"
run "case_5 a caller in the defining file is NOT caught" 0 "$d"

if [[ "$fails" -eq 0 ]]; then
    # The canonical trailer, last line of stdout and nothing after it:
    # run-selftests.sh reads exactly this shape, and the counts are counted
    # rather than written down so adding a case cannot leave them stale.
    echo "selftest: $cases cases, $reds red-proved"
    exit 0
fi
echo "check-raw-pcsc-open selftest: $fails case(s) failed"
exit 1
