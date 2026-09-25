#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Selftest for check-signing-no-module-loader.sh -- three cases, one per exit
# code the check can return. A check that has never failed is not a check, and
# this one is red by construction today, so its self-test is the only thing
# proving that the red is the red it claims and not a broken invocation.
#
# Usage: check-signing-no-module-loader.selftest.sh <build-dir>
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
subject="$here/check-signing-no-module-loader.sh"
[[ -f "$subject" ]] || { echo "missing subject: $subject" >&2; exit 2; }

build="${1:-}"
if [[ -z "$build" ]]; then
    echo "usage: $(basename "$0") <build-dir>" >&2
    exit 2
fi
real="$(ls "$build"/lib/LibreSCRS/libLibreSCRS_Signing.so.*.*.* 2>/dev/null | head -1)"
if [[ -z "$real" || ! -f "$real" ]]; then
    echo "ERROR: no built libLibreSCRS_Signing.so.<version> under $build -- nothing to measure" >&2
    exit 2
fi

work="$(mktemp -d /var/tmp/librescrs-signing-loader-selftest.XXXXXX)"
trap 'rm -rf "$work"' EXIT

fails=0
run() { # run <name> <expected-rc> <build-dir>
    local name="$1" want="$2" dir="$3" got
    bash "$subject" "$dir" >"$work/out" 2>&1
    got=$?
    if [[ "$got" -eq "$want" ]]; then
        printf '  ok    %-56s rc=%s\n' "$name" "$got"
    else
        printf '  FAIL  %-56s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# case_a -- the real build tree. Red by construction while the signing facade
# resolves and acquires a PKCS#11 module in-process. A green here would mean
# either the facade changed (then wire the check into CI and delete this line)
# or the check stopped looking.
run "case_a the shipped signing library links the loader" 1 "$build"

# case_b -- a library that genuinely defines neither name must pass. Without
# this case a check that greps for the wrong thing, or exits 1 unconditionally,
# is indistinguishable from a working one.
mkdir -p "$work/clean/lib/LibreSCRS"
printf 'int librescrs_selftest_marker(void) { return 0; }\n' > "$work/empty.c"
if ! cc -shared -fPIC -o "$work/clean/lib/LibreSCRS/libLibreSCRS_Signing.so.5.0.0" "$work/empty.c" 2>"$work/cc.err"; then
    echo "  FAIL  case_b could not build a synthetic library" >&2
    sed 's/^/          /' "$work/cc.err" >&2
    fails=$((fails + 1))
else
    run "case_b a library without the loader passes" 0 "$work/clean"
fi

# case_c -- a stripped artefact must be refused, not reported OK. The loader's
# symbols are hidden, so .dynsym alone cannot see them: reading a stripped
# library would print OK for a library that links the loader, which is the
# exact false green this exit code exists for.
mkdir -p "$work/stripped/lib/LibreSCRS"
cp "$real" "$work/stripped/lib/LibreSCRS/libLibreSCRS_Signing.so.5.0.0"
strip "$work/stripped/lib/LibreSCRS/libLibreSCRS_Signing.so.5.0.0"
run "case_c a stripped library cannot be measured" 2 "$work/stripped"

# case_d -- an empty tree is the vacuum case: nothing to read is not OK.
mkdir -p "$work/vacuum/lib/LibreSCRS"
run "case_d an empty build tree cannot be measured" 2 "$work/vacuum"

if [[ "$fails" -eq 0 ]]; then
    echo "check-signing-no-module-loader selftest: all cases passed"
    exit 0
fi
echo "check-signing-no-module-loader selftest: $fails case(s) failed"
exit 1
