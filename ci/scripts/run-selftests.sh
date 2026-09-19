#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# run-selftests.sh -- run every self-test this repository ships, and make each
# one say what it measured.
#
# Property, not proxy: a self-test nothing executes proves the same as no
# self-test at all, and a runner that only reads exit codes accepts `exit 0` as
# a body. So this asks two things of every self-test:
#
#   * it exits 0, and
#   * its last line of stdout is    selftest: <n> cases, <r> red-proved
#     with n > 0 and r > 0, where r counts the cases in which the GATE returned
#     non-zero on a perturbed input. A proof that never saw the gate fail is a
#     claim about the gate's happy path.
#
# The set is chosen by pathspec rather than by a list here: a self-test that
# lands outside the scanned paths is invisible to the runner, and the wiring
# check asks this script -- with --list -- what it would execute and compares
# that against what the repository ships. Two copies of the pathspec, one here
# and one there, so a narrowed pathspec is a failure rather than a silence.
#
# Interpreter by extension, never a guess: a Python self-test run under bash
# prints a syntax error and exits non-zero, which reads as a failing gate
# rather than a mis-run one. An extension with no interpreter is exit 2.
#
# Usage:
#   ./ci/scripts/run-selftests.sh           run them all
#   ./ci/scripts/run-selftests.sh --list    print what it would run, one per line
#
# Exit codes -- a consumer writes the condition as `rc = 0`, never "not 1":
#
#   0  every self-test passed and proved a red case
#   1  one of them failed, or ran no case, or proved no red case
#   2  cannot measure: no self-tests found, an interpreter is missing, an
#      unknown extension, or a self-test itself said it could not judge
set -uo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" \
    || { echo "FATAL: cannot resolve own directory -- cannot measure" >&2; exit 2; }
repo="$(git -C "$here" rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$repo" ] || { echo "FATAL: $here is not a git checkout -- cannot measure" >&2; exit 2; }
cd "$repo" || { echo "FATAL: cannot enter $repo" >&2; exit 2; }

# Uniform in every repository. `packaging/`, `scripts/`, `Scripts/` and `e2e/`
# are here because self-tests live in all of them somewhere in this project,
# and a pathspec that differs per repository is how four of them stopped being
# counted.
mapfile -t tests < <(git ls-files -- \
    'ci/*' 'tools/*' 'packaging/*' 'scripts/*' 'Scripts/*' 'e2e/*' \
    | grep '\.selftest\.' | sort)

if [ "${#tests[@]}" -eq 0 ]; then
    echo "FATAL: no self-tests found under the scanned paths -- wrong root?" >&2
    exit 2
fi

if [ "$#" -gt 0 ]; then
    if [ "$1" = "--list" ] && [ "$#" -eq 1 ]; then
        printf '%s\n' "${tests[@]}"
        exit 0
    fi
    echo "FATAL: usage: $(basename -- "$0") [--list]" >&2
    exit 2
fi

# Interpreters first, all of them, before running anything: a tool this host
# does not have is "I cannot judge", never a pass and never a silent skip.
declare -A interp=()
for t in "${tests[@]}"; do
    case "$t" in
        *.selftest.py) interp[$t]="python3" ;;
        *.selftest.sh) interp[$t]="bash" ;;
        *) echo "FATAL: $t: no interpreter for this extension" >&2; exit 2 ;;
    esac
done
while IFS= read -r tool; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool is not on PATH -- cannot run the self-tests that need it" >&2; exit 2; }
done < <(printf '%s\n' "${interp[@]}" | sort -u)

work="$(mktemp -d "${TMPDIR:-/var/tmp}/run-selftests.XXXXXX")" \
    || { echo "FATAL: cannot create a temporary directory -- cannot measure" >&2; exit 2; }
trap 'rm -rf "$work"' EXIT
out="$work/out"
err="$work/err"

sum_cases=0
sum_red=0
failed=0
unjudged=0

for t in "${tests[@]}"; do
    # The status is taken from the `if` itself. Reading $? after a `case` is how
    # the barrier's counter came to report N/N while a self-test was failing.
    # stdout and stderr stay apart: the trailer is the last line of STDOUT, and
    # a self-test that writes a warning to stderr afterwards must not read as a
    # missing trailer.
    if "${interp[$t]}" "$t" >"$out" 2>"$err"; then st=0; else st=$?; fi
    last="$(tail -n 1 "$out")"

    if [ "$st" = 2 ]; then
        printf 'CANNOT JUDGE  %s (exit 2)\n' "$t"
        tail -n 5 "$out" "$err" | sed 's/^/  | /' 
        unjudged=1
        continue
    fi
    if [ "$st" != 0 ]; then
        printf 'FAIL  %s (exit %s)\n' "$t" "$st"
        tail -n 10 "$out" "$err" | sed 's/^/  | /' 
        failed=1
        continue
    fi

    if [[ ! "$last" =~ ^selftest:\ ([0-9]+)\ cases,\ ([0-9]+)\ red-proved$ ]]; then
        printf 'FAIL  %s exits 0 but its last line is not the canonical trailer\n' "$t"
        printf '  | last line: %s\n' "$last"
        failed=1
        continue
    fi
    n="${BASH_REMATCH[1]}"
    r="${BASH_REMATCH[2]}"
    if [ "$n" -eq 0 ]; then
        printf 'FAIL  %s ran no case\n' "$t"
        failed=1
        continue
    fi
    if [ "$r" -eq 0 ]; then
        printf 'FAIL  %s proved no red case -- it never saw the gate fail\n' "$t"
        failed=1
        continue
    fi
    sum_cases=$((sum_cases + n))
    sum_red=$((sum_red + r))
    printf 'ok    %-58s %s cases, %s red-proved\n' "$t" "$n" "$r"
done

printf 'run-selftests: %s selftests, %s cases, %s red-proved\n' \
    "${#tests[@]}" "$sum_cases" "$sum_red"

[ "$failed" = 0 ] || exit 1
[ "$unjudged" = 0 ] || exit 2
exit 0
