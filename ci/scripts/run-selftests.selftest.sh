#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# run-selftests.selftest.sh -- prove the self-test runner can fail.
#
# The runner is a gate, so it needs the same proof it demands of everything it
# runs. Every case builds a throwaway git repository under /var/tmp (never
# /tmp, which is a RAM filesystem on the development host), puts stand-in
# self-tests in it, and runs the real runner against that tree. `git add` is
# enough: the runner reads the index through `git ls-files`.
#
# Cases:
#   1   two green self-tests with valid trailers        -> 0, and the totals add up
#   2   a self-test that exits 1                        -> 1, and it is named
#   3   a self-test whose whole body is `exit 0`        -> 1 (no trailer)
#   4   a trailer claiming 0 red-proved                 -> 1
#   5   a trailer claiming 0 cases                      -> 1
#   6   a valid trailer that is not the last line       -> 1
#   7   a self-test that exits 2                        -> 2, never 0
#   8   no self-test in the tree at all                 -> 2
#   9   a .selftest.rb, an extension with no interpreter -> 2
#  10   an untracked self-test on disk                   -> absent from --list
set -uo pipefail

SUBJECT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/run-selftests.sh"
[ -f "$SUBJECT" ] || { echo "FATAL: $SUBJECT is missing" >&2; exit 2; }

WORK="$(mktemp -d /var/tmp/run-selftests-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fails=0

check() {  # check <label> <want-rc> <got-rc>
    cases=$((cases + 1))
    if [ "$2" != 0 ]; then red=$((red + 1)); fi
    if [ "$2" = "$3" ]; then
        printf 'PASS  %-2s want rc=%s\n' "$1" "$2"
    else
        printf 'FAIL  %-2s want rc=%s, got rc=%s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}

says() {  # says <label> <file> <text>
    if grep -qF -- "$3" "$2"; then
        printf 'PASS  %-2s output names %s\n' "$1" "$3"
    else
        printf 'FAIL  %-2s output does not name %s\n' "$1" "$3"
        fails=$((fails + 1))
    fi
}

fixture() {  # fixture <name> -> prints the repository root
    local root="$WORK/$1"
    mkdir -p "$root/ci/scripts"
    cp "$SUBJECT" "$root/ci/scripts/run-selftests.sh"
    chmod +x "$root/ci/scripts/run-selftests.sh"
    git -C "$root" init -q
    git -C "$root" config user.email t@t
    git -C "$root" config user.name t
    git -C "$root" add ci/scripts/run-selftests.sh
    printf '%s' "$root"
}

# stand_in <root> <relpath> <exit-code> <trailer-or-empty> [<line-after-trailer>]
stand_in() {
    local root="$1" rel="$2" code="$3" trailer="${4:-}" after="${5:-}"
    mkdir -p "$root/$(dirname -- "$rel")"
    {
        printf '#!/usr/bin/env bash\n'
        printf 'echo "case 1: OK"\n'
        [ -z "$trailer" ] || printf 'echo "%s"\n' "$trailer"
        [ -z "$after" ] || printf 'echo "%s"\n' "$after"
        printf 'exit %s\n' "$code"
    } > "$root/$rel"
    chmod +x "$root/$rel"
    git -C "$root" add "$rel"
}

run() {  # run <root> [args...] -> rc; output in $WORK/out
    local root="$1"; shift
    if ( cd "$root" && bash ci/scripts/run-selftests.sh "$@" ) > "$WORK/out" 2>&1; then
        echo 0
    else
        echo $?
    fi
}

# --- case 1: the control. Without it every other case could be an error path.
r="$(fixture c1)"
stand_in "$r" ci/scripts/a.selftest.sh 0 'selftest: 3 cases, 2 red-proved'
stand_in "$r" ci/scripts/b.selftest.sh 0 'selftest: 2 cases, 1 red-proved'
check 1 0 "$(run "$r")"
says 1 "$WORK/out" 'run-selftests: 2 selftests, 5 cases, 3 red-proved'

# --- case 2: a self-test that fails
r="$(fixture c2)"
stand_in "$r" ci/scripts/a.selftest.sh 0 'selftest: 3 cases, 2 red-proved'
stand_in "$r" ci/scripts/bad.selftest.sh 1 'selftest: 1 cases, 1 red-proved'
check 2 1 "$(run "$r")"
says 2 "$WORK/out" 'ci/scripts/bad.selftest.sh'

# --- case 3: `exit 0` as the whole body -- the attack this runner exists for
r="$(fixture c3)"
stand_in "$r" ci/scripts/a.selftest.sh 0 'selftest: 3 cases, 2 red-proved'
printf '#!/usr/bin/env bash\nexit 0\n' > "$r/ci/scripts/hollow.selftest.sh"
chmod +x "$r/ci/scripts/hollow.selftest.sh"
git -C "$r" add ci/scripts/hollow.selftest.sh
check 3 1 "$(run "$r")"
says 3 "$WORK/out" 'ci/scripts/hollow.selftest.sh'

# --- case 4: it ran cases and none of them saw the gate red
r="$(fixture c4)"
stand_in "$r" ci/scripts/green.selftest.sh 0 'selftest: 3 cases, 0 red-proved'
check 4 1 "$(run "$r")"
says 4 "$WORK/out" 'proved no red case'

# --- case 5: a trailer that admits it ran nothing
r="$(fixture c5)"
stand_in "$r" ci/scripts/empty.selftest.sh 0 'selftest: 0 cases, 0 red-proved'
check 5 1 "$(run "$r")"
says 5 "$WORK/out" 'ran no case'

# --- case 6: the trailer is there, but something follows it
r="$(fixture c6)"
stand_in "$r" ci/scripts/late.selftest.sh 0 'selftest: 3 cases, 2 red-proved' 'all good'
check 6 1 "$(run "$r")"
says 6 "$WORK/out" 'not the canonical trailer'

# --- case 7: a self-test that cannot judge is not a pass
r="$(fixture c7)"
stand_in "$r" ci/scripts/a.selftest.sh 0 'selftest: 3 cases, 2 red-proved'
stand_in "$r" ci/scripts/blind.selftest.sh 2 ''
check 7 2 "$(run "$r")"
says 7 "$WORK/out" 'CANNOT JUDGE'

# --- case 8: an empty set is "wrong root?", never "all clear"
r="$(fixture c8)"
check 8 2 "$(run "$r")"
says 8 "$WORK/out" 'wrong root?'

# --- case 9: an extension with no interpreter
r="$(fixture c9)"
stand_in "$r" ci/scripts/a.selftest.sh 0 'selftest: 3 cases, 2 red-proved'
printf 'puts 1\n' > "$r/ci/scripts/other.selftest.rb"
git -C "$r" add ci/scripts/other.selftest.rb
check 9 2 "$(run "$r")"
says 9 "$WORK/out" 'no interpreter'

# --- case 10: --list is what the repository SHIPS, not what is on disk
r="$(fixture c10)"
stand_in "$r" ci/scripts/a.selftest.sh 0 'selftest: 3 cases, 2 red-proved'
stand_in "$r" tools/b.selftest.sh 0 'selftest: 1 cases, 1 red-proved'
printf '#!/usr/bin/env bash\nexit 0\n' > "$r/ci/scripts/untracked.selftest.sh"
check 10 0 "$(run "$r" --list)"
if [ "$(sort "$WORK/out")" = "$(printf 'ci/scripts/a.selftest.sh\ntools/b.selftest.sh')" ]; then
    printf 'PASS  10 --list is exactly the tracked set\n'
else
    printf 'FAIL  10 --list is %s\n' "$(tr '\n' ' ' < "$WORK/out")"
    fails=$((fails + 1))
fi

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fails" = 0 ]
