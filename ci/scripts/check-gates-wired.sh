#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-gates-wired.sh -- a gate nobody runs is not a gate.
#
# Property, not proxy: every shipped script under ci/scripts/, tools/ and
# packaging/ci/ must be REACHABLE, by name, from something CI actually
# executes -- a workflow file, or the build system a workflow drives.
# Reachability is transitive: a script named by a reachable script is reachable.
# Anything else must be listed in ci/gate-wiring-exceptions.txt WITH a reason;
# a listed path that is no longer tracked fails too, so amnesty cannot go stale.
#
# Why this exists: a self-tested, green script that no workflow ever names
# measures nothing on every push, and nothing says so -- unwiring a gate
# changes no output, so it is the cheapest thing in CI to lose. Two scanners
# shipped in this project self-tested and green with no workflow naming either,
# which is the shape that hides it. Every path ci/gate-wiring-exceptions.txt
# stands down is recorded there with a reason.
#
# Three shapes this gate had to be taught, each found by its own selftest:
#  * Comment lines are stripped before the search, so naming a script inside a
#    `#` comment does not count as wiring -- otherwise the cheapest way to turn
#    this gate green is to write the name in a comment.
#  * The match is anchored on a name boundary, never a bare substring: without
#    the anchor `wired.sh` is "named" by every file mentioning
#    `check-gates-wired.sh`. That is how the first draft reported a false green.
#  * An exception is a reachability ROOT, not a pardon: a path listed in
#    ci/gate-wiring-exceptions.txt counts as run, so whatever that script calls
#    counts as run too and must not be reported as unwired. That matters for a
#    script CI really runs under a name no workflow spells out -- one invoked
#    through a variable, say -- and it is why an entry has to carry a reason.
#
# What this gate does NOT claim: that a named script is executed, or that its
# exit code is honoured. It claims no shipped gate is invisible to every place
# CI looks -- the weaker half of the property, and the half that was false.
#
# The match is textual. Any non-comment line of a reachable file that spells a
# script's name wires that script -- a docstring, a trailing comment after code
# or a quoted string counts as much as a `run:` line does. So keep script names
# out of prose inside scripts CI runs: a name left in a docstring keeps this
# gate green after the step that really ran the script is deleted.
#
# Exit: 0 wired (or accounted for) - 1 something is unwired - 2 cannot measure.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -uo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo" || { echo "FATAL: cannot enter $repo" >&2; exit 2; }
git -C "$repo" rev-parse --show-toplevel >/dev/null 2>&1 \
    || { echo "FATAL: $repo is not a git checkout -- cannot measure" >&2; exit 2; }

ALLOW="ci/gate-wiring-exceptions.txt"
rc=0

# One pathspec, the same one run-selftests.sh picks its set with, byte-identical
# in every repository: a pathspec that differed per repository is how four
# self-tests stopped being counted. It is wider than the directories any single
# repository uses, on purpose -- a gate that ships anywhere this project keeps
# scripts is in the candidate set.
#
# Measured when it was widened: 23 shipped scripts came into view across the six
# C++ repositories that nothing named -- a whole e2e harness, the packaging
# payload helpers, a release certificate-expiry check that sat outside the
# scanned path, and a dev installer. Each is now wired or carries a reason.
SCAN_PATHSPEC=('ci/*' 'tools/*' 'packaging/*' 'scripts/*' 'Scripts/*' 'e2e/*')

mapfile -t all_scripts < <(git ls-files -- "${SCAN_PATHSPEC[@]}" | grep -E '\.(sh|py)$' | sort)
# `.selftest.` is a PARTITION now, not an exclusion. The two halves are judged by
# two different rules because they are reached in two different ways: a gate is
# reached by being named, a self-test by falling inside the runner's pathspec.
mapfile -t candidates < <(printf '%s\n' ${all_scripts[@]+"${all_scripts[@]}"} \
    | grep -v '^$' | grep -v '\.selftest\.' || true)
mapfile -t shipped_selftests < <(printf '%s\n' ${all_scripts[@]+"${all_scripts[@]}"} \
    | grep -v '^$' | grep '\.selftest\.' || true)
[ "${#candidates[@]}" -eq 0 ] && { echo "FATAL: no candidate scripts found -- wrong root?" >&2; exit 2; }

mapfile -t roots < <(git ls-files -- '.github/workflows/*.yml' '.github/workflows/*.yaml' \
    'CMakeLists.txt' '*/CMakeLists.txt' '*.cmake' '*/*.cmake' | sort -u)
[ "${#roots[@]}" -eq 0 ] && { echo "FATAL: no workflow or CMake roots found -- cannot measure" >&2; exit 2; }

esc() { printf '%s' "$1" | sed 's/[][\\.^$*+?(){}|]/\\&/g'; }

pat=""
declare -A byname=()
for c in "${candidates[@]}"; do
    b="$(basename -- "$c")"
    byname[$b]="${byname[$b]:-}${byname[$b]:+ }$c"
    pat="${pat:+$pat|}$(esc "$b")"
done
RE="(^|[^A-Za-z0-9_.-])($pat)"

declare -A allowed=()
if [ -f "$ALLOW" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue;; esac
        path="${line%%[[:space:]]*}"
        reason="${line#"$path"}"; reason="${reason#"${reason%%[![:space:]]*}"}"
        if [ -z "$reason" ]; then
            echo "FAIL: $ALLOW: '$path' carries no reason" >&2; rc=1; continue
        fi
        if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
            echo "FAIL: $ALLOW: '$path' is not a tracked file (stale entry)" >&2; rc=1; continue
        fi
        allowed[$path]=1
    done < "$ALLOW"
fi

# An exception is a root, not a pardon: what it calls is called too.
declare -A reachable=()
frontier=("${roots[@]}")
for p in "${!allowed[@]}"; do frontier+=("$p"); done

while [ "${#frontier[@]}" -gt 0 ]; do
    next=()
    for f in "${frontier[@]}"; do
        [ -f "$f" ] || continue
        while IFS= read -r hit; do
            hit="${hit##*[!A-Za-z0-9_.-]}"
            for c in ${byname[$hit]:-}; do
                [ "$c" = "$f" ] && continue
                [ -n "${reachable[$c]:-}" ] && continue
                reachable[$c]=1; next+=("$c")
            done
        done < <(grep -v '^[[:space:]]*#' -- "$f" | grep -oE "$RE" | sort -u)
    done
    frontier=("${next[@]}")
done

for c in "${candidates[@]}"; do
    if [ -n "${allowed[$c]:-}" ]; then
        echo "SKIP: $c -- listed in $ALLOW"
        continue
    fi
    [ -n "${reachable[$c]:-}" ] && continue
    echo "FAIL: $c is shipped but no workflow or build file names it" >&2
    rc=1
done

# --- R_SELFTEST: what the runner would execute == what the repository ships ---
#
# The rule above measures reachability by NAME, and that is the wrong instrument
# for a self-test: the runner does not name them, it selects them by pathspec. So
# a self-test could be added and reached by nothing, or dropped out of the
# runner's pathspec, and a check built on names would stay green over it. Half
# the shipped proofs of red were invisible here for exactly that reason.
#
# The question asked instead is the runner's own: what WOULD you execute. Both
# directions are compared, because a set equal in one direction is not equal --
# a runner naming something the repository does not track is as broken as a
# self-test the runner skips.
runner=""
for r_cand in ci/scripts/run-selftests.sh tools/run-selftests.sh; do
    [ -x "$r_cand" ] && { runner="$r_cand"; break; }
done
if [ -z "$runner" ]; then
    echo "FATAL: no executable run-selftests.sh under ci/scripts/ or tools/ --" >&2
    echo "       a repository that ships self-tests and has nothing to run them is" >&2
    echo "       the situation this rule exists for, so this is not a pass." >&2
    exit 2
fi
if ! listed_raw="$(./"$runner" --list 2>/dev/null)"; then
    echo "FATAL: $runner --list failed -- cannot ask the runner what it would run" >&2
    exit 2
fi
mapfile -t listed < <(printf '%s\n' "$listed_raw" | grep -v '^$' | sort)
if [ "${#listed[@]}" -eq 0 ]; then
    echo "FATAL: $runner --list printed nothing while this repository ships" >&2
    echo "       ${#shipped_selftests[@]} self-test(s). An empty answer is not an empty set." >&2
    exit 2
fi

_sel_tmp="$(mktemp -d "${TMPDIR:-/var/tmp}/cgw.XXXXXX")" || exit 2
printf '%s\n' ${shipped_selftests[@]+"${shipped_selftests[@]}"} | grep -v '^$' | sort > "$_sel_tmp/shipped"
printf '%s\n' "${listed[@]}" > "$_sel_tmp/listed"
while IFS= read -r f; do
    [ -n "$f" ] || continue
    echo "FAIL: $f is shipped but the runner would not run it" >&2
    echo "      ($runner picks its set by pathspec; this file is outside it)" >&2
    rc=1
done < <(comm -23 "$_sel_tmp/shipped" "$_sel_tmp/listed")
while IFS= read -r f; do
    [ -n "$f" ] || continue
    echo "FAIL: $runner would run $f, which this repository does not track" >&2
    rc=1
done < <(comm -13 "$_sel_tmp/shipped" "$_sel_tmp/listed")
rm -rf "$_sel_tmp"

[ "$rc" -eq 0 ] && echo "OK: every shipped gate is wired (or accounted for), and the runner's set is the shipped set (${#listed[@]} self-tests)"
exit "$rc"
