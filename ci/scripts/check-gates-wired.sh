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

# 'Scripts/*' is here because the macOS host keeps its gate scripts there, and
# this file is byte-identical in every repository: a pathspec that differed per
# repository is how four self-tests stopped being counted. The C++ repositories
# have no Scripts/ directory, so their candidate set is unchanged.
mapfile -t candidates < <(git ls-files -- 'ci/scripts/*' 'tools/*' 'Scripts/*' 'packaging/ci/*' 'packaging/arch/*' \
    | grep -E '\.(sh|py)$' | grep -v '\.selftest\.' | sort)
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

[ "$rc" -eq 0 ] && echo "OK: every shipped gate is wired (or accounted for)"
exit "$rc"
