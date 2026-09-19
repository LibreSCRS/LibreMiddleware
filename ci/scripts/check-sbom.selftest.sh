#!/usr/bin/env bash
# Selftest for check-sbom.py. Six shapes: one publishable bill, and the five
# ways a bill can be worthless while still being a file the release job
# happily signs.
#
# It exists because the claim it guards is otherwise only measurable at a tag.
# The producer runs in the release job and nowhere else, so its refusal to
# write an empty bill first turns red on the one run that must not fail. These
# cases put the same refusal on every push, over documents built here.
#
# The producer is deliberately not named in this prose: the wiring gate treats
# any non-comment line of a reachable file that spells a script's name as
# wiring it, and a docstring here would keep it looking wired long after its
# last real caller was gone.
#
# What this does NOT claim: that the bill describes the artefact beside it.
# That is the producer's property -- it derives both from one tree -- and no
# reading of the finished document can recover it.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-sbom.py"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d) || exit 2
trap 'rm -rf "$work"' EXIT
fails=0
cases=0
red=0

# expect <want-rc> <label> <file...>
expect() {
    want=$1; label=$2; shift 2
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$want" != 0 ]; then red=$((red + 1)); fi
    python3 "$subject" "$@" >"$work/out" 2>&1
    got=$?
    if [ "$got" != "$want" ]; then
        echo "FAIL: $label: expected rc=$want, got rc=$got" >&2
        sed 's/^/    /' "$work/out" >&2
        fails=$((fails + 1))
    else
        echo "ok: $label (rc=$got)"
    fi
}

printf '%s' '{"bomFormat":"CycloneDX","components":[{"name":"openssl","version":"3"}]}' \
    > "$work/good.json"
printf '%s' '{"bomFormat":"CycloneDX","components":[]}' > "$work/empty.json"
printf '%s' '{"bomFormat":"CycloneDX","components":[{"version":"3"}]}' \
    > "$work/nameless.json"
printf '%s' '{"bomFormat":"SPDX","components":[{"name":"openssl"}]}' \
    > "$work/wrongformat.json"
printf '%s' '{"bomFormat":"CycloneDX"}' > "$work/nolist.json"
printf '%s' 'not json at all' > "$work/broken.json"

expect 0 "a bill with a named component is publishable" "$work/good.json"
expect 1 "an empty component list is refused" "$work/empty.json"
expect 1 "a component with no name is refused" "$work/nameless.json"
expect 1 "a document that is not CycloneDX is refused" "$work/wrongformat.json"
expect 1 "a document with no components array is refused" "$work/nolist.json"
expect 1 "an unparseable document is refused" "$work/broken.json"
expect 1 "a bill that never arrived is refused" "$work/absent.json"
expect 2 "no arguments is a usage error, not a pass"

# The whole point of taking a list: one good bill must not launder a bad one.
expect 1 "one empty bill in a set fails the set" "$work/good.json" "$work/empty.json"

if [ "$fails" -ne 0 ]; then
    echo "check-sbom.selftest: $fails case(s) failed" >&2
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 1
fi
echo "check-sbom.selftest: all cases passed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
