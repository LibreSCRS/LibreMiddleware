#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-bundled-licenses.selftest.sh -- prove the licence check can fail.
#
# Every case builds its own manifest and licence files under /var/tmp, and each
# fixture is asserted to PASS before it is perturbed: a perturbation measured
# against another failure measures nothing, and a summary that reads the same in
# both states is how that goes unnoticed.
#
# Cases (all four are perturbations, all four must go non-zero):
#   digest_stale        the file changed and the pin did not      -> 1
#   text_missing        a named licence file is not there         -> 1
#   entry_without_pin   an entry with no digest at all            -> 1
#   no_components       a manifest that pins nothing              -> 2 (never 0)
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-bundled-licenses.sh"
WORK="$(mktemp -d /var/tmp/liccheck-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cases=0; red=0; fail=0; baseline_green=0; baseline_broken=0; BASELINE_OK=no; ROOT=""

fixture() {
    local root="$WORK/$1"
    mkdir -p "$root/one" "$root/two"
    printf 'licence text one\n' > "$root/one/COPYING"
    printf 'licence text two\n' > "$root/two/LICENSE"
    local h1 h2
    h1="$(sha256sum "$root/one/COPYING" | cut -d' ' -f1)"
    h2="$(sha256sum "$root/two/LICENSE" | cut -d' ' -f1)"
    printf '{ "components": [\n  {"name":"one","text":"one/COPYING","sha256":"%s"},\n  {"name":"two","text":"two/LICENSE","sha256":"%s"}\n] }\n' \
        "$h1" "$h2" > "$root/licenses.json"
    ROOT="$root"
    local out rc
    out="$(bash "$CHECK" "$root/licenses.json" 2>&1)"; rc=$?
    if [ "$rc" != 0 ]; then
        echo "case $1: FATAL -- the fixture is not green before perturbation (rc=$rc); not counted"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1)); baseline_broken=$((baseline_broken + 1)); BASELINE_OK=no
        return 1
    fi
    BASELINE_OK=yes; baseline_green=$((baseline_green + 1))
}

expect() {
    local name="$1" want="$2"; shift 2
    local out rc
    if [ "$BASELINE_OK" != yes ]; then
        echo "case $name: SKIPPED -- its baseline was not green"
        return
    fi
    cases=$((cases + 1))
    out="$(bash "$CHECK" "$ROOT/licenses.json" 2>&1)"; rc=$?
    if [ "$rc" = "$want" ]; then
        echo "case $name: OK   -- exit $rc"
        [ "$want" != 0 ] && red=$((red + 1))
    else
        echo "case $name: FAIL -- expected exit $want, got $rc"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1)); return
    fi
    local want_s
    for want_s in "$@"; do
        case "$out" in
            *"$want_s"*) ;;
            *) echo "  case $name: FAIL -- the output does not name '$want_s'"; fail=$((fail + 1)) ;;
        esac
    done
}

# 1. The finding this exists for: a submodule move changed the file and the pin
#    went on asserting the old one.
fixture digest_stale && printf 'licence text one, amended\n' > "$ROOT/one/COPYING"
expect digest_stale 1 'one' 'hashes to'

# 2. A named file that is not there is not an absence of a finding.
fixture text_missing && rm -f "$ROOT/two/LICENSE"
expect text_missing 1 'two' 'is not there'

# 3. An entry with nothing to compare against.
fixture entry_without_pin && python3 - "$ROOT/licenses.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
del d["components"][0]["sha256"]
json.dump(d, open(p, "w"))
PY
expect entry_without_pin 1 'one' 'no licence file or no digest'

# 4. A manifest that pins nothing cannot be a pass.
fixture no_components && printf '{ "components": [] }\n' > "$ROOT/licenses.json"
expect no_components 2

echo "selftest: baselines green $baseline_green, broken $baseline_broken"
echo "selftest: $cases cases, $red red-proved"
[ "$fail" = 0 ] && [ "$red" -gt 0 ] && [ "$baseline_broken" = 0 ]
