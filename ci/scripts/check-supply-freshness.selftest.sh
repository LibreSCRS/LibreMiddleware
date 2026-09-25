#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-supply-freshness.selftest.sh -- prove the freshness check can fail, and
# fail for the right reason.
#
# The check it drives reads two things it cannot be given here: the pins in a
# tree, and what upstream has published since. Both are substituted:
# SUPPLY_FRESHNESS_REPO points it at a throwaway tree shaped like this one, and
# SUPPLY_FRESHNESS_FIXTURE at a directory of canned upstream answers. Neither is
# ever set in CI -- the workflow passes a token and the check talks to the real
# API. What is under test here is the judgement, which is the part that has been
# wrong in every version of this idea: which release counts as newer, how a
# version sorts, when an old pin is a finding, and when the answer is "I cannot
# tell" rather than "fine".
#
# Cases:
#   newer_patch_same_series   a newer patch in the pin's own series     -> 1
#   newer_other_series        newer release, different series           -> 0 (reported)
#   offline                   --offline                                 -> 2 (never 0)
#   pin_older_than_threshold  pin published two years ago               -> 1
#   unknown_version_mapping   a pin file that does not parse            -> 2 (never 0)
#   empty_matching_refs       upstream changed its tag scheme           -> 2 (never 0)
#   lexical_sort              3.5.10 must beat 3.5.9                    -> 0
#   allowance_cannot_excuse_a_patch   an allowance over a same-series
#                                     release                           -> 1
#   expired_allowance         an allowance whose date has passed         -> 1
#   unowned_allowance         an exception nobody has taken (PENDING)    -> 1
#   ownerless_allowance       an entry with no owner field at all        -> 1
#   orphaned_allowance        an entry for a component that is current   -> 1
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-supply-freshness.sh"
WORK="$(mktemp -d /var/tmp/freshness-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fail=0
baseline_green=0
baseline_broken=0
BASELINE_OK=no
TREE=""
FIX=""

iso_days_ago() { date -u -d "@$(( $(date -u +%s) - ${1:-0} * 86400 ))" +%Y-%m-%dT%H:%M:%SZ; }

# tree <name>: a throwaway tree carrying every pin the check requires, all of
# them current, so a case perturbs exactly one thing.
tree() {
    local root="$WORK/$1"
    mkdir -p "$root/thirdparty/openssl-3.5.8" "$root/thirdparty/miniz" \
             "$root/thirdparty/nlohmann" "$root/thirdparty/curl-source/include/curl" \
             "$root/thirdparty/opensc-source" "$root/ci"
    printf '3.1.2\n' > "$root/thirdparty/miniz/VERSION.txt"
    {
        printf '#define NLOHMANN_JSON_VERSION_MAJOR 3\n'
        printf '#define NLOHMANN_JSON_VERSION_MINOR 11\n'
        printf '#define NLOHMANN_JSON_VERSION_PATCH 3\n'
    } > "$root/thirdparty/nlohmann/json.hpp"
    {
        printf '#define LIBCURL_VERSION_MAJOR 8\n'
        printf '#define LIBCURL_VERSION_MINOR 22\n'
        printf '#define LIBCURL_VERSION_PATCH 0\n'
    } > "$root/thirdparty/curl-source/include/curl/curlver.h"
    printf '07d0d40b0e4051f6fe11f3a92cec56d320670d85\n' > "$root/thirdparty/opensc-source/.pinned-sha"
    TREE="$root"
}

# fixture <name>: canned upstream answers, everything current.
fixture() {
    local d="$WORK/$1-fixture"
    mkdir -p "$d"
    printf '3.5.0\n3.5.1\n3.5.7\n3.5.8\n' > "$d/openssl.refs"
    iso_days_ago 25 > "$d/openssl.published"
    printf '8.20.0\n8.21.0\n8.22.0\n'     > "$d/curl.refs"
    iso_days_ago 17 > "$d/curl.published"
    printf '3.1.0\n3.1.1\n3.1.2\n'        > "$d/miniz.refs"
    iso_days_ago 80 > "$d/miniz.published"
    printf '3.11.0\n3.11.2\n3.11.3\n'     > "$d/nlohmann.refs"
    iso_days_ago 30 > "$d/nlohmann.published"
    printf '3.12.0\n'                     > "$d/nlohmann.newest-overall"
    iso_days_ago 86 > "$d/opensc.published"
    FIX="$d"
}

# expect <name> <want-rc> [<substring>...]
expect() {
    local name="$1" want="$2"; shift 2
    local out rc
    if [ "$BASELINE_OK" != yes ]; then
        echo "case $name: SKIPPED -- its baseline was not green, so the perturbation proves nothing"
        return
    fi
    cases=$((cases + 1))
    out="$(SUPPLY_FRESHNESS_REPO="$TREE" SUPPLY_FRESHNESS_FIXTURE="$FIX" \
           SUPPLY_FRESHNESS_ALLOWANCES="$TREE/ci/allowances.txt" \
           bash "$CHECK" "${EXTRA_ARGS[@]}" 2>&1)"; rc=$?
    if [ "$rc" = "$want" ]; then
        echo "case $name: OK   -- exit $rc"
        [ "$want" != 0 ] && red=$((red + 1))
    else
        echo "case $name: FAIL -- expected exit $want, got $rc"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1))
        return
    fi
    local want_s
    for want_s in "$@"; do
        case "$out" in
            *"$want_s"*) ;;
            *) echo "  case $name: FAIL -- the output does not name '$want_s'"
               echo "$out" | sed 's/^/    /'
               fail=$((fail + 1)) ;;
        esac
    done
}

# green <name>: assert the unperturbed pair is a pass BEFORE the perturbation,
# and gate the case on it.
#
# A perturbation measured against another failure measures nothing, and this
# harness said so line by line while its trailer read exactly as it does when
# everything is fine -- so two rounds of review read `12 cases, 10 red-proved`
# as a pass while eleven baselines were failing. A case whose baseline is not
# green is now SKIPPED and not counted, so the trailer's own numbers change: a
# broken baseline cannot produce the healthy summary.
green() {
    local out rc
    out="$(SUPPLY_FRESHNESS_REPO="$TREE" SUPPLY_FRESHNESS_FIXTURE="$FIX" \
           SUPPLY_FRESHNESS_ALLOWANCES="$TREE/ci/allowances.txt" bash "$CHECK" 2>&1)"; rc=$?
    if [ "$rc" != 0 ]; then
        echo "case $1: FATAL -- the unperturbed pair is not green (rc=$rc); this case measures nothing and is not counted"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1))
        baseline_broken=$((baseline_broken + 1))
        BASELINE_OK=no
        return 1
    fi
    BASELINE_OK=yes
    baseline_green=$((baseline_green + 1))
    return 0
}

EXTRA_ARGS=()

# 1. The failure this check exists for: a security release in the pin's own
#    series. This is the shape the bundled crypto sat in for seven months.
tree newer_patch; fixture newer_patch; green newer_patch
printf '3.5.0\n3.5.1\n3.5.7\n3.5.8\n3.5.9\n' > "$FIX/openssl.refs"
expect newer_patch_same_series 1 'openssl' '3.5.9' 'behind'

# 2. A newer release in a DIFFERENT series is a report, not a failure: moving a
#    minor is a decision, and this check does not get to make it.
tree other_series; fixture other_series; green other_series
printf '3.13.0\n' > "$FIX/nlohmann.newest-overall"
expect newer_other_series 0 'nlohmann' '3.13.0'

# 3. Not being able to reach upstream is not a pass.
tree offline; fixture offline; green offline
EXTRA_ARGS=(--offline)
expect offline 2
EXTRA_ARGS=()

# 4. A pin nobody has looked at for two years, newest in its series or not.
tree old_pin; fixture old_pin; green old_pin
iso_days_ago 730 > "$FIX/miniz.published"
expect pin_older_than_threshold 1 'miniz' 'older than'

# 5. A pin the check cannot turn into an upstream version. miniz is the reason
#    this case exists: its version macro is the zlib version it emulates, so a
#    check that guessed would compare 11.3.2 against a 3.x tag list and call it
#    behind by eight majors.
tree bad_pin; fixture bad_pin; green bad_pin
printf 'not-a-version\n' > "$TREE/thirdparty/miniz/VERSION.txt"
expect unknown_version_mapping 2 'miniz' 'CANNOT MEASURE'

# 6. Upstream renames its tags and the series query comes back empty. Silence
#    from a query is not evidence of currency.
tree no_refs; fixture no_refs; green no_refs
: > "$FIX/openssl.refs"
expect empty_matching_refs 2 'openssl' 'CANNOT MEASURE'

# 7. Sorting. A lexical maximum says 3.5.9 is newer than 3.5.10 and reports a
#    pin that IS current as behind; this is the bug that arrives with 3.5.10 and
#    nothing else in this file would catch it.
tree sorting
mv "$TREE/thirdparty/openssl-3.5.8" "$TREE/thirdparty/openssl-3.5.10"
fixture sorting
printf '3.5.8\n3.5.9\n3.5.10\n' > "$FIX/openssl.refs"
expect lexical_sort 0 'openssl' '3.5.10'

# 8. An allowance must not be able to excuse a release in the pin's own series.
#    That is the failure this whole check exists for, and a file anyone can edit
#    would otherwise be the cheapest way to silence it.
tree allow_patch; fixture allow_patch; green allow_patch
printf '3.5.0\n3.5.8\n3.5.9\n' > "$FIX/openssl.refs"
printf 'openssl 2099-01-01 owner:release-owner we would rather not\n' > "$TREE/ci/allowances.txt"
expect allowance_cannot_excuse_a_patch 1 'openssl' '3.5.9' 'behind'

# 9. An allowance whose date has passed fails instead of going on excusing
#    something, so a deliberate deferral cannot become permanent by being
#    forgotten.
tree expired; fixture expired; green expired
iso_days_ago 730 > "$FIX/miniz.published"
printf 'miniz 2020-01-01 owner:release-owner deferred once, long ago\n' > "$TREE/ci/allowances.txt"
expect expired_allowance 1 'miniz' 'expired'

# 10. An exception nobody has taken is not permission. Not keeping a pin current
#     is a decision about what ships, and this check does not get to assume it.
tree unowned; fixture unowned; green unowned
iso_days_ago 730 > "$FIX/miniz.published"
printf 'miniz 2099-01-01 owner:PENDING nobody has decided this yet\n' > "$TREE/ci/allowances.txt"
expect unowned_allowance 1 'miniz' 'older than'

# 11. An entry with no owner field at all is malformed, not lenient.
tree ownerless; fixture ownerless; green ownerless
iso_days_ago 730 > "$FIX/miniz.published"
printf 'miniz 2099-01-01 a reason but no owner field\n' > "$TREE/ci/allowances.txt"
expect ownerless_allowance 1 'miniz' 'names no owner'

# 12. An entry is consulted only when the pin it names is already a finding, so a
#     malformed or expired one for a CURRENT component would never be read. The
#     file is validated whatever every pin's verdict turns out to be.
tree orphaned; fixture orphaned; green orphaned
printf 'curl 2020-01-01 owner:release-owner expired, and curl is current\n' > "$TREE/ci/allowances.txt"
expect orphaned_allowance 1 'curl' 'expired'

# 13. The green this check must be able to reach. An owner records the decision
#     and everything else is current, so the answer is 0 -- if no state of the
#     tree could produce that, the check would be a colour rather than a measure.
tree approved; fixture approved; green approved
iso_days_ago 730 > "$FIX/miniz.published"
printf 'miniz 2099-01-01 owner:release-owner reviewed and deliberately held at this version\n' \
    > "$TREE/ci/allowances.txt"
expect all_allowances_approved 0 'allowed' 'decided by release-owner'

if [ "$baseline_broken" != 0 ]; then
    echo "selftest: $baseline_broken of $((baseline_green + baseline_broken)) baselines were not green -- nothing below was measured against a pass"
fi
echo "selftest: baselines green $baseline_green, broken $baseline_broken"
echo "selftest: $cases cases, $red red-proved"
[ "$fail" = 0 ] && [ "$red" -gt 0 ] && [ "$baseline_broken" = 0 ]
