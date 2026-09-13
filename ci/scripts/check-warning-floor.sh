#!/usr/bin/env bash
# check-warning-floor.sh <build-dir>
#
# warning-gate.py refuses to judge a log with fewer compile lines than
# ci/warning-baseline.json's min_compile_units -- the anti-vacuum rule that
# stops an incremental build from being recorded as a measurement. The rule
# has one failure mode nobody watches: when the tree LOSES compile units, the
# recorded floor becomes unreachable and the gate goes red on a perfectly
# healthy full build, with a message that blames the build ("this is an
# incremental build, not a measurement") instead of the stale number.
#
# Measured on LibreKDE: the recorded floor is 122, written before the in-repo
# fake agent was deleted; a clean CI-configured tree has 111 compile edges. The
# first push would fail build-linux at the warning step, and the steps after it
# -- the test-manifest gate, qmllint and the whole LibreKDE ctest run -- would
# never execute.
#
# Asserts min_compile_units <= the compile edges the CONFIGURED graph holds,
# and prints both numbers so a stale floor is visible rather than inferred.
# Ninja only, by design: a missing build.ninja is exit 2 (cannot measure),
# never 0 -- an unmeasurable gate that returns success is the defect this
# whole file exists to prevent.
#
# Exit: 0 floor is reachable - 1 floor is unreachable - 2 cannot measure.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -uo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build="${1:?usage: check-warning-floor.sh <build-dir>}"
base="$repo/ci/warning-baseline.json"

[ -f "$base" ] || { echo "FATAL: no baseline at $base" >&2; exit 2; }
[ -f "$build/build.ninja" ] || { echo "FATAL: no $build/build.ninja (Ninja generator required)" >&2; exit 2; }

floor="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("min_compile_units", -1))' "$base")" \
    || { echo "FATAL: cannot read min_compile_units from $base" >&2; exit 2; }
case "$floor" in ''|*[!0-9-]*) echo "FATAL: min_compile_units is not a number: '$floor'" >&2; exit 2;; esac
[ "$floor" -lt 0 ] && { echo "FATAL: $base has no min_compile_units" >&2; exit 2; }
[ "$floor" -eq 0 ] && { echo "FAIL: min_compile_units is 0 -- the anti-vacuum rule is disarmed" >&2; exit 1; }

units="$(grep -cE '^build .*: (CXX|C|OBJCXX|OBJC)_COMPILER' "$build/build.ninja")"
[ "$units" -eq 0 ] && { echo "FATAL: $build/build.ninja has no compile edges -- cannot measure" >&2; exit 2; }

if [ "$floor" -gt "$units" ]; then
    echo "FAIL: ci/warning-baseline.json min_compile_units=$floor but the configured graph" >&2
    echo "      has only $units compile edges. No full build can ever reach that floor, so" >&2
    echo "      warning-gate.py will refuse every log and blame the build. Re-record with:" >&2
    echo "        ./ci/scripts/warning-gate.py --update --build-dir $build <full-build.log>" >&2
    echo "      or set min_compile_units to $units if the categories are still current." >&2
    exit 1
fi
if [ "$floor" -lt "$units" ]; then
    echo "note: min_compile_units=$floor, configured graph has $units -- floor is $((units-floor)) low."
    echo "      Reachable, so this is not a failure; re-record when the categories are next measured."
fi
echo "OK: min_compile_units=$floor is reachable ($units compile edges configured)"
exit 0
