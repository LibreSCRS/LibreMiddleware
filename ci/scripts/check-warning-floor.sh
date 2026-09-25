#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-warning-floor.sh <build-dir> [--leg <name>]
#
# warning-gate.py refuses to judge a log with fewer compile lines than
# ci/warning-baseline.json's min_compile_units -- the anti-vacuum rule that
# stops an incremental build from being recorded as a measurement. The rule
# has one failure mode nobody watches: when the tree LOSES compile units, the
# recorded floor becomes unreachable and the gate goes red on a perfectly
# healthy full build, with a message that blames the build ("this is an
# incremental build, not a measurement") instead of the stale number.
#
# A floor is recorded once and the tree keeps moving: delete a component and
# the recorded number can end up above what a clean CI-configured tree builds.
# From then on every full build fails at the warning step, and every step the
# workflow runs after it -- the remaining gates and the whole ctest run --
# never executes, for a reason the message does not name.
#
# Asserts min_compile_units -- from the baseline section for the compiler that
# configured the tree, the same section warning-gate.py judges against -- is
# <= the compile edges the CONFIGURED graph holds,
# and prints both numbers so a stale floor is visible rather than inferred.
# --leg names the workflow leg, exactly as warning-gate.py takes it: a matrix
# that builds one compiler in two configurations keeps one section per leg, and
# each leg's floor is read from its own.
#
# Ninja only, by design: a missing build.ninja is exit 2 (cannot measure),
# never 0 -- an unmeasurable gate that returns success is the defect this
# whole file exists to prevent.
#
# Exit: 0 floor is reachable - 1 floor is unreachable - 2 cannot measure.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -uo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
build="${1:?usage: check-warning-floor.sh <build-dir> [--leg <name>]}"
leg=""
if [ "$#" -gt 1 ]; then
    if [ "$#" -eq 3 ] && [ "$2" = "--leg" ] && [ -n "$3" ]; then leg="$3"
    else echo "FATAL: usage: check-warning-floor.sh <build-dir> [--leg <name>]" >&2; exit 2; fi
fi
base="$repo/ci/warning-baseline.json"

[ -f "$base" ] || { echo "FATAL: no baseline at $base" >&2; exit 2; }
[ -f "$build/build.ninja" ] || { echo "FATAL: no $build/build.ninja (Ninja generator required)" >&2; exit 2; }

# The floor lives in the baseline's section for the compiler that configured
# this tree, and which section that is -- and how an older layout is read -- is
# warning-gate.py's decision, so it is asked rather than restated here. Reading
# the top level instead found nothing once the gate began keying the baseline by
# compiler, and failed every build with "no min_compile_units".
gate="$repo/ci/scripts/warning-gate.py"
[ -f "$gate" ] || { echo "FATAL: no $gate to read the compiler key with" >&2; exit 2; }
read -r key floor < <(python3 -B - "$gate" "$build" "$base" "$leg" <<'PY'
import importlib.util, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("warning_gate", sys.argv[1])
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
key = gate.baseline_key(Path(sys.argv[2]), sys.argv[4] or None)  # exits 2 if unconfigured
base = json.loads(Path(sys.argv[3]).read_text())
sect = gate.section(base, key)
floor = gate.compile_unit_floor(base, sect)
print(key, -2 if sect is None else (-1 if floor is None else floor))
PY
) || { echo "FATAL: cannot read the compiler key or the floor for $build" >&2; exit 2; }
case "$floor" in ''|*[!0-9-]*) echo "FATAL: min_compile_units is not a number: '$floor'" >&2; exit 2;; esac
[ "$floor" -eq -2 ] && { echo "FATAL: $base has no section for $key, the key $build is judged by" >&2; exit 2; }
[ "$floor" -lt 0 ] && { echo "FATAL: $base has no min_compile_units for $key" >&2; exit 2; }
[ "$floor" -eq 0 ] && { echo "FAIL: $key min_compile_units is 0 -- the anti-vacuum rule is disarmed" >&2; exit 1; }

units="$(grep -cE '^build .*: (CXX|C|OBJCXX|OBJC)_COMPILER' "$build/build.ninja")"
[ "$units" -eq 0 ] && { echo "FATAL: $build/build.ninja has no compile edges -- cannot measure" >&2; exit 2; }

if [ "$floor" -gt "$units" ]; then
    echo "FAIL: ci/warning-baseline.json $key min_compile_units=$floor but the configured graph" >&2
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
echo "OK: $key min_compile_units=$floor is reachable ($units compile edges configured)"
exit 0
