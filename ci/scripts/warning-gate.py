#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Hold the compiler's diagnostics against a baseline that survives a compiler
that is not the one CI runs.

CI here builds with GCC 13 and the machine this was written on has GCC 16.
Neither diagnostic set is authoritative over the other, so an unknown compiler
key is REPORTED, with a JSON section to paste, and does not fail the build.

Counting is by the [-Wname] tag, never by the message text: diagnostics are
localised, and on the machine that wrote this they read
`warning: напомена више редова [-Wcomment]`. The job exports LC_ALL=C anyway,
but a gate that only works when someone remembers to is not a gate.

Falling BELOW the baseline never fails the build -- a gate that punishes fixing
warnings does not survive contact -- it prints `stale baseline, run --update`.

The anti-vacuum rule is the one that matters most. A zero from an incremental
ninja build means nothing was recompiled, not that nothing warned; that is the
same class as a stale binary passing a test filter, and it has cost this project
real time. A log with fewer compile lines than the baseline expects is refused,
not scored.

Usage:
  ci/scripts/warning-gate.py --check  <build.log> --build-dir <dir>
  ci/scripts/warning-gate.py --update <build.log> --build-dir <dir>

Exit codes:
  0  at or below the baseline for this compiler, or an unknown compiler
  1  a known category grew, or a category appeared that the baseline has not seen
  2  refusing to judge: no baseline, no build dir, or a log that is not a
     measurement
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE = REPO_ROOT / "ci" / "warning-baseline.json"

TAG = re.compile(r"\[-W([A-Za-z0-9=+-]+)\]")
COMPILE_LINE = re.compile(r"Building (?:CXX|C|OBJCXX|OBJC) object ")


def fatal(msg):
    print(f"warning-gate: FATAL: {msg}", file=sys.stderr)
    sys.exit(2)



def compiler_facts(build):
    """CMAKE_CXX_COMPILER_ID is NOT a cache variable in modern CMake; it lives in
    CMakeFiles/<cmake version>/CMakeCXXCompiler.cmake. Reading only CMakeCache.txt
    finds nothing and a gate that then guesses is worse than one that stops."""
    cid = ver = None
    for f in sorted(build.glob("CMakeFiles/*/CMakeCXXCompiler.cmake")):
        text = f.read_text(errors="replace")
        m = re.search(r'set\(CMAKE_CXX_COMPILER_ID "([^"]*)"\)', text)
        v = re.search(r'set\(CMAKE_CXX_COMPILER_VERSION "([^"]*)"\)', text)
        if m:
            cid, ver = m.group(1), (v.group(1) if v else "0")
            break
    return cid, ver


def compiler_key(build: Path):
    if not (build / "CMakeCache.txt").is_file():
        fatal(f"no CMakeCache.txt in {build} — that is not a configured build tree")
    cid, ver = compiler_facts(build)
    if not cid:
        fatal(f"{build} names no CMAKE_CXX_COMPILER_ID — that is not a configured build tree")
    return f"{cid}-{(ver or '0').split('.')[0]}"


def scan(log: Path):
    if not log.is_file():
        fatal(f"no build log at {log}")
    text = log.read_text(errors="replace")
    counts = Counter()
    for line in text.splitlines():
        for m in TAG.finditer(line):
            counts["-W" + m.group(1)] += 1
    units = len(COMPILE_LINE.findall(text))
    return counts, units


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("log")
    args = ap.parse_args()
    if args.check == args.update:
        print("warning-gate: FATAL: usage: warning-gate.py --check|--update <build.log> "
              "--build-dir <dir>", file=sys.stderr)
        return 2

    build = Path(args.build_dir)
    if not build.is_dir():
        fatal(f"build dir '{build}' not found")
    key = compiler_key(build)
    counts, units = scan(Path(args.log))

    base = json.loads(BASELINE.read_text()) if BASELINE.is_file() else None
    expected_units = (base or {}).get("min_compile_units", 0)

    if units < expected_units:
        fatal(f"log has {units} compile lines, baseline expects >= {expected_units} — "
              "this is an incremental build, not a measurement")

    if args.update:
        # A vacuum log must not be recorded either: it would pin
        # min_compile_units to the vacuum and disarm the rule for good.
        if units == 0:
            fatal("log has 0 compile lines — refusing to record a measurement "
                  "that did not happen")
        out = base or {}
        out["min_compile_units"] = units if base is None else min(
            units, base.get("min_compile_units", units)) or units
        out["min_compile_units"] = units
        out[key] = dict(sorted(counts.items()))
        BASELINE.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
        total = sum(counts.values())
        print(f"ci/warning-baseline.json: {key}, {total} warning(s) in "
              f"{len(counts)} categor(ies) over {units} compile units")
        return 0

    if base is None:
        fatal("no baseline at ci/warning-baseline.json")

    if key not in base:
        print(f"warning-gate: {key} is not in the baseline; reporting, not failing.")
        print(f"Neither diagnostic set is authoritative over the other. To adopt "
              f"this one, add:")
        print(json.dumps({key: dict(sorted(counts.items()))}, indent=2))
        return 0

    want = base[key]
    rc = 0
    for cat in sorted(set(counts) | set(want)):
        got, allowed = counts.get(cat, 0), want.get(cat, 0)
        if cat not in want and got:
            print(f"{cat}: {got} — a category the baseline has not seen")
            rc = 1
        elif got > allowed:
            print(f"{cat}: {got}, baseline {allowed}")
            rc = 1
        elif got < allowed:
            print(f"{cat}: {got}, baseline {allowed} — stale baseline, run --update")
    if rc == 0:
        print(f"{sum(counts.values())} warning(s) over {units} compile units, "
              f"at or below the {key} baseline")
    return rc


if __name__ == "__main__":
    sys.exit(main())
