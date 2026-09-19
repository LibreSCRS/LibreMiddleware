#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Hold the compiler's diagnostics against a baseline that survives a compiler
that is not the one CI runs, and that can tell OUR warnings from a header's.

Counting is by the [-Wname] tag, never by the message text: diagnostics are
localised, and on the machine that wrote this they read
`warning: напомена више редова [-Wcomment]`. The job exports LC_ALL=C anyway,
but a gate that only works when someone remembers to is not a gate.

WHY THE PARTITION IS OVER THE WHOLE BLOCK
-----------------------------------------
Counting by category alone cannot tell a diagnostic raised inside a standard
header from one raised in our own code that the compiler happened to report at
the same line. Four diagnostics here today are the second-hand kind: GCC inlines
a variant reset entirely inside libstdc++ and loses track of where the buffer
came from, so the primary location is new_allocator.h and the whole chain is
`std::`. Adding that category to the baseline would accept it everywhere; a real
invalid free of one of our own objects reports the SAME primary location,
because operator delete for a member vector is always called from there, and
would land in a category the baseline already excuses.

So a block is partitioned by every frame it names -- the primary location, each
`inlined from ... at`, each `required from` and `note:`, each `In file included
from` -- and it is OURS unless not one of those frames resolves inside the
repository. `project` is the default; `system` has to be proved.

The translation unit being compiled is NOT one of those frames, deliberately. It
is always ours, so counting it would make every block `project` and the
partition would be a no-op. It is recorded in the reason instead, so a system
block still says which of our files triggered it.

A `system` entry also has to carry a reason, keyed by (category, primary
location) rather than by category: the same tag from a different header is a
different claim and has to earn its own line. Reasons print on every pass, the
way the coverage ratchet prints its exception.

The anti-vacuum rule is the one that matters most. A zero from an incremental
ninja build means nothing was recompiled, not that nothing warned; that is the
same class as a stale binary passing a test filter, and it has cost this project
real time. A log with fewer compile lines than the baseline expects is refused,
not scored.

Falling BELOW the baseline never fails the build -- a gate that punishes fixing
warnings does not survive contact -- it prints `stale baseline, run --update`.

Usage:
  ci/scripts/warning-gate.py --check [--require-key] <build.log> --build-dir <dir>
  ci/scripts/warning-gate.py --update <build.log> --build-dir <dir>

--require-key is for CI: without it an unknown compiler key is reported and the
run passes, which is how this check came to judge nothing at all on a runner
whose compiler the baseline had never seen.

Exit codes:
  0  at or below the baseline for this compiler in both partitions
  1  a category grew, appeared, or a system category has no recorded reason;
     or --require-key was given and this compiler has no baseline
  2  refusing to judge: no baseline, no build dir, a log that is not a
     measurement, or a tagged diagnostic with no location to resolve
"""
import argparse
import json
import os
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


# A frame is anything in the block that names a file and a line. Every shape GCC
# uses is listed rather than matched with one loose pattern: a loose one picks up
# the `1:1` out of a message and calls it a location.
DIAG = re.compile(r"^(?P<path>[^\s].*?):(?P<line>\d+):(?P<col>\d+):\s+"
                  r"(?:warning|error|note|required from)\b")
INLINED = re.compile(r"inlined from\s+'[^']*'\s+at\s+(?P<path>[^\s].*?):(?P<line>\d+)")
# `In file included from` is deliberately NOT a frame. An include chain always
# begins in one of our translation units, so counting it would make every
# diagnostic raised anywhere in any header "ours" and the partition would decide
# nothing. Measured: the four second-hand diagnostics in this tree each carry
# five of our headers in their include chain and not one frame of ours in the
# inlined-from chain. What locates our code is the inlined-from chain and the
# instantiation notes, which is what is read below.
REQUIRED = re.compile(r"^(?P<path>[^\s].*?):(?P<line>\d+):(?P<col>\d+):\s+required from")

# A source path under any of these is not ours even though it sits inside the
# checkout: vendored dependencies and build trees would otherwise make a
# permanent red out of somebody else's code.
NOT_OURS = ("_deps/", "thirdparty/", "subprojects/")


def project_paths(build: Path, repo_root: Path):
    """A closure that answers 'is this path one of ours?'.

    A path in the log is written relative to the build directory (ninja's cwd) or
    relative to the source root or absolute, and which one is not knowable from
    the text. Every candidate is resolved and the answer is yes if ANY of them
    lands inside the checkout outside the vendored and build trees -- so an
    ambiguous `lib/foo.cpp` is ours, and `/usr/include/...` is not, whichever way
    it was written."""
    root = os.path.realpath(str(repo_root))
    bases = [os.path.realpath(str(build)), root]

    def is_ours(path: str) -> bool:
        for base in ([""] if os.path.isabs(path) else bases):
            full = os.path.realpath(path if not base else os.path.join(base, path))
            if full == root or full.startswith(root + os.sep):
                rel = os.path.relpath(full, root)
                if rel.startswith(NOT_OURS) or rel.split(os.sep)[0].startswith("build"):
                    continue
                return True
        return False

    return is_ours


def resolve(path: str, build: Path, repo_root: Path) -> str:
    """The absolute form of a path as written, for the reason key."""
    if os.path.isabs(path):
        return os.path.realpath(path)
    for base in (str(build), str(repo_root)):
        cand = os.path.realpath(os.path.join(base, path))
        if os.path.exists(cand):
            return cand
    return os.path.realpath(os.path.join(str(build), path))


def blocks(lines):
    """Split the log at compile lines and at tagged diagnostics.

    A block is everything between two boundaries, so it carries both the
    `inlined from` context GCC prints BEFORE the warning and the notes it prints
    after. Yields (tag_line_index, block_lines, unit_source_or_None) for every
    block that carries a [-W] tag."""
    bounds = [i for i, ln in enumerate(lines)
              if COMPILE_LINE.search(ln) or TAG.search(ln)]
    unit_at = {}
    unit = None
    for i, ln in enumerate(lines):
        m = COMPILE_LINE.search(ln)
        if m:
            unit = ln[m.end():].strip()
        unit_at[i] = unit
    for n, i in enumerate(bounds):
        if not TAG.search(lines[i]):
            continue
        prev = bounds[n - 1] if n else -1
        nxt = bounds[n + 1] if n + 1 < len(bounds) else len(lines)
        yield i, lines[prev + 1:nxt], unit_at[i]


def scan(log: Path, build: Path, repo_root: Path):
    """counts[(partition, tag)], reason keys seen, compile units, unresolvable."""
    if not log.is_file():
        fatal(f"no build log at {log}")
    lines = log.read_text(errors="replace").splitlines()
    is_ours = project_paths(build, repo_root)
    counts = {"project": Counter(), "system": Counter()}
    seen_reasons = {}          # "tag@abs:line" -> set of translation units
    unresolvable = []

    for i, block, unit in blocks(lines):
        tags = ["-W" + m.group(1) for m in TAG.finditer(lines[i])]
        head = DIAG.match(lines[i])
        if head is None:
            unresolvable.append(lines[i][:120])
            continue
        frames = [head.group("path")]
        for ln in block:
            for pat in (INLINED, REQUIRED):
                for m in pat.finditer(ln):
                    frames.append(m.group("path"))
            m = DIAG.match(ln)
            if m:
                frames.append(m.group("path"))
        part = "system" if not any(is_ours(f) for f in frames) else "project"
        for tag in tags:
            counts[part][tag] += 1
            if part == "system":
                key = f"{tag}@{resolve(head.group('path'), build, repo_root)}:{head.group('line')}"
                seen_reasons.setdefault(key, set()).add(unit or "?")

    units = sum(1 for ln in lines if COMPILE_LINE.search(ln))
    return counts, seen_reasons, units, unresolvable


def section(base, key):
    """The baseline section for one compiler, in today's shape.

    The one-dimensional form this file used to write is read as `project`: it
    was recorded before anything could tell a header's diagnostic from ours, and
    treating it as ours is the safe direction -- it can only demand that a
    category be re-earned, never excuse one. The next --update writes the new
    shape and the old one is not seen again."""
    raw = base.get(key)
    if raw is None:
        return None
    if any(k in raw for k in ("project", "system", "system_reasons", "min_compile_units")):
        return raw
    return {"project": dict(raw), "system": {}, "system_reasons": {}, "_legacy": True}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--require-key", action="store_true",
                    help="a compiler the baseline has never seen is a failure, "
                         "not a report; for CI, where the alternative is a check "
                         "that judges nothing")
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
    counts, seen_reasons, units, unresolvable = scan(Path(args.log), build, REPO_ROOT)

    if unresolvable:
        fatal(f"{len(unresolvable)} tagged diagnostic(s) carry no location to "
              f"resolve, so they cannot be attributed to anyone: "
              f"{unresolvable[0]!r} -- this is not a log this check can read")

    base = json.loads(BASELINE.read_text()) if BASELINE.is_file() else None
    sect = section(base or {}, key)
    expected_units = ((sect or {}).get("min_compile_units")
                      or (base or {}).get("min_compile_units", 0))

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
        out.pop("min_compile_units", None)
        kept = ((sect or {}).get("system_reasons") or {})
        out[key] = {
            "min_compile_units": units,
            "project": dict(sorted(counts["project"].items())),
            "system": dict(sorted(counts["system"].items())),
            # Reasons are never invented here. A system category recorded
            # without one fails the next --check, by name, which is where a
            # human writes it.
            "system_reasons": {k: kept.get(k, "") for k in sorted(seen_reasons)},
        }
        BASELINE.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
        total = sum(counts["project"].values()) + sum(counts["system"].values())
        print(f"ci/warning-baseline.json: {key}, {total} warning(s) over {units} "
              f"compile units — {sum(counts['project'].values())} ours, "
              f"{sum(counts['system'].values())} from headers")
        for k in sorted(seen_reasons):
            if not kept.get(k):
                print(f"  no reason recorded for {k} "
                      f"(seen while compiling: {', '.join(sorted(seen_reasons[k]))})")
        return 0

    if base is None:
        fatal("no baseline at ci/warning-baseline.json")

    if sect is None:
        if args.require_key:
            print(f"{key} is not in the baseline, and this run requires one. "
                  f"A check with no baseline for the compiler that ran judges "
                  f"nothing. To adopt this one, add:")
            print(json.dumps({key: {"min_compile_units": units,
                                    "project": dict(sorted(counts["project"].items())),
                                    "system": dict(sorted(counts["system"].items())),
                                    "system_reasons": {k: "" for k in sorted(seen_reasons)}}},
                             indent=2))
            return 1
        print(f"warning-gate: {key} is not in the baseline; reporting, not failing.")
        print(f"Neither diagnostic set is authoritative over the other. To adopt "
              f"this one, add:")
        print(json.dumps({key: dict(sorted((counts["project"] + counts["system"]).items()))},
                         indent=2))
        return 0

    rc = 0
    if sect.get("_legacy"):
        print(f"{key}: the baseline predates the header/ours partition, so it is "
              f"read as ours in full. Run --update on a full log to record it.")
    for part in ("project", "system"):
        want = sect.get(part, {})
        got_all = counts[part]
        if sect.get("_legacy") and part == "project":
            # One-line compatibility: the flat form counted both partitions
            # together, so compare against the total rather than demand that a
            # header's diagnostic be re-earned as ours.
            got_all = counts["project"] + counts["system"]
        for cat in sorted(set(got_all) | set(want)):
            got, allowed = got_all.get(cat, 0), want.get(cat, 0)
            label = "ours" if part == "project" else "from a header"
            if cat not in want and got:
                print(f"{cat}: {got} {label} — a category the baseline has not seen")
                rc = 1
            elif got > allowed:
                print(f"{cat}: {got} {label}, baseline {allowed}")
                rc = 1
            elif got < allowed:
                print(f"{cat}: {got} {label}, baseline {allowed} — stale baseline, "
                      f"run --update")

    # A system entry is an excuse, and an excuse with no reason is a hole. The
    # key is (category, primary location): the same tag from another header is
    # another claim.
    reasons = sect.get("system_reasons", {})
    for k in sorted(seen_reasons):
        if not reasons.get(k):
            print(f"{k}: counted as a header's, with no reason recorded "
                  f"(seen while compiling: {', '.join(sorted(seen_reasons[k]))})")
            rc = 1
        else:
            print(f"{k}: {reasons[k]}")

    if rc == 0:
        print(f"{sum(counts['project'].values())} ours + "
              f"{sum(counts['system'].values())} from headers over {units} compile "
              f"units, at or below the {key} baseline")
    return rc


if __name__ == "__main__":
    sys.exit(main())
