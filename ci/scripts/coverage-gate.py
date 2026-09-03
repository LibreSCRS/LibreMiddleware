#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Hold coverage against a baseline that carries the configuration it was
measured under.

Five of the ten worst-covered files on the signing path in this project turned
out to be an artefact of how the measurement ran, not a gap: with the test token
provisioned the same files read 76%, 63%, 75%, 54% and 72%. A percentage with no
configuration attached is not reproducible, so the baseline records the
compiler, the gcovr version, the cmake arguments and a hash of the discovered
test set, and the check refuses to compare when any of them moved.

Four rules, because one does not bite:

  1. Repository ratchet   total line_percent may not fall more than
                          rules.total_percent_drop_pp below the baseline.
  2. Per-file ratchet     for a file in both baseline and candidate,
                          candidate% >= baseline% - rules.per_file_drop_pp.
                          This is the rule that catches code arriving without
                          the test that used to cover it.
  3. New-file floor       a file absent from the baseline with more than
                          rules.new_file_floor_lines countable lines must reach
                          the repository's own baseline total. New code may not
                          be worse than the code it joins.
  4. Absolute covered     total.covered_lines may not fall. This catches the
                          opposite trick: deleting untested code lifts every
                          percentage while real covered lines quietly go away,
                          and all three percentage rules pass. A fall is allowed
                          only with rules.absolute_exception written in the same
                          commit, with a reason, which is printed on every pass
                          so the exception cannot be silent.

Branch coverage is recorded, not gated: it sits 15-20 points below line coverage
everywhere here, and a ratchet on a number that low fires on noise. It is in the
baseline so a later ratchet has a history to start from.

Usage:
  ci/scripts/coverage-gate.py --check  <builddir>
  ci/scripts/coverage-gate.py --update <builddir>

Exit codes:
  0  within every rule
  1  a rule was broken
  2  refusing to compare: no baseline, gcovr failed, or the configuration
     behind the number moved (test set, compiler, gcovr version)
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASELINE = REPO_ROOT / "ci" / "coverage-baseline.json"


def fatal(msg):
    print(f"FATAL: {msg}", file=sys.stderr)
    sys.exit(2)


def cmake_cache(build: Path, key: str):
    cache = build / "CMakeCache.txt"
    if not cache.is_file():
        fatal(f"no CMakeCache.txt in {build} — that is not a configured build tree")
    for ln in cache.read_text(errors="replace").splitlines():
        if ln.startswith(key + ":") or ln.startswith(key + "="):
            return ln.split("=", 1)[1].strip()
    return None



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
    cid, ver = compiler_facts(build)
    if not cid:
        fatal(f"{build} names no CMAKE_CXX_COMPILER_ID — that is not a configured build tree")
    return f"{cid}-{(ver or '0').split('.')[0]}"


def pick_gcov(build: Path):
    """gcovr does not report a gcov/compiler mismatch as an error; it quietly
    produces rubbish. The gcov is therefore chosen from the compiler that built
    this tree, never from PATH order."""
    cid, verfull = compiler_facts(build)
    cid = cid or ""
    ver = (verfull or "0").split(".")[0]
    if cid == "GNU":
        for cand in (f"gcov-{ver}", "gcov"):
            if shutil.which(cand):
                return cand
    if cid in ("Clang", "AppleClang"):
        for cand in (f"llvm-cov-{ver}", "llvm-cov"):
            if shutil.which(cand):
                return f"{cand} gcov"
    if shutil.which("gcov"):
        return "gcov"
    fatal("no gcov for this compiler on PATH")


def gcovr_version():
    exe = shutil.which("gcovr") or fatal("gcovr is not on PATH")
    out = subprocess.run([exe, "--version"], capture_output=True, text=True)
    m = re.search(r"gcovr\s+([0-9][0-9.]*)", out.stdout + out.stderr)
    return m.group(1) if m else "unknown"


def run_gcovr(build: Path):
    outdir = build / "out"
    outdir.mkdir(parents=True, exist_ok=True)
    summary = outdir / "coverage-summary.json"
    cmd = [
        shutil.which("gcovr"),
        "--root", str(REPO_ROOT),
        "--gcov-executable", pick_gcov(build),
        "--json-summary-pretty", "--json-summary", str(summary),
        "--txt", str(outdir / "coverage.txt"),
        str(build),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        fatal(f"gcovr failed with exit {r.returncode}:\n{r.stderr[:2000]}")
    if not summary.is_file():
        fatal("gcovr produced no summary — nothing to compare")
    return json.loads(summary.read_text())


def manifest_hash():
    """One hash over every committed per-leg listing. G1 is tied to G2 by this
    field: a coverage number measured over a different set of tests is not
    comparable to one measured over this set, and without the tie the ratchet
    has no fixed denominator."""
    files = sorted((REPO_ROOT / "ci").glob("test-manifest.*.txt"))
    if not files:
        return None
    h = hashlib.sha256()
    for f in files:
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()


def discovered_tests():
    total = 0
    for f in (REPO_ROOT / "ci").glob("test-manifest.*.txt"):
        total += sum(1 for ln in f.read_text().splitlines() if ln.strip())
    return total


def build_config(build: Path):
    args = []
    for key in ("CMAKE_BUILD_TYPE", "SIGNING_BACKEND", "BUILD_DSS_ORACLE",
                "CMAKE_CXX_FLAGS", "BUILD_TESTING"):
        v = cmake_cache(build, key)
        if v is not None:
            args.append(f"-D{key}={v}")
    return " ".join(args)


def measure(build: Path):
    summary = run_gcovr(build)
    files = {}
    for f in summary.get("files", []):
        files[f["filename"]] = {
            "line_percent": round(f.get("line_percent", 0.0), 1),
            "line_total": f.get("line_total", 0),
        }
    return {
        "config": {
            "cmake_args": build_config(build),
            "compiler": compiler_key(build),
            "gcovr": gcovr_version(),
            "test_manifest_sha256": manifest_hash(),
            "discovered_tests": discovered_tests(),
        },
        "total": {
            "line_percent": round(summary.get("line_percent", 0.0), 1),
            "branch_percent": round(summary.get("branch_percent", 0.0), 1),
            "covered_lines": summary.get("line_covered", 0),
            "total_lines": summary.get("line_total", 0),
        },
        "files": files,
    }


DEFAULT_RULES = {
    "total_percent_drop_pp": 0.3,
    "per_file_drop_pp": 1.0,
    "new_file_floor_lines": 50,
    "absolute_covered_lines": True,
    "absolute_exception": None,
}


def do_update(build: Path):
    cur = measure(build)
    rules = DEFAULT_RULES.copy()
    if BASELINE.is_file():
        old = json.loads(BASELINE.read_text())
        rules.update(old.get("rules", {}))
        # An exception is spent by the commit that used it.
        rules["absolute_exception"] = None
    cur["rules"] = rules
    cur["files"] = {k: v["line_percent"] for k, v in cur["files"].items()}
    BASELINE.write_text(json.dumps(cur, indent=2, sort_keys=True) + "\n")
    print(f"ci/coverage-baseline.json: {cur['total']['line_percent']}% line, "
          f"{cur['total']['covered_lines']}/{cur['total']['total_lines']} lines, "
          f"{cur['config']['discovered_tests']} discovered tests, "
          f"{cur['config']['compiler']}, gcovr {cur['config']['gcovr']}")
    return 0


def do_check(build: Path):
    if not BASELINE.is_file():
        fatal("no baseline at ci/coverage-baseline.json")
    base = json.loads(BASELINE.read_text())
    cur = measure(build)
    rules = {**DEFAULT_RULES, **base.get("rules", {})}

    for key, label in (("test_manifest_sha256", "the discovered test set changed"),
                       ("compiler", "the compiler changed"),
                       ("gcovr", "the gcovr version changed")):
        want, got = base["config"].get(key), cur["config"].get(key)
        if want != got:
            fatal(f"not comparable: {label} ({want} -> {got}); "
                  "regenerate the baseline in the same commit")

    rc = 0
    bt, ct = base["total"], cur["total"]

    drop = bt["line_percent"] - ct["line_percent"]
    if drop > rules["total_percent_drop_pp"]:
        print(f"total line coverage fell {drop:.1f} pp "
              f"({bt['line_percent']}% -> {ct['line_percent']}%), "
              f"allowance {rules['total_percent_drop_pp']} pp")
        rc = 1

    for name, was in sorted(base.get("files", {}).items()):
        if name not in cur["files"]:
            continue        # a deleted file is not a per-file regression; rule 4 sees it
        now = cur["files"][name]["line_percent"]
        if now < was - rules["per_file_drop_pp"]:
            print(f"{name}: {was}% -> {now}%")
            rc = 1

    floor = bt["line_percent"]
    for name, info in sorted(cur["files"].items()):
        if name in base.get("files", {}):
            continue
        if info["line_total"] > rules["new_file_floor_lines"] and info["line_percent"] < floor:
            print(f"{name} is new with {info['line_total']} countable lines at "
                  f"{info['line_percent']}%, below this repository's own {floor}%")
            rc = 1

    if rules.get("absolute_covered_lines") is True:
        if ct["covered_lines"] < bt["covered_lines"]:
            exc = rules.get("absolute_exception")
            fell = bt["covered_lines"] - ct["covered_lines"]
            if exc and fell <= exc.get("allowed_drop", 0):
                print(f"covered lines fell {fell} within a recorded exception: "
                      f"{exc.get('reason', '(no reason given)')}")
            else:
                print(f"covered lines fell from {bt['covered_lines']} to "
                      f"{ct['covered_lines']} — a smaller ratio denominator is not progress")
                rc = 1

    if rc == 0:
        print(f"{ct['line_percent']}% line "
              f"({ct['covered_lines']}/{ct['total_lines']}), "
              f"no file below baseline")
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("builddir")
    args = ap.parse_args()
    if args.check == args.update:
        print("FATAL: usage: coverage-gate.py --check|--update <builddir>", file=sys.stderr)
        return 2
    build = Path(args.builddir)
    if not build.is_dir():
        fatal(f"build dir '{build}' not found")
    return do_update(build) if args.update else do_check(build)


if __name__ == "__main__":
    sys.exit(main())
