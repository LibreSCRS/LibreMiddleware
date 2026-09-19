#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Prove the coverage gate can fail, on every one of its four rules, without
building anything.

gcovr is stubbed on PATH exactly the way ctest is stubbed for the manifest
gate's selftest, so each case is a prepared summary rather than a compilation.

Cases:
   1  identical                                        -> 0
   2  total down 0.2 pp (inside the allowance)         -> 0
   3  total down 0.4 pp                                -> 1
   4  one file down 1.5 pp                             -> 1, and it is named
   5  one file down 0.5 pp                             -> 0
   6  new file, 51 lines, below the repository floor   -> 1
   7  new file, 49 lines, below the floor              -> 0
   8  a file deleted, the rest unchanged               -> 0 by rule 2
   9  the discovered test set moved                    -> 2
  10  a different compiler                             -> 2
  11  no baseline                                      -> 2
  12  covered lines fell while the PERCENTAGE ROSE     -> 1  (rule 4)
  13  the same input with a recorded exception         -> 0, reason printed
  14  --update with the test token unset               -> 2, and it is named
  15  --check --expect-key against another key         -> 1, not 2
  16  no environment contract at all                   -> 2

Cases 14 to 16 are the half that was missing. The committed baseline of one
repository here was recorded without the software token provisioned: sixteen
files on the signing path read 0.0% because the tests covering them skipped, and
the one rule that matters for a release which deletes code cannot fire on a file
at zero. Measured against the gate as it was: it had no reference to the token
anywhere, --expect-key did not exist, and a baseline from another environment
came back as exit 2 -- the same answer as "gcovr broke", which the barrier and CI
read as "I did not measure".
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(os.environ.get("GATE", Path(__file__).resolve().parent / "coverage-gate.py"))
WORK = Path(tempfile.mkdtemp(prefix="covgate-selftest.", dir="/var/tmp"))
passed = failed = 0
cases = red = 0


def summary(total_pct, covered, total_lines, files, branch=30.0):
    return {
        "line_percent": total_pct, "line_covered": covered, "line_total": total_lines,
        "branch_percent": branch, "branch_covered": 1, "branch_total": 10,
        "files": [
            {"filename": n, "line_percent": p, "line_total": t,
             "line_covered": int(round(p * t / 100.0)),
             "branch_percent": 0.0, "branch_covered": 0, "branch_total": 0}
            for n, (p, t) in files.items()
        ],
    }


def make_repo(name, summary_obj, compiler=("GNU", "16.2.1"), manifest="A.One\nA.Two\n"):
    root = WORK / name
    (root / "ci" / "scripts").mkdir(parents=True)
    (root / "build").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    shutil.copy(GATE, root / "ci" / "scripts" / "coverage-gate.py")
    (root / "ci" / "test-manifest.linux.txt").write_text(manifest)
    # The contract every --update is held to. Two variables, so a case can drop
    # one of them and still be testing the contract rather than its absence.
    (root / "ci" / "coverage-env.txt").write_text(
        "require SELFTEST_TOKEN_CONF\n"
        "require SELFTEST_TOKEN_LIB\n"
        "runner selftest\n")
    (root / "build" / "CMakeCache.txt").write_text("CMAKE_BUILD_TYPE:STRING=Debug\n")
    # The compiler identity is NOT in CMakeCache.txt; CMake writes it here.
    cmf = root / "build" / "CMakeFiles" / "4.4.2"
    cmf.mkdir(parents=True, exist_ok=True)
    (cmf / "CMakeCXXCompiler.cmake").write_text(
        f'set(CMAKE_CXX_COMPILER_ID "{compiler[0]}")\n'
        f'set(CMAKE_CXX_COMPILER_VERSION "{compiler[1]}")\n')
    (root / "prepared.json").write_text(json.dumps(summary_obj))
    stub = root / "bin" / "gcovr"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "--version" ]; then echo "gcovr 8.6"; exit 0; fi\n'
        'prev=""\n'
        'for a in "$@"; do\n'
        '  if [ "$prev" = "--json-summary" ]; then mkdir -p "$(dirname "$a")"; '
        'cp "$SELFTEST_PREPARED" "$a"; fi\n'
        '  prev="$a"\n'
        "done\n"
        "exit 0\n")
    stub.chmod(0o755)
    return root


def run(root, *args, drop_env=(), path=None):
    env = dict(os.environ)
    for name in drop_env:
        env.pop(name, None)
    # `path` replaces PATH outright, which is the only way to prove what the gate
    # does when a tool is MISSING: prepending a fixture directory can add a tool,
    # never take one away.
    env["PATH"] = path if path is not None else f"{root}/bin:" + env["PATH"]
    env["SELFTEST_PREPARED"] = str(root / "prepared.json")
    for name in ("SELFTEST_TOKEN_CONF", "SELFTEST_TOKEN_LIB"):
        if name not in drop_env:
            env[name] = str(root / name.lower())
        else:
            env.pop(name, None)
    r = subprocess.run([sys.executable, str(root / "ci" / "scripts" / "coverage-gate.py"),
                        *args, str(root / "build")],
                       capture_output=True, text=True, env=env, cwd=root)
    return r.returncode, r.stdout + r.stderr


def seed(root):
    return run(root, "--update")


def check(label, expected, actual, extra=True, out=""):
    global passed, failed, cases, red
    cases += 1
    if expected == actual and extra:
        print(f"case {label}: OK   — exit {actual}")
        passed += 1
        # red-proved counts what was OBSERVED, not what was declared: counted
        # before the comparison, this number stays 11 while two cases fail, and
        # a trailer that cannot move is not a measurement.
        if expected != 0:
            red += 1
    else:
        print(f"case {label}: FAIL — expected exit {expected}, got {actual}\n    {out.strip()[:300]}")
        failed += 1


BASE_FILES = {"lib/a.cpp": (80.0, 100), "lib/b.cpp": (60.0, 200)}
BASE = summary(66.7, 200, 300, BASE_FILES)

try:
    # 1
    r = make_repo("c1", BASE); seed(r)
    rc, out = run(r, "--check"); check(1, 0, rc, out=out)

    # 2 / 3 — rule 1 in isolation. Covered lines must NOT fall in either, or
    # rule 4 fires and the case would pass for the wrong reason: with a fixed
    # denominator rule 4 is strictly tighter than rule 1's allowance, so rule 1
    # only ever bites when code is ADDED and the ratio dilutes.
    r = make_repo("c2", BASE); seed(r)
    (r / "prepared.json").write_text(json.dumps(summary(66.5, 200, 301, BASE_FILES)))
    rc, out = run(r, "--check"); check(2, 0, rc, out=out)
    r = make_repo("c3", BASE); seed(r)
    (r / "prepared.json").write_text(json.dumps(summary(66.3, 200, 302, BASE_FILES)))
    rc, out = run(r, "--check"); check(3, 1, rc, "total line coverage fell" in out, out)

    # 4 / 5
    r = make_repo("c4", BASE); seed(r)
    f = dict(BASE_FILES); f["lib/a.cpp"] = (78.5, 100)
    (r / "prepared.json").write_text(json.dumps(summary(66.7, 200, 300, f)))
    rc, out = run(r, "--check"); check(4, 1, rc, "lib/a.cpp" in out, out)
    r = make_repo("c5", BASE); seed(r)
    f = dict(BASE_FILES); f["lib/a.cpp"] = (79.5, 100)
    (r / "prepared.json").write_text(json.dumps(summary(66.7, 200, 300, f)))
    rc, out = run(r, "--check"); check(5, 0, rc, out=out)

    # 6 / 7
    r = make_repo("c6", BASE); seed(r)
    f = dict(BASE_FILES); f["lib/new.cpp"] = (10.0, 51)
    (r / "prepared.json").write_text(json.dumps(summary(66.7, 205, 351, f)))
    rc, out = run(r, "--check"); check(6, 1, rc, "lib/new.cpp" in out, out)
    r = make_repo("c7", BASE); seed(r)
    f = dict(BASE_FILES); f["lib/new.cpp"] = (10.0, 49)
    (r / "prepared.json").write_text(json.dumps(summary(66.7, 205, 349, f)))
    rc, out = run(r, "--check"); check(7, 0, rc, out=out)

    # 8: a deleted file, everything else unchanged
    r = make_repo("c8", BASE); seed(r)
    f = {"lib/a.cpp": (80.0, 100)}
    (r / "prepared.json").write_text(json.dumps(summary(80.0, 200, 250, f)))
    rc, out = run(r, "--check"); check(8, 0, rc, out=out)

    # 9 / 10: the configuration behind the number moved
    r = make_repo("c9", BASE); seed(r)
    (r / "ci" / "test-manifest.linux.txt").write_text("A.One\nA.Two\nA.Three\n")
    rc, out = run(r, "--check"); check(9, 2, rc, "discovered test set" in out, out)
    r = make_repo("c10", BASE); seed(r)
    (r / "build" / "CMakeFiles" / "4.4.2" / "CMakeCXXCompiler.cmake").write_text(
        'set(CMAKE_CXX_COMPILER_ID "GNU")\nset(CMAKE_CXX_COMPILER_VERSION "13.2.0")\n')
    rc, out = run(r, "--check"); check(10, 2, rc, "compiler changed" in out, out)

    # 11
    r = make_repo("c11", BASE)
    rc, out = run(r, "--check"); check(11, 2, rc, "no baseline" in out, out)

    # 12: the shape all three percentage rules miss — an untested file deleted,
    # so every percentage RISES while real covered lines go away.
    r = make_repo("c12", BASE); seed(r)
    f = {"lib/a.cpp": (80.0, 100)}
    (r / "prepared.json").write_text(json.dumps(summary(80.0, 80, 100, f)))
    rc, out = run(r, "--check")
    check(12, 1, rc, "covered lines fell from 200 to 80" in out, out)

    # 13: the same input, with the exception written into the baseline
    r = make_repo("c13", BASE); seed(r)
    b = json.loads((r / "ci" / "coverage-baseline.json").read_text())
    b["rules"]["absolute_exception"] = {
        "reason": "the untested vendored shim was removed", "allowed_drop": 200}
    (r / "ci" / "coverage-baseline.json").write_text(json.dumps(b, indent=2))
    (r / "prepared.json").write_text(json.dumps(summary(80.0, 80, 100, f)))
    rc, out = run(r, "--check")
    check(13, 0, rc, "vendored shim" in out, out)

    # 14: recording from an environment that cannot run what it counts
    r = make_repo("c14", BASE)
    rc, out = run(r, "--update", drop_env=("SELFTEST_TOKEN_CONF",))
    check(14, 2, rc, "SELFTEST_TOKEN_CONF" in out and "refusing to record" in out, out)

    # 15: a baseline from another environment is a mismatch, not an inability
    r = make_repo("c15", BASE); seed(r)
    rc, out = run(r, "--check", "--expect-key", "GNU-13")
    check(15, 1, rc, "not this environment's baseline" in out, out)
    rc, out = run(r, "--check", "--expect-key", "GNU-16")
    check("15b", 0, rc, out=out)

    # 16: no contract at all. A missing contract is the situation the contract
    # exists for, with nothing to say so.
    r = make_repo("c16", BASE)
    (r / "ci" / "coverage-env.txt").unlink()
    rc, out = run(r, "--update")
    check(16, 2, rc, "coverage-env.txt" in out, out)

    # 17: gcovr absent. gcov is on PATH and gcovr is not, which is how this
    # gate fails when a pip install into a container did not land. The whole
    # point of the 1/2 split is that CI can tell "coverage fell" from "I could
    # not measure", so an absent tool has to be 2 -- and before the guard it was
    # a TypeError, which exits 1 and reads as a regression.
    r = make_repo("c17", BASE); seed(r)
    only = r / "onlygcov"
    only.mkdir()
    (only / "gcov").write_text("#!/bin/sh\nexit 0\n")
    (only / "gcov").chmod(0o755)
    rc, out = run(r, "--check", path=str(only))
    check(17, 2, rc, "gcovr is not on PATH" in out, out)

    print(f"selftest: {passed} passed, {failed} failed")
    print(f"selftest: {cases} cases, {red} red-proved")
finally:
    shutil.rmtree(WORK, ignore_errors=True)

sys.exit(0 if failed == 0 else 1)
