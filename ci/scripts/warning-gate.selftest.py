#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Prove the warning gate can fail, and prove it refuses a log that is not a
measurement.

Cases:
   1  exactly the baseline                                  -> 0
   2  one more of a known category                          -> 1
   3  a category the baseline has not seen                  -> 1
   4  one fewer                                             -> 0, "stale baseline"
   5  a compiler the baseline does not have                 -> 0, prints a section
   6  a log with three compile lines                        -> 2 (incremental, not a measurement)
   7  no baseline                                           -> 2
   8  a localised message still counts by its [-W] tag      -> 0
   9  --update over a vacuum log is refused                 -> 2, baseline untouched
"""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "warning-gate.py"
WORK = Path(tempfile.mkdtemp(prefix="warngate-selftest.", dir="/var/tmp"))
passed = failed = 0


def make_log(path, units, warnings):
    lines = []
    for i in range(units):
        lines.append(f"[{i+1}/{units}] Building CXX object lib/CMakeFiles/x.dir/f{i}.cpp.o")
    lines.extend(warnings)
    path.write_text("\n".join(lines) + "\n")


def make_repo(name, compiler=("GNU", "16.2.1")):
    root = WORK / name
    (root / "ci" / "scripts").mkdir(parents=True)
    cmf = root / "build" / "CMakeFiles" / "4.4.2"
    cmf.mkdir(parents=True)
    (root / "build" / "CMakeCache.txt").write_text("CMAKE_BUILD_TYPE:STRING=Release\n")
    (cmf / "CMakeCXXCompiler.cmake").write_text(
        f'set(CMAKE_CXX_COMPILER_ID "{compiler[0]}")\n'
        f'set(CMAKE_CXX_COMPILER_VERSION "{compiler[1]}")\n')
    shutil.copy(GATE, root / "ci" / "scripts" / "warning-gate.py")
    return root


def run(root, *args):
    r = subprocess.run([sys.executable, str(root / "ci" / "scripts" / "warning-gate.py"),
                        *args, "--build-dir", str(root / "build")],
                       capture_output=True, text=True, cwd=root)
    return r.returncode, r.stdout + r.stderr


def check(label, expected, actual, extra=True, out=""):
    global passed, failed
    if expected == actual and extra:
        print(f"case {label}: OK   — exit {actual}")
        passed += 1
    else:
        print(f"case {label}: FAIL — expected exit {expected}, got {actual}\n    {out.strip()[:250]}")
        failed += 1


W = ["f.h:1:1: warning: multi-line comment [-Wcomment]"] * 30
try:
    # 1
    r = make_repo("c1"); make_log(r / "build.log", 620, W)
    run(r, "--update", str(r / "build.log"))
    rc, out = run(r, "--check", str(r / "build.log")); check(1, 0, rc, out=out)

    # 2
    r = make_repo("c2"); make_log(r / "build.log", 620, W)
    run(r, "--update", str(r / "build.log"))
    make_log(r / "more.log", 620, W + [W[0]])
    rc, out = run(r, "--check", str(r / "more.log"))
    check(2, 1, rc, "-Wcomment: 31, baseline 30" in out, out)

    # 3
    r = make_repo("c3"); make_log(r / "build.log", 620, W)
    run(r, "--update", str(r / "build.log"))
    make_log(r / "new.log", 620, W + ["x.cpp:2:2: warning: dangling else [-Wdangling-else]"])
    rc, out = run(r, "--check", str(r / "new.log"))
    check(3, 1, rc, "has not seen" in out, out)

    # 4
    r = make_repo("c4"); make_log(r / "build.log", 620, W)
    run(r, "--update", str(r / "build.log"))
    make_log(r / "fewer.log", 620, W[:-1])
    rc, out = run(r, "--check", str(r / "fewer.log"))
    check(4, 0, rc, "stale baseline" in out, out)

    # 5: another compiler is reported, not judged
    r = make_repo("c5"); make_log(r / "build.log", 620, W)
    run(r, "--update", str(r / "build.log"))
    (r / "build" / "CMakeFiles" / "4.4.2" / "CMakeCXXCompiler.cmake").write_text(
        'set(CMAKE_CXX_COMPILER_ID "GNU")\nset(CMAKE_CXX_COMPILER_VERSION "13.2.0")\n')
    rc, out = run(r, "--check", str(r / "build.log"))
    check(5, 0, rc, "GNU-13" in out and "not in the baseline" in out, out)

    # 6: an incremental build is not a measurement
    r = make_repo("c6"); make_log(r / "build.log", 620, W)
    run(r, "--update", str(r / "build.log"))
    make_log(r / "inc.log", 3, [])
    rc, out = run(r, "--check", str(r / "inc.log"))
    check(6, 2, rc, "incremental build, not a measurement" in out, out)

    # 7
    r = make_repo("c7"); make_log(r / "build.log", 620, W)
    rc, out = run(r, "--check", str(r / "build.log"))
    check(7, 2, rc, "no baseline" in out, out)

    # 8: the diagnostic text is localised; the tag is not
    r = make_repo("c8")
    make_log(r / "build.log", 620,
             ["f.h:1:1: warning: напомена више редова [-Wcomment]"] * 30)
    run(r, "--update", str(r / "build.log"))
    rc, out = run(r, "--check", str(r / "build.log"))
    check(8, 0, rc, "30 warning(s)" in out, out)

    # 9: --update over a vacuum log is refused and changes nothing
    r = make_repo("c9"); make_log(r / "build.log", 620, W)
    run(r, "--update", str(r / "build.log"))
    before = (r / "ci" / "warning-baseline.json").read_bytes()
    make_log(r / "vacuum.log", 0, [])
    rc, out = run(r, "--update", str(r / "vacuum.log"))
    after = (r / "ci" / "warning-baseline.json").read_bytes()
    check(9, 2, rc, before == after, out)

    print(f"selftest: {passed} passed, {failed} failed")
finally:
    shutil.rmtree(WORK, ignore_errors=True)

sys.exit(0 if failed == 0 else 1)
