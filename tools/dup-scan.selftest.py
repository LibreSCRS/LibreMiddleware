#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
"""Self-test for dup-scan.py.

The scan's whole value is that it reports a twin nobody meant to keep and stays
quiet about the ones somebody did.  Both halves can fail silently: a
normalisation that never collides reports nothing over a tree of copies, and an
allowlist that swallows a group keeps swallowing it after the group stops being
identical.  Every case below is one of those.

Exit 0 when every case behaves; 1 otherwise, naming the cases that did not.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCAN = os.path.join(HERE, "dup-scan.py")

ONE = "LibreMiddleware"
TWO = "LibreAgent"


def body(seed: str, lines: int = 40) -> str:
    out = ["// SPDX-License-Identifier: LGPL-2.1-or-later", "#pragma once"]
    for i in range(lines):
        out.append(f"constexpr int {seed}_{i} = {i};")
    return "\n".join(out) + "\n"


IDENTICAL = body("shared")
IDENTICAL_WITH_DIFFERENT_COMMENTS = (
    "// a comment the normaliser must drop\n" + IDENTICAL.replace("#pragma once",
                                                                  "#pragma once\n\n"))
DIVERGED = IDENTICAL.replace("shared_7 = 7", "shared_7 = 99")
SHORT = body("tiny", 5)


def git(repo, *args):
    subprocess.run(["git", "-C", repo] + list(args), check=True,
                   capture_output=True, text=True)


def make_repo(root, name, files):
    repo = os.path.join(root, name)
    os.makedirs(repo)
    subprocess.run(["git", "-C", repo, "init", "-q"], check=True,
                   capture_output=True, text=True)
    git(repo, "config", "user.email", "selftest@example.invalid")
    git(repo, "config", "user.name", "selftest")
    for rel, content in files.items():
        path = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "selftest fixture")


def workspace(root, tag, one_files, two_files):
    path = os.path.join(root, tag)
    os.makedirs(path)
    make_repo(path, ONE, one_files)
    make_repo(path, TWO, two_files)
    return path


def registry(root, tag, rows):
    path = os.path.join(root, f"registry-{tag}.tsv")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# name\tcanonical\tmirrors\n")
        for row in rows:
            fh.write("\t".join(row) + "\n")
    return path


def run_scan(ws, reg, repo=None):
    cmd = [sys.executable, SCAN, "--workspace", ws, "--registry", reg]
    if repo:
        cmd += ["--repo", repo]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main() -> int:
    failures = []

    def check(case, ok, detail=""):
        if ok:
            print(f"ok    {case}")
        else:
            print(f"FAIL  {case}  {detail}")
            failures.append(case)

    root = tempfile.mkdtemp(prefix="dup-scan-selftest-")
    try:
        empty = registry(root, "empty", [])
        sanctioned = registry(root, "sanctioned", [
            ("dup:vendored-pair", f"{ONE}/include/vendored.h", f"{TWO}/include/vendored.h"),
        ])

        ws = workspace(root, "distinct", {"include/a.h": body("alpha")},
                       {"include/b.h": body("beta")})
        rc, out = run_scan(ws, empty)
        check("distinct files pass", rc == 0, f"rc={rc}\n{out}")

        ws = workspace(root, "twins", {"include/vendored.h": IDENTICAL},
                       {"include/vendored.h": IDENTICAL})
        rc, out = run_scan(ws, empty)
        check("an unregistered twin fails", rc == 1, f"rc={rc}\n{out}")
        check("the twin is named", "vendored.h" in out, out)

        rc, out = run_scan(ws, sanctioned)
        check("a registered twin passes", rc == 0, f"rc={rc}\n{out}")
        check("a registered twin is still reported", "ALLOWED" in out, out)

        ws = workspace(root, "diverged", {"include/vendored.h": IDENTICAL},
                       {"include/vendored.h": DIVERGED})
        rc, out = run_scan(ws, sanctioned)
        check("a registered twin that diverged fails", rc == 1, f"rc={rc}\n{out}")
        check("divergence is named MIRROR-BROKEN", "MIRROR-BROKEN" in out, out)

        ws = workspace(root, "gone", {"include/vendored.h": IDENTICAL},
                       {"include/other.h": body("other")})
        rc, out = run_scan(ws, sanctioned)
        check("a registered member that vanished fails", rc == 1, f"rc={rc}\n{out}")
        check("the vanished member is named", "MIRROR-GONE" in out, out)

        # Comments and blank lines are not substance: two files that differ
        # only there are the same file for this scan's purpose.
        ws = workspace(root, "comments", {"include/vendored.h": IDENTICAL},
                       {"include/vendored.h": IDENTICAL_WITH_DIFFERENT_COMMENTS})
        rc, out = run_scan(ws, empty)
        check("comment-only difference still counts as a twin", rc == 1, f"rc={rc}\n{out}")

        ws = workspace(root, "short", {"include/tiny.h": SHORT},
                       {"include/tiny.h": SHORT})
        rc, out = run_scan(ws, empty)
        check("a file below the floor is ignored", rc == 0, f"rc={rc}\n{out}")

        # A pattern row allows two vendored trees to coincide without pinning
        # WHICH files coincide -- pinning that set would be pinning an accident.
        patterned = registry(root, "patterned", [
            ("dup:vendored-trees", f"{ONE}/thirdparty/linux/*", f"{ONE}/thirdparty/macosx/*"),
        ])
        ws = workspace(root, "patterned",
                       {"thirdparty/linux/a.h": IDENTICAL,
                        "thirdparty/macosx/a.h": IDENTICAL,
                        "thirdparty/linux/b.h": body("b-linux"),
                        "thirdparty/macosx/b.h": body("b-macosx")},
                       {"include/other.h": body("other")})
        rc, out = run_scan(ws, patterned)
        check("a pattern row allows a vendored pair", rc == 0, f"rc={rc}\n{out}")
        check("the pattern row still reports it", "ALLOWED" in out, out)
        check("a pattern row claims nothing about files that differ",
              "MIRROR-BROKEN" not in out, out)

        # ... and it does not launder a twin outside the trees it names.
        ws = workspace(root, "patterned-outside",
                       {"thirdparty/linux/a.h": IDENTICAL, "include/elsewhere.h": IDENTICAL},
                       {"include/other.h": body("other")})
        rc, out = run_scan(ws, patterned)
        check("a pattern row does not cover paths outside it", rc == 1, f"rc={rc}\n{out}")

        broken = os.path.join(root, "not-a-repo")
        os.makedirs(os.path.join(broken, ONE, "include"))
        with open(os.path.join(broken, ONE, "include", "vendored.h"), "w") as fh:
            fh.write(IDENTICAL)
        rc, out = run_scan(broken, empty)
        check("a checkout that is not a git repository exits 2", rc == 2, f"rc={rc}\n{out}")
        check("and says why", "FATAL" in out, out)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    if failures:
        print(f"\n{len(failures)} selftest case(s) failed: " + ", ".join(failures))
        return 1
    print("\nall dup-scan selftest cases behave")
    return 0


if __name__ == "__main__":
    sys.exit(main())
