#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
"""Self-test for canonical-types.py.

A registry gate whose regex quietly matches nothing is the most comfortable
false green there is: it prints "0 violations" over a tree full of them.  So
this builds a throwaway workspace of real git checkouts and feeds the gate one
deliberately broken case of every kind it claims to catch -- plus the clean
case, plus the case where the gate cannot measure at all and must say so
instead of passing.

Exit 0 when every case behaves; 1 otherwise, naming the cases that did not.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "canonical-types.py")

# The gate resolves checkouts by name, so a throwaway workspace has to carry
# real repository names or nothing is scanned and every case reads as clean.
ONE = "LibreMiddleware"
TWO = "LibreAgent"
CANON = f"{ONE}/include/widget.h"

CLEAN_HEADER = """// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
namespace demo {
struct Widget
{
    int a = 0;
};
inline int helperName(int x) { return x + 1; }
} // namespace demo
"""

MIRROR_MARKED = f"""// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
// MIRROR-OF: {CANON} -- the Qt-free module may not link the core
namespace demo {{
struct Widget
{{
    int a = 0;
}};
}} // namespace demo
"""

MIRROR_UNMARKED = """// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
namespace demo {
struct Widget
{
    int a = 0;
};
} // namespace demo
"""

SECOND_DECLARATION = """// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
namespace other {
struct Widget
{
    int b = 0;
};
} // namespace other
"""

HEADER_WITHOUT_WIDGET = """// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
namespace demo {
struct SomethingElse
{
    int a = 0;
};
inline int helperName(int x) { return x + 1; }
} // namespace demo
"""

CALL_SITE = """#pragma once
namespace two {
inline int use() { return helperName(1); }
} // namespace two
"""

SECOND_DEFINITION = """#pragma once
namespace two {
inline int helperName(int x) { return x + 2; }
} // namespace two
"""


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
    for rel, body in files.items():
        path = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
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


def run_gate(ws, reg, repo=None):
    cmd = [sys.executable, GATE, "--workspace", ws, "--registry", reg]
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

    root = tempfile.mkdtemp(prefix="canonical-types-selftest-")
    try:
        plain = registry(root, "plain", [
            ("Widget", CANON, "-"),
            ("func:helperName", CANON, "-"),
        ])
        mirrored = registry(root, "mirrored", [
            ("Widget", CANON, f"{TWO}/src/mirror.h"),
            ("func:helperName", CANON, "-"),
        ])

        ws = workspace(root, "clean", {"include/widget.h": CLEAN_HEADER},
                       {"src/unrelated.h": "#pragma once\nnamespace two { int q = 0; }\n"})
        rc, out = run_gate(ws, plain)
        check("clean tree passes", rc == 0, f"rc={rc}\n{out}")
        check("clean tree really scanned", "2 registered names" in out, out)

        ws = workspace(root, "second-decl", {"include/widget.h": CLEAN_HEADER},
                       {"src/copy.h": SECOND_DECLARATION})
        rc, out = run_gate(ws, plain)
        check("off-registry declaration fails", rc == 1, f"rc={rc}\n{out}")
        check("off-registry names the site",
              "OFF-REGISTRY" in out and f"{TWO}/src/copy.h" in out, out)
        rc, out = run_gate(ws, plain, repo=TWO)
        check("single-repo subset flags its own violation", rc == 1, f"rc={rc}\n{out}")
        check("single-repo subset invents no MISSING", "MISSING" not in out, out)

        ws = workspace(root, "missing", {"include/widget.h": HEADER_WITHOUT_WIDGET},
                       {"src/unrelated.h": "#pragma once\n"})
        rc, out = run_gate(ws, plain)
        check("canonical site that lost its type fails", rc == 1, f"rc={rc}\n{out}")
        check("that failure is named MISSING", "MISSING" in out and "Widget" in out, out)

        ws = workspace(root, "unmarked", {"include/widget.h": CLEAN_HEADER},
                       {"src/mirror.h": MIRROR_UNMARKED})
        rc, out = run_gate(ws, mirrored)
        check("registered mirror without its marker fails", rc == 1, f"rc={rc}\n{out}")
        check("unmarked mirror is named", "MIRROR-UNMARKED" in out, out)

        ws = workspace(root, "marked", {"include/widget.h": CLEAN_HEADER},
                       {"src/mirror.h": MIRROR_MARKED})
        rc, out = run_gate(ws, mirrored)
        check("registered mirror with its marker passes", rc == 0, f"rc={rc}\n{out}")

        ws = workspace(root, "mirror-gone", {"include/widget.h": CLEAN_HEADER},
                       {"src/unrelated.h": "#pragma once\n"})
        rc, out = run_gate(ws, mirrored)
        check("registered mirror that vanished fails", rc == 1, f"rc={rc}\n{out}")
        check("vanished mirror is named", "MIRROR-GONE" in out, out)

        ws = workspace(root, "call-site", {"include/widget.h": CLEAN_HEADER},
                       {"src/caller.h": CALL_SITE})
        rc, out = run_gate(ws, plain)
        check("a call site is not a declaration", rc == 0, f"rc={rc}\n{out}")

        ws = workspace(root, "second-def", {"include/widget.h": CLEAN_HEADER},
                       {"src/second.h": SECOND_DEFINITION})
        rc, out = run_gate(ws, plain)
        check("a second function definition fails", rc == 1, f"rc={rc}\n{out}")
        check("second definition names the function", "helperName" in out, out)

        # A workspace whose named checkout is not a git repository: `git
        # ls-files` exits 128 with empty output, and empty output through a
        # careless gate reads as "nothing declared anywhere, all clean".
        # A prototype in a header and the body in the source file are one
        # implementation the language makes you write twice, not two owners.
        proto = ("#pragma once\nnamespace demo {\nint helperName(int x);\n"
                 "} // namespace demo\n")
        ws = workspace(root, "prototype", {"include/widget.h": CLEAN_HEADER},
                       {"src/proto.h": proto})
        rc, out = run_gate(ws, plain)
        check("a prototype is not a second owner", rc == 0, f"rc={rc}\n{out}")

        # A mirror the project does not author -- another platform's client, a
        # vendored third party -- is recorded without demanding a comment in
        # someone else's file.
        unmarked = registry(root, "unmarked-ok", [
            ("Widget", CANON, f"~{TWO}/src/mirror.h"),
        ])
        ws = workspace(root, "tilde", {"include/widget.h": CLEAN_HEADER},
                       {"src/mirror.h": MIRROR_UNMARKED})
        rc, out = run_gate(ws, unmarked)
        check("a ~mirror needs no marker", rc == 0, f"rc={rc}\n{out}")
        ws = workspace(root, "tilde-gone", {"include/widget.h": CLEAN_HEADER},
                       {"src/other.h": "#pragma once\n"})
        rc, out = run_gate(ws, unmarked)
        check("a ~mirror must still exist", rc == 1, f"rc={rc}\n{out}")

        broken = os.path.join(root, "not-a-repo")
        os.makedirs(os.path.join(broken, ONE, "include"))
        with open(os.path.join(broken, ONE, "include", "widget.h"), "w") as fh:
            fh.write(CLEAN_HEADER)
        rc, out = run_gate(broken, plain)
        check("a checkout that is not a git repository exits 2", rc == 2, f"rc={rc}\n{out}")
        check("and says why", "FATAL" in out, out)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    if failures:
        print(f"\n{len(failures)} selftest case(s) failed: " + ", ".join(failures))
        return 1
    print("\nall canonical-types selftest cases behave")
    return 0


if __name__ == "__main__":
    sys.exit(main())
