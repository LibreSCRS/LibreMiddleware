#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
"""Whole-file duplication scan across the side-by-side checkouts.

Normalises every tracked source file -- comments stripped, blank lines dropped
-- hashes the body, and reports the bodies that appear at more than one path.
Files under ``--min-lines`` normalised lines are ignored: a header guard and a
licence block are not duplication.

Some twins are deliberate, and the registry is where that is said.  A row whose
name carries the ``dup:`` prefix in ``canonical-types.tsv`` names a group of
paths that are ALLOWED to be identical -- a vendored third-party header set a
Qt-free module may not reach across for, two vendored builds of the same
library for two platforms.  Such a group is still printed, because the point is
not to hide it: if its members ever stop being identical the gate says so, and
the reason the group is allowed stops being true silently.

Exit codes: 0 clean (only sanctioned groups, all still intact), 1 an
unsanctioned duplicate or a sanctioned group that broke, 2 could not measure.
"""
from __future__ import annotations

import argparse
import collections
import fnmatch
import hashlib
import os
import re
import subprocess
import sys

REPOS = [
    "LibreMiddleware",
    "LibreAgent",
    "LibreLinux",
    "LibreCelik",
    "LibreKDE",
    "LibreDarwin",
    "LibreMac",
]

EXT = {".h", ".hpp", ".hh", ".c", ".cc", ".cpp", ".cxx", ".swift", ".mm", ".m"}


class Fatal(Exception):
    """The scan could not measure.  Exit 2, never 0."""


def default_workspace() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def sanctioned_groups(registry: str):
    """The ``dup:`` rows of the registry, as sets of workspace-relative paths."""
    groups = []
    if not os.path.isfile(registry):
        raise Fatal(f"registry not found: {registry}")
    with open(registry, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            cols = [c.strip() for c in raw.rstrip("\n").split("\t") if c.strip() != ""]
            if len(cols) < 2 or not cols[0].startswith("dup:"):
                continue
            members = [cols[1]]
            if len(cols) >= 3 and cols[2] != "-":
                members += [m.strip() for m in cols[2].split(",") if m.strip()]
            patterned = any("*" in m for m in members)
            groups.append({"id": cols[0][4:], "members": set(members), "lineno": lineno,
                           "seen": False, "patterned": patterned})
    return groups


def group_is_sanctioned(paths, row) -> bool:
    """A duplicate group answers to a registry row.

    An exact row names its members path for path, and every one of them must be
    in the group -- that is what lets the scan say MIRROR-BROKEN when such a
    pair stops being identical.

    A row with a glob in it is the other kind: two vendored builds of the same
    third-party library for two platforms, where dozens of files happen to be
    identical and a few legitimately are not.  Pinning that set exactly would
    be pinning an accident, so a pattern row only says these paths are ALLOWED
    to coincide, and claims nothing about which of them do.
    """
    if not row["patterned"]:
        return paths == row["members"]
    if not all(any(fnmatch.fnmatch(p, m) for m in row["members"]) for p in paths):
        return False
    return all(any(fnmatch.fnmatch(p, m) for p in paths) for m in row["members"])


def normalise(path: str):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    out = []
    for line in text.splitlines():
        line = re.sub(r"//.*$", "", line).strip()
        if line:
            out.append(line)
    return out


def collect(workspace: str, repos, min_lines: int):
    by_hash = collections.defaultdict(list)
    for repo in repos:
        repo_path = os.path.join(workspace, repo)
        if not os.path.isdir(repo_path):
            continue
        proc = subprocess.run(["git", "-C", repo_path, "ls-files"],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise Fatal(f"git -C {repo_path} ls-files exited {proc.returncode}: "
                        f"{proc.stderr.strip()}")
        names = [n for n in proc.stdout.split("\n") if n]
        if not names:
            raise Fatal(f"git -C {repo_path} ls-files listed no files at all")
        for rel in names:
            if os.path.splitext(rel)[1] not in EXT:
                continue
            body = normalise(os.path.join(repo_path, rel))
            if body is None or len(body) < min_lines:
                continue
            digest = hashlib.sha256("\n".join(body).encode()).hexdigest()
            by_hash[digest].append((f"{repo}/{rel}", len(body)))
    # No global "nothing was hashed" fatal here: every repository already had
    # its `git ls-files` return code and its emptiness checked above, and a
    # tree whose files all sit under the line floor is a legitimate tree.
    return by_hash


def main() -> int:
    ap = argparse.ArgumentParser(description="cross-checkout duplicate-body scan")
    ap.add_argument("--workspace", default=None)
    ap.add_argument("--repo", default=None)
    ap.add_argument("--registry", default=None)
    ap.add_argument("--min-lines", type=int, default=30)
    args = ap.parse_args()

    workspace = os.path.abspath(args.workspace or default_workspace())
    registry = args.registry or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             "canonical-types.tsv")
    try:
        groups = sanctioned_groups(registry)
        repos = [args.repo] if args.repo else REPOS
        if args.repo and not os.path.isdir(os.path.join(workspace, args.repo)):
            raise Fatal(f"no such checkout: {os.path.join(workspace, args.repo)}")
        by_hash = collect(workspace, repos, args.min_lines)
    except Fatal as exc:
        print(f"FATAL  {exc}", file=sys.stderr)
        print("EXIT=2")
        return 2

    dups = {h: v for h, v in by_hash.items() if len(v) > 1}
    unsanctioned = 0
    removable = 0
    allowed_shown = 0

    for _, members in sorted(dups.items(), key=lambda kv: -kv[1][0][1]):
        paths = {p for p, _ in members}
        size = members[0][1]
        match = next((g for g in groups if group_is_sanctioned(paths, g)), None)
        if match is not None:
            match["seen"] = True
            allowed_shown += 1
            print(f"ALLOWED  {size:5d} lines x{len(members)}  [{match['id']}]  "
                  + "  |  ".join(p for p, _ in members))
            continue
        unsanctioned += 1
        removable += size * (len(members) - 1)
        print(f"{size:5d} lines x{len(members)}  " + "  |  ".join(p for p, _ in members))

    broken = 0
    scanned = {args.repo} if args.repo else set(repos)
    for group in groups:
        if group["seen"] or group["patterned"]:
            continue
        if not all(m.split("/", 1)[0] in scanned for m in group["members"]):
            continue
        missing = [m for m in group["members"] if not os.path.isfile(os.path.join(workspace, m))]
        if missing:
            print(f"MIRROR-GONE  [{group['id']}] registered member(s) absent: "
                  + ", ".join(sorted(missing)))
        else:
            print(f"MIRROR-BROKEN  [{group['id']}] registered as identical, "
                  "but the bodies no longer match: " + ", ".join(sorted(group["members"])))
        broken += 1

    scope = f"--repo {args.repo}" if args.repo else "all checkouts"
    print(f"\n{unsanctioned} unsanctioned duplicate groups, {removable} removable "
          f"normalised lines; {allowed_shown} sanctioned groups intact, "
          f"{broken} broken ({scope})")
    if unsanctioned == 0 and broken == 0:
        print("only allowlisted third-party groups remain")
    print(f"EXIT={1 if (unsanctioned or broken) else 0}")
    return 1 if (unsanctioned or broken) else 0


if __name__ == "__main__":
    sys.exit(main())
