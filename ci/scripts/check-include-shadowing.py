#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""No directory on any include path holds a file that a standard header include
can resolve to on a case-insensitive file system.

`#include <version>` is searched for in every -I, -isystem and -iquote directory
before the standard library's own. On a case-insensitive file system -- the
default on macOS -- a file named `VERSION` in one of those directories IS
`version`, so the standard library's own `#include <version>` opens it and the
build fails inside the standard headers with `version:1:1: error: expected
unqualified-id`. A case-sensitive Linux build never sees it, so the only
builds that could catch it are the macOS ones, and they catch it after the push.
The same shape has broken the macOS build more than once: from a repository
root on the include path, and from a vendored dependency's pin file.

So this reads the include path the way the compiler is handed it -- every
directory named by -I, -isystem, -iquote or -idirafter in compile_commands.json,
joined or separate, relative ones resolved against the entry's own directory --
and fails on any file directly inside one of them whose name, folded to lower
case, is the name of a standard C or C++ header that has no extension. Names
with an extension cannot collide (`version.txt` is not `version`), and a file
in a SUBdirectory is not reachable by a bare `<name>`, so neither is flagged.

The list below is the standard's, not this tree's: a rule that listed only the
names seen so far would pass the next one.

Usage:
  ci/scripts/check-include-shadowing.py <build-dir>

The build tree must be configured with CMAKE_EXPORT_COMPILE_COMMANDS=ON.

Exit codes:
  0  no include directory holds such a file
  1  at least one does; each is printed with the flag that exposes it
  2  cannot measure: no compile_commands.json, no entries, or no include
     directory in any of them
"""
import json
import shlex
import sys
from pathlib import Path

# C++ standard library headers (C++23, plus the C++26 names already shipped by
# libstdc++ or libc++) and the <cname> C compatibility headers. Every one of
# them is a bare name, which is the whole hazard.
STANDARD_HEADERS = frozenset("""
algorithm any array atomic barrier bit bitset charconv chrono codecvt compare
complex concepts condition_variable contracts coroutine debugging deque
exception execution expected filesystem flat_map flat_set format forward_list
fstream functional future generator hazard_pointer hive initializer_list
inplace_vector iomanip ios iosfwd iostream istream iterator latch limits linalg
list locale map mdspan memory memory_resource mutex new numbers numeric
optional ostream print queue random ranges ratio rcu regex scoped_allocator
semaphore set shared_mutex simd source_location span spanstream sstream stack
stacktrace stdexcept stdfloat stop_token streambuf string string_view
strstream syncstream system_error text_encoding thread tuple type_traits
typeindex typeinfo unordered_map unordered_set utility valarray variant vector
version
cassert ccomplex cctype cerrno cfenv cfloat cinttypes ciso646 climits clocale
cmath csetjmp csignal cstdalign cstdarg cstdbool cstddef cstdint cstdio
cstdlib cstring ctgmath ctime cuchar cwchar cwctype
""".split())

INCLUDE_FLAGS = ("-isystem", "-iquote", "-idirafter", "-I")


def fatal(msg):
    print(f"FATAL: {msg} -- cannot measure", file=sys.stderr)
    sys.exit(2)


def include_dirs(entry):
    """Yield (flag, absolute directory) for every include directory of one
    compile_commands.json entry."""
    args = entry.get("arguments")
    if args is None:
        args = shlex.split(entry.get("command", ""))
    base = Path(entry.get("directory", "."))
    i = 0
    while i < len(args):
        a = args[i]
        for flag in INCLUDE_FLAGS:
            if a == flag and i + 1 < len(args):
                i += 1
                yield flag, base / args[i]
                break
            if a.startswith(flag) and len(a) > len(flag) and a != flag:
                yield flag, base / a[len(flag):]
                break
        i += 1


def main():
    if len(sys.argv) != 2:
        print("usage: check-include-shadowing.py <build-dir>", file=sys.stderr)
        return 2
    db = Path(sys.argv[1]) / "compile_commands.json"
    if not db.is_file():
        fatal(f"no {db} (configure with -DCMAKE_EXPORT_COMPILE_COMMANDS=ON)")
    try:
        entries = json.loads(db.read_text())
    except (OSError, ValueError) as e:
        fatal(f"{db} does not parse: {e}")
    if not isinstance(entries, list) or not entries:
        fatal(f"{db} has no entries")

    # directory -> (flag, first translation unit that uses it)
    dirs = {}
    for e in entries:
        for flag, d in include_dirs(e):
            d = Path(str(d)).resolve()
            dirs.setdefault(d, (flag, e.get("file", "?")))
    if not dirs:
        fatal(f"{db} names no include directory at all")

    findings = []
    scanned = missing = 0
    for d in sorted(dirs):
        if not d.is_dir():
            missing += 1
            continue
        scanned += 1
        for f in sorted(d.iterdir()):
            if f.is_file() and f.name.lower() in STANDARD_HEADERS:
                flag, tu = dirs[d]
                findings.append((f, f.name.lower(), flag, tu))

    for f, std, flag, tu in findings:
        print(f"{f}: shadows <{std}> on a case-insensitive file system "
              f"({flag}{f.parent}, e.g. while compiling {tu})")
    if findings:
        print(f"FAIL: {len(findings)} file(s) on the include path can stand in for "
              f"a standard header. Rename them, or take their directory off the "
              f"include path.")
        return 1
    print(f"OK: {scanned} include directories scanned, none holds a file named like a "
          f"standard header ({missing} named but absent)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
