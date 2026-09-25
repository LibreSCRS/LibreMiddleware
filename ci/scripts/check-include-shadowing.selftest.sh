#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-include-shadowing.selftest.sh -- prove the include-shadowing check can
# fail, and fail for the right reason. Each case builds a throwaway
# compile_commands.json and asserts the exit code AND the message.
#
# The restored-defect case copies this repository's own vendored miniz
# directory and puts back the bare `VERSION` pin file it carried before the
# rename: that exact file broke every macOS build, and the check must be red
# over it while the directory as it is now stays green.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CHECK="$HERE/check-include-shadowing.py"
T="$(mktemp -d "${TMPDIR:-/var/tmp}/cis-selftest.XXXXXX")"
trap 'rm -rf "$T"' EXIT
cases=0
red=0
fails=0

# say <assertion-rc> <label> <gate-rc-the-case-expects>
say() {
    cases=$((cases + 1))
    [ "${3:-0}" != 0 ] && red=$((red + 1))
    if [ "$1" = 0 ]; then printf 'PASS  %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; fails=1; fi
}

# db <case> <json-entry>... : write <case>/b/compile_commands.json
db() {
    local d="$T/$1"; shift
    mkdir -p "$d/b"
    { printf '['; local first=1 e
      for e in "$@"; do [ "$first" = 1 ] || printf ','; first=0; printf '%s' "$e"; done
      printf ']\n'; } > "$d/b/compile_commands.json"
}
entry_args() {  # entry_args <dir> <arg>...
    local dir="$1"; shift
    local a out=""
    for a in "$@"; do out="$out,\"$a\""; done
    printf '{"directory":"%s","file":"x.cpp","arguments":["c++"%s,"-c","x.cpp"]}' "$dir" "$out"
}
run() { python3 "$CHECK" "$T/$1/b" >"$T/out" 2>&1; echo $?; }

# 1 clean include dir
mkdir -p "$T/c1/inc"; : > "$T/c1/inc/foo.h"
db c1 "$(entry_args "$T/c1" -I"$T/c1/inc")"
rc=$(run c1); [ "$rc" = 0 ] && grep -q '^OK: 1 include directories scanned' "$T/out"
say $? "1 an include dir with only headers that have extensions is green" 0

# 2 RESTORED DEFECT: the vendored miniz directory with its old bare VERSION back
mkdir -p "$T/c2/miniz"; cp -p "$REPO"/thirdparty/miniz/* "$T/c2/miniz/"
printf '3.1.2\n' > "$T/c2/miniz/VERSION"
db c2 "$(entry_args "$T/c2" -I"$T/c2/miniz")"
rc=$(run c2); [ "$rc" = 1 ] && grep -q 'miniz/VERSION: shadows <version>' "$T/out"
say $? "2 PERTURBATION: miniz with its old VERSION pin restored is red, and names it" 1

# 3 the same directory as it is in this tree now is green
mkdir -p "$T/c3/miniz"; cp -p "$REPO"/thirdparty/miniz/* "$T/c3/miniz/"
db c3 "$(entry_args "$T/c3" -I"$T/c3/miniz")"
rc=$(run c3); [ "$rc" = 0 ] && grep -q '^OK:' "$T/out"
say $? "3 the vendored miniz directory as tracked is green" 0

# 4 separate-argument -isystem, mixed case
mkdir -p "$T/c4/inc"; : > "$T/c4/inc/String"
db c4 "$(entry_args "$T/c4" -isystem "$T/c4/inc")"
rc=$(run c4); [ "$rc" = 1 ] && grep -q 'String: shadows <string>' "$T/out" && grep -q '(-isystem' "$T/out"
say $? "4 PERTURBATION: -isystem <dir> holding 'String' is red" 1

# 5 joined -iquote
mkdir -p "$T/c5/inc"; : > "$T/c5/inc/MEMORY"
db c5 "$(entry_args "$T/c5" -iquote"$T/c5/inc")"
rc=$(run c5); [ "$rc" = 1 ] && grep -q 'MEMORY: shadows <memory>' "$T/out"
say $? "5 PERTURBATION: -iquote<dir> holding 'MEMORY' is red" 1

# 6 an extension, or a subdirectory, cannot collide
mkdir -p "$T/c6/inc/sub"; : > "$T/c6/inc/VERSION.txt"; : > "$T/c6/inc/version.h"; : > "$T/c6/inc/sub/version"
db c6 "$(entry_args "$T/c6" -I"$T/c6/inc")"
rc=$(run c6); [ "$rc" = 0 ] && grep -q '^OK:' "$T/out"
say $? "6 VERSION.txt, version.h and sub/version are not flagged" 0

# 7 the `command` string form, with a relative -I resolved against `directory`
mkdir -p "$T/c7/src/inc"; : > "$T/c7/src/inc/Version"
db c7 "{\"directory\":\"$T/c7/src\",\"file\":\"x.cpp\",\"command\":\"c++ -I inc -c x.cpp\"}"
rc=$(run c7); [ "$rc" = 1 ] && grep -q "$T/c7/src/inc/Version: shadows <version>" "$T/out"
say $? "7 PERTURBATION: a relative -I in a command string is resolved and red" 1

# 8 no compile_commands.json is cannot-measure, never a pass
mkdir -p "$T/c8/b"
rc=$(run c8); [ "$rc" = 2 ] && grep -q 'no .*compile_commands.json' "$T/out"
say $? "8 no compile_commands.json is 2, not 0" 2

# 9 an empty database is cannot-measure
db c9
rc=$(run c9); [ "$rc" = 2 ] && grep -q 'has no entries' "$T/out"
say $? "9 an empty compile_commands.json is 2, not 0" 2

# 10 entries with no include directory at all are cannot-measure
db c10 "$(entry_args "$T/c10" -O2)"
rc=$(run c10); [ "$rc" = 2 ] && grep -q 'names no include directory' "$T/out"
say $? "10 a database naming no include directory is 2, not 0" 2

[ "$fails" -eq 0 ] || echo "selftest: FAILED"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit "$fails"
