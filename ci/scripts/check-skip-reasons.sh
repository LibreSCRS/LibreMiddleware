#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-skip-reasons.sh — a skipped test must say why it was skipped.
#
# A test that skips without a reason is indistinguishable from a test that
# passed, both in a CI summary and to whoever reads the log six months later.
# This repository carried fourteen of them, each one filling the #else branch
# of a compile-time switch.
#
# The check reads only tracked sources (git ls-files), strips comments, and
# requires every GTEST_SKIP() to stream something. A reason computed at run time
# (`GTEST_SKIP() << env.skipReason`) is a better reason than a literal, so the
# rule is not "must be a literal": it is that once every blank string literal is
# removed, something must remain. QSKIP() and XCTSkip are held to the same rule
# on their first argument.
#
# It cannot stop a determined lie — GTEST_SKIP() << "x" satisfies it — and does
# not pretend to. It stops the accident.
#
# Usage:
#   ci/scripts/check-skip-reasons.sh
#
# Exit codes:
#   0  every skip in a tracked source carries a reason
#   1  at least one does not; each is printed as file:line
#   2  refusing to judge (not in a git work tree)
set -uo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || { echo "FATAL: not a git work tree — this check reads git ls-files, nothing else" >&2; exit 2; }

SCRATCH="$(mktemp -d /var/tmp/check-skip-reasons.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

git ls-files -z -- '*.c' '*.cc' '*.cpp' '*.cxx' '*.h' '*.hh' '*.hpp' '*.m' '*.mm' '*.swift' \
    > "$SCRATCH/files.z"

# One awk per file: strip comments first (a doc comment that merely mentions
# GTEST_SKIP() is not a skip), then read each skip's argument list, following
# it across line breaks until the terminating semicolon.
#
# The regex deliberately avoids POSIX character classes: mawk, which is the
# default awk on the CI runner, does not support them, and a pattern that
# silently matches nothing there would make this gate vacuous.
scan() {
    awk -v FN="$1" '
    {
        line = $0; out = ""; i = 1; n = length(line)
        while (i <= n) {
            two = substr(line, i, 2)
            if (inblock) { if (two == "*/") { inblock = 0; i += 2 } else { i++ }; continue }
            if (two == "/*") { inblock = 1; i += 2; continue }
            if (two == "//") { break }
            out = out substr(line, i, 1); i++
        }
        code[NR] = out
    }
    END {
        for (k = 1; k <= NR; k++) {
            if (code[k] ~ /GTEST_SKIP[ \t]*\(\)/) {
                s = code[k]; sub(/.*GTEST_SKIP[ \t]*\(\)/, "", s)
                j = k
                while (s !~ /;/ && j < NR) { j++; s = s " " code[j] }
                if (s !~ /<</) { printf "%s:%d: GTEST_SKIP() carries no reason\n", FN, k; continue }
                sub(/;.*/, "", s); gsub(/<</, " ", s)
                if (!haswords(s)) printf "%s:%d: GTEST_SKIP() reason is empty or blank\n", FN, k
                continue
            }
            if (code[k] ~ /QSKIP[ \t]*\(/) {
                s = code[k]; sub(/.*QSKIP[ \t]*\(/, "", s)
                j = k
                while (s !~ /\)/ && j < NR) { j++; s = s " " code[j] }
                sub(/\).*/, "", s)
                if (!haswords(s)) printf "%s:%d: QSKIP() reason is empty or blank\n", FN, k
                continue
            }
            if (code[k] ~ /XCTSkip/) {
                s = code[k]; sub(/.*XCTSkip[A-Za-z]*/, "", s)
                j = k
                while (s !~ /[;)]/ && j < NR) { j++; s = s " " code[j] }
                sub(/[;)].*/, "", s)
                if (!haswords(s)) printf "%s:%d: XCTSkip reason is empty or blank\n", FN, k
            }
        }
    }
    # A reason is present when, after every blank string literal is deleted,
    # something other than whitespace and punctuation remains. That accepts a
    # run-time reason and rejects "" and "   ".
    function haswords(t) {
        gsub(/"[ \t]*"/, "", t)
        gsub(/^[ \t(]+/, "", t)
        gsub(/[ \t)]+$/, "", t)
        return (t ~ /[^ \t]/)
    }' "$1"
}

: > "$SCRATCH/bad.txt"
scanned=0
while IFS= read -r -d '' f; do
    scan "$f" >> "$SCRATCH/bad.txt"
    rc=$?
    if [ "$rc" != 0 ]; then
        echo "FATAL: the scanner failed on $f (exit $rc) — a scanner that does not run is not a clean repository" >&2
        exit 2
    fi
    scanned=$((scanned + 1))
done < "$SCRATCH/files.z"

# A repository with no tracked sources is not a repository this gate can judge.
if [ "$scanned" -eq 0 ]; then
    echo "FATAL: no tracked source files matched — nothing was scanned" >&2
    exit 2
fi

n=$(wc -l < "$SCRATCH/bad.txt")
if [ "$n" -eq 0 ]; then
    echo "$scanned tracked source file(s) scanned, every skip carries a reason"
    exit 0
fi

cat "$SCRATCH/bad.txt"
echo "$n skip(s) without a reason"
exit 1
