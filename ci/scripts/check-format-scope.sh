#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-format-scope.sh — every tracked source file must be reachable by the
# formatter.
#
# The format job has always run clang-format over a hand-written list of
# directories. Nothing said that list covered the repository, and it did not:
# ninety-odd tracked sources sat outside it here, fifty-four of them the
# installed public headers. All of them already satisfied clang-format, so
# simply widening the search would have produced a check that was green the
# moment it was written.
#
# The gate is therefore on reach, not on formatting. One file, ci/format-dirs.txt,
# is read by both the format step and this script, so a new top-level directory
# cannot appear that nobody formats without this saying so. Anything that
# genuinely does not belong under a formatted root goes in ci/format-exclude.txt
# with a comment saying why — never silently.
#
# Usage:
#   ci/scripts/check-format-scope.sh
#
# Exit codes:
#   0  every tracked source is under a formatted root or explicitly excluded
#   1  at least one is not; they are listed
#   2  refusing to judge: ci/format-dirs.txt is missing, empty, or names a
#      directory that does not exist. A gate with no roots is a vacuum gate.
set -uo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

DIRS_FILE="ci/format-dirs.txt"
EXCLUDE_FILE="ci/format-exclude.txt"

if [ ! -f "$DIRS_FILE" ]; then
    echo "FATAL: no $DIRS_FILE — a gate with no roots cannot judge anything" >&2
    exit 2
fi

mapfile -t dirs < <(grep -v '^[[:space:]]*#' "$DIRS_FILE" | grep -v '^[[:space:]]*$')
if [ "${#dirs[@]}" -eq 0 ]; then
    echo "FATAL: $DIRS_FILE lists no directories — a gate with no roots is a vacuum gate" >&2
    exit 2
fi

for d in "${dirs[@]}"; do
    if [ ! -d "$d" ]; then
        echo "FATAL: $DIRS_FILE names '$d', which does not exist — the list is stale" >&2
        exit 2
    fi
done

SCRATCH="$(mktemp -d /var/tmp/check-format-scope.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

git ls-files | grep -E '\.(c|cc|cpp|cxx|h|hh|hpp|m|mm)$' | sort > "$SCRATCH/tracked.txt"

# Covered: the path lies under one of the roots.
: > "$SCRATCH/covered.txt"
for d in "${dirs[@]}"; do
    grep -E "^$(printf '%s' "$d" | sed 's/[].[^$\\*/]/\\&/g')/" "$SCRATCH/tracked.txt" >> "$SCRATCH/covered.txt" || true
done
sort -u "$SCRATCH/covered.txt" -o "$SCRATCH/covered.txt"

comm -23 "$SCRATCH/tracked.txt" "$SCRATCH/covered.txt" > "$SCRATCH/outside.txt"

# Excluded: matches an explicit grep -E pattern, each carrying its own comment.
if [ -f "$EXCLUDE_FILE" ]; then
    mapfile -t patterns < <(grep -v '^[[:space:]]*#' "$EXCLUDE_FILE" | grep -v '^[[:space:]]*$')
    for pat in "${patterns[@]:-}"; do
        [ -n "$pat" ] || continue
        grep -Ev "$pat" "$SCRATCH/outside.txt" > "$SCRATCH/outside.next" || true
        mv "$SCRATCH/outside.next" "$SCRATCH/outside.txt"
    done
fi

n=$(wc -l < "$SCRATCH/outside.txt")
if [ "$n" -eq 0 ]; then
    total=$(wc -l < "$SCRATCH/tracked.txt")
    echo "$total tracked source file(s), all reachable by the formatter"
    exit 0
fi

cat "$SCRATCH/outside.txt"
echo "$n tracked source file(s) are outside every formatted directory"
echo "Add a root to $DIRS_FILE, or an explicit pattern with a comment to $EXCLUDE_FILE"
exit 1
