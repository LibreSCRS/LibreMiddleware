#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-manifest-gate.sh — compare the set of tests a build directory discovered
# against a list committed beside it.
#
# ctest reports whatever the build directory happened to discover, and that is
# not one number for one commit: different configurations of this project have
# reported 1791, 1883, 1889, 1961 and 1994 tests. A suite that quietly stops
# being registered therefore reads as success, and a test that moves between
# repositories can vanish while both sides stay green.
#
# One committed listing per CI leg is the smallest shape that can be compared.
# Removing a test stays allowed; it just has to be visible in the same change.
#
# Usage:
#   ci/scripts/test-manifest-gate.sh --check  <builddir> <leg>
#   ci/scripts/test-manifest-gate.sh --update <builddir> <leg>
#
# Exit codes:
#   0  the discovered set matches ci/test-manifest.<leg>.txt
#   1  it differs; the diff and a +N / -M summary are printed
#   2  refusing to judge: no manifest, ctest failed, an empty listing, or any
#      _NOT_BUILT entry. Those describe a build that did not happen, not a set
#      of tests, and a number this script cannot defend is worse than none.
set -uo pipefail

# Deterministic, locale-independent ordering: without this the committed list
# and a fresh listing sort differently on machines with different locales, and
# every diff is noise.
export LC_ALL=C

usage() {
    echo "FATAL: usage: test-manifest-gate.sh --check|--update <builddir> <leg>" >&2
    exit 2
}

[ $# -eq 3 ] || usage
case "$1" in
    --check|--update) ACTION="${1#--}" ;;
    *) usage ;;
esac
BUILD_DIR="$2"
LEG="$3"

case "$LEG" in
    ""|*/*) echo "FATAL: leg name '$LEG' is not a single path segment" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MANIFEST="${REPO_ROOT}/ci/test-manifest.${LEG}.txt"
REL_MANIFEST="ci/test-manifest.${LEG}.txt"

if [ ! -d "$BUILD_DIR" ]; then
    echo "FATAL: build dir '$BUILD_DIR' not found" >&2
    exit 2
fi

SCRATCH="$(mktemp -d /var/tmp/test-manifest-gate.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

raw="${SCRATCH}/raw.txt"
listing="${SCRATCH}/listing.txt"

# ctest's status is read on its own, never through the pipe: a pipeline's `$?`
# is the last stage's, so a failed ctest piped into sed reports success.
ctest --test-dir "$BUILD_DIR" -N > "$raw" 2>&1
ctest_rc=$?
if [ "$ctest_rc" != 0 ]; then
    echo "FATAL: ctest -N failed with exit $ctest_rc — this is not a test set" >&2
    sed -n '1,20p' "$raw" >&2
    exit 2
fi

sed -nE 's/^ *Test +#[0-9]+: +//p' "$raw" | sort > "$listing"

count=$(wc -l < "$listing" | tr -d "[:space:]")   # BSD wc pads; see below
if [ "$count" -eq 0 ]; then
    echo "FATAL: ctest -N discovered no tests in '$BUILD_DIR' — this is a build that did not happen, not a test set" >&2
    exit 2
fi

notbuilt=$(grep -c '_NOT_BUILT$' "$listing" || true)
if [ "$notbuilt" != 0 ]; then
    echo "FATAL: manifest carries $notbuilt _NOT_BUILT entries — this is a build that did not happen, not a test set" >&2
    grep '_NOT_BUILT$' "$listing" | sed -n '1,10p' >&2
    exit 2
fi

if [ "$ACTION" = "update" ]; then
    cp "$listing" "$MANIFEST"
    echo "$REL_MANIFEST: recorded $count tests"
    exit 0
fi

if [ ! -f "$MANIFEST" ]; then
    echo "FATAL: no manifest at $REL_MANIFEST" >&2
    exit 2
fi

if cmp -s "$listing" "$MANIFEST"; then
    echo "$count tests, manifest matches"
    exit 0
fi

# BSD `wc -l` pads its output to a fixed width, so on a macOS runner these
# read "+       1 / -       0 tests". GNU wc does not pad, which is why the
# Linux legs never showed it.
added=$(comm -23 "$listing" "$MANIFEST" | wc -l | tr -d "[:space:]")
removed=$(comm -13 "$listing" "$MANIFEST" | wc -l | tr -d "[:space:]")
diff -u "$MANIFEST" "$listing" || true
echo "+$added / -$removed tests against $REL_MANIFEST"
echo "Regenerate it in the same change: ci/scripts/test-manifest-gate.sh --update $BUILD_DIR $LEG"
exit 1
