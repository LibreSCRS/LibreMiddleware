#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# check-signing-backend.sh — assert the signing backend a build was asked for
# is the one it actually got.
#
# SIGNING_BACKEND (lib/libresign/CMakeLists.txt) is a plain CACHE STRING. Its
# set_property(... PROPERTY STRINGS ...) is advisory — a cmake-gui affordance,
# not validation. CMake therefore accepts a misspelled -D flag name without
# error: the stray variable is recorded as UNINITIALIZED, SIGNING_BACKEND keeps
# its "native" default, and every DSS / cross-backend target quietly disappears
# from the build. The job stays green forever while testing nothing it claims
# to test. The same holds for a misspelled *value* ("boht"), which matches
# neither the native nor the dss branch and leaves LibreSign with no backend
# compile definition at all.
#
# This guard is deliberately bidirectional: it fails when the expected backend
# is missing AND when an unexpected one is present, so it cannot be satisfied
# by a build that simply defines everything.
#
# Usage: check-signing-backend.sh <build-dir> <native|dss|both>
set -euo pipefail

build_dir="${1:?usage: check-signing-backend.sh <build-dir> <native|dss|both>}"
expected="${2:?usage: check-signing-backend.sh <build-dir> <native|dss|both>}"

case "$expected" in
    native | dss | both) ;;
    *)
        echo "FAIL: expected backend must be native, dss or both (got '$expected')" >&2
        exit 1
        ;;
esac

cache="$build_dir/CMakeCache.txt"
if [ ! -f "$cache" ]; then
    echo "FAIL: no CMakeCache.txt under '$build_dir' — nothing to verify" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. The cache entry must hold exactly the requested value.
#
# This is the check that catches the flag-name typo: -DSIGNIGN_BACKEND=both
# leaves SIGNING_BACKEND at "native", so the exact comparison below fails
# instead of degrading silently. Compared as a whole string, never with a
# substring grep — "native" is a substring of nothing here today, but a future
# value could make a substring match trivially true.
# ---------------------------------------------------------------------------
cache_lines="$(grep -c '^SIGNING_BACKEND:' "$cache" || true)"
if [ "$cache_lines" != "1" ]; then
    echo "FAIL: expected exactly one SIGNING_BACKEND cache entry, found $cache_lines" >&2
    exit 1
fi

actual="$(sed -n 's/^SIGNING_BACKEND:STRING=//p' "$cache")"
if [ "$actual" != "$expected" ]; then
    echo "FAIL: SIGNING_BACKEND is '$actual', expected '$expected'." >&2
    echo "      A mistyped -D flag name does not fail configure; it leaves the" >&2
    echo "      default in place. Check the flag spelling in the workflow." >&2
    grep '^SIGNING_BACKEND' "$cache" >&2 || true
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. The compile definitions must have actually reached the generated build.
#
# LIBRESIGN_HAS_DSS / LIBRESIGN_HAS_NATIVE are target_compile_definitions, NOT
# cache variables — grepping CMakeCache.txt for them matches nothing and would
# make this guard a no-op. They land in the generator's command lines.
#
# The match is anchored on the exact "-DTOKEN=1" spelling with a fixed-string
# compare. A bare substring search for LIBRESIGN_HAS_DSS also matches
# LIBRESIGN_HAS_DSS_ORACLE, which BUILD_DSS_ORACLE defines on the test-support
# library in a plain native build — that false positive would report DSS as
# present on every native leg.
# ---------------------------------------------------------------------------
build_files=()
if [ -f "$build_dir/build.ninja" ]; then
    build_files+=("$build_dir/build.ninja")
fi
while IFS= read -r f; do
    build_files+=("$f")
done < <(find "$build_dir" -name 'flags.make' -type f 2>/dev/null)

if [ "${#build_files[@]}" -eq 0 ]; then
    echo "FAIL: found no generated build files (build.ninja / flags.make) under" >&2
    echo "      '$build_dir' — cannot verify the compile definitions" >&2
    exit 1
fi

case "$expected" in
    native) want_native=yes want_dss=no ;;
    dss) want_native=no want_dss=yes ;;
    both) want_native=yes want_dss=yes ;;
esac

check_definition() {
    local token="$1" want="$2" present=no
    if grep -qF -- "-D$token=1" "${build_files[@]}"; then
        present=yes
    fi
    if [ "$present" != "$want" ]; then
        echo "FAIL: -D$token=1 present=$present, expected=$want for SIGNING_BACKEND=$expected" >&2
        return 1
    fi
    echo "  ok: -D$token=1 present=$present (expected $want)"
}

check_definition LIBRESIGN_HAS_NATIVE "$want_native"
check_definition LIBRESIGN_HAS_DSS "$want_dss"

# ---------------------------------------------------------------------------
# 3. Behavioural ground truth: the cross-backend cases must actually be in the
#    suite. cross_backend_test.cpp compiles its real TESTs only under
#    #if defined(LIBRESIGN_HAS_NATIVE) && defined(LIBRESIGN_HAS_DSS); otherwise
#    it emits a single DISABLED placeholder that never runs. Checking the
#    discovered test list therefore proves the definitions did more than appear
#    on a command line. Skipped when the tree was configured without tests.
# ---------------------------------------------------------------------------
testing="$(sed -n 's/^BUILD_TESTING:BOOL=//p' "$cache")"
if [ "$testing" != "ON" ]; then
    echo "  note: BUILD_TESTING=$testing — skipping the discovered-test check"
    echo "PASS: signing backend '$expected' verified in $build_dir"
    exit 0
fi

listing="$(ctest --test-dir "$build_dir" -N -R '^CrossBackendTest\.' 2>/dev/null || true)"
if printf '%s' "$listing" | grep -q 'CrossBackendTest.BothBackendsAvailable'; then
    live_cases=yes
else
    live_cases=no
fi

want_cases=no
if [ "$expected" = "both" ]; then
    want_cases=yes
fi

if [ "$live_cases" != "$want_cases" ]; then
    echo "FAIL: CrossBackendTest live cases present=$live_cases, expected=$want_cases" >&2
    echo "      for SIGNING_BACKEND=$expected. Discovered listing:" >&2
    printf '%s\n' "$listing" >&2
    exit 1
fi
echo "  ok: CrossBackendTest live cases present=$live_cases (expected $want_cases)"

echo "PASS: signing backend '$expected' verified in $build_dir"
