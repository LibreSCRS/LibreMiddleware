#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-manifest-gate.selftest.sh — prove the manifest gate can fail, and prove
# it declines to judge an input it cannot defend.
#
# A gate that has never failed is not a gate. Every case below runs against a
# throwaway tree under /var/tmp (never /tmp, which is a RAM filesystem here)
# with a stub `ctest` on PATH, so no build is needed and no real repository is
# touched.
#
# Cases:
#   1  identical listing                      -> 0
#   2  one test removed from the build        -> 1, and the diff names it
#   3  one test added to the build            -> 1
#   4  listing carries _NOT_BUILT             -> 2 (refuses to compare)
#   5  empty listing                          -> 2
#   6  no manifest committed                  -> 2
#   7  --update refuses an empty listing      -> 2, and the file is unchanged
#   8  ctest itself fails                     -> 2
set -uo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/test-manifest-gate.sh"
WORK="$(mktemp -d /var/tmp/tmgate-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

# Build a fake repository root with a ci/ directory and a stub ctest whose
# output the caller dictates.
make_env() {
    local name="$1" listing="$2" ctest_rc="${3:-0}"
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/bin" "$root/build"
    cp "$GATE" "$root/ci/scripts/test-manifest-gate.sh"
    chmod +x "$root/ci/scripts/test-manifest-gate.sh"
    {
        echo '#!/usr/bin/env bash'
        printf 'cat <<%s\n' "'LIST'"
        printf '%s\n' "$listing"
        echo "LIST"
        echo "exit $ctest_rc"
    } > "$root/bin/ctest"
    chmod +x "$root/bin/ctest"
    echo "$root"
}

# The stub reproduces ctest -N's real shape: a header, numbered lines, a total.
listing_of() {
    local i=1
    echo "Test project /nowhere"
    while [ $# -gt 0 ]; do
        printf '  Test #%d: %s\n' "$i" "$1"
        i=$((i + 1)); shift
    done
    echo ""
    echo "Total Tests: $((i - 1))"
}

check() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   — exit $actual"
        pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"
        fail=$((fail + 1))
    fi
}

three="$(listing_of Alpha.One Beta.Two Gamma.Three)"
two="$(listing_of Alpha.One Gamma.Three)"
four="$(listing_of Alpha.One Beta.Two Gamma.Three Delta.Four)"
notbuilt="$(listing_of Alpha.One Beta.Two SomeSuite_NOT_BUILT)"
empty="$(printf 'Test project /nowhere\n\nTotal Tests: 0\n')"

# --- case 1: identical listing -> 0
root="$(make_env c1 "$three")"
( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --update build linux >/dev/null 2>&1 )
out="$( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --check build linux 2>&1 )"; rc=$?
check 1 0 $rc
case "$out" in *"3 tests, manifest matches"*) ;; *) echo "  case 1: FAIL — wrong message: $out"; fail=$((fail + 1)) ;; esac

# --- case 2: one test removed -> 1, and it is named
root="$(make_env c2 "$three")"
( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --update build linux >/dev/null 2>&1 )
# The build now discovers one fewer test than the committed manifest.
( cd "$root" && { echo '#!/usr/bin/env bash'; printf 'cat <<%s\n' "'LIST'"; printf '%s\n' "$two"; echo "LIST"; } > bin/ctest; chmod +x bin/ctest )
out="$( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --check build linux 2>&1 )"; rc=$?
check 2 1 $rc
case "$out" in *"Beta.Two"*) ;; *) echo "  case 2: FAIL — the diff does not name Beta.Two"; fail=$((fail + 1)) ;; esac
case "$out" in *"+0 / -1 tests"*) ;; *) echo "  case 2: FAIL — wrong summary: $out"; fail=$((fail + 1)) ;; esac

# --- case 3: one test added -> 1
root="$(make_env c3 "$three")"
( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --update build linux >/dev/null 2>&1 )
( cd "$root" && { echo '#!/usr/bin/env bash'; printf 'cat <<%s\n' "'LIST'"; printf '%s\n' "$four"; echo "LIST"; } > bin/ctest; chmod +x bin/ctest )
out="$( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --check build linux 2>&1 )"; rc=$?
check 3 1 $rc
case "$out" in *"+1 / -0 tests"*) ;; *) echo "  case 3: FAIL — wrong summary: $out"; fail=$((fail + 1)) ;; esac

# --- case 4: _NOT_BUILT in the listing -> 2, no comparison at all
root="$(make_env c4 "$three")"
( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --update build linux >/dev/null 2>&1 )
( cd "$root" && { echo '#!/usr/bin/env bash'; printf 'cat <<%s\n' "'LIST'"; printf '%s\n' "$notbuilt"; echo "LIST"; } > bin/ctest; chmod +x bin/ctest )
out="$( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --check build linux 2>&1 )"; rc=$?
check 4 2 $rc
case "$out" in *"_NOT_BUILT"*) ;; *) echo "  case 4: FAIL — message does not name _NOT_BUILT"; fail=$((fail + 1)) ;; esac

# --- case 5: empty listing -> 2
root="$(make_env c5 "$three")"
( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --update build linux >/dev/null 2>&1 )
( cd "$root" && { echo '#!/usr/bin/env bash'; printf 'cat <<%s\n' "'LIST'"; printf '%s\n' "$empty"; echo "LIST"; } > bin/ctest; chmod +x bin/ctest )
out="$( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --check build linux 2>&1 )"; rc=$?
check 5 2 $rc

# --- case 6: no manifest committed -> 2
root="$(make_env c6 "$three")"
out="$( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --check build linux 2>&1 )"; rc=$?
check 6 2 $rc
case "$out" in *"no manifest at ci/test-manifest.linux.txt"*) ;; *) echo "  case 6: FAIL — wrong message: $out"; fail=$((fail + 1)) ;; esac

# --- case 7: --update refuses an empty listing, and leaves the file alone
root="$(make_env c7 "$three")"
( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --update build linux >/dev/null 2>&1 )
before="$(sha256sum "$root/ci/test-manifest.linux.txt" | cut -d' ' -f1)"
( cd "$root" && { echo '#!/usr/bin/env bash'; printf 'cat <<%s\n' "'LIST'"; printf '%s\n' "$empty"; echo "LIST"; } > bin/ctest; chmod +x bin/ctest )
out="$( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --update build linux 2>&1 )"; rc=$?
after="$(sha256sum "$root/ci/test-manifest.linux.txt" | cut -d' ' -f1)"
check 7 2 $rc
if [ -n "$before" ] && [ "$before" = "$after" ]; then
    echo "case 7b: OK   — manifest unchanged after a refused --update"
    pass=$((pass + 1))
else
    echo "case 7b: FAIL — a refused --update still rewrote the manifest"
    fail=$((fail + 1))
fi

# --- case 8: ctest itself fails -> 2
root="$(make_env c8 "$three")"
( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --update build linux >/dev/null 2>&1 )
( cd "$root" && { echo '#!/usr/bin/env bash'; echo 'echo "ctest: broken" >&2'; echo 'exit 8'; } > bin/ctest; chmod +x bin/ctest )
out="$( cd "$root" && PATH="$root/bin:$PATH" bash ci/scripts/test-manifest-gate.sh --check build linux 2>&1 )"; rc=$?
check 8 2 $rc

echo "selftest: $pass passed, $fail failed"
[ "$fail" = 0 ]
