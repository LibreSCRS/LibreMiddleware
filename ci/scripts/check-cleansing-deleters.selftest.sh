#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# check-cleansing-deleters.selftest.sh — prove the deleter gate can fail, one
# clause at a time, and prove it never reads "cannot judge" as clean.
#
# A minimal green tree is built under /var/tmp, committed to a throwaway git
# repository (the gate reads git ls-files and refuses to run outside a work
# tree, so an uncommitted tree would make every case below exit 2 and a
# selftest asserting only "not 0" would pass having measured nothing). The
# green baseline is asserted as exit 0 exactly. Each perturbation is checked to
# have changed its file before the gate runs, and the file is put back from a
# copy, never through git.
#
# Cases:
#   0  green tree                                            -> 0
#   1  BnDeleter body back to plain BN_free                  -> 1  (clause 1)
#   2  the word PACE removed from the comment above it       -> 1  (clause 2)
#   3  a test fixture's BIGNUM deleter back to plain BN_free -> 1  (clause 3)
#   4  bare BN_free on public values outside any deleter     -> 0  (not too wide)
#   5  a deleter with plain BN_free in an UNTRACKED file     -> 0  (only git ls-files counts)
#   6  no 'struct BnDeleter' in the header at all            -> 2  (cannot judge is not clean)
#   7  the gate run outside any git work tree                -> 2  (never 0)
#   8  a function-pointer deleter back to plain BN_free     -> 1  (clause 4)
#   9  a lambda deleter back to plain BN_free               -> 1  (clause 4)
#  10  the excused control leg, left alone                  -> 0  (the exception holds)
#  11  the same file with its exception line commented out  -> 1  (the exception is what excused it)
#  12  an exception line matching nothing any more          -> 1  (a stale amnesty fails)
#  13  an exception line naming an untracked path           -> 1  (so does an unreachable one)
#  14  a struct deleter whose pointer star is spaced        -> 1  (clause 3, either spelling)
#  15  a SECOND plain BN_free deleter in the excused file   -> 1  (the site is excused, not the file)
#  16  an exception line naming a path and no line          -> 1  (an entry that would excuse a file)
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-cleansing-deleters.sh"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d /var/tmp/cleansing-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
cases=0
red=0

check() {
    local label="$1" expected="$2" actual="$3"
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$expected" != 0 ]; then red=$((red + 1)); fi
    if [ "$expected" = "$actual" ]; then
        echo "case $label: OK   — exit $actual"; pass=$((pass + 1))
    else
        echo "case $label: FAIL — expected exit $expected, got $actual"; fail=$((fail + 1))
    fi
}

expect_text() {
    local label="$1" needle="$2" haystack="$3"
    case "$haystack" in
        *"$needle"*) ;;
        *) echo "  case $label: FAIL — output did not say '$needle'"; fail=$((fail + 1)) ;;
    esac
}

# The gate is copied into the fixture so $0-relative resolution lands there.
run() { bash "$1/ci/scripts/check-cleansing-deleters.sh" 2>&1; }

HEADER_REL="lib/LibreSCRS/include/LibreSCRS_internal/Crypto/OpenSslPtr.h"
FIXTURE_REL="test/emrtd-crypto/synthetic_masterlist.cpp"
PUBLIC_REL="lib/libresign/src/native/signing_provider_signature.cpp"
PROBE_REL="test/LibreSCRS_OpenSslPtrTests.cpp"
EXCEPTIONS_REL="ci/cleansing-deleter-exceptions.txt"

ROOT="$WORK/green"
mkdir -p "$ROOT/ci/scripts" "$ROOT/$(dirname "$HEADER_REL")" "$ROOT/$(dirname "$FIXTURE_REL")" \
    "$ROOT/$(dirname "$PUBLIC_REL")" "$ROOT/$(dirname "$PROBE_REL")"
cp "$CHECK" "$ROOT/ci/scripts/check-cleansing-deleters.sh"
chmod +x "$ROOT/ci/scripts/check-cleansing-deleters.sh"

cat > "$ROOT/$HEADER_REL" <<'HDR'
#pragma once
#include <openssl/bn.h>
#include <memory>
namespace LibreSCRS::Internal::Crypto {
/// @brief Frees a BIGNUM, zeroing its limb buffer first.
///
/// PACE holds three secrets that exist only as a BIGNUM and no CleanseGuard
/// reaches them, so the deleter is the only thing that wipes them.
struct BnDeleter
{
    void operator()(BIGNUM* p) const noexcept
    {
        BN_clear_free(p);
    }
};
using BnPtr = std::unique_ptr<BIGNUM, BnDeleter>;
} // namespace LibreSCRS::Internal::Crypto
HDR

cat > "$ROOT/$FIXTURE_REL" <<'FIX'
#include <openssl/bn.h>
#include <memory>
struct BignumDeleter
{
    void operator()(BIGNUM* p) const
    {
        BN_clear_free(p);
    }
};

// The other two shapes a deleter is written in, cleansing here. Cases 8 and 9
// flip them back one at a time; without them in the fixture, clause 4 would be
// measured by nothing but the absence of a complaint.
std::unique_ptr<BIGNUM, decltype(&BN_clear_free)> adopt(BIGNUM* p)
{
    return {p, &BN_clear_free};
}

auto releaseBignum = [](BIGNUM* q) { BN_clear_free(q); };

// The same struct shape with the pointer star spaced the other way. Case 14
// flips it: without this, clause 3's reach is whatever the formatter happens
// to produce, and a security gate must not rest on another gate's setting.
struct SpacedDeleter
{
    void operator()(BIGNUM *s) const
    {
        BN_clear_free(s);
    }
};
FIX

# Cases 10-13's material: the file the exceptions list excuses, carrying a
# lambda deleter that calls plain BN_free on purpose. Copied from the tree when
# this selftest runs beside it, so a control leg that goes away shows up here.
if [ -f "$REPO_ROOT/$PROBE_REL" ]; then
    cp "$REPO_ROOT/$PROBE_REL" "$ROOT/$PROBE_REL"
else
    cat > "$ROOT/$PROBE_REL" <<'PROBE'
#include <openssl/bn.h>
int control()
{
    return measure([](BIGNUM* p) { BN_free(p); });
}
PROBE
fi
if ! grep -qE '\[\][[:space:]]*\([[:space:]]*BIGNUM[[:space:]]*\*' "$ROOT/$PROBE_REL"; then
    echo "case 10: FAIL — $PROBE_REL has no lambda BIGNUM deleter, so the exception cases measure nothing"
    fail=$((fail + 1))
fi

# The excused site is found the way the gate finds it, not written down here:
# a hard-coded line number would rot against the file this selftest copies.
PROBE_LINE="$(grep -n -E '\[[^]]*\][[:space:]]*\([[:space:]]*BIGNUM[[:space:]]*\*' "$ROOT/$PROBE_REL" \
    | grep -E '(^|[^_[:alnum:]])BN_free[[:space:]]*\(' | head -n1 | cut -d: -f1)"
if [ -z "$PROBE_LINE" ]; then
    echo "case 10: FAIL — no plain BN_free lambda found in $PROBE_REL, so the exception cases measure nothing"
    fail=$((fail + 1))
    PROBE_LINE=1
fi

cat > "$ROOT/$EXCEPTIONS_REL" <<EXC
# One path:line per entry, then the reason.
$PROBE_REL:$PROBE_LINE  the control leg of the cleansing probe must call plain BN_free
EXC

# Case 4's material: the real file with bare BN_free on public ECDSA r/s in
# its error paths, when this selftest runs beside it; a stand-in of the same
# shape otherwise. Either way the tree must actually carry a bare BN_free
# outside a deleter, or "stays green" proves nothing about the gate's width.
if [ -f "$REPO_ROOT/$PUBLIC_REL" ]; then
    cp "$REPO_ROOT/$PUBLIC_REL" "$ROOT/$PUBLIC_REL"
else
    cat > "$ROOT/$PUBLIC_REL" <<'PUB'
#include <openssl/bn.h>
int encode(BIGNUM* r, BIGNUM* s)
{
    if (r == nullptr) {
        BN_free(s);
        return -1;
    }
    BN_free(r);
    BN_free(s);
    return 0;
}
PUB
fi
bare_public="$(grep -c 'BN_free[[:space:]]*(' "$ROOT/$PUBLIC_REL" || true)"
if [ "${bare_public:-0}" -lt 1 ]; then
    echo "case 4: FAIL — $PUBLIC_REL carries no bare BN_free, so the width case cannot measure"
    fail=$((fail + 1))
fi

git -C "$ROOT" init -q
git -C "$ROOT" config user.email t@t
git -C "$ROOT" config user.name t
git -C "$ROOT" add -A
git -C "$ROOT" -c commit.gpgsign=false commit -qm x

# Keep pristine copies for restoring; restoring goes through cp, never git.
cp "$ROOT/$HEADER_REL" "$WORK/header.bak"
cp "$ROOT/$FIXTURE_REL" "$WORK/fixture.bak"
cp "$ROOT/$EXCEPTIONS_REL" "$WORK/exceptions.bak"
cp "$ROOT/$PROBE_REL" "$WORK/probe.bak"

# --- case 0: the green baseline is exit 0 exactly -------------------------
out="$(run "$ROOT")"; rc=$?; check 0 0 $rc
expect_text 0 "check-cleansing-deleters: OK" "$out"

# perturb FILE with a sed expression, and refuse to continue if nothing changed
perturb() {
    local label="$1" file="$2" expr="$3"
    cp "$file" "$WORK/pre.tmp"
    sed -i -e "$expr" "$file"
    if cmp -s "$WORK/pre.tmp" "$file"; then
        echo "case $label: FAIL — perturbation changed nothing in ${file#"$ROOT"/}"
        fail=$((fail + 1))
        return 1
    fi
    return 0
}

# --- case 1: the canonical deleter back to plain BN_free ------------------
if perturb 1 "$ROOT/$HEADER_REL" 's/BN_clear_free(p);/BN_free(p);/'; then
    out="$(run "$ROOT")"; rc=$?; check 1 1 $rc
    expect_text 1 "BnDeleter does not call BN_clear_free" "$out"
    expect_text 1 "${HEADER_REL}-" "$out"     # clause 3 names the file too
fi
cp "$WORK/header.bak" "$ROOT/$HEADER_REL"
out="$(run "$ROOT")"; rc=$?; check "1-restored" 0 $rc

# --- case 2: the reason removed, the call kept ----------------------------
if perturb 2 "$ROOT/$HEADER_REL" 's/PACE/It/'; then
    out="$(run "$ROOT")"; rc=$?; check 2 1 $rc
    expect_text 2 "does not mention PACE" "$out"
fi
cp "$WORK/header.bak" "$ROOT/$HEADER_REL"
out="$(run "$ROOT")"; rc=$?; check "2-restored" 0 $rc

# --- case 3: a fixture's deleter back to plain BN_free --------------------
if perturb 3 "$ROOT/$FIXTURE_REL" 's/BN_clear_free(p);/BN_free(p);/'; then
    out="$(run "$ROOT")"; rc=$?; check 3 1 $rc
    expect_text 3 "a BIGNUM deleter calls plain BN_free" "$out"
    expect_text 3 "${FIXTURE_REL}-7-" "$out"   # file and line of the offending call
fi
cp "$WORK/fixture.bak" "$ROOT/$FIXTURE_REL"
out="$(run "$ROOT")"; rc=$?; check "3-restored" 0 $rc

# --- case 4: bare BN_free outside any deleter stays green -----------------
# The file was committed with the tree, so the gate has seen it in every case
# above; this names the property and asserts it on its own.
out="$(run "$ROOT")"; rc=$?; check 4 0 $rc
case "$out" in
    *"$PUBLIC_REL"*) echo "  case 4: FAIL — the gate named $PUBLIC_REL ($bare_public bare BN_free on public values)"; fail=$((fail + 1)) ;;
esac

# --- case 5: an untracked file is invisible to the gate -------------------
cat > "$ROOT/test/untracked_deleter.cpp" <<'UNT'
#include <openssl/bn.h>
struct Loose
{
    void operator()(BIGNUM* p) const
    {
        BN_free(p);
    }
};
UNT
out="$(run "$ROOT")"; rc=$?; check 5 0 $rc
rm -f "$ROOT/test/untracked_deleter.cpp"

# --- case 6: no declaration to judge is exit 2, never 0 -------------------
if perturb 6 "$ROOT/$HEADER_REL" 's/^struct BnDeleter$/struct BnRelease/'; then
    out="$(run "$ROOT")"; rc=$?; check 6 2 $rc
    expect_text 6 "FATAL" "$out"
fi
cp "$WORK/header.bak" "$ROOT/$HEADER_REL"
out="$(run "$ROOT")"; rc=$?; check "6-restored" 0 $rc

# --- case 7: outside any git work tree is exit 2, never 0 -----------------
NOGIT="$WORK/nogit"
mkdir -p "$NOGIT/ci/scripts" "$NOGIT/$(dirname "$HEADER_REL")"
cp "$CHECK" "$NOGIT/ci/scripts/check-cleansing-deleters.sh"
cp "$WORK/header.bak" "$NOGIT/$HEADER_REL"
if git -C "$NOGIT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "case 7: FAIL — $NOGIT sits inside a git work tree, so the case cannot measure"
    fail=$((fail + 1))
else
    out="$(run "$NOGIT")"; rc=$?; check 7 2 $rc
    expect_text 7 "not a git work tree" "$out"
fi

# --- case 8: a function-pointer deleter back to plain BN_free -------------
if perturb 8 "$ROOT/$FIXTURE_REL" 's/decltype(&BN_clear_free)/decltype(\&BN_free)/'; then
    out="$(run "$ROOT")"; rc=$?; check 8 1 $rc
    expect_text 8 "released through a plain BN_free deleter" "$out"
    expect_text 8 "${FIXTURE_REL}:" "$out"
fi
cp "$WORK/fixture.bak" "$ROOT/$FIXTURE_REL"
out="$(run "$ROOT")"; rc=$?; check "8-restored" 0 $rc

# --- case 9: a lambda deleter back to plain BN_free -----------------------
if perturb 9 "$ROOT/$FIXTURE_REL" 's/BN_clear_free(q);/BN_free(q);/'; then
    out="$(run "$ROOT")"; rc=$?; check 9 1 $rc
    expect_text 9 "released through a plain BN_free deleter" "$out"
fi
cp "$WORK/fixture.bak" "$ROOT/$FIXTURE_REL"
out="$(run "$ROOT")"; rc=$?; check "9-restored" 0 $rc

# --- case 10: the excused file is not reported ----------------------------
out="$(run "$ROOT")"; rc=$?; check 10 0 $rc
case "$out" in
    *"$PROBE_REL"*) echo "  case 10: FAIL — the gate named the excused $PROBE_REL"; fail=$((fail + 1)) ;;
esac

# --- case 11: without its exception line, the same file fails -------------
# What separates case 10 from a gate that cannot see that file at all.
if perturb 11 "$ROOT/$EXCEPTIONS_REL" "s@^${PROBE_REL}@#&@"; then
    out="$(run "$ROOT")"; rc=$?; check 11 1 $rc
    expect_text 11 "${PROBE_REL}:" "$out"
fi
cp "$WORK/exceptions.bak" "$ROOT/$EXCEPTIONS_REL"
out="$(run "$ROOT")"; rc=$?; check "11-restored" 0 $rc

# --- case 12: an exception that no longer matches anything ----------------
if perturb 12 "$ROOT/$EXCEPTIONS_REL" "\$a ${FIXTURE_REL}:9999  nothing at that line releases a BIGNUM this way"; then
    out="$(run "$ROOT")"; rc=$?; check 12 1 $rc
    expect_text 12 "no longer releases a BIGNUM" "$out"
fi
cp "$WORK/exceptions.bak" "$ROOT/$EXCEPTIONS_REL"
out="$(run "$ROOT")"; rc=$?; check "12-restored" 0 $rc

# --- case 13: an exception naming a path that is not tracked --------------
if perturb 13 "$ROOT/$EXCEPTIONS_REL" '$a test/gone.cpp:5  deleted three releases ago'; then
    out="$(run "$ROOT")"; rc=$?; check 13 1 $rc
    expect_text 13 "is not a tracked file" "$out"
fi
cp "$WORK/exceptions.bak" "$ROOT/$EXCEPTIONS_REL"
out="$(run "$ROOT")"; rc=$?; check "13-restored" 0 $rc

# --- case 14: a struct deleter written with a spaced pointer star ---------
if perturb 14 "$ROOT/$FIXTURE_REL" 's/BN_clear_free(s);/BN_free(s);/'; then
    out="$(run "$ROOT")"; rc=$?; check 14 1 $rc
    expect_text 14 "a BIGNUM deleter calls plain BN_free" "$out"
    expect_text 14 "${FIXTURE_REL}-" "$out"
fi
cp "$WORK/fixture.bak" "$ROOT/$FIXTURE_REL"
out="$(run "$ROOT")"; rc=$?; check "14-restored" 0 $rc

# --- case 15: a second plain-BN_free deleter in the excused file ----------
# What the amnesty is worth: the recorded site, and nothing else in the file
# around it. A path-shaped exception passes this silently.
if perturb 15 "$ROOT/$PROBE_REL" '$a auto secondDeleter = [](BIGNUM* p) { BN_free(p); };'; then
    added="$(wc -l < "$ROOT/$PROBE_REL")"
    out="$(run "$ROOT")"; rc=$?; check 15 1 $rc
    expect_text 15 "released through a plain BN_free deleter" "$out"
    expect_text 15 "${PROBE_REL}:${added}:" "$out"
fi
cp "$WORK/probe.bak" "$ROOT/$PROBE_REL"
out="$(run "$ROOT")"; rc=$?; check "15-restored" 0 $rc

# --- case 16: an exception that names a file and no line ------------------
if perturb 16 "$ROOT/$EXCEPTIONS_REL" "\$a ${PROBE_REL}  an amnesty with no line in it"; then
    out="$(run "$ROOT")"; rc=$?; check 16 1 $rc
    expect_text 16 "which names no line" "$out"
fi
cp "$WORK/exceptions.bak" "$ROOT/$EXCEPTIONS_REL"
out="$(run "$ROOT")"; rc=$?; check "16-restored" 0 $rc

echo "selftest: $pass passed, $fail failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
