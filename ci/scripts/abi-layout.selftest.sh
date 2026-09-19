#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-layout.selftest.sh — prove the layout check can be fooled, then that it
# is not.
#
# A classifier that has never been fooled is not a classifier. Seven
# perturbations:
#
#   1  two frozen dumps (4.2.0 vs the tree this gate landed on) → NON-ADDITIVE,
#      an exact number of vanished lines
#   2  a virtual appended AFTER the last one                    → ADDITIVE
#   3  a virtual inserted BEFORE an existing slot               → NON-ADDITIVE
#   4  a field appended to a plugin-facing aggregate            → NON-ADDITIVE
#   5  a brand-new public header appears                        → visible, ADDITIVE
#   6  --update over a non-additive difference while the SONAME integer
#      stands still                                             → refused
#   7  --update anywhere but the canonical toolchain            → refused
#
# Cases 2-5 measure the CLASSIFIER: they run over a copy of include/, never
# over the tree, and compare the perturbed snapshot against an unperturbed
# snapshot of the same copy — so they are independent of whichever baseline the
# repository currently carries.
#
# Cases 6-7 measure the TEETH, which live in abi-layout.sh's --update path.
# That path rewrites ci/abi/layout-baseline.txt, so they run against a
# throwaway copy of the repository skeleton and never touch the real one.
#
# Case 1 runs the classifier over two committed, frozen files rather than over
# the live tree, because it asserts an exact count and that number is only
# meaningful while both of its inputs stand still.

set -uo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LAYOUT="${REPO_ROOT}/ci/scripts/abi-layout.sh"
CLASSIFY="${REPO_ROOT}/ci/scripts/abi-layout-classify.py"
FROZEN_OLD="${REPO_ROOT}/ci/abi/selftest/layout-4.2.0.txt"
FROZEN_NEW="${REPO_ROOT}/ci/abi/selftest/layout-7b637674.txt"

# The exact number of baseline facts that stop holding between the two frozen
# dumps. Measured, not assumed; constant only because both inputs are frozen.
EXPECTED_CASE1_GONE=14

WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/librescrs-abi-layout-selftest.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0
cases=0
# red-proved: a case in which the classifier or --update returned non-zero on
# a perturbed input. Cases 2 and 5 are the additive controls, so they are not.
red=0

ok()   { printf 'case %s: OK   — %s\n' "$1" "$2"; pass=$((pass + 1)); }
bad()  { printf 'case %s: FAIL — %s\n' "$1" "$2"; fail=$((fail + 1)); }

# Take a snapshot of a header tree into a file. Echoes nothing; returns the
# script's exit code.
snap() {
    local include_root="$1" out="$2" bdir="$3"
    mkdir -p "$bdir"
    LIBRESCRS_ABI_LAYOUT_INCLUDE_ROOT="$include_root" \
        "$LAYOUT" --print "$bdir" > "$out" 2> "${out}.err"
}

# Assert that a perturbation actually changed something before its verdict is
# read. A perturbation that changed nothing proves nothing.
changed() {
    local a="$1" b="$2" case_id="$3"
    local ha hb
    ha="$(sha256sum < "$a" | cut -d' ' -f1)"
    hb="$(sha256sum < "$b" | cut -d' ' -f1)"
    if [[ "$ha" == "$hb" ]]; then
        printf 'case %s: snapshot changed: NO (%s) — perturbation was inert\n' "$case_id" "$ha"
        return 1
    fi
    printf 'case %s: snapshot changed: yes (%s -> %s)\n' "$case_id" "${ha:0:12}" "${hb:0:12}"
    return 0
}

# A throwaway repository skeleton, so --update has somewhere to write.
mkfakerepo() {
    local d="$1" soversion="$2" baseline="$3" include_src="$4"
    mkdir -p "$d/ci/scripts" "$d/ci/abi"
    cp -p "$LAYOUT" "$d/ci/scripts/abi-layout.sh"
    cp -p "$CLASSIFY" "$d/ci/scripts/abi-layout-classify.py"
    cp -p "${REPO_ROOT}/ci/abi/vtable-probe.cpp" "$d/ci/abi/vtable-probe.cpp"
    cp -p "$baseline" "$d/ci/abi/layout-baseline.txt"
    printf 'set(LIBRESCRS_ABI_SOVERSION %s CACHE STRING "selftest")\n' "$soversion" \
        > "$d/CMakeLists.txt"
    cp -a "$include_src" "$d/include"
    mkdir -p "$d/build"
}

# ---------------------------------------------------------------------------
# Case 1 — the two frozen dumps.
# ---------------------------------------------------------------------------
cases=$((cases + 1)); red=$((red + 1))
for f in "$FROZEN_OLD" "$FROZEN_NEW"; do
    if [[ ! -f "$f" ]]; then
        bad 1 "frozen fixture missing: $f"
        f_missing=1
    fi
done
if [[ -z "${f_missing:-}" ]]; then
    printf 'case 1: frozen inputs %s %s\n' \
        "$(sha256sum < "$FROZEN_OLD" | cut -c1-12)" \
        "$(sha256sum < "$FROZEN_NEW" | cut -c1-12)"
    python3 "$CLASSIFY" "$FROZEN_OLD" "$FROZEN_NEW" > "$WORK/case1.txt" 2>&1
    rc=$?
    gone=$(grep -c '^  - ' "$WORK/case1.txt")
    if [[ $rc -eq 1 && "$gone" -eq "$EXPECTED_CASE1_GONE" ]]; then
        ok 1 "NON-ADDITIVE, exactly ${gone} vanished lines, exit ${rc}"
    else
        bad 1 "expected exit 1 with ${EXPECTED_CASE1_GONE} vanished lines; got exit ${rc} with ${gone}"
        sed -n '1,20p' "$WORK/case1.txt"
    fi
fi

# ---------------------------------------------------------------------------
# Pristine copy of the public headers + its unperturbed snapshot.
# ---------------------------------------------------------------------------
mkdir -p "$WORK/pristine"
cp -a "${REPO_ROOT}/include" "$WORK/pristine/include"
if ! snap "$WORK/pristine/include" "$WORK/ref.txt" "$WORK/bd-ref"; then
    bad 0 "could not snapshot the unperturbed header copy"
    sed -n '1,20p' "$WORK/ref.txt.err"
    echo "selftest: ${pass} passed, ${fail} failed"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 1
fi

# perturb <case> <python-snippet-file-relative-path...> — copies pristine into
# $WORK/<case>/include, applies a python edit, snapshots, classifies.
run_case() {
    local id="$1" expect="$2" py="$3" extra_check="${4:-}" where="${5:-verdict}"
    cases=$((cases + 1))
    if [[ "$expect" != additive ]]; then red=$((red + 1)); fi
    local d="$WORK/case$id"
    mkdir -p "$d"
    cp -a "$WORK/pristine/include" "$d/include"
    if ! python3 -c "$py" "$d/include"; then
        bad "$id" "perturbation script failed"
        return
    fi
    if ! snap "$d/include" "$d/snap.txt" "$d/bd"; then
        bad "$id" "snapshot failed after perturbation"
        sed -n '1,20p' "$d/snap.txt.err"
        return
    fi
    if ! changed "$WORK/ref.txt" "$d/snap.txt" "$id"; then
        bad "$id" "perturbation did not change the snapshot"
        return
    fi
    python3 "$CLASSIFY" "$WORK/ref.txt" "$d/snap.txt" > "$d/verdict.txt" 2>&1
    local rc=$?
    if [[ "$expect" == "additive" ]]; then
        if [[ $rc -ne 0 ]]; then
            bad "$id" "expected ADDITIVE (exit 0); got exit ${rc}"
            sed -n '1,15p' "$d/verdict.txt"
            return
        fi
    else
        if [[ $rc -ne 1 ]]; then
            bad "$id" "expected NON-ADDITIVE (exit 1); got exit ${rc}"
            sed -n '1,15p' "$d/verdict.txt"
            return
        fi
    fi
    if [[ -n "$extra_check" ]]; then
        local haystack="$d/verdict.txt"
        [[ "$where" == "snapshot" ]] && haystack="$d/snap.txt"
        if ! grep -qE -- "$extra_check" "$haystack"; then
            bad "$id" "expected pattern not found in ${where}: ${extra_check}"
            sed -n '1,15p' "$haystack"
            return
        fi
    fi
    ok "$id" "$(head -1 "$d/verdict.txt")"
}

# ---------------------------------------------------------------------------
# Case 2 — a virtual appended AFTER the last one is additive.
# ---------------------------------------------------------------------------
read -r -d '' PY2 <<'PY' || true
import sys, pathlib
p = pathlib.Path(sys.argv[1]) / 'LibreSCRS' / 'Plugin' / 'CardPlugin.h'
s = p.read_text(encoding='utf-8')
anchor = '"activateSigningKey signPin parameter must be Secure::String const&");'
i = s.index(anchor)
j = s.index('\n    }\n', i) + len('\n    }\n')
s = s[:j] + ('\n    [[nodiscard]] virtual int selftestAppendedVirtual() const { return 0; }\n') + s[j:]
p.write_text(s, encoding='utf-8')
PY
run_case 2 additive "$PY2" 'ADDITIVE'

# ---------------------------------------------------------------------------
# Case 3 — a virtual inserted BEFORE an existing slot is not.
# ---------------------------------------------------------------------------
read -r -d '' PY3 <<'PY' || true
import sys, pathlib
p = pathlib.Path(sys.argv[1]) / 'LibreSCRS' / 'Plugin' / 'CardPlugin.h'
s = p.read_text(encoding='utf-8')
anchor = '    [[nodiscard]] virtual Auth::PreReadAuthMethod preReadAuth('
i = s.index(anchor)
s = s[:i] + '    [[nodiscard]] virtual int selftestInsertedVirtual() const { return 0; }\n\n' + s[i:]
p.write_text(s, encoding='utf-8')
PY
run_case 3 nonadditive "$PY3" '\| .*preReadAuth'

# ---------------------------------------------------------------------------
# Case 4 — a field appended to a plugin-facing aggregate is not.
# ---------------------------------------------------------------------------
read -r -d '' PY4 <<'PY' || true
import sys, pathlib
p = pathlib.Path(sys.argv[1]) / 'LibreSCRS' / 'Plugin' / 'PluginTypes.h'
s = p.read_text(encoding='utf-8')
anchor = '    [[nodiscard]] bool operator==(const CertificateData&) const noexcept = default;'
i = s.index(anchor)
s = s[:i] + '    std::uint64_t selftestAppendedField = 0;\n' + s[i:]
p.write_text(s, encoding='utf-8')
PY
run_case 4 nonadditive "$PY4" 'LibreSCRS::Plugin::CertificateData'

# ---------------------------------------------------------------------------
# Case 5 — a brand-new public header must show up in the snapshot at all.
# This guards the check's REACH, not its verdict: the umbrella translation unit
# is generated by find, so nobody has to remember to list a new header.
# ---------------------------------------------------------------------------
read -r -d '' PY5 <<'PY' || true
import sys, pathlib
p = pathlib.Path(sys.argv[1]) / 'LibreSCRS' / 'Plugin' / 'SelftestProbeType.h'
p.write_text(
    '#pragma once\n'
    '#include <cstdint>\n'
    'namespace LibreSCRS::Plugin {\n'
    'struct SelftestProbeType\n'
    '{\n'
    '    std::uint32_t first;\n'
    '    std::uint64_t second;\n'
    '};\n'
    '}\n', encoding='utf-8')
PY
run_case 5 additive "$PY5" 'LibreSCRS::Plugin::SelftestProbeType' snapshot

# ---------------------------------------------------------------------------
# Case 6 — --update refuses a non-additive difference while the SONAME integer
# stands still, and names both numbers.
# ---------------------------------------------------------------------------
cases=$((cases + 1)); red=$((red + 1))
base_soversion="$(sed -n 's/^# soversion: \([0-9]*\)$/\1/p' "$WORK/ref.txt" | head -1)"
if [[ -z "$base_soversion" ]]; then
    bad 6 "reference snapshot carries no '# soversion:' header line"
else
    d="$WORK/case6"
    mkfakerepo "$d" "$base_soversion" "$WORK/ref.txt" "$WORK/case3/include"
    "$d/ci/scripts/abi-layout.sh" --update "$d/build" > "$d/out.txt" 2>&1
    rc=$?
    if [[ $rc -eq 1 ]] \
       && grep -q "tree=${base_soversion} baseline=${base_soversion}" "$d/out.txt"; then
        ok 6 "$(head -1 "$d/out.txt")"
    else
        bad 6 "expected exit 1 naming tree=${base_soversion} baseline=${base_soversion}; got exit ${rc}"
        sed -n '1,10p' "$d/out.txt"
    fi
    if ! cmp -s "$d/ci/abi/layout-baseline.txt" "$WORK/ref.txt"; then
        bad 6 "the refused --update wrote the baseline anyway"
    fi
fi

# ---------------------------------------------------------------------------
# Case 7 — --update is refused anywhere but the canonical toolchain. Member
# offsets are facts about one toolchain, so exactly one may record them.
# ---------------------------------------------------------------------------
cases=$((cases + 1)); red=$((red + 1))
d="$WORK/case7"
mkfakerepo "$d" "$((base_soversion + 1))" "$WORK/ref.txt" "$WORK/pristine/include"
mkdir -p "$d/stub"
cat > "$d/stub/uname" <<'STUB'
#!/bin/sh
case "$1" in
  -s) echo Darwin ;;
  *)  echo Darwin ;;
esac
STUB
chmod 0755 "$d/stub/uname"
PATH="$d/stub:$PATH" "$d/ci/scripts/abi-layout.sh" --update "$d/build" > "$d/out.txt" 2>&1
rc=$?
if [[ $rc -eq 1 ]] && grep -qi 'darwin' "$d/out.txt"; then
    ok 7 "$(head -1 "$d/out.txt")"
else
    bad 7 "expected exit 1 refusing on Darwin; got exit ${rc}"
    sed -n '1,10p' "$d/out.txt"
fi
if ! cmp -s "$d/ci/abi/layout-baseline.txt" "$WORK/ref.txt"; then
    bad 7 "the refused --update wrote the baseline anyway"
fi

# ---------------------------------------------------------------------------
echo "selftest: ${pass} passed, ${fail} failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[[ $fail -eq 0 ]]
