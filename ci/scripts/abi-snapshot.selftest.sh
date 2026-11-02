#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-snapshot.selftest.sh — prove the ABI snapshot can fail, and can refuse.
#
# The gate this proves is the last thing standing between a silently changed
# public ABI and a release tag, and until this file existed nobody had watched
# it go red. Worse, it could be disarmed for good without a single red run:
# `--update` over a tree that exports nothing used to write a baseline of
# comments only, and every later `--check` against the same empty tree then
# passed. That is the case this file exists for, so it is measured in both
# directions: the baseline losing a symbol, and the tree losing one.
#
# Every case builds a throwaway repository under /var/tmp (never /tmp, a RAM
# filesystem on the development host) holding a copy of this gate and a stub
# shared object named the way CMake names the real ones. The stub is the point:
# a case that leans on the repository's own build tree would measure whatever
# was last built there.
#
# Cases:
#   1  control: --update over the stub tree, then --check          -> 0
#   2  one symbol removed from the baseline                        -> 1
#   3  one exported symbol removed from the shared object          -> 1
#   4  an empty build tree, --check                                -> 2
#   5  an empty build tree, --update: refused, baseline untouched   -> 2
#   6  control: the same run under a PATH shim that HAS c++filt    -> 0
#   7  c++filt taken off PATH                                      -> 2
#   8  an exported data symbol                                     -> 2
#   9  Internal:: / detail:: functions are not recorded            -> 0
#  10  a public function taking an Internal:: type is recorded,
#      and changing that parameter is drift                        -> 1
#  11  one function exported by two libraries, --check / --update  -> 1
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SUBJECT:-$HERE/abi-snapshot.sh}"
[ -f "$SUBJECT" ] || { echo "FATAL: $SUBJECT is missing" >&2; exit 2; }

# A compiler is the only way to get a shared object whose exported set this
# file controls. Without one the answer is "I could not measure", never a pass.
for tool in g++ nm c++filt; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool not found on PATH -- cannot build the fixture" >&2; exit 2; }
done

WORK="$(mktemp -d /var/tmp/abi-snapshot-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fails=0

check() {  # check <label> <want-rc> <got-rc>
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero over a
    # perturbed input.
    if [ "$2" != 0 ]; then red=$((red + 1)); fi
    if [ "$2" = "$3" ]; then
        printf 'ok    %-52s rc=%s\n' "$1" "$3"
    else
        printf 'FAIL  %-52s rc=%s want=%s\n' "$1" "$3" "$2"
        sed 's/^/        /' "$WORK/out"
        fails=$((fails + 1))
    fi
}

says() {  # says <label> <text>
    if grep -qF -- "$2" "$WORK/out"; then
        printf 'ok    %-52s says %s\n' "$1" "$2"
    else
        printf 'FAIL  %-52s does not say %s\n' "$1" "$2"
        sed 's/^/        /' "$WORK/out"
        fails=$((fails + 1))
    fi
}

# stub <name> [--without-beta] -> prints the fixture root
stub() {
    # One `local` per name: bash 5.3 does not let the second assignment in a
    # single `local` see the first, and under `set -u` that is an unbound
    # variable rather than an empty one.
    local name="$1"
    local omit="${2:-}"
    local root="$WORK/$name"
    mkdir -p "$root/ci/scripts" "$root/ci/abi" "$root/build/lib/LibreSCRS"
    cp "$SUBJECT" "$root/ci/scripts/abi-snapshot.sh"
    chmod 0755 "$root/ci/scripts/abi-snapshot.sh"
    {
        printf 'namespace LibreSCRS {\n'
        printf 'int selftestAlpha(int x) { return x + 1; }\n'
        [ -n "$omit" ] || printf 'int selftestBeta(int x) { return x + 2; }\n'
        printf 'int selftestGamma(int x) { return x + 3; }\n'
        printf '}\n'
    } > "$root/stub.cpp"
    # The filename shape the gate looks for: libLibreSCRS_*.so.<X>.<Y>.<Z>.
    g++ -shared -fPIC -o "$root/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
        "$root/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build the stub shared object" >&2; sed 's/^/        /' "$WORK/gcc.err" >&2; exit 2; }
    printf '%s' "$root"
}

run() {  # run <root> <args...> -> rc; output in $WORK/out
    local root="$1"; shift
    if ( cd "$root" && ./ci/scripts/abi-snapshot.sh "$@" ) > "$WORK/out" 2>&1; then
        echo 0
    else
        echo $?
    fi
}

# --- case 1: the control. Without it every refusal below could be an error path.
root="$(stub control)"
rc=$(run "$root" --update build)
check "control: --update over the stub tree" 0 "$rc"
if ! grep -q 'selftestBeta' "$root/ci/abi/5.x-baseline.txt"; then
    echo "FATAL: the fixture's own baseline does not carry the stub symbols" >&2
    exit 2
fi
rc=$(run "$root" --check build)
check "control: --check against what --update wrote" 0 "$rc"
command cp -f "$root/ci/abi/5.x-baseline.txt" "$WORK/baseline.good"

# --- case 2: the baseline loses a symbol -- drift from the recorded side.
root2="$(stub baseline-short)"
run "$root2" --update build >/dev/null
grep -v 'selftestBeta' "$WORK/baseline.good" > "$root2/ci/abi/5.x-baseline.txt"
if cmp -s "$WORK/baseline.good" "$root2/ci/abi/5.x-baseline.txt"; then
    echo "FATAL: the perturbation changed nothing -- it would pass for the wrong reason" >&2
    exit 2
fi
rc=$(run "$root2" --check build)
check "a symbol missing from the baseline is drift" 1 "$rc"
says "a symbol missing from the baseline is drift" "selftestBeta"

# --- case 3: the tree loses a symbol -- drift from the measured side.
root3="$(stub tree-short --without-beta)"
command cp -f "$WORK/baseline.good" "$root3/ci/abi/5.x-baseline.txt"
rc=$(run "$root3" --check build)
check "a symbol missing from the library is drift" 1 "$rc"
says "a symbol missing from the library is drift" "selftestBeta"

# --- case 4/5: a tree that exports nothing. This is the one that could disarm
#     the gate for every later run, so --update must refuse and leave the
#     baseline byte-for-byte as it was.
root4="$(stub empty-tree)"
run "$root4" --update build >/dev/null
command cp -f "$WORK/baseline.good" "$root4/ci/abi/5.x-baseline.txt"
rm -f "$root4/build/lib/LibreSCRS/"*.so.*
rc=$(run "$root4" --check build)
check "an empty tree cannot be judged" 2 "$rc"
rc=$(run "$root4" --update build)
check "an empty tree is refused by --update" 2 "$rc"
if cmp -s "$WORK/baseline.good" "$root4/ci/abi/5.x-baseline.txt"; then
    printf 'ok    %-52s baseline untouched\n' "the refused --update wrote nothing"
else
    printf 'FAIL  %-52s the refused --update overwrote the baseline\n' "the refused --update wrote nothing"
    fails=$((fails + 1))
fi

# --- case 6/7: the tool that was silenced. The shim is proved to work with
#     c++filt present before c++filt is taken out of it, or a broken shim
#     would read as the finding.
SHIM="$WORK/shim"
mkdir -p "$SHIM"
for t in bash sh nm c++filt awk sort find wc basename dirname mktemp diff cat sed grep cp mkdir rm head tr env printf ls uname; do
    p="$(command -v "$t" 2>/dev/null)" && ln -sf "$p" "$SHIM/$t"
done
root5="$(stub shim-tree)"
run "$root5" --update build >/dev/null
rc=$( if ( cd "$root5" && PATH="$SHIM" ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "control: the PATH shim with c++filt still judges" 0 "$rc"
rm -f "$SHIM/c++filt"
rc=$( if ( cd "$root5" && PATH="$SHIM" ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "c++filt off PATH is 'cannot measure'" 2 "$rc"
says "c++filt off PATH is 'cannot measure'" "c++filt not found on PATH"

# --- case 8: a binding class the snapshot has no rule for -------------------
# The snapshot records T and declares which classes it deliberately does not,
# because the policy says vague-linkage entries are not the public API: they are
# how the object model emits a vtable or an inline member, and the compiler
# decides which exist. Recording them would put inlining decisions into the ABI.
#
# What that must NOT do is drop something that IS the ABI. An exported DATA
# symbol is part of a C++ contract, and the old T-only clause threw it away
# without a word. This case is that symbol.
root6="$(stub data-symbol)"
run "$root6" --update build >/dev/null
{
    printf 'namespace LibreSCRS {\n'
    printf 'int selftestAlpha(int x) { return x + 1; }\n'
    printf 'int selftestBeta(int x) { return x + 2; }\n'
    printf 'int selftestGamma(int x) { return x + 3; }\n'
    printf 'int selftestExportedGlobal = 7;\n'
    printf '}\n'
} > "$root6/stub.cpp"
g++ -shared -fPIC -o "$root6/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
    "$root6/stub.cpp" 2>"$WORK/gcc.err" \
    || { echo "FATAL: could not rebuild the stub with a data symbol" >&2; exit 2; }
# The fixture really does export one, or the case would pass for the wrong reason.
if ! nm -D -U "$root6/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
        | awk '$2 == "D" || $2 == "B" { found = 1 } END { exit !found }'; then
    echo "FATAL: the fixture exports no data symbol -- nothing to detect" >&2
    exit 2
fi
rc=$(run "$root6" --check build)
check "an exported data symbol is not dropped in silence" 2 "$rc"
says "an exported data symbol is not dropped in silence" "no
       rule for"

# --- case 9: an Internal:: or detail:: symbol is no contract ----------------
#     It is exported for the in-tree plugins, which are version-locked to the
#     tree: it is not recorded, and changing it is not drift.
root9="$WORK/internal"
mkdir -p "$root9/ci/scripts" "$root9/ci/abi" "$root9/build/lib/LibreSCRS"
cp "$SUBJECT" "$root9/ci/scripts/abi-snapshot.sh"
chmod 0755 "$root9/ci/scripts/abi-snapshot.sh"
build_internal() {  # build_internal <internal-function-name>
    {
        printf 'namespace LibreSCRS {\n'
        printf 'int selftestAlpha(int x) { return x + 1; }\n'
        printf 'namespace Internal { int %s(int x) { return x + 4; } }\n' "$1"
        printf 'namespace detail { int selftestDetail(int x) { return x + 5; } }\n'
        printf '}\n'
    } > "$root9/stub.cpp"
    g++ -shared -fPIC -o "$root9/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
        "$root9/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build the internal-symbol stub" >&2; exit 2; }
}
build_internal selftestInternal
rc=$(run "$root9" --update build)
check "internal symbols: --update" 0 "$rc"
if grep -qE 'selftestInternal|selftestDetail' "$root9/ci/abi/5.x-baseline.txt"; then
    echo "FAIL  an Internal:: or detail:: symbol was recorded"
    fails=$((fails + 1))
fi
build_internal selftestInternalRenamed
rc=$(run "$root9" --check build)
check "a changed Internal:: symbol is not drift" 0 "$rc"

# --- case 10: a public function that takes an Internal:: type ---------------
#     Only the function's own name decides. Its parameter types are not its
#     name: a public member whose signature mentions an Internal:: type is
#     still declared in a public header, and a change to that signature is
#     drift like any other.
root10="$WORK/internal-param"
mkdir -p "$root10/ci/scripts" "$root10/ci/abi" "$root10/build/lib/LibreSCRS"
cp "$SUBJECT" "$root10/ci/scripts/abi-snapshot.sh"
chmod 0755 "$root10/ci/scripts/abi-snapshot.sh"
build_internal_param() {  # build_internal_param <internal-type-name>
    {
        printf 'namespace LibreSCRS {\n'
        printf 'namespace Internal { struct %s { int x; }; }\n' "$1"
        printf 'int selftestAlpha(int x) { return x + 1; }\n'
        printf 'int selftestTakesInternal(const Internal::%s& a) { return a.x; }\n' "$1"
        printf '}\n'
    } > "$root10/stub.cpp"
    g++ -shared -fPIC -o "$root10/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
        "$root10/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build the internal-parameter stub" >&2; exit 2; }
}
build_internal_param SelftestCommand
rc=$(run "$root10" --update build)
check "public function, Internal:: parameter: --update" 0 "$rc"
if grep -qF 'selftestTakesInternal(LibreSCRS::Internal::SelftestCommand const&)' \
        "$root10/ci/abi/5.x-baseline.txt"; then
    printf 'ok    %-52s recorded\n' "a public function with an Internal:: parameter"
else
    printf 'FAIL  %-52s not recorded\n' "a public function with an Internal:: parameter"
    sed 's/^/        /' "$root10/ci/abi/5.x-baseline.txt"
    fails=$((fails + 1))
fi
build_internal_param SelftestCommandRenamed
rc=$(run "$root10" --check build)
check "its changed parameter type is drift" 1 "$rc"
says "its changed parameter type is drift" "selftestTakesInternal"

# --- case 11: one function exported by two libraries ------------------------
#     A library that absorbs another one's implementation exports its
#     functions a second time, and the snapshot would record both copies as
#     two promises. The control is two libraries with disjoint exports, so the
#     refusal below is about the shared function and not about a second file.
root11="$WORK/two-owners"
mkdir -p "$root11/ci/scripts" "$root11/ci/abi" "$root11/build/lib/LibreSCRS"
cp "$SUBJECT" "$root11/ci/scripts/abi-snapshot.sh"
chmod 0755 "$root11/ci/scripts/abi-snapshot.sh"
build_lib11() {  # build_lib11 <Module> <function-name...>
    local module="$1"; shift
    local fn
    {
        printf 'namespace LibreSCRS {\n'
        for fn in "$@"; do printf 'int %s(int x) { return x + 1; }\n' "$fn"; done
        printf '}\n'
    } > "$root11/$module.cpp"
    g++ -shared -fPIC -o "$root11/build/lib/LibreSCRS/libLibreSCRS_$module.so.5.0.0" \
        "$root11/$module.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build the $module stub" >&2; exit 2; }
}
build_lib11 Owner selftestOwned
build_lib11 Other selftestOther
rc=$(run "$root11" --update build)
check "control: two libraries, disjoint exports" 0 "$rc"
command cp -f "$root11/ci/abi/5.x-baseline.txt" "$WORK/baseline.two"
build_lib11 Other selftestOther selftestOwned
rc=$(run "$root11" --check build)
check "a function exported by two libraries" 1 "$rc"
says "a function exported by two libraries" "exported by more than one library"
says "a function exported by two libraries" "selftestOwned"
rc=$(run "$root11" --update build)
check "the duplicate is refused by --update" 1 "$rc"
if cmp -s "$WORK/baseline.two" "$root11/ci/abi/5.x-baseline.txt"; then
    printf 'ok    %-52s baseline untouched\n' "the refused duplicate wrote nothing"
else
    printf 'FAIL  %-52s the refused --update overwrote the baseline\n' "the refused duplicate wrote nothing"
    fails=$((fails + 1))
fi

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fails" = 0 ]
