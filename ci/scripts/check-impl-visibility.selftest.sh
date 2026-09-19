#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-impl-visibility.selftest.sh — prove the Impl-visibility gate can refuse
# to judge.
#
# The gate is wired three times, one of them from the release workflow, and
# until this file existed it had never been observed returning anything but
# zero. Cases 1 and 2 were measured against the pre-guard gate on this
# machine: each printed "Impl visibility clean" and exited 0.
#
#   1  c++filt missing from PATH          -> 2, and the message names the tool
#   2  every artefact present, no symbols -> 2, and the message names the count
#   3  a tree of real libraries, no leak  -> 0   (the control)
#   4  one of them carries ::Impl::       -> 1, and the symbol is named
#   5  the core libraries are gone        -> 2, and the message names the count
#
# Cases 1, 2 and 5 are zero-byte files under /var/tmp named exactly like a
# shared build tree, so `nm` reads no symbol from them. That is the subject of
# case 2, and it is why case 1 asserts its own message instead of only its exit
# code: on that fixture both guards would answer 2, and a case that cannot tell
# which guard spoke is not a case.
#
# Cases 3 and 4 need libraries that really carry symbols, so they are compiled
# here -- nine of them, the exact container counts the gate expects, one pair of
# sources differing in a single type name. The tree this repository builds is
# deliberately NOT the fixture: the job that runs the self-tests never compiles,
# so a case that needed build/ would answer "cannot judge" on every push, and
# the gate over the real tree belongs to the full local build instead. The
# control is what makes case 4 a measurement: without it a red could come from
# anything about the fixture.
#
# No build artefact of this repository is needed, so this runs in a job that
# never compiled.
set -uo pipefail

GATE="$(cd "$(dirname "$0")" && pwd)/check-impl-visibility.sh"
[ -f "$GATE" ] || { echo "FATAL: $GATE not found" >&2; exit 2; }

WORK="$(mktemp -d /var/tmp/impl-visibility-selftest.XXXXXX)" || exit 2
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fail=0

# A build tree whose file names and counts are exactly what the gate expects of
# a shared build: seven core libraries, a plugin and the PKCS#11 module.
make_tree() {
    root="$1"
    mkdir -p "$root/lib/LibreSCRS" "$root/plugins" "$root/lib/pkcs11"
    for module in Auth Certificate Plugin SecureChannel Signing SmartCard Trust; do
        : > "$root/lib/LibreSCRS/libLibreSCRS_$module.so"
    done
    : > "$root/plugins/libselftest-plugin.so"
    : > "$root/lib/pkcs11/librescrs-pkcs11.so"
}

# PATH holding every tool the gate uses except the one named. Building it from
# `command -v` rather than a hard-coded /usr/bin keeps this working on a runner
# whose binutils live elsewhere.
shim_path_without() {
    missing="$1"
    dir="$WORK/shim-no-$missing"
    mkdir -p "$dir"
    for tool in bash env nm awk grep sort basename sed find uname wc c++filt; do
        [ "$tool" = "$missing" ] && continue
        resolved="$(command -v "$tool" 2>/dev/null)" || {
            echo "FATAL: $tool not found on this host; cannot build the fixture PATH" >&2
            exit 2
        }
        ln -sf "$resolved" "$dir/$tool"
    done
    printf '%s\n' "$dir"
}

report() {
    name="$1"; want_rc="$2"; got_rc="$3"; want_text="$4"; out="$5"
    cases=$((cases + 1))
    ok=1
    [ "$got_rc" = "$want_rc" ] || ok=0
    case "$out" in *"$want_text"*) ;; *) ok=0 ;; esac
    if [ "$ok" = 1 ]; then
        printf 'case %s: OK   — exit %s, and the message says "%s"\n' "$name" "$got_rc" "$want_text"
        [ "$got_rc" = 0 ] || red=$((red + 1))
    else
        printf 'case %s: FAIL — wanted exit %s saying "%s", got exit %s\n' \
            "$name" "$want_rc" "$want_text" "$got_rc"
        printf '%s\n' "$out" | sed 's/^/    /'
        fail=$((fail + 1))
    fi
    return 0
}

# --- case 1: the demangler is missing ----------------------------------------
# Pre-guard behaviour, measured: every c++filt invocation ended in
# `2>/dev/null | grep ... || true`, so the pipeline was empty, all five
# container-counting guards were satisfied and the gate printed a clean result.
tree1="$WORK/tree-no-cxxfilt"
make_tree "$tree1"
shim="$(shim_path_without c++filt)" || exit 2
out="$(PATH="$shim" bash "$GATE" "$tree1" 2>&1)"; rc=$?
report 1 2 "$rc" "c++filt not found" "$out"

# --- case 2: every artefact in place, and not one symbol read ----------------
# Seven core libraries and two modules is what the counters check; none of them
# yields a symbol. Counting containers is not counting symbols.
tree2="$WORK/tree-no-symbols"
make_tree "$tree2"
out="$(bash "$GATE" "$tree2" 2>&1)"; rc=$?
report 2 2 "$rc" "0 symbols" "$out"

# --- cases 3 and 4: a tree that really exports something ---------------------
# The two sources differ in one token: `struct Body` against `struct Impl`. The
# gate matches the demangled `::Impl::` segment, so that one token is the whole
# defect, and the control above it is what proves the tree is otherwise clean.
for tool in g++ nm c++filt; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool not found on PATH -- cannot compile the fixture" >&2; exit 2; }
done

src="$WORK/src"
mkdir -p "$src"
cat > "$src/clean.cpp" <<'CPP'
namespace LibreSCRS { namespace Selftest {
struct Body { int step(int x); };
int Body::step(int x) { return x + 1; }
int alpha(int x) { return Body{}.step(x); }
} }
CPP
sed 's/Body/Impl/g' "$src/clean.cpp" > "$src/leak.cpp"
if cmp -s "$src/clean.cpp" "$src/leak.cpp"; then
    echo "FATAL: the perturbation changed nothing -- it would pass for the wrong reason" >&2
    exit 2
fi
g++ -shared -fPIC -o "$src/clean.so" "$src/clean.cpp" 2>"$WORK/gcc.err" \
    && g++ -shared -fPIC -o "$src/leak.so" "$src/leak.cpp" 2>>"$WORK/gcc.err" \
    || { echo "FATAL: could not compile the fixture libraries" >&2; sed 's/^/    /' "$WORK/gcc.err" >&2; exit 2; }
if ! nm -D -U "$src/leak.so" | awk '$2 == "T" { print $3 }' | c++filt | grep -qF '::Impl::'; then
    echo "FATAL: the leaky fixture exports no ::Impl:: symbol -- nothing to detect" >&2
    exit 2
fi

# Same shape as make_tree, with libraries that are not empty.
tree3="$WORK/tree-real"
make_tree "$tree3"
for module in Auth Certificate Plugin SecureChannel Signing SmartCard Trust; do
    command cp -f "$src/clean.so" "$tree3/lib/LibreSCRS/libLibreSCRS_$module.so"
done
command cp -f "$src/clean.so" "$tree3/plugins/libselftest-plugin.so"
command cp -f "$src/clean.so" "$tree3/lib/pkcs11/librescrs-pkcs11.so"
out="$(bash "$GATE" "$tree3" 2>&1)"; rc=$?
report 3 0 "$rc" "Impl visibility clean" "$out"

command cp -f "$src/leak.so" "$tree3/lib/LibreSCRS/libLibreSCRS_Trust.so"
out="$(bash "$GATE" "$tree3" 2>&1)"; rc=$?
report 4 1 "$rc" "LibreSCRS::Selftest::Impl::step(int)" "$out"

# --- case 5: the containers themselves are gone ------------------------------
# The counter that Faza-0 case 2 showed is not a symbol count is still a real
# rule, and this is the shape it exists for: with no core library present the
# gate must refuse rather than report a clean tree.
rm -f "$tree3/lib/LibreSCRS/"*.so
out="$(bash "$GATE" "$tree3" 2>&1)"; rc=$?
report 5 2 "$rc" "found 0" "$out"

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
