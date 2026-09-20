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
#   6  one of them carries ::Impl_::      -> 1, and the symbol is named
#   7  an allowance that matches nothing  -> 1, and the row is named
#   8  an allowance missing a field       -> 2
#
# Case 6 is why cases 3 and 4 are not enough. Until this file was written the
# rule matched the demangled segment `::Impl::`, so renaming the pimpl to `Impl_`
# exported the same implementation detail past every rule: `_` is a word
# character, and both `grep -F '::Impl::'` and `::Impl\b` are blind to it.
# Measured against the gate as it was: exit 0 on exactly the tree case 6 uses.
# The rule is now an allowlist against the recorded surface, so the spelling does
# not enter into it.
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

GATE="${GATE:-$(cd "$(dirname "$0")" && pwd)/check-impl-visibility.sh}"
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

# The same perturbation with the one spelling the old rule could not see.
sed 's/Body/Impl_/g' "$src/clean.cpp" > "$src/leak_.cpp"
if cmp -s "$src/leak.cpp" "$src/leak_.cpp"; then
    echo "FATAL: the two leaky fixtures are the same file -- one of them proves nothing" >&2
    exit 2
fi
g++ -shared -fPIC -o "$src/leak_.so" "$src/leak_.cpp" 2>>"$WORK/gcc.err" \
    || { echo "FATAL: could not compile the Impl_ fixture" >&2; sed 's/^/    /' "$WORK/gcc.err" >&2; exit 2; }
if ! nm -D -U "$src/leak_.so" | awk '$2 == "T" { print $3 }' | c++filt | grep -qF '::Impl_::'; then
    echo "FATAL: the Impl_ fixture exports no ::Impl_:: symbol -- nothing to detect" >&2
    exit 2
fi
# The two libraries really do export different symbol sets. Without this the
# next two cases could both pass over one artefact.
if cmp -s <(nm -D -U "$src/clean.so") <(nm -D -U "$src/leak_.so"); then
    echo "FATAL: the perturbed library exports exactly what the clean one does" >&2
    exit 2
fi

# The recorded surface for this fixture, in the format abi-snapshot.sh writes and
# through the same pipeline: the clean library's dynamic T-binding symbols, one
# section per core library. The gate compares against this instead of the
# repository's, because the fixture is not this repository's ABI.
fixture_surface="$WORK/fixture-surface.txt"
{
    echo "# fixture surface for check-impl-visibility.selftest.sh"
    for module in Auth Certificate Plugin SecureChannel Signing SmartCard Trust; do
        echo "== libLibreSCRS_$module.so =="
        nm -D -U "$src/clean.so" | awk '$2 == "T" { print $3 }' | c++filt | sort -u
    done
} > "$fixture_surface"
export LIBRESCRS_ABI_BASELINE="$fixture_surface"

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

# --- case 6: the spelling the old rule could not see -------------------------
tree6="$WORK/tree-impl-underscore"
make_tree "$tree6"
for module in Auth Certificate Plugin SecureChannel Signing SmartCard Trust; do
    command cp -f "$src/clean.so" "$tree6/lib/LibreSCRS/libLibreSCRS_$module.so"
done
command cp -f "$src/clean.so" "$tree6/plugins/libselftest-plugin.so"
command cp -f "$src/clean.so" "$tree6/lib/pkcs11/librescrs-pkcs11.so"
command cp -f "$src/leak_.so" "$tree6/lib/LibreSCRS/libLibreSCRS_Signing.so"
out="$(bash "$GATE" "$tree6" 2>&1)"; rc=$?
report 6 1 "$rc" "LibreSCRS::Selftest::Impl_::step(int)" "$out"

# --- cases 7 and 8: the allowances of the static-archive pass ----------------
# The four inline `grep -v` lines these rows replaced could not fail: when the
# symbol one of them excused disappeared, the line kept passing. A row that
# matches nothing does not.
ar_src="$WORK/ar"
mkdir -p "$ar_src"
cat > "$ar_src/residual.cpp" <<'CPP'
namespace LibreSCRS { namespace Selftest {
struct Keeper { int hold(int x); };
int Keeper::hold(int x) { return x - 1; }
} }
CPP
if ! g++ -c -fPIC -o "$ar_src/residual.o" "$ar_src/residual.cpp" 2>>"$WORK/gcc.err"; then
    echo "FATAL: could not compile the archive fixture" >&2
    exit 2
fi
tree7="$WORK/tree-static"
mkdir -p "$tree7/lib/LibreSCRS" "$tree7/plugins" "$tree7/lib/pkcs11"
for module in Auth Certificate Plugin SecureChannel Signing SmartCard Trust; do
    ar rcs "$tree7/lib/LibreSCRS/libLibreSCRS_$module.a" "$ar_src/residual.o" 2>/dev/null
done
command cp -f "$src/clean.so" "$tree7/plugins/libselftest-plugin.so"
command cp -f "$src/clean.so" "$tree7/lib/pkcs11/librescrs-pkcs11.so"

stale="$WORK/residuals-stale.txt"
printf '%s\n' \
  "libLibreSCRS_Trust.a  LibreSCRS::Selftest::LongGone::Impl::  a reason for a symbol no archive carries" \
  > "$stale"
out="$(LIBRESCRS_IMPL_RESIDUALS="$stale" bash "$GATE" "$tree7" 2>&1)"; rc=$?
report 7 1 "$rc" "STALE" "$out"

short="$WORK/residuals-short.txt"
printf '%s\n' "libLibreSCRS_Trust.a  LibreSCRS::Selftest::Keeper::hold" > "$short"
out="$(LIBRESCRS_IMPL_RESIDUALS="$short" bash "$GATE" "$tree7" 2>&1)"; rc=$?
report 8 2 "$rc" "all three fields" "$out"

# --- case 9: the same spelling, in the half of the surface the modules are ----
# Case 6 puts the leak in a CORE library, where the recorded surface catches it
# whatever it is called. The plugin and pkcs11 pass is a different rule over a
# different table, and it read `::Impl::` literally: a module exporting
# `Impl_::step` was reported clean. librescrs-pkcs11.so is in that half.
tree9="$WORK/tree-plugin-underscore"
make_tree "$tree9"
for module in Auth Certificate Plugin SecureChannel Signing SmartCard Trust; do
    command cp -f "$src/clean.so" "$tree9/lib/LibreSCRS/libLibreSCRS_$module.so"
done
command cp -f "$src/clean.so" "$tree9/lib/pkcs11/librescrs-pkcs11.so"
command cp -f "$src/leak_.so" "$tree9/plugins/libselftest-plugin.so"
out="$(bash "$GATE" "$tree9" 2>&1)"; rc=$?
report 9 1 "$rc" "LibreSCRS::Selftest::Impl_::step(int)" "$out"

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
