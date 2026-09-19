#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-impl-visibility.selftest.sh — prove the Impl-visibility gate can refuse
# to judge.
#
# The gate is wired three times, once of them from the release workflow, and
# until this file existed it had never been observed returning anything but
# zero. Both cases below were measured against the pre-guard gate on this
# machine: each printed "Impl visibility clean" and exited 0.
#
#   1  c++filt missing from PATH          -> 2, and the message names the tool
#   2  every artefact present, no symbols -> 2, and the message names the count
#
# Both fixtures are zero-byte files under /var/tmp named exactly like a shared
# build tree, so `nm` reads no symbol from them. That is the subject of case 2,
# and it is why case 1 asserts its own message instead of only its exit code:
# on this fixture both guards would answer 2, and a case that cannot tell which
# guard spoke is not a case.
#
# No build artefact is needed, so this runs in a job that never compiled.
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

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
