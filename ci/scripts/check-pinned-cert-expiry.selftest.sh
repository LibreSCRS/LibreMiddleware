#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-pinned-cert-expiry.selftest.sh — prove the pre-expiry alert can say no.
#
# The check runs in the release-gate leg of CI and is the only thing that warns
# before a pinned trust-list signing certificate expires and the runtime
# hard-fails. Until this file existed nothing had ever observed it returning
# non-zero, and the two certificates it guards are years out, so a real run
# cannot show it either.
#
# Every case builds its own header under /var/tmp from a freshly generated
# self-signed certificate, so the dates are chosen rather than waited for.
#
#   1  notAfter 80 days out, inside the 90-day window  -> 1
#   2  notAfter 100 days out, outside it               -> 0
#   3  a header with no pinned array at all            -> 2, not 0
#   4  openssl missing from PATH                       -> 2, not 1
#   5  THRESHOLD_DAYS=0 against the 80-day header      -> 1, the window is not
#                                                         an environment handle
#
# Case 5 is beyond the four the specification lists; it is the one that fails
# if the environment fallback ever comes back, which is the change this
# self-test was written alongside.
set -uo pipefail

GATE="$(cd "$(dirname "$0")/.." && pwd)/check-pinned-cert-expiry.sh"
[ -f "$GATE" ] || { echo "FATAL: $GATE not found" >&2; exit 2; }
for tool in openssl python3; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool not found; cannot build the fixture" >&2; exit 2; }
done

WORK="$(mktemp -d /var/tmp/pinned-cert-selftest.XXXXXX)" || exit 2
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fail=0

# A repository-shaped fixture: the gate reads a fixed path below the directory
# it is run from, so the fixture is a directory, not an argument.
make_fixture() {
    root="$WORK/$1"
    days="$2"
    mkdir -p "$root/lib/libresign/src/native"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
        -keyout "$root/key.pem" -outform DER -out "$root/cert.der" \
        -days "$days" -subj '/CN=librescrs pinned-cert self-test' >/dev/null 2>&1 \
        || { echo "FATAL: could not generate a $days-day certificate" >&2; exit 2; }
    python3 - "$root/cert.der" > "$root/lib/libresign/src/native/pinned_tl_certs.h" <<'PY'
import pathlib
import sys

der = pathlib.Path(sys.argv[1]).read_bytes()
body = ", ".join(f"0x{b:02X}" for b in der)
print("#pragma once")
print("#include <array>")
print("#include <cstdint>")
print(f"inline constexpr std::array<uint8_t, {len(der)}> kSelfTestPinnedCert = {{ {body} }};")
PY
    printf '%s\n' "$root"
}

# PATH holding every tool the gate uses except the one named.
shim_path_without() {
    missing="$1"
    dir="$WORK/shim-no-$missing"
    mkdir -p "$dir"
    for tool in bash env python3 openssl basename; do
        [ "$tool" = "$missing" ] && continue
        resolved="$(command -v "$tool" 2>/dev/null)" \
            || { echo "FATAL: $tool not found; cannot build the fixture PATH" >&2; exit 2; }
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

near="$(make_fixture near 80)"
far="$(make_fixture far 100)"

# --- case 1: inside the window ------------------------------------------------
out="$(cd "$near" && bash "$GATE" 2>&1)"; rc=$?
report 1 1 "$rc" "within 90-day window" "$out"

# --- case 2: outside the window ----------------------------------------------
out="$(cd "$far" && bash "$GATE" 2>&1)"; rc=$?
report 2 0 "$rc" "OK" "$out"

# --- case 3: a header that pins nothing --------------------------------------
# The vacuum guard: a header the regex finds no array in must not read as a
# header whose every array is healthy.
empty="$WORK/empty"
mkdir -p "$empty/lib/libresign/src/native"
printf '#pragma once\n' > "$empty/lib/libresign/src/native/pinned_tl_certs.h"
out="$(cd "$empty" && bash "$GATE" 2>&1)"; rc=$?
report 3 2 "$rc" "no pinned-cert arrays found" "$out"

# --- case 4: the tool that reads the certificate is gone ----------------------
# Before the tool guard this raised FileNotFoundError out of python and exited
# 1: fail-closed, but spelled like an expiring certificate.
shim="$(shim_path_without openssl)" || exit 2
out="$(cd "$near" && PATH="$shim" bash "$GATE" 2>&1)"; rc=$?
report 4 2 "$rc" "openssl not found on PATH" "$out"

# --- case 5: the window is not an environment handle --------------------------
# THRESHOLD_DAYS=0 used to turn the check off for whoever exported it.
out="$(cd "$near" && THRESHOLD_DAYS=0 bash "$GATE" 2>&1)"; rc=$?
report 5 1 "$rc" "within 90-day window" "$out"

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fail" = 0 ]
