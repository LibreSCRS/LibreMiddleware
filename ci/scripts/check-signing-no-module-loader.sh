#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# check-signing-no-module-loader.sh -- does the signing library still link the
# in-process PKCS#11 module loader?
#
# Property, not proxy: libLibreSCRS_Signing.so is the library a host links to
# sign a document. Two names decide whether signing loads a PKCS#11 module in
# this process: the module-path resolver, and the module manager's acquire --
# the one function that dlopens the module and drives C_Initialize. If neither
# is defined in the library, signing cannot be reaching for a module; if either
# is, it can.
#
# The measurement is the DEFINED symbol set of the build-tree library, which
# still carries .symtab: the loader's own symbols are hidden (-fvisibility=
# hidden), so a .dynsym-only reading of an installed or stripped artefact would
# report the absence of something it simply cannot see. Both conditions are
# therefore checked before any verdict is given, and a tree that cannot be
# measured exits 2 rather than reporting OK -- the failure mode this whole
# family of gates exists to rule out.
#
# This check is RED BY CONSTRUCTION while the signing facade resolves and
# acquires a module in-process, which is what it does today. It is listed in
# ci/gate-wiring-exceptions.txt for that reason and is wired into CI on the day
# the facade stops doing so; until then its self-test is what keeps it honest.
#
# Usage: check-signing-no-module-loader.sh <build-dir>
#
# Exit: 0 no loader in the signing library - 1 the loader is linked in
#       2 cannot measure (no library, no symbol table, empty symbol listing)
set -uo pipefail

build="${1:-}"
if [[ -z "$build" ]]; then
    echo "usage: $(basename "$0") <build-dir>" >&2
    exit 2
fi

# The versioned file, not the development symlink: a symlink resolves to the
# same bytes today but says nothing about which artefact was measured.
so="$(ls "$build"/lib/LibreSCRS/libLibreSCRS_Signing.so.*.*.* 2>/dev/null | head -1)"
if [[ -z "$so" || ! -f "$so" ]]; then
    echo "ERROR: no libLibreSCRS_Signing.so.<version> under $build/lib/LibreSCRS -- cannot measure" >&2
    exit 2
fi

if ! readelf -S "$so" 2>/dev/null | grep -q '\.symtab'; then
    echo "ERROR: $so carries no .symtab (stripped?) -- the hidden loader symbols are unmeasurable" >&2
    exit 2
fi

out="$(nm -C --defined-only "$so" 2>/dev/null)"
if [[ -z "$out" ]]; then
    echo "ERROR: nm listed no defined symbol in $so -- cannot measure" >&2
    exit 2
fi

if hits="$(printf '%s\n' "$out" | grep -E 'resolvePkcs11ModulePath|Pkcs11ModuleManager::acquire')"; then
    echo "check-signing-no-module-loader: the signing library still defines the module loader:" >&2
    printf '%s\n' "$hits" | sed 's/^/  /' >&2
    exit 1
fi

echo "check-signing-no-module-loader: OK ($(basename "$so") defines no PKCS#11 module loader)"
