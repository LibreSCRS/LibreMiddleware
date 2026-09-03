#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-pkcs11-rpath.sh — install-time guard for librescrs-pkcs11
#
# Enforces ONE invariant on a finished install tree:
#
#   librescrs-pkcs11.so carries a relative RPATH/RUNPATH, so the runtime loader
#   resolves the sibling LibreSCRS shared libraries without LD_LIBRARY_PATH
#   being set in the consumer's environment.
#
# This script used to carry a second invariant — "p11-kit lists the module" —
# and it could not observe what it claimed to. It exported P11_KIT_MODULE_PATH,
# a variable p11-kit does not have (the ones it does are P11_KIT_DEBUG,
# P11_KIT_NO_USER_CONFIG, P11_KIT_STRICT, P11_KIT_URI_LOWERCASE), so instead of
# reading its synthetic configuration it read the machine's own — and matched
# the module name by prefix, which also matches the agent proxy. It exited zero
# when p11-kit was absent, reporting success for something it had not looked at.
# Registration is now covered by a check that enumerates what a host actually
# loads, so it is not restated here.
#
# Usage:
#   check-pkcs11-rpath.sh <install-prefix>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <install-prefix>" >&2
    exit 2
fi

PREFIX="$1"
if [[ ! -d "$PREFIX" ]]; then
    echo "error: install prefix not found: $PREFIX" >&2
    exit 2
fi

# Resolve module .so. The library directory is a property of the build that
# installed it: lib on Arch, lib64 on Fedora, a multiarch triplet on Debian.
MODULE=""
for libdir in lib lib64 "lib/$(uname -m)-linux-gnu"; do
    candidate="$PREFIX/$libdir/pkcs11/librescrs-pkcs11.so"
    if [[ -f "$candidate" ]]; then
        MODULE="$candidate"
        break
    fi
done
if [[ -z "$MODULE" ]]; then
    echo "error: librescrs-pkcs11.so not found under $PREFIX/{lib,lib64,lib/<triplet>}/pkcs11/" >&2
    exit 1
fi

echo "module: $MODULE"

# ---------------------------------------------------------------------------
# Invariant 1: RPATH/RUNPATH points to sibling lib dir
# ---------------------------------------------------------------------------
# An absent reader is a failure, not a skip: a check that reports success on a
# host where it inspected nothing is worse than no check at all.
UNAME=$(uname -s)
case "$UNAME" in
    Linux)
        command -v readelf >/dev/null 2>&1 || {
            echo "error: readelf not available; the rpath cannot be observed." >&2
            echo "       Install binutils in the test environment rather than skipping." >&2
            exit 2
        }
        # readelf -d prints both DT_RPATH (legacy) and DT_RUNPATH. Either
        # is acceptable; the binding semantics differ but both let the
        # loader resolve sibling NEEDED entries from a relative path.
        RPATH=$(readelf -d "$MODULE" 2>/dev/null \
            | awk -F'[][]' '/R(UN)?PATH/ {print $2}' \
            | tr ':' '\n')
        EXPECTED='$ORIGIN/..'
        ;;
    Darwin)
        command -v otool >/dev/null 2>&1 || {
            echo "error: otool not available; the rpath cannot be observed." >&2
            exit 2
        }
        # otool -l emits LC_RPATH load commands as "path <value>" lines.
        RPATH=$(otool -l "$MODULE" 2>/dev/null \
            | awk '/LC_RPATH/{flag=1;next} flag && /path /{print $2; flag=0}')
        EXPECTED='@loader_path/..'
        ;;
    *)
        echo "error: unsupported platform: $UNAME" >&2
        exit 2
        ;;
esac

if [[ -z "$RPATH" ]]; then
    echo "FAIL: $MODULE has no RPATH/RUNPATH set" >&2
    echo "      expected an entry containing '$EXPECTED'" >&2
    echo "      consumers will fail to load the module unless" >&2
    echo "      LD_LIBRARY_PATH is set externally." >&2
    exit 1
fi

if ! grep -Fqx -- "$EXPECTED" <<<"$RPATH" \
   && ! grep -Fq -- "$EXPECTED" <<<"$RPATH"; then
    echo "FAIL: $MODULE RPATH does not contain '$EXPECTED'" >&2
    echo "      actual:" >&2
    sed 's/^/        /' <<<"$RPATH" >&2
    exit 1
fi

echo "  rpath ok: $(tr '\n' ' ' <<<"$RPATH")"

echo "PASS"
