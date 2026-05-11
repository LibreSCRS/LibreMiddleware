#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-pkcs11-rpath.sh — install-time guard for librescrs-pkcs11
#
# Enforces two invariants on a finished install tree:
#
#   1) librescrs-pkcs11.so carries a relative RPATH/RUNPATH so the
#      runtime loader resolves sibling LibreSCRS shared libraries
#      without LD_LIBRARY_PATH being set in the consumer's environment.
#
#   2) p11-kit list-modules, invoked with LD_LIBRARY_PATH UNSET, lists
#      the module — i.e. the loader actually resolves the NEEDED chain
#      from RPATH alone, the way real consumers will at runtime.
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

# Resolve module .so. Distros may install to lib/ or lib64/.
MODULE=""
for libdir in lib lib64; do
    candidate="$PREFIX/$libdir/pkcs11/librescrs-pkcs11.so"
    if [[ -f "$candidate" ]]; then
        MODULE="$candidate"
        break
    fi
done
if [[ -z "$MODULE" ]]; then
    echo "error: librescrs-pkcs11.so not found under $PREFIX/{lib,lib64}/pkcs11/" >&2
    exit 1
fi

echo "module: $MODULE"

# ---------------------------------------------------------------------------
# Invariant 1: RPATH/RUNPATH points to sibling lib dir
# ---------------------------------------------------------------------------
UNAME=$(uname -s)
case "$UNAME" in
    Linux)
        # readelf -d prints both DT_RPATH (legacy) and DT_RUNPATH. Either
        # is acceptable; the binding semantics differ but both let the
        # loader resolve sibling NEEDED entries from a relative path.
        RPATH=$(readelf -d "$MODULE" 2>/dev/null \
            | awk -F'[][]' '/R(UN)?PATH/ {print $2}' \
            | tr ':' '\n')
        EXPECTED='$ORIGIN/..'
        ;;
    Darwin)
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

# ---------------------------------------------------------------------------
# Invariant 2: p11-kit resolves the module without LD_LIBRARY_PATH
# ---------------------------------------------------------------------------
# p11-kit must be present; without it the registration step in the
# install rule has nothing to consume anyway.
if ! command -v p11-kit >/dev/null 2>&1; then
    echo "warn: p11-kit not installed; skipping live-load probe" >&2
    exit 0
fi

# Point p11-kit at a synthetic config that references the freshly
# installed .so by absolute path, so the probe is independent of any
# user/system .module that may already be installed.
MODULE_CONF_DIR=$(mktemp -d)
trap 'rm -rf "$MODULE_CONF_DIR"' EXIT
cat >"$MODULE_CONF_DIR/librescrs.module" <<EOF
module: $MODULE
priority: 10
EOF

# Strip LD_LIBRARY_PATH so the probe exercises the runtime loader path a
# real consumer sees, not whatever the developer's shell happens to set.
OUTPUT=$(
    env -u LD_LIBRARY_PATH \
        P11_KIT_MODULE_PATH="$MODULE_CONF_DIR" \
        p11-kit list-modules --verbose 2>&1
)

if grep -q "couldn't load module:.*librescrs-pkcs11.so" <<<"$OUTPUT"; then
    REASON=$(grep "couldn't load module:.*librescrs-pkcs11.so" <<<"$OUTPUT" \
        | sed 's/.*librescrs-pkcs11.so: //')
    echo "FAIL: p11-kit cannot load $MODULE without LD_LIBRARY_PATH" >&2
    echo "      reason: $REASON" >&2
    echo "      RPATH is set but does not resolve a NEEDED dependency." >&2
    exit 1
fi

if ! grep -q "^module: librescrs" <<<"$OUTPUT"; then
    echo "FAIL: p11-kit did not register 'librescrs' module" >&2
    echo "      p11-kit list-modules output:" >&2
    sed 's/^/        /' <<<"$OUTPUT" >&2
    exit 1
fi

echo "  p11-kit ok: module loaded without LD_LIBRARY_PATH"
echo "PASS"
