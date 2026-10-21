#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# check-opensc-plugin-no-pcsc.sh — the OpenSC card plugin carries no PC/SC
# reader driver.
#
# The plugin reaches a card only through the bridge reader it installs over the
# session it is handed. Its copy of OpenSC is therefore built without the PC/SC
# reader driver: with it, every context the plugin created enumerated every
# reader on the host and connected to each one. The vendored OpenSC is built
# twice for that, and nothing but the link line decides which copy the plugin
# gets, so this check reads the copy the plugin was given and the plugin itself.
#
# Both are judged by their symbol tables. A PC/SC symbol (SCard*, or one of
# OpenSC's own pcsc_* reader functions) in either is a failure. The CT-API
# driver that stands in for PC/SC (OpenSC requires exactly one reader driver)
# must be there: an image without it is not the plugin's copy at all, or has
# no symbol table to read, and either way it cannot be judged.
#
# Usage: check-opensc-plugin-no-pcsc.sh [BUILD_DIR]   (default: build)
# Exit:  0 no PC/SC in the plugin - 1 PC/SC found - 2 cannot measure.
set -uo pipefail

build_dir="${1:-build}"

command -v nm >/dev/null 2>&1 \
    || { echo "ERROR: nm not found on PATH -- cannot read a symbol table" >&2; exit 2; }

archive="$build_dir/thirdparty/opensc-plugin-install/lib/libopensc.a"
module=""
for candidate in "$build_dir/plugins/libopensc-plugin.so" "$build_dir/plugins/libopensc-plugin.dylib"; do
    if [[ -f "$candidate" ]]; then
        module="$candidate"
    fi
done

if [[ ! -f "$archive" ]]; then
    echo "ERROR: cannot measure: the plugin's OpenSC archive is not at $archive" >&2
    exit 2
fi
if [[ -z "$module" ]]; then
    echo "ERROR: cannot measure: no libopensc-plugin.so or .dylib under $build_dir/plugins" >&2
    exit 2
fi

# symbol_names <image> -- one symbol name per line, the leading underscore the
# Mach-O symbol table adds removed so both platforms read the same names.
symbol_names() {
    local out
    out="$(nm "$1" 2>/dev/null)" || return 2
    printf '%s\n' "$out" | awk 'NF >= 2 { print $NF }' | sed 's/^_//'
}

# Every image is judged before the verdict, so a PC/SC symbol found in one is
# reported as such even when the other cannot be read.
found=0
unmeasured=0
for image in "$archive" "$module"; do
    if ! names="$(symbol_names "$image")"; then
        echo "ERROR: cannot measure: nm cannot read $image" >&2
        unmeasured=1
        continue
    fi
    pcsc="$(printf '%s\n' "$names" | grep -E '^(SCard[A-Za-z]*|pcsc_[A-Za-z0-9_]*)$' | sort -u)"
    if [[ -n "$pcsc" ]]; then
        echo "FAIL: $image carries the PC/SC reader driver:"
        printf '%s\n' "$pcsc" | sed 's/^/  /'
        found=1
        continue
    fi
    # grep without -q: under pipefail an early exit would SIGPIPE printf and
    # read as "not found" on any symbol table large enough to matter.
    if ! printf '%s\n' "$names" | grep -x 'ctapi_init' >/dev/null; then
        echo "ERROR: cannot measure: $image has no ctapi_init, so it is not the plugin's" >&2
        echo "       copy of OpenSC or its symbol table is gone" >&2
        unmeasured=1
    fi
done

if [[ "$found" -ne 0 ]]; then
    exit 1
fi
if [[ "$unmeasured" -ne 0 ]]; then
    exit 2
fi
echo "check-opensc-plugin-no-pcsc: OK ($archive and $module carry no PC/SC symbol)"
exit 0
