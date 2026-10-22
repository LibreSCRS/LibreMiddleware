#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Linker launcher on macOS: runs the link command it is given, then signs its
# output ad hoc with the smart-card entitlement.
#
#   sign-smartcard-after-link.sh <entitlements.plist> <link command...>
set -eu
plist=$1
shift
"$@"
out=
prev=
for arg in "$@"; do
    if [ "$prev" = "-o" ]; then
        out=$arg
    fi
    prev=$arg
done
if [ -z "$out" ]; then
    echo "sign-smartcard-after-link.sh: the link command names no -o output" >&2
    exit 1
fi
exec codesign --force --sign - --entitlements "$plist" "$out"
