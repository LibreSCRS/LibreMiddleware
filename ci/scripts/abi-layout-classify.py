#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Classify an ABI layout diff as ADDITIVE (safe within a SONAME) or
NON-ADDITIVE (requires a SOVERSION bump).

ADDITIVE  = only new lines; every line present in the baseline is still present,
            byte-identical, with the same vtable slot index.
NON-ADDITIVE = a baseline line disappeared: a sizeof/align changed, a member
            offset moved, a vtable slot changed occupant, or a type/enum/symbol
            was removed. Appending a virtual AFTER the last existing slot is
            additive; inserting one is not.

Comment lines (leading '#') carry the toolchain and the SONAME integer the
snapshot was taken under; they are metadata, not ABI facts, and are skipped.
"""
import sys

if len(sys.argv) != 3:
    print("usage: abi-layout-classify.py <baseline> <snapshot>", file=sys.stderr)
    sys.exit(2)

base = [l.rstrip('\n') for l in open(sys.argv[1], encoding='utf-8')]
new = set(l.rstrip('\n') for l in open(sys.argv[2], encoding='utf-8'))
gone = [l for l in base if l and not l.startswith('#') and l not in new]
if gone:
    print("NON-ADDITIVE — these baseline facts no longer hold:")
    for l in gone:
        print("  -", l[:150])
    sys.exit(1)
print("ADDITIVE — every baseline fact still holds.")
sys.exit(0)
