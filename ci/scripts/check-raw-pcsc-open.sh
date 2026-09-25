#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# check-raw-pcsc-open.sh — guard the diagnostic raw-PC/SC escape hatch.
#
# PCSCConnection's reader-name ctor is private and friended only to
# CardSession (the sole sanctioned opener), so production code cannot open a
# raw PC/SC connection through the type system. The one sanctioned escape
# hatch, PCSCConnection::openRawDiagnostic(), exists solely for the
# diagnostic CLI tools (tools/) and hardware-probe tests (test/). This guard
# fails CI if any production library source under lib/ names that factory, so
# the one-session-per-reader invariant cannot regress via the escape hatch.
#
# What it catches, and what it does not. It catches an honest caller: a source
# under lib/ that names the factory to open a raw connection. It does NOT catch a
# caller inside EITHER declaring file -- both are excluded by name, because that
# is where the factory is declared and defined -- and the .cpp of the two is a
# production file of several hundred lines, not just a header. The permanent
# answer is linker separation: the diagnostic factory in an archive only the
# tools and the tests link, not a better grep.
#
# It also has to refuse a tree it cannot measure. A recursive grep over a lib/
# that is empty or absent finds nothing, which reads exactly like a clean scan:
# this check printed OK for a tree with no sources in it at all. The files that
# declare and define the factory must therefore be there, and the header must
# still declare it, before any verdict is given.
#
# Exit: 0 no production caller - 1 a production caller - 2 cannot measure.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# The exact paths that legitimately declare + define the factory itself.
# Anchored to the full path (not a basename) so a future, unrelated file that
# happens to share the basename cannot silently slip past the guard.
decl_h="lib/smartcard/src/pcsc_connection.h"
decl_cpp="lib/smartcard/src/pcsc_connection.cpp"

# Vacuum guard, ahead of the scan: an empty or unreadable tree must not be
# reported as clean.
if [[ ! -f "$decl_h" || ! -f "$decl_cpp" ]]; then
    echo "ERROR: check-raw-pcsc-open cannot measure $repo_root:" >&2
    echo "       expected $decl_h and $decl_cpp to exist" >&2
    exit 2
fi
if ! grep -q 'openRawDiagnostic' "$decl_h"; then
    echo "ERROR: check-raw-pcsc-open cannot measure $repo_root:" >&2
    echo "       $decl_h no longer declares openRawDiagnostic, so there is" >&2
    echo "       nothing here for this gate to confine" >&2
    exit 2
fi

# Scan production sources. grep exit codes: 0 = match, 1 = no match,
# >=2 = a real scan error (e.g. unreadable tree). Distinguish them so the
# guard fails CLOSED on a scan error instead of silently reporting OK.
set +e
raw="$(grep -rn 'openRawDiagnostic' lib/)"
rc=$?
set -e
if [[ "$rc" -ge 2 ]]; then
    echo "ERROR: check-raw-pcsc-open could not scan lib/ (grep exit $rc)" >&2
    exit 1
fi

# Every match OUTSIDE the declaring/defining files is a production caller and
# therefore a violation.
hits="$(printf '%s\n' "$raw" | grep -v -e "^${decl_h}:" -e "^${decl_cpp}:" || true)"
hits="$(printf '%s\n' "$hits" | grep -v '^[[:space:]]*$' || true)"

if [[ -n "$hits" ]]; then
    echo "ERROR: production code under lib/ must open PC/SC via CardSession::open," >&2
    echo "       not PCSCConnection::openRawDiagnostic (diagnostic-only):" >&2
    printf '%s\n' "$hits" >&2
    exit 1
fi

echo "check-raw-pcsc-open: OK (no lib/ source uses openRawDiagnostic)"
