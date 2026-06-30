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
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# The exact paths that legitimately declare + define the factory itself.
# Anchored to the full path (not a basename) so a future, unrelated file that
# happens to share the basename cannot silently slip past the guard.
decl_h="lib/smartcard/src/pcsc_connection.h"
decl_cpp="lib/smartcard/src/pcsc_connection.cpp"

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
