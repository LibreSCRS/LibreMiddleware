#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Pre-expiry alert for pinned TL signing certificates.
#
# Fails if any std::array<uint8_t,N> in
# lib/libresign/src/native/pinned_tl_certs.h has notAfter within the
# next 90 days, so a release rotation lands well before the cert
# expires and triggers the runtime hard-fail in
# tl_signature_verifier.cpp.
#
# Usage: check-pinned-cert-expiry.sh [--days <n>]
#
# The window is an argument, not an environment variable. It used to be
# `${THRESHOLD_DAYS:-90}`, which meant any caller could export
# THRESHOLD_DAYS=0 and this check would pass on a certificate expiring
# tomorrow -- measured: 0 gave exit 0 and 100000 gave exit 1, so the value was
# read and a caller could pick it. A switch that turns a release check off is
# not a transfer of ownership; whoever wants a different window says so on the
# command line, where the workflow that did it is the record.
set -euo pipefail

THRESHOLD_DAYS=90
while [[ $# -gt 0 ]]; do
    case "$1" in
        --days)
            [[ $# -ge 2 ]] || { echo "check-pinned-cert-expiry: --days needs a value" >&2; exit 2; }
            THRESHOLD_DAYS="$2"
            shift 2
            ;;
        --days=*)
            THRESHOLD_DAYS="${1#*=}"
            shift
            ;;
        *)
            echo "check-pinned-cert-expiry: usage: $(basename "$0") [--days <n>]" >&2
            exit 2
            ;;
    esac
done

if [[ ! "$THRESHOLD_DAYS" =~ ^[0-9]+$ ]]; then
    echo "check-pinned-cert-expiry: --days takes a whole number of days, got '$THRESHOLD_DAYS'" >&2
    exit 2
fi

# Without these the check cannot say anything about a certificate, and an
# unreadable certificate must not be spelled the same way as an expiring one.
for tool in openssl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "check-pinned-cert-expiry: $tool not found on PATH -- cannot judge expiry" >&2
        exit 2
    fi
done

HEADER="lib/libresign/src/native/pinned_tl_certs.h"
if [[ ! -f "$HEADER" ]]; then
    echo "check-pinned-cert-expiry: $HEADER not found (run from repo root)" >&2
    exit 2
fi

python3 - "$HEADER" "$THRESHOLD_DAYS" <<'PY'
import datetime
import re
import subprocess
import sys
import tempfile
from pathlib import Path

header = Path(sys.argv[1]).read_text()
threshold_days = int(sys.argv[2])
threshold = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=threshold_days)

# Match every `inline constexpr std::array<uint8_t, N> kName = { ... };`
# block. The body holds 0xHH byte literals; convert to binary DER and
# pipe through `openssl x509 -inform DER -noout -enddate`.
pattern = re.compile(
    r"inline\s+constexpr\s+std::array<uint8_t,\s*\d+>\s+(\w+)\s*=\s*\{(.*?)\};",
    re.DOTALL,
)

bad = 0
matched = 0
for match in pattern.finditer(header):
    name = match.group(1)
    body = match.group(2)
    bytes_seen = [int(h, 16) for h in re.findall(r"0[xX]([0-9A-Fa-f]{1,2})", body)]
    if not bytes_seen:
        continue
    matched += 1
    der = bytes(bytes_seen)
    with tempfile.NamedTemporaryFile(suffix=".der") as f:
        f.write(der)
        f.flush()
        result = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-enddate"],
            stdin=open(f.name, "rb"),
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        print(f"check-pinned-cert-expiry: openssl rejected {name}: {result.stderr.strip()}", file=sys.stderr)
        bad += 1
        continue
    notafter_str = result.stdout.strip().split("=", 1)[1]
    # OpenSSL format: "Nov 17 10:11:46 2027 GMT"
    dt = datetime.datetime.strptime(notafter_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    if dt < threshold:
        days = (dt - datetime.datetime.now(datetime.timezone.utc)).days
        print(
            f"check-pinned-cert-expiry: {name} notAfter={notafter_str} ({days} days) within {threshold_days}-day window",
            file=sys.stderr,
        )
        bad += 1
    else:
        days = (dt - datetime.datetime.now(datetime.timezone.utc)).days
        print(f"check-pinned-cert-expiry: {name} notAfter={notafter_str} ({days} days) OK")

if matched == 0:
    print("check-pinned-cert-expiry: no pinned-cert arrays found", file=sys.stderr)
    sys.exit(2)
sys.exit(1 if bad else 0)
PY
