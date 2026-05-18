#!/usr/bin/env bash
# Pre-expiry alert for pinned TL signing certificates.
#
# Fails if any std::array<uint8_t,N> in
# lib/libresign/src/native/pinned_tl_certs.h has notAfter within the
# next 90 days, so a release rotation lands well before the cert
# expires and triggers the runtime hard-fail in
# tl_signature_verifier.cpp.
set -euo pipefail

THRESHOLD_DAYS="${THRESHOLD_DAYS:-90}"

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
