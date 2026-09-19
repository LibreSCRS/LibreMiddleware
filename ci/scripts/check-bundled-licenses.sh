#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-bundled-licenses.sh -- the licence texts shipped beside the vendored code
# are the ones the manifest pins.
#
# thirdparty/licenses.json names, per bundled component, the licence file and a
# sha256 of it. Nothing read that hash: the manifest is consumed downstream by
# packaging, and in this repository it was four pinned digests that no step ever
# compared. Moving the curl submodule changed its COPYING file and the manifest
# went on asserting the previous one -- a signed statement about what a package
# is licensed under, quietly describing a different file.
#
# Property, not proxy: the hash is recomputed from the file on disk. There is
# nothing else it could be compared against, which is the point -- a manifest
# entry is only worth its digest if somebody recomputes it.
#
# Exit: 0 every pinned digest matches - 1 one does not, or a named file is
#       missing - 2 cannot measure (no manifest, unparseable, no python3)
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST="${1:-$repo/thirdparty/licenses.json}"

[ -f "$MANIFEST" ] || { echo "FATAL: $MANIFEST not found -- cannot measure" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 not on PATH -- cannot measure" >&2; exit 2; }

python3 - "$MANIFEST" "$(dirname "$MANIFEST")" <<'PY'
import hashlib
import json
import os
import sys

manifest, root = sys.argv[1], sys.argv[2]
try:
    with open(manifest, encoding="utf-8") as fh:
        doc = json.load(fh)
    components = doc["components"]
except Exception as exc:  # noqa: BLE001 - any shape problem is "cannot measure"
    print("FATAL: %s: %s" % (manifest, exc), file=sys.stderr)
    raise SystemExit(2)

if not components:
    print("FATAL: %s lists no components -- a manifest that pins nothing is not a pass"
          % manifest, file=sys.stderr)
    raise SystemExit(2)

rc = 0
for c in components:
    name = c.get("name", "<unnamed>")
    rel = c.get("text")
    want = c.get("sha256")
    if not rel or not want:
        print("FAIL: %s: the entry carries no licence file or no digest" % name, file=sys.stderr)
        rc = 1
        continue
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        print("FAIL: %s: %s is named in the manifest and is not there" % (name, rel), file=sys.stderr)
        rc = 1
        continue
    with open(path, "rb") as fh:
        got = hashlib.sha256(fh.read()).hexdigest()
    if got != want:
        print("FAIL: %s: %s hashes to %s, the manifest pins %s" % (name, rel, got, want),
              file=sys.stderr)
        rc = 1

if rc == 0:
    print("check-bundled-licenses: %d pinned licence text(s) match" % len(components))
raise SystemExit(rc)
PY
