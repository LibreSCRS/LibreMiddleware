#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Refuse to publish a release whose bill of materials is missing or empty.

The producer already refuses to write an empty bill. This refuses to PUBLISH
one: it reads the document that actually reached the release directory, so it
also catches the bill that never arrived -- a job that produced none, or a
download step that did not merge it. Neither of those says anything today.

The two claims are deliberately made in two places. The producer runs against
this tree and knows what it looked for; this runs against the release
directory and knows only what a consumer will download. A byte-identical copy
of that producer shipped in five repositories, most of which carry at most a
fragment of the pins it reads; the copy that was wired into a release carried
none of them, printed "0 components", exited 0, and the empty document was
signed and published.

What it reads is the document, not the job that produced it: the bill must
parse, name CycloneDX, carry a non-empty components array, and every
component must have a name. It does not verify that the bill describes the
artefact beside it -- that is the producer's job.

Usage:  check-sbom.py <bill.cdx.json> [<bill.cdx.json> ...]
"""

import json
import sys


def check(path: str) -> str:
    """Return an error string, or "" when the bill is publishable."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return f"{path}: missing — the build job published no bill of materials"
    except (OSError, ValueError) as exc:
        return f"{path}: unreadable ({exc})"

    if doc.get("bomFormat") != "CycloneDX":
        return f"{path}: not a CycloneDX document"
    components = doc.get("components")
    if not isinstance(components, list):
        return f"{path}: no components array"
    if not components:
        return (
            f"{path}: zero components — a signed bill claiming this artefact "
            f"bundles nothing must not be published"
        )
    nameless = [c for c in components if not c.get("name")]
    if nameless:
        return f"{path}: {len(nameless)} components carry no name"
    print(f"check-sbom: {path}: {len(components)} components")
    return ""


def main(argv):
    if not argv:
        print("usage: check-sbom.py <bill.cdx.json> ...", file=sys.stderr)
        return 2
    errors = [e for e in (check(p) for p in argv) if e]
    for e in errors:
        print(f"::error::{e}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
