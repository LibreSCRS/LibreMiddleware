#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# make-sbom.sh [output-path]
#
# A CycloneDX bill of materials for one artefact set, listing what is bundled
# inside the binaries rather than what the distribution resolved around them.
#
# Why by hand rather than by a scanner: a scanner reads package metadata, and
# the whole problem is that the shipped metadata says nothing about a statically
# linked OpenSSL 3.5.5. Measured on a real build, lintian flagged the bundled
# curl and said nothing at all about the bundled OpenSSL, so this file is the
# only place either version will ever appear. If a scanner is available its
# output is worth comparing against this one, but this one is the source of
# truth, because its inputs are the pins the build actually used.
#
# Every version and commit below is read from the tree, never typed here.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${1:-$PWD/sbom.cdx.json}"
version="$(tr -d '[:space:]' < "$repo/VERSION")"

# Every lookup below tolerates absence, because not every repository bundles
# everything: a missing pin means the component is not there, not that the
# script should stop. Without the `|| true` the failing grep would take `set -e`
# with it and the whole bill of materials would vanish over a component the
# repository correctly does not have.
pin_from_pkgbuild() {   # pin_from_pkgbuild <substring of the source URL>
  grep -oE "https://github.com/[^\"]*$1[^\"]*/([0-9a-f]{40})\.tar\.gz" \
    "$repo/packaging/arch/PKGBUILD" 2>/dev/null | grep -oE '[0-9a-f]{40}' | head -1 || true
}

opensc_sha="$(pin_from_pkgbuild OpenSC || true)"
curl_sha="$(pin_from_pkgbuild curl || true)"
curlver_h="$repo/thirdparty/curl-source/include/curl/curlver.h"
curl_ver=""
if [ -f "$curlver_h" ]; then
  curl_maj="$(awk '/^#define LIBCURL_VERSION_MAJOR /{print $3}' "$curlver_h")"
  curl_min="$(awk '/^#define LIBCURL_VERSION_MINOR /{print $3}' "$curlver_h")"
  curl_pat="$(awk '/^#define LIBCURL_VERSION_PATCH /{print $3}' "$curlver_h")"
  [ -n "$curl_maj" ] && [ -n "$curl_min" ] && [ -n "$curl_pat" ] && curl_ver="$curl_maj.$curl_min.$curl_pat"
fi
openssl_dir="$(ls -d "$repo"/thirdparty/openssl-* 2>/dev/null | head -1 || true)"
openssl_ver=""
[ -n "$openssl_dir" ] && openssl_ver="$(basename "$openssl_dir" | sed 's/^openssl-//')"
qcbor_sha=""
[ -f "$repo/cmake/FetchQCBOR.cmake" ] && \
  qcbor_sha="$(awk '/GIT_TAG/{print $2; exit}' "$repo/cmake/FetchQCBOR.cmake")"

component() {  # component <name> <version> <purl> <licence>
  printf '    {\n      "type": "library",\n      "name": "%s",\n      "version": "%s",\n      "purl": "%s",\n      "licenses": [{"license": {"id": "%s"}}]\n    }' \
    "$1" "$2" "$3" "$4"
}

{
  printf '{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.5",\n  "version": 1,\n'
  printf '  "metadata": {\n    "component": {\n      "type": "application",\n      "name": "%s",\n      "version": "%s"\n    }\n  },\n' \
    "$(basename "$repo")" "$version"
  printf '  "components": [\n'
  first=1
  emit() { [ $first -eq 1 ] || printf ',\n'; first=0; component "$@"; }
  [ -n "$openssl_ver" ] && emit openssl "$openssl_ver" "pkg:generic/openssl@$openssl_ver" Apache-2.0
  [ -n "$curl_sha" ] && [ -n "$curl_ver" ] && emit curl "$curl_ver" "pkg:github/curl/curl@$curl_sha" curl
  [ -n "$opensc_sha" ]  && emit opensc "git-$opensc_sha" "pkg:github/OpenSC/OpenSC@$opensc_sha" LGPL-2.1-or-later
  [ -n "$qcbor_sha" ]   && emit qcbor "git-$qcbor_sha" "pkg:github/laurencelundblade/QCBOR@$qcbor_sha" BSD-3-Clause
  [ -d "$repo/thirdparty/nlohmann" ] && emit nlohmann-json in-tree "pkg:generic/nlohmann-json" MIT
  [ -d "$repo/thirdparty/miniz" ] && emit miniz in-tree "pkg:generic/miniz" MIT
  printf '\n  ]\n}\n'
} > "$out"

# The count is ASSERTED, not merely printed. Every lookup above tolerates
# absence by design, which is right for one missing pin and catastrophic for
# all of them at once: a bill with no components is not a small bill, it is a
# signed document stating that this artefact bundles nothing. What it reads
# here is six optional things -- an unpacked OpenSSL directory, two commit
# hashes in the Arch recipe, a QCBOR pin in cmake/, and two in-tree header
# libraries -- and the QCBOR arm already finds nothing here, which is the point:
# every arm is allowed to come up empty, so nothing but this assertion stands
# between a tree that has moved or renamed a pin and a bill printing
# "make-sbom: 0 components", exiting 0, and being signed and published beside
# the only downloadable binary of the release.
python3 - "$out" <<'REFUSE_EMPTY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    doc = json.load(fh)
n = len(doc["components"])
print("make-sbom: %d components" % n)
if n == 0:
    print(
        "make-sbom: ERROR: no components — this script reads pins from THIS "
        "tree and found none. A bill of materials claiming an artefact "
        "bundles nothing must not be published, let alone signed.",
        file=sys.stderr,
    )
    raise SystemExit(1)
REFUSE_EMPTY
echo "make-sbom: wrote $out"
