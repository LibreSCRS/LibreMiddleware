#!/usr/bin/env bash
set -euo pipefail
# Guard the vendored OpenSC submodule against drift. The bundled
# `librescrs-opensc-pkcs11` fallback module depends on the merged srbeid
# CardEdge driver (recognises Serbian eID / PKS / RFZO ATRs and routes
# them to the iso7816 / cardos path); without those commits in the
# submodule's history, the fallback module silently fails to claim the
# Serbian-card slots and the dispatcher falls through to the in-tree
# PKCS#15 module — degrading multi-card behaviour. Post-rebase upstream
# SHAs (the original PR-history SHAs are not ancestors of upstream
# master after the upstream maintainer rebase).
REQUIRED_COMMITS=(82d8fb895 7d5d10ef3 c1b5267e8 28ace0595)
cd "$(dirname "$0")/../thirdparty/opensc-source"
for sha in "${REQUIRED_COMMITS[@]}"; do
    git merge-base --is-ancestor "$sha" HEAD || {
        echo "ERROR: opensc-source missing required commit $sha"
        echo "       Update thirdparty/opensc-source submodule (or repin"
        echo "       the parent commit) so the srbeid driver is in scope."
        exit 1
    }
done
echo "opensc-pin: all required commits present (HEAD=$(git rev-parse --short HEAD))"
