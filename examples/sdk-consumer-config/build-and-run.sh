#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# End-to-end driver for the Config-package consumer test. Builds
# LibreMiddleware as SHARED into a temp prefix, configures the consumer
# example with CMAKE_PREFIX_PATH pointing there, builds the consumer,
# runs it. Exits non-zero on any failure — drives the install-and-link
# regression check for the LibreMiddleware CMake Config package.
#
# Usage:
#   bash examples/sdk-consumer-config/build-and-run.sh

set -euo pipefail

LM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="$(mktemp -d -t lm-config-XXXXX)"
trap "rm -rf $WORK_DIR" EXIT

PREFIX="$WORK_DIR/prefix"
LM_BUILD="$WORK_DIR/lm-build"
CONSUMER_BUILD="$WORK_DIR/consumer-build"

echo "==> Building LibreMiddleware as SHARED, installing to $PREFIX"
cmake -S "$LM_ROOT" -B "$LM_BUILD" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DLIBREMIDDLEWARE_BUILD_SHARED=ON \
    -DBUILD_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX="$PREFIX"
cmake --build "$LM_BUILD" -j4

echo "==> Auditing symbol visibility on the SHARED LM build"
# Shared-config coverage for ci/scripts/check-impl-visibility.sh.
# The static-build CI job (cf. .github/workflows/ci.yml) runs the script
# against `build/`; this invocation closes the parity gap by scanning the
# LM core .so files, the plugin/pkcs11 modules, and the
# LibreSCRS_Pkcs11Inject static archive that ship from the SHARED build
# into the consumer prefix.
bash "$LM_ROOT/ci/scripts/check-impl-visibility.sh" "$LM_BUILD"

cmake --install "$LM_BUILD"

echo "==> Building consumer against installed LM"
cmake -S "$LM_ROOT/examples/sdk-consumer-config" -B "$CONSUMER_BUILD" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_PREFIX_PATH="$PREFIX"
cmake --build "$CONSUMER_BUILD" -j4

echo "==> Running consumer"
# LD_LIBRARY_PATH is needed because the consumer was configured without an
# embedded RPATH to $PREFIX/lib. In a distro install both paths are in the
# standard linker cache (e.g. /usr/lib) and this env var substitutes for
# that here. Distro packagers shipping LibreMiddleware would not need
# this step.
LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}" \
    "$CONSUMER_BUILD/sdk_consumer_config"
echo "==> OK"
