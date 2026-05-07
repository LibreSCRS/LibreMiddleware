#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# OpenSC fallback hardware validation runner.
#
# Automates:
#   1. Build of bundled CardEdge OpenSC driver + test target
#   2. Per-user install of bundled driver + opensc.conf generation
#   3. opensc-tool --name sanity check (aborts on generic response)
#   4. Relocation of libcardedge-plugin.so + libpkcs15-plugin.so to disabled/
#   5. ctest -L HARDWARE (runs only our OpenSC fallback integration tests)
#   6. Restore plugins on any exit path (trap EXIT)
#
# Environment (optional):
#   LIBRESCRS_TEST_PIN          — PIN for tests 5 and 6; without it they SKIP

set -euo pipefail

# Absolute paths — survive any cwd
readonly REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
readonly BUILD_DIR="${REPO_DIR}/build"
readonly PLUGIN_DIR="${BUILD_DIR}/plugins"
readonly DISABLED_DIR="${PLUGIN_DIR}/disabled"
readonly OPENSC_SRC="${OPENSC_SRC:-/home/nhirsl/Dev/Code/LibreSCRS/OpenSC/src}"
readonly CONF_DIR="${HOME}/.config/opensc"
readonly CONF_FILE="${CONF_DIR}/opensc.conf"
readonly LIB_DIR="${HOME}/.local/lib"
readonly BUNDLED_DRIVER="librescrs-cardedge-opensc.so"

readonly PLUGINS_TO_DISABLE=(
    "libcardedge-plugin.so"
    "libpkcs15-plugin.so"
)

restore_plugins() {
    local rc=$?
    if [[ -d "${DISABLED_DIR}" ]]; then
        for so in "${PLUGINS_TO_DISABLE[@]}"; do
            if [[ -f "${DISABLED_DIR}/${so}" ]]; then
                mv "${DISABLED_DIR}/${so}" "${PLUGIN_DIR}/${so}"
                echo "restored: ${so}" >&2
            fi
        done
        rmdir --ignore-fail-on-non-empty "${DISABLED_DIR}"
    fi
    return $rc
}
trap restore_plugins EXIT

echo "=== Step 1/5: Build bundled driver + test target ==="
cmake -S "${REPO_DIR}" -B "${BUILD_DIR}" \
    -DBUILD_CARDEDGE_OPENSC_DRIVER=ON \
    -DOPENSC_INCLUDE_DIR="${OPENSC_SRC}" \
    -DBUILD_TESTING=ON
cmake --build "${BUILD_DIR}" -j4 \
    --target librescrs-cardedge-opensc \
             cardedge-plugin pkcs15-plugin opensc-plugin \
             OpenSCFallbackIntegrationTest

echo "=== Step 2/5: Install bundled driver + opensc.conf ==="
install -D "${BUILD_DIR}/lib/cardedge-opensc-driver/${BUNDLED_DRIVER}" "${LIB_DIR}/${BUNDLED_DRIVER}"
mkdir -p "${CONF_DIR}"
cat > "${CONF_FILE}" <<EOF
app default {
    card_drivers = librescrs, internal;
    card_driver librescrs {
        module = ${LIB_DIR}/${BUNDLED_DRIVER};
    }
    framework pkcs15 {
        emulate librescrs {
            module = ${LIB_DIR}/${BUNDLED_DRIVER};
        }
    }
}
EOF
echo "wrote: ${CONF_FILE}"

echo "=== Step 3/5: Sanity probe — opensc-tool --name ==="
export OPENSC_CONF="${CONF_FILE}"
if ! probe_output=$(opensc-tool --name 2>&1); then
    echo "opensc-tool --name failed: ${probe_output}" >&2
    exit 2
fi
echo "opensc-tool --name → ${probe_output}"
# The bundled driver's DRIVER_DESCRIPTION is "LibreSCRS Serbian CardEdge driver"
# (see lib/cardedge-opensc-driver/src/librescrs_opensc.c). If opensc-tool
# prints *that* literal string instead of an ATR-specific card name, the
# driver matched but no ATR entry hit — a generic-bind condition we want
# to fatal on. An empty response means OpenSC could not reach the card.
# If DRIVER_DESCRIPTION ever changes, update the substring below.
if [[ "${probe_output}" == *"LibreSCRS Serbian CardEdge driver"* ]] || [[ -z "${probe_output// }" ]]; then
    echo "FATAL: generic or empty card name. Bundled driver is not being picked up." >&2
    echo "       Fix driver install or opensc.conf before continuing." >&2
    exit 3
fi

echo "=== Step 4/5: Relocate plugins to disabled/ ==="
mkdir -p "${DISABLED_DIR}"
for so in "${PLUGINS_TO_DISABLE[@]}"; do
    if [[ -f "${PLUGIN_DIR}/${so}" ]]; then
        mv "${PLUGIN_DIR}/${so}" "${DISABLED_DIR}/${so}"
        echo "disabled: ${so}"
    else
        echo "skip (not present): ${so}"
    fi
done

echo "=== Step 5/5: Run OpenSCFallbackIntegrationTest ==="
# Project gotcha: no top-level CTestTestfile.cmake — ctest must be scoped to build/test/
ctest --test-dir "${BUILD_DIR}/test" -L HARDWARE --output-on-failure
# trap restores plugins on exit
