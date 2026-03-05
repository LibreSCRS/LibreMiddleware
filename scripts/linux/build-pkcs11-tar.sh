#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build a LibreSCRS PKCS#11 module tarball for Linux.
#
# Usage:  ./scripts/linux/build-pkcs11-tar.sh [BUILD_DIR]
#   BUILD_DIR  CMake build directory (default: build)
#
# Prerequisites:
#   - CMake Release build already compiled in BUILD_DIR
#
# Output: LibreSCRS-pkcs11-<VERSION>-linux-<ARCH>.tar.gz in the project root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="${1:-$PROJECT_ROOT/build}"

# Version from git tag
VERSION=$(git -C "$PROJECT_ROOT" describe --tags --abbrev=0 2>/dev/null || true)
if [[ -z "$VERSION" ]]; then
    echo "ERROR: Could not determine version from git tags"
    exit 1
fi
echo "Version: $VERSION"

ARCH=$(uname -m)
LIB_DIR="$BUILD_DIR/lib/pkcs11"

if [[ ! -d "$LIB_DIR" ]]; then
    echo "ERROR: PKCS#11 build directory not found: $LIB_DIR"
    echo "       Run: cmake --build $BUILD_DIR --target librescrs-pkcs11"
    exit 1
fi

# Find the real (non-symlink) versioned .so
SO_VERSIONED=$(find "$LIB_DIR" -maxdepth 1 -name "librescrs-pkcs11.so.[0-9]*.[0-9]*" ! -type l | sort -V | tail -1)
if [[ -z "$SO_VERSIONED" ]]; then
    echo "ERROR: No versioned .so found in $LIB_DIR"
    exit 1
fi

PKCS11_HEADERS_DIR="$PROJECT_ROOT/lib/pkcs11/include/pkcs11"
PKCS11_VERSION_H="$LIB_DIR/pkcs11_version.h"

# Stage package
STAGING_PARENT="$(mktemp -d)"
PKG_NAME="librescrs-pkcs11-$VERSION-linux-$ARCH"
STAGING="$STAGING_PARENT/$PKG_NAME"

mkdir -p "$STAGING/lib" "$STAGING/include/pkcs11"

echo "Staging library..."
cp "$SO_VERSIONED" "$STAGING/lib/librescrs-pkcs11.so.$VERSION"
(
    cd "$STAGING/lib"
    ln -sf "librescrs-pkcs11.so.$VERSION" "librescrs-pkcs11.so.1"
    ln -sf "librescrs-pkcs11.so.1"        "librescrs-pkcs11.so"
)

echo "Copying headers..."
cp "$PKCS11_HEADERS_DIR/pkcs11.h"  "$STAGING/include/pkcs11/"
cp "$PKCS11_HEADERS_DIR/pkcs11t.h" "$STAGING/include/pkcs11/"
cp "$PKCS11_HEADERS_DIR/pkcs11f.h" "$STAGING/include/pkcs11/"
cp "$PKCS11_VERSION_H"             "$STAGING/include/"

cat > "$STAGING/README.txt" << EOF
LibreSCRS PKCS#11 Module for Linux — version $VERSION ($ARCH)
==============================================================

CONTENTS
  lib/librescrs-pkcs11.so.$VERSION   The shared PKCS#11 module
  lib/librescrs-pkcs11.so.1          Soname symlink
  lib/librescrs-pkcs11.so            Unversioned symlink
  include/pkcs11/                     Standard OASIS PKCS#11 v3.x headers
  include/pkcs11_version.h            LibreSCRS version macros

INSTALLATION
  Copy the lib/ contents to a directory on the library path, e.g.:
    sudo cp lib/librescrs-pkcs11.so.$VERSION /usr/local/lib/
    sudo ln -sf librescrs-pkcs11.so.$VERSION /usr/local/lib/librescrs-pkcs11.so.1
    sudo ln -sf librescrs-pkcs11.so.1        /usr/local/lib/librescrs-pkcs11.so
    sudo ldconfig

  To register the module with a PKCS#11-aware application, point it at the
  full path of librescrs-pkcs11.so (or the versioned file).

  Example — verify with OpenSC tools:
    pkcs11-tool --module /usr/local/lib/librescrs-pkcs11.so --list-slots

DEPENDENCIES
  The module links against:
    libpcsclite.so   (PC/SC lite smart card daemon client)
    libz, libstdc++, libm

  Ensure pcscd is installed and running:
    sudo apt install pcscd libpcsclite1   # Debian/Ubuntu
    sudo dnf install pcsc-lite           # Fedora/RHEL

LICENSE
  LGPL-2.1-or-later  — see https://github.com/LibreSCRS/LibreMiddleware
EOF

OUTPUT="$PROJECT_ROOT/LibreSCRS-pkcs11-$VERSION-linux-$ARCH.tar.gz"
echo "Creating tarball..."
tar -czf "$OUTPUT" -C "$STAGING_PARENT" "$PKG_NAME"

echo ""
echo "Tarball created: $OUTPUT"
