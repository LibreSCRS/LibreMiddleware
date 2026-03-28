#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build a LibreSCRS CardEdge PKCS#11 module ZIP for macOS.
#
# Usage:  ./scripts/macos/build-cardedge-pkcs11-zip.sh [BUILD_DIR]
#   BUILD_DIR  CMake build directory (default: build)
#
# Prerequisites:
#   - CMake Release build already compiled in BUILD_DIR
#
# Output: LibreSCRS-cardedge-pkcs11-<VERSION>-macos.zip in the project root.

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

LIB_DIR="$BUILD_DIR/lib/cardedge-pkcs11"

if [[ ! -d "$LIB_DIR" ]]; then
    echo "ERROR: PKCS#11 build directory not found: $LIB_DIR"
    echo "       Run: cmake --build $BUILD_DIR --target librescrs-cardedge-pkcs11"
    exit 1
fi

# Find the real (non-symlink) versioned dylib
DYLIB_VERSIONED=$(find "$LIB_DIR" -maxdepth 1 -name "librescrs-cardedge-pkcs11.[0-9]*.dylib" ! -type l | sort -V | tail -1)
if [[ -z "$DYLIB_VERSIONED" ]]; then
    echo "ERROR: No versioned dylib found in $LIB_DIR"
    exit 1
fi

PKCS11_HEADERS_DIR="$PROJECT_ROOT/lib/cardedge-pkcs11/include/cardedge-pkcs11"
PKCS11_VERSION_H="$LIB_DIR/cardedge_pkcs11_version.h"

# Stage package
STAGING_PARENT="$(mktemp -d)"
PKG_NAME="librescrs-cardedge-pkcs11-$VERSION-macos"
STAGING="$STAGING_PARENT/$PKG_NAME"

mkdir -p "$STAGING/lib" "$STAGING/include/cardedge-pkcs11"

echo "Staging library..."
cp "$DYLIB_VERSIONED" "$STAGING/lib/librescrs-cardedge-pkcs11.$VERSION.dylib"
(
    cd "$STAGING/lib"
    ln -sf "librescrs-cardedge-pkcs11.$VERSION.dylib" "librescrs-cardedge-pkcs11.1.dylib"
    ln -sf "librescrs-cardedge-pkcs11.1.dylib"        "librescrs-cardedge-pkcs11.dylib"
)

echo "Ad-hoc signing..."
codesign --force --sign - "$STAGING/lib/librescrs-cardedge-pkcs11.$VERSION.dylib"

echo "Copying headers..."
cp "$PKCS11_HEADERS_DIR/pkcs11.h"  "$STAGING/include/cardedge-pkcs11/"
cp "$PKCS11_HEADERS_DIR/pkcs11t.h" "$STAGING/include/cardedge-pkcs11/"
cp "$PKCS11_HEADERS_DIR/pkcs11f.h" "$STAGING/include/cardedge-pkcs11/"
cp "$PKCS11_VERSION_H"             "$STAGING/include/"

cat > "$STAGING/README.txt" << EOF
LibreSCRS PKCS#11 Module for macOS — version $VERSION
======================================================

CONTENTS
  lib/librescrs-cardedge-pkcs11.$VERSION.dylib   Universal (arm64 + x86_64) PKCS#11 module
  lib/librescrs-cardedge-pkcs11.1.dylib          Soname symlink
  lib/librescrs-cardedge-pkcs11.dylib            Unversioned symlink
  include/cardedge-pkcs11/                        Standard OASIS PKCS#11 v3.x headers
  include/cardedge_pkcs11_version.h               LibreSCRS version macros

INSTALLATION
  Copy the lib/ contents to a directory of your choice, e.g.:
    sudo cp -R lib/ /usr/local/lib/

  Example — verify with OpenSC tools:
    pkcs11-tool --module /usr/local/lib/librescrs-cardedge-pkcs11.dylib --list-slots

DEPENDENCIES
  The module links only against system frameworks:
    PCSC.framework   (built-in macOS smart card subsystem)
    libz, libc++, libSystem

GATEKEEPER NOTE
  This build is ad-hoc signed (no Apple notarisation).  On first use
  macOS may warn "unidentified developer".  To allow it:
    System Settings → Privacy & Security → scroll down → "Allow Anyway"

LICENSE
  LGPL-2.1-or-later  — see https://github.com/LibreSCRS/LibreMiddleware
EOF

OUTPUT="$PROJECT_ROOT/LibreSCRS-cardedge-pkcs11-$VERSION-macos.zip"
echo "Creating ZIP..."
(cd "$STAGING_PARENT" && zip -r -y "$OUTPUT" "$PKG_NAME")

echo ""
echo "ZIP created: $OUTPUT"
