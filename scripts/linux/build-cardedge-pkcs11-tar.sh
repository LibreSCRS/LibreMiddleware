#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Build a LibreSCRS CardEdge PKCS#11 module tarball for Linux.
#
# Usage:  ./scripts/linux/build-cardedge-pkcs11-tar.sh [BUILD_DIR]
#   BUILD_DIR  CMake build directory (default: build)
#
# Prerequisites:
#   - CMake Release build already compiled in BUILD_DIR
#
# Output: LibreSCRS-cardedge-pkcs11-<VERSION>-linux-<ARCH>.tar.gz in the project root.

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
LIB_DIR="$BUILD_DIR/lib/cardedge-pkcs11"

if [[ ! -d "$LIB_DIR" ]]; then
    echo "ERROR: PKCS#11 build directory not found: $LIB_DIR"
    echo "       Run: cmake --build $BUILD_DIR --target librescrs-cardedge-pkcs11"
    exit 1
fi

# Find the real (non-symlink) versioned .so
SO_VERSIONED=$(find "$LIB_DIR" -maxdepth 1 -name "librescrs-cardedge-pkcs11.so.[0-9]*.[0-9]*" ! -type l | sort -V | tail -1)
if [[ -z "$SO_VERSIONED" ]]; then
    echo "ERROR: No versioned .so found in $LIB_DIR"
    exit 1
fi

PKCS11_HEADERS_DIR="$PROJECT_ROOT/lib/cardedge-pkcs11/include/cardedge-pkcs11"
PKCS11_VERSION_H="$LIB_DIR/cardedge_pkcs11_version.h"

# Stage package
STAGING_PARENT="$(mktemp -d)"
PKG_NAME="librescrs-cardedge-pkcs11-$VERSION-linux-$ARCH"
STAGING="$STAGING_PARENT/$PKG_NAME"

mkdir -p "$STAGING/lib" "$STAGING/include/cardedge-pkcs11" "$STAGING/p11-kit"

echo "Staging library..."
cp "$SO_VERSIONED" "$STAGING/lib/librescrs-cardedge-pkcs11.so.$VERSION"
(
    cd "$STAGING/lib"
    ln -sf "librescrs-cardedge-pkcs11.so.$VERSION" "librescrs-cardedge-pkcs11.so.1"
    ln -sf "librescrs-cardedge-pkcs11.so.1"        "librescrs-cardedge-pkcs11.so"
)

echo "Creating p11-kit module file..."
cat > "$STAGING/p11-kit/librescrs.module" << 'MODEOF'
# p11-kit module registration for LibreSCRS PKCS#11
# Install to: /usr/share/p11-kit/modules/ (system-wide)
#         or: ~/.config/pkcs11/modules/    (per-user)
module: /usr/local/lib/librescrs-cardedge-pkcs11.so
MODEOF

echo "Copying headers..."
cp "$PKCS11_HEADERS_DIR/pkcs11.h"  "$STAGING/include/cardedge-pkcs11/"
cp "$PKCS11_HEADERS_DIR/pkcs11t.h" "$STAGING/include/cardedge-pkcs11/"
cp "$PKCS11_HEADERS_DIR/pkcs11f.h" "$STAGING/include/cardedge-pkcs11/"
cp "$PKCS11_VERSION_H"             "$STAGING/include/"

cat > "$STAGING/README.txt" << EOF
LibreSCRS PKCS#11 Module for Linux — version $VERSION ($ARCH)
==============================================================

CONTENTS
  lib/librescrs-cardedge-pkcs11.so.$VERSION   The shared PKCS#11 module
  lib/librescrs-cardedge-pkcs11.so.1          Soname symlink
  lib/librescrs-cardedge-pkcs11.so            Unversioned symlink
  include/cardedge-pkcs11/                     Standard OASIS PKCS#11 v3.x headers
  include/cardedge_pkcs11_version.h            LibreSCRS version macros
  p11-kit/librescrs.module            p11-kit module registration file

INSTALLATION
  1. Copy the library:
    sudo cp lib/librescrs-cardedge-pkcs11.so.$VERSION /usr/local/lib/
    sudo ln -sf librescrs-cardedge-pkcs11.so.$VERSION /usr/local/lib/librescrs-cardedge-pkcs11.so.1
    sudo ln -sf librescrs-cardedge-pkcs11.so.1        /usr/local/lib/librescrs-cardedge-pkcs11.so
    sudo ldconfig

  2. Register with p11-kit (makes the module available to all p11-kit
     consumers — Chromium, GnuTLS apps, GNOME Keyring, etc.):

    System-wide:
      sudo cp p11-kit/librescrs.module /usr/share/p11-kit/modules/

    Per-user:
      mkdir -p ~/.config/pkcs11/modules
      cp p11-kit/librescrs.module ~/.config/pkcs11/modules/

  3. Verify:
    p11-kit list-modules | grep -A5 librescrs
    pkcs11-tool --module /usr/local/lib/librescrs-cardedge-pkcs11.so --list-slots

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

OUTPUT="$PROJECT_ROOT/LibreSCRS-cardedge-pkcs11-$VERSION-linux-$ARCH.tar.gz"
echo "Creating tarball..."
tar -czf "$OUTPUT" -C "$STAGING_PARENT" "$PKG_NAME"

echo ""
echo "Tarball created: $OUTPUT"
