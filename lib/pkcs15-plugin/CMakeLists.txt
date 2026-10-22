# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

librescrs_add_plugin(pkcs15-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/pkcs15_card_plugin.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
        # The shared internal Crypto headers (the PKCS#1 v1.5 DigestInfo builder).
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
    LINK_LIBRARIES PKCS15 EMRTDCrypto LibreSCRS_SmartCard LibreSCRS_SecureChannel LibreSCRS_Certificate
)
