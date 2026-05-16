# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

librescrs_add_plugin(emrtd-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/emrtd_card_plugin.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/emrtd/src
        ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    LINK_LIBRARIES EMRTD LibreSCRS_Plugin LibreSCRS_SmartCard LibreSCRS_SecureChannel
)
