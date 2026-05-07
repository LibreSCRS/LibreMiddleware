# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

librescrs_add_plugin(cardedge-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/cardedge_card_plugin.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/cardedge/src
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    LINK_LIBRARIES CardEdge
)
