# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

librescrs_add_plugin(piv-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/piv_card_plugin.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/piv/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    LINK_LIBRARIES PIV
)
