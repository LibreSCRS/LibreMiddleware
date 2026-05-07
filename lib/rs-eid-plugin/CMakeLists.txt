# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

librescrs_add_plugin(rs-eid-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/eid_card_plugin.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/rs-eid/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    LINK_LIBRARIES RsEId LibreSCRS_Trust
    COMPILE_DEFINITIONS
        LIBREMIDDLEWARE_CERT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/certificates"
)
