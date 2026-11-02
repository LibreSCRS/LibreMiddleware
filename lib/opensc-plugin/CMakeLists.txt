# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

librescrs_add_plugin(opensc-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/opensc_card_plugin.cpp src/opensc_reader_bridge.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        # OpenSslPtr.h (X509Ptr) for extractSubjectCN exception safety.
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
        # Internal derivation engine + quirk table headers (same
        # consumption pattern as pkcs15-plugin).
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
        # pkcs15_types.h for the standard PKCS#15 AID constant used by the
        # probe (header-only; no link against the pkcs15 lib).
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
    # The plugin's own copy of OpenSC, built without the PC/SC reader driver:
    # the plugin reaches the card only through its bridge reader.
    LINK_LIBRARIES SmartCard_Impl opensc_plugin_static_with_deps
)
