# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

librescrs_add_plugin(opensc-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/opensc_card_plugin.cpp src/opensc_reader_bridge.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        # pkcs15_cert_ptr.h was relocated to the sibling opensc-pkcs11
        # internal source dir so a second OpenSC consumer
        # (OpenScSlot::enumerateObjects) can reuse the Pkcs15CertPtr
        # RAII wrapper without duplicating it. Header-only, hidden visibility.
        ${PROJECT_SOURCE_DIR}/lib/opensc-pkcs11/src
        # OpenSslPtr.h (X509Ptr) for extractSubjectCN exception safety.
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
        # Internal derivation engine + quirk table headers (same
        # consumption pattern as pkcs15-plugin).
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
    LINK_LIBRARIES SmartCard_Impl opensc_static_with_deps
)
