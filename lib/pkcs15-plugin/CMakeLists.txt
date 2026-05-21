# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# Qt6::Core is required by the plugin's diagnostic logging
# (Q_LOGGING_CATEGORY / qCWarning) — the only Qt dependency in this TU,
# and scoped to this plugin to keep LM core Qt-free. Hosts route the
# `librescrs.pkcs15.plugin` category through QT_LOGGING_RULES at runtime.
find_package(Qt6 COMPONENTS Core REQUIRED)

librescrs_add_plugin(pkcs15-plugin
    MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/manifest.json
    SOURCES  src/pkcs15_card_plugin.cpp
    INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
    LINK_LIBRARIES PKCS15 EMRTDCrypto LibreSCRS_SmartCard LibreSCRS_SecureChannel Qt6::Core
)
