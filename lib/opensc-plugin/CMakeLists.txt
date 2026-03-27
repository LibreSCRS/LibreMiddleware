# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(opensc-plugin SHARED
    src/opensc_card_plugin.cpp
)
target_link_libraries(opensc-plugin
    PRIVATE CardPlugin SmartCard PkgConfig::OPENSC OpenSSL_Crypto
)
set_target_properties(opensc-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "opensc-plugin"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
