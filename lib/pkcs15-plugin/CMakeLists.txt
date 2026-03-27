# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(pkcs15-plugin SHARED
    src/pkcs15_card_plugin.cpp
)
target_link_libraries(pkcs15-plugin PRIVATE CardPlugin PKCS15)
set_target_properties(pkcs15-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "pkcs15-plugin"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
