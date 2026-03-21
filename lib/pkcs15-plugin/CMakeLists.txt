# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rescrs-plugin-pkcs15 SHARED
    src/pkcs15_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-pkcs15 PRIVATE CardPlugin PKCS15)
set_target_properties(rescrs-plugin-pkcs15 PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-pkcs15"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
