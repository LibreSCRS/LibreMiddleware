# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rescrs-plugin-emrtd SHARED
    src/emrtd_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-emrtd PRIVATE CardPlugin EMRTD)
set_target_properties(rescrs-plugin-emrtd PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-emrtd"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
