# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rescrs-plugin-eu-vrc SHARED
    src/eu_vrc_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-eu-vrc PRIVATE CardPlugin EuVrc)
set_target_properties(rescrs-plugin-eu-vrc PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-eu-vrc"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
