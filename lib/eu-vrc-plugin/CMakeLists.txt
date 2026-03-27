# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(eu-vrc-plugin SHARED
    src/eu_vrc_card_plugin.cpp
)
target_link_libraries(eu-vrc-plugin PRIVATE CardPlugin EuVrc)
set_target_properties(eu-vrc-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "eu-vrc-plugin"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
