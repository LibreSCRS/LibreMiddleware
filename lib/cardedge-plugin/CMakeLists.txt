# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rescrs-plugin-cardedge SHARED
    src/cardedge_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-cardedge PRIVATE CardPlugin CardEdge)
set_target_properties(rescrs-plugin-cardedge PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-cardedge"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
