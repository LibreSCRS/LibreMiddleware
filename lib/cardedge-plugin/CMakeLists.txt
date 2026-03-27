# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(cardedge-plugin SHARED
    src/cardedge_card_plugin.cpp
)
target_link_libraries(cardedge-plugin PRIVATE CardPlugin CardEdge)
set_target_properties(cardedge-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "cardedge-plugin"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
