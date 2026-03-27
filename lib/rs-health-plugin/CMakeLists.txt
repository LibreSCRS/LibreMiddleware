# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rs-health-plugin SHARED
    src/health_card_plugin.cpp
)
target_link_libraries(rs-health-plugin PRIVATE CardPlugin RsHealth)
set_target_properties(rs-health-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rs-health-plugin"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
