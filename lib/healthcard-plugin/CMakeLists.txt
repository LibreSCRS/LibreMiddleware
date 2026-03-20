# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rescrs-plugin-rs-health SHARED
    src/health_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-rs-health PRIVATE CardPlugin HealthCard)
set_target_properties(rescrs-plugin-rs-health PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-rs-health"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
