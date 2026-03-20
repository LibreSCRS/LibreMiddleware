# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rescrs-plugin-vehicle SHARED
    src/vehicle_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-vehicle PRIVATE CardPlugin VehicleCard)
set_target_properties(rescrs-plugin-vehicle PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-vehicle"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
