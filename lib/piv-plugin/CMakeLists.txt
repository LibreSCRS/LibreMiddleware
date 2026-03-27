# SPDX-License-Identifier: LGPL-2.1-or-later

add_library(rescrs-plugin-piv SHARED
    src/piv_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-piv PRIVATE CardPlugin PIV)
set_target_properties(rescrs-plugin-piv PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-piv"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
