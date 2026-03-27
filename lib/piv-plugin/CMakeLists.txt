# SPDX-License-Identifier: LGPL-2.1-or-later

add_library(piv-plugin SHARED
    src/piv_card_plugin.cpp
)
target_link_libraries(piv-plugin PRIVATE CardPlugin PIV)
set_target_properties(piv-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "piv-plugin"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
