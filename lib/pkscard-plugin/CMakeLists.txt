# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rescrs-plugin-rs-pks SHARED
    src/pks_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-rs-pks PRIVATE CardPlugin PKSCard)
set_target_properties(rescrs-plugin-rs-pks PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-rs-pks"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
