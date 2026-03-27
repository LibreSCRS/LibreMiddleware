# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(emrtd-plugin SHARED
    src/emrtd_card_plugin.cpp
)
target_link_libraries(emrtd-plugin PRIVATE CardPlugin EMRTD)
set_target_properties(emrtd-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "emrtd-plugin"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
