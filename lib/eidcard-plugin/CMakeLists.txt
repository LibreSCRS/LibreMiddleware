# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rescrs-plugin-rs-eid SHARED
    src/eid_card_plugin.cpp
)
target_link_libraries(rescrs-plugin-rs-eid PRIVATE CardPlugin EIdCard)
target_compile_definitions(rescrs-plugin-rs-eid PRIVATE
    LIBREMIDDLEWARE_CERT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/certificates/all"
)
set_target_properties(rescrs-plugin-rs-eid PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rescrs-plugin-rs-eid"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
