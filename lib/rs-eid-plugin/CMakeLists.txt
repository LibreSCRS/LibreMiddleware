# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(rs-eid-plugin SHARED
    src/eid_card_plugin.cpp
)
target_link_libraries(rs-eid-plugin PRIVATE CardPlugin RsEId)
target_compile_definitions(rs-eid-plugin PRIVATE
    LIBREMIDDLEWARE_CERT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/certificates/all"
)
set_target_properties(rs-eid-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "rs-eid-plugin"
    LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
