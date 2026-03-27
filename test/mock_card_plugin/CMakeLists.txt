# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(mock-card-plugin SHARED mock_card_plugin.cpp)
target_link_libraries(mock-card-plugin PRIVATE CardPlugin)
set_target_properties(mock-card-plugin PROPERTIES
    PREFIX "lib"
    OUTPUT_NAME "mock-plugin"
)
