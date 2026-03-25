# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(EuVrc STATIC
    src/eu_vrc_card.cpp
    src/eu_vrc_detection.cpp
)

target_include_directories(EuVrc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(EuVrc PUBLIC SmartCard)
set_target_properties(EuVrc PROPERTIES POSITION_INDEPENDENT_CODE ON)
