# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(EuVrc STATIC
    src/eu_vrc_card.cpp
    src/eu_vrc_detection.cpp
    src/eu_vrc_card.h
    src/eu_vrc_detection.h
    src/eu_vrc_protocol.h
    src/eu_vrc_types.h
)

target_compile_definitions(EuVrc PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(EuVrc PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
)

target_link_libraries(EuVrc PUBLIC SmartCard_Impl)
set_target_properties(EuVrc PROPERTIES POSITION_INDEPENDENT_CODE ON)

librescrs_warnings_as_errors(EuVrc)
