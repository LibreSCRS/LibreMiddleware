# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(EMRTD STATIC
    src/emrtd_card.cpp
    src/data_group.cpp
    include/emrtd/emrtd_card.h
    include/emrtd/emrtd_types.h
    include/emrtd/data_group.h
)

target_include_directories(EMRTD PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(EMRTD PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(EMRTD PUBLIC EMRTDCrypto SmartCard)
