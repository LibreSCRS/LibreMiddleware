# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(PKSCard STATIC
    src/pkscard.cpp
    # Public headers
    include/pkscard/pkscard.h
)

target_include_directories(PKSCard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(PKSCard PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(PKSCard PUBLIC SmartCard PRIVATE CardEdge)
