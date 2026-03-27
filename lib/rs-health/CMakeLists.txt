# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(RsHealth STATIC
    src/healthcard.cpp
    include/rshealth/healthcard.h
    include/rshealth/healthtypes.h
)

target_include_directories(RsHealth PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(RsHealth PUBLIC SmartCard)
set_target_properties(RsHealth PROPERTIES POSITION_INDEPENDENT_CODE ON)
