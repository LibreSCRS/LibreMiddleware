# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(HealthCard STATIC
    src/healthcard.cpp
    include/healthcard/healthcard.h
    include/healthcard/healthtypes.h
)

target_include_directories(HealthCard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(HealthCard PUBLIC SmartCard)
set_target_properties(HealthCard PROPERTIES POSITION_INDEPENDENT_CODE ON)
