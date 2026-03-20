# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(VehicleCard STATIC
    src/vehiclecard.cpp
    include/vehiclecard/vehiclecard.h
    include/vehiclecard/vehicletypes.h
)

target_include_directories(VehicleCard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(VehicleCard PUBLIC SmartCard)
set_target_properties(VehicleCard PROPERTIES POSITION_INDEPENDENT_CODE ON)
