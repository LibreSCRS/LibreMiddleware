# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(RsHealth STATIC
    src/healthcard.cpp
    src/healthcard.h
    src/healthtypes.h
    src/health_protocol.h
)

target_compile_definitions(RsHealth PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(RsHealth PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
)

target_link_libraries(RsHealth PUBLIC SmartCard_Impl)
set_target_properties(RsHealth PROPERTIES POSITION_INDEPENDENT_CODE ON)

librescrs_warnings_as_errors(RsHealth)
