# SPDX-License-Identifier: LGPL-2.1-or-later

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(PIV STATIC
    src/piv_card.cpp
    include/piv/piv_types.h
    include/piv/piv_card.h
)

target_include_directories(PIV PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(PIV PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(PIV PUBLIC SmartCard CardPlugin OpenSSL_Crypto)

set_target_properties(PIV PROPERTIES POSITION_INDEPENDENT_CODE ON)
