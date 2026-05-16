# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(EMRTD STATIC
    src/emrtd_card.cpp
    src/data_group.cpp
    src/emrtd_card.h
    src/emrtd_types.h
    src/data_group.h
)

target_compile_definitions(EMRTD PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(EMRTD PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
)

set_target_properties(EMRTD PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(EMRTD PUBLIC EMRTDCrypto SmartCard_Impl LibreSCRS_SecureChannel)
