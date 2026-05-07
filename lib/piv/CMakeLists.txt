# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(PIV STATIC
    src/piv_card.cpp
    src/piv_pkcs11_provider.cpp
    src/piv_types.h
    src/piv_card.h
    src/piv_pkcs11_provider.h
    src/piv_protocol.h
)

target_compile_definitions(PIV PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(PIV PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
)

target_link_libraries(PIV PUBLIC SmartCard_Impl LibreSCRS_Plugin PRIVATE OpenSSL_Crypto)

set_target_properties(PIV PROPERTIES POSITION_INDEPENDENT_CODE ON)
