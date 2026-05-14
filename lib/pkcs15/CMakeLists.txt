# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(PKCS15 STATIC
    src/pkcs15_parser.cpp
    src/pkcs15_card.cpp
    src/pkcs15_pkcs11_card.cpp
    src/pkcs15_pkcs11_slot.cpp
    src/pkcs15_types.h
    src/pkcs15_parser.h
    src/pkcs15_card.h
    src/pkcs15_pkcs11_card.h
    src/pkcs15_pkcs11_slot.h
)

target_compile_definitions(PKCS15 PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(PKCS15 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/include
    ${PROJECT_SOURCE_DIR}/lib/plugin/src
)

target_link_libraries(PKCS15 PUBLIC SmartCard_Impl LibreSCRS::SmartCard PRIVATE OpenSSL_Crypto EMRTDCrypto LibreSCRS::Secure)

set_target_properties(PKCS15 PROPERTIES POSITION_INDEPENDENT_CODE ON)
