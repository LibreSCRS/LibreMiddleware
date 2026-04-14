# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(PKCS15 STATIC
    src/pkcs15_parser.cpp
    src/pkcs15_card.cpp
    src/pkcs15_pkcs11_provider.cpp
    include/pkcs15/pkcs15_types.h
    include/pkcs15/pkcs15_parser.h
    include/pkcs15/pkcs15_card.h
    include/pkcs15/pkcs15_pkcs11_provider.h
)

target_include_directories(PKCS15 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(PKCS15 PUBLIC SmartCard PRIVATE OpenSSL_Crypto EMRTDCrypto)

set_target_properties(PKCS15 PROPERTIES POSITION_INDEPENDENT_CODE ON)
