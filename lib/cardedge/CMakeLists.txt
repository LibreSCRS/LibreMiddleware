# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(CardEdge STATIC
    src/cardedge.cpp
    src/cardedge_pkcs11_provider.cpp
    # Private headers (IDE visibility)
    src/cardedge.h
    src/cardedgetypes.h
    src/cardedge_pkcs11_provider.h
    src/pki_applet_guard.h
    src/cardedge_protocol.h
)

target_compile_definitions(CardEdge PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(CardEdge PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/pkcs15/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
)

set_target_properties(CardEdge PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(CardEdge PUBLIC SmartCard_Impl PKCS15 PRIVATE OpenSSL_Crypto z)
