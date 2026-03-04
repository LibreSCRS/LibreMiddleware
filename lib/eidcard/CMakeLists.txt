# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(EIdCard STATIC
    src/eidcard.cpp
    src/card_reader_gemalto.cpp
    src/card_reader_apollo.cpp
    src/card_verifier.cpp
    src/eid_pkcs11_provider.cpp
    # Private headers (IDE visibility)
    src/card_protocol.h
    src/card_reader_base.h
    src/card_reader_gemalto.h
    src/card_reader_apollo.h
    src/card_verifier.h
    # Public headers
    include/eidcard/eidcard.h
    include/eidcard/eidtypes.h
    include/eidcard/eid_pkcs11_provider.h
)

target_include_directories(EIdCard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(EIdCard PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(EIdCard PUBLIC SmartCard CardEdge OpenSSL_Crypto z)
