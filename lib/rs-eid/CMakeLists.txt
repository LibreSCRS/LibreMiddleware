# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(RsEId STATIC
    src/eidcard.cpp
    src/card_reader_gemalto.cpp
    src/card_reader_apollo.cpp
    src/card_verifier.cpp
    # Private headers (IDE visibility)
    src/card_protocol.h
    src/card_reader_base.h
    src/card_reader_gemalto.h
    src/card_reader_apollo.h
    src/card_verifier.h
    src/eidcard.h
    src/eidtypes.h
)

target_compile_definitions(RsEId PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(RsEId PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
)

set_target_properties(RsEId PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(RsEId PUBLIC SmartCard_Impl PRIVATE OpenSSL_Crypto z)
