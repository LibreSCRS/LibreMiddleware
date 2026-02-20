# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(EIdCard STATIC
    src/eidcard.cpp
    src/card_reader_gemalto.cpp
    src/card_reader_apollo.cpp
    src/card_verifier.cpp
    include/eidcard/eidcard.h
    include/eidcard/eidtypes.h
)

target_include_directories(EIdCard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(EIdCard PUBLIC SmartCard OpenSSL_Crypto z)
