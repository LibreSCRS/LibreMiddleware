# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PCSC REQUIRED)

add_library(SmartCard STATIC
    src/apdu.cpp
    src/pcsc_connection.cpp
    src/tlv.cpp
    src/ber.cpp
    include/smartcard/apdu.h
    include/smartcard/pcsc_connection.h
    include/smartcard/tlv.h
    include/smartcard/ber.h
)

target_include_directories(SmartCard PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(SmartCard PUBLIC PCSC::PCSC)
