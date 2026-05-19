# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PCSC REQUIRED)
find_package(Threads REQUIRED)

add_library(SmartCard_Impl STATIC
    src/apdu.cpp
    src/pcsc_connection.cpp
    src/tlv.cpp
    src/ber.cpp
    src/monitor.cpp
    # Bucket-B internal headers (LM-private)
    src/apdu.h
    src/ber.h
    src/tlv.h
    src/ipcsc_scan_provider.h
    src/pcsc_scan_provider.h
    # Bucket-C headers: public within LM, LC bridge surface
    include/smartcard/i_connection.h
    include/smartcard/pcsc_connection.h
    include/smartcard/secure_buffer.h
    include/smartcard/monitor_event.h
    include/smartcard/monitor.h
)

target_compile_definitions(SmartCard_Impl PRIVATE LIBRESCRS_INTERNAL_BUILD)

# PUBLIC include dir (BUILD_INTERFACE-wrapped) now carries only the four
# LC-bridge headers (pcsc_connection, secure_buffer, monitor, monitor_event).
# Internal LM consumers that link SmartCard_Impl still need
# <smartcard/pcsc_connection.h> etc. while the LC bridge surface remains,
# but external (non-LM) consumers cannot reach them — the headers
# are not exported via install() or package config.
#
# NOTE: the LC-bridge headers above carry the host-facing surface; the
# transport-layer headers (apdu, ber, tlv, ipcsc_scan_provider,
# pcsc_scan_provider) live in src/ and require an explicit PRIVATE include
# of lib/smartcard/src from consumers.
target_include_directories(SmartCard_Impl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# PRIVATE: lets SmartCard_Impl's own .cpp files resolve "apdu.h" etc. and
# lets pcsc_connection.h's `#include "apdu.h"` resolve when compiling our
# own sources. External consumers that need to transitively resolve this
# (because they include <smartcard/pcsc_connection.h>, which pulls apdu.h)
# opt in by adding lib/smartcard/src to their own PRIVATE include dirs.
target_include_directories(SmartCard_Impl PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(SmartCard_Impl PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(SmartCard_Impl PUBLIC PCSC::PCSC Threads::Threads OpenSSL_Crypto)
