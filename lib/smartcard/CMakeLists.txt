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
    src/date_format.cpp
    src/chunked_read.cpp
    src/monitor.cpp
    src/secure_wipe.cpp
    # Internal core-transport headers (LM-private; #error-guarded against
    # external use, reached through the PRIVATE lib/smartcard/src include
    # path that every LIBRESCRS_INTERNAL_BUILD consumer already carries).
    src/apdu.h
    src/ber.h
    src/tlv.h
    src/date_format.h
    src/ipcsc_scan_provider.h
    src/pcsc_scan_provider.h
    src/pcsc_connection.h
    src/monitor.h
    # LC-bridge leaf types: small, dependency-free public-include surface
    # that may be reached from external consumers via the PUBLIC include
    # path below. All three are self-contained — IConnection forward-
    # declares APDUCommand/APDUResponse, secure_buffer is a leaf RAII
    # wrapper, and monitor_event is a POD — so the public surface does
    # not transitively drag internal core-transport headers into
    # LM-internal consumers.
    include/smartcard/i_connection.h
    include/smartcard/secure_buffer.h
    include/smartcard/secure_wipe.h
    include/smartcard/monitor_event.h
    # Internal helper: SmartCard_Impl-private chunked file-read loop,
    # LIBRESCRS_INTERNAL_BUILD-gated. Placed under include/ so that
    # LIBRESCRS_INTERNAL_BUILD consumers reach it via <smartcard/...>
    # without each adding lib/smartcard/src to their include path.
    include/smartcard/chunked_read.h
)

target_compile_definitions(SmartCard_Impl PRIVATE LIBRESCRS_INTERNAL_BUILD)

# PUBLIC include dir (BUILD_INTERFACE-wrapped) carries only the LC-bridge
# leaf headers (i_connection, secure_buffer, monitor_event). The
# PCSCConnection / Monitor surfaces live in src/ because they transitively
# pull internal core-transport types (apdu, ipcsc_scan_provider) and LC
# does not reach for them directly — the public Monitor surface lives at
# <LibreSCRS/SmartCard/MonitorService.h> instead.
target_include_directories(SmartCard_Impl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# PRIVATE: lets SmartCard_Impl's own .cpp files resolve "apdu.h" /
# "pcsc_connection.h" / "monitor.h" etc., and lets the internal
# core-transport headers' `<smartcard/i_connection.h>` /
# `<smartcard/monitor_event.h>` includes resolve when compiling our own
# sources. External LM-internal consumers that include
# `<pcsc_connection.h>` etc. opt in by adding lib/smartcard/src to their
# own PRIVATE include dirs.
target_include_directories(SmartCard_Impl PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(SmartCard_Impl PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(SmartCard_Impl PUBLIC PCSC::PCSC Threads::Threads PRIVATE OpenSSL_Crypto)
