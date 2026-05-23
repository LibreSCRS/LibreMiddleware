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
    # Bucket-B internal headers (LM-private; #error-guarded against external
    # use, reached through the PRIVATE lib/smartcard/src include path that
    # every LIBRESCRS_INTERNAL_BUILD consumer already carries).
    src/apdu.h
    src/ber.h
    src/tlv.h
    src/ipcsc_scan_provider.h
    src/pcsc_scan_provider.h
    src/pcsc_connection.h
    src/monitor.h
    # Bucket-C LC-bridge surface: small, dependency-free leaf types that
    # may be reached from external consumers via the PUBLIC include path
    # below. All three are self-contained — IConnection forward-declares
    # APDUCommand/APDUResponse, secure_buffer is a leaf RAII wrapper, and
    # monitor_event is a POD — so the bucket-C surface no longer
    # transitively drags bucket-B headers into LM-internal consumers.
    include/smartcard/i_connection.h
    include/smartcard/secure_buffer.h
    include/smartcard/monitor_event.h
)

target_compile_definitions(SmartCard_Impl PRIVATE LIBRESCRS_INTERNAL_BUILD)

# PUBLIC include dir (BUILD_INTERFACE-wrapped) now carries only the two
# LC-bridge leaf headers (secure_buffer, monitor_event). The IConnection /
# PCSCConnection / Monitor surfaces moved to src/ once it became clear they
# transitively pull bucket-B types (apdu, ipcsc_scan_provider) and that LC
# no longer reaches for them directly — the public Monitor surface lives
# at <LibreSCRS/SmartCard/MonitorService.h> instead.
target_include_directories(SmartCard_Impl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

# PRIVATE: lets SmartCard_Impl's own .cpp files resolve "apdu.h" /
# "pcsc_connection.h" / "monitor.h" etc., and lets the bucket-B headers'
# `<smartcard/i_connection.h>` / `<smartcard/monitor_event.h>` includes
# resolve when compiling our own sources. External LM-internal consumers
# that include `<pcsc_connection.h>` etc. opt in by adding
# lib/smartcard/src to their own PRIVATE include dirs (already done — the
# path was previously needed to resolve the bucket-B transport headers
# pulled transitively by the old bucket-C surface).
target_include_directories(SmartCard_Impl PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(SmartCard_Impl PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(SmartCard_Impl PUBLIC PCSC::PCSC Threads::Threads OpenSSL_Crypto)
