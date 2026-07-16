# SPDX-License-Identifier: LGPL-2.1-or-later

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCSC libpcsclite)
endif()

if(NOT PCSC_FOUND)
    message(STATUS "eid-sod-verify: libpcsclite not found — diagnostic tool skipped")
    return()
endif()

add_executable(eid-sod-verify main.cpp)
target_include_directories(eid-sod-verify PRIVATE ${PCSC_INCLUDE_DIRS})
target_link_libraries(eid-sod-verify PRIVATE OpenSSL_Crypto ${PCSC_LIBRARIES})
target_compile_definitions(eid-sod-verify
    PRIVATE LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}")
