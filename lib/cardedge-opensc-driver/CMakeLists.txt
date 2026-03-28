# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

option(BUILD_CARDEDGE_OPENSC_DRIVER "Build CardEdge OpenSC card driver module" OFF)

enable_language(C)

if(NOT BUILD_CARDEDGE_OPENSC_DRIVER)
    message(STATUS "CardEdge OpenSC driver: skipped (set -DBUILD_CARDEDGE_OPENSC_DRIVER=ON to build)")
    return()
endif()

find_library(OPENSC_LIB opensc REQUIRED)

# Headers: available on Linux via libopensc-dev / opensc-devel package.
# On macOS (Homebrew) headers are not installed — clone OpenSC source at the
# tag matching your brew install and pass -DOPENSC_INCLUDE_DIR=/path/to/OpenSC/src
if(NOT DEFINED OPENSC_INCLUDE_DIR)
    find_path(OPENSC_INCLUDE_DIR libopensc/opensc.h
        PATHS
            /usr/include
            /usr/local/include
            /opt/homebrew/include
    )
endif()
if(NOT OPENSC_INCLUDE_DIR OR NOT EXISTS "${OPENSC_INCLUDE_DIR}/libopensc/opensc.h")
    message(FATAL_ERROR
        "OpenSC headers not found.\n"
        "Linux: install libopensc-dev (Debian/Ubuntu) or opensc-devel (Fedora)\n"
        "macOS: clone https://github.com/OpenSC/OpenSC (tag matching your brew install) then pass:\n"
        "  -DOPENSC_INCLUDE_DIR=/path/to/OpenSC/src")
endif()

add_library(librescrs-cardedge-opensc SHARED
    src/librescrs_opensc.c
)

target_include_directories(librescrs-cardedge-opensc PRIVATE ${OPENSC_INCLUDE_DIR})
find_package(ZLIB REQUIRED)
target_link_libraries(librescrs-cardedge-opensc PRIVATE ${OPENSC_LIB} ZLIB::ZLIB)

set_target_properties(librescrs-cardedge-opensc PROPERTIES
    PREFIX ""
    OUTPUT_NAME "librescrs-cardedge-opensc"
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)
