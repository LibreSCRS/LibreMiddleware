# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

cmake_minimum_required(VERSION 3.24.0 FATAL_ERROR)

set(CMAKE_OSX_DEPLOYMENT_TARGET 15.0)
set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GitVersion)

set(PROJECT_VERSION_MAJOR ${GIT_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${GIT_VERSION_MINOR})
set(PROJECT_VERSION_PATCH ${GIT_VERSION_PATCH})
set(PROJECT_VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH})

project(LibreMiddleware VERSION ${PROJECT_VERSION} LANGUAGES CXX)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Export certificates directory for consumers
set(LIBREMIDDLEWARE_CERTIFICATES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/certificates/all"
    CACHE PATH "Path to Serbian CA certificates" FORCE)

add_subdirectory(thirdparty)
add_subdirectory(lib/plugin)

# All card plugins build into a single directory for registry discovery
set(LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/plugins" CACHE PATH
    "Directory where card plugin .so files are placed")

# Export plugin directory for consumers (e.g. LibreCelik via FetchContent)
set(LIBREMIDDLEWARE_PLUGIN_DIR "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}" CACHE PATH
    "Directory containing LibreMiddleware card plugins (for consumers)")

add_subdirectory(lib/smartcard)
add_subdirectory(lib/cardedge)
add_subdirectory(lib/eidcard)
add_subdirectory(lib/eu-vrc)
add_subdirectory(lib/healthcard)
add_subdirectory(lib/emrtd-crypto)
add_subdirectory(lib/emrtd)
add_subdirectory(lib/pkcs15)
add_subdirectory(lib/piv)
add_subdirectory(lib/pkcs11)
add_subdirectory(lib/opensc-driver)

# Card plugins (shared libraries loaded at runtime)
add_subdirectory(lib/eidcard-plugin)
add_subdirectory(lib/eu-vrc-plugin)
add_subdirectory(lib/healthcard-plugin)
add_subdirectory(lib/emrtd-plugin)
add_subdirectory(lib/cardedge-plugin)
add_subdirectory(lib/pkcs15-plugin)
add_subdirectory(lib/piv-plugin)

# OpenSC fallback plugin (optional, requires system libopensc)
option(BUILD_OPENSC_PLUGIN "Build OpenSC fallback plugin" ON)
option(REQUIRE_OPENSC_PLUGIN "Fail if OpenSC plugin cannot be built" OFF)

if(BUILD_OPENSC_PLUGIN)
    # Try pkg-config first (Ubuntu libopensc-dev provides libopensc.pc)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(OPENSC QUIET IMPORTED_TARGET libopensc)
    endif()

    # Fallback: find_library + manual include dir (Arch/Manjaro, or -DOPENSC_INCLUDE_DIR=...)
    if(NOT OPENSC_FOUND)
        find_library(OPENSC_LIBRARY NAMES opensc)
        if(OPENSC_LIBRARY AND OPENSC_INCLUDE_DIR)
            set(OPENSC_FOUND TRUE)
            add_library(PkgConfig::OPENSC UNKNOWN IMPORTED)
            set_target_properties(PkgConfig::OPENSC PROPERTIES
                IMPORTED_LOCATION "${OPENSC_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${OPENSC_INCLUDE_DIR}"
            )
        endif()
    endif()

    if(OPENSC_FOUND)
        add_subdirectory(lib/opensc-plugin)
    else()
        message(STATUS "libopensc not found — skipping OpenSC fallback plugin (set OPENSC_INCLUDE_DIR for manual detection)")
    endif()
endif()

if(REQUIRE_OPENSC_PLUGIN AND NOT OPENSC_FOUND)
    message(FATAL_ERROR "REQUIRE_OPENSC_PLUGIN=ON but libopensc not found")
endif()

option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()

add_subdirectory(tools)
