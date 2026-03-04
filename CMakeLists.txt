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

# Export certificates directory for consumers
set(LIBREMIDDLEWARE_CERTIFICATES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/certificates/all"
    CACHE PATH "Path to Serbian CA certificates" FORCE)

add_subdirectory(thirdparty)
add_subdirectory(lib/smartcard)
add_subdirectory(lib/cardedge)
add_subdirectory(lib/eidcard)
add_subdirectory(lib/vehiclecard)
add_subdirectory(lib/healthcard)
add_subdirectory(lib/pkscard)
add_subdirectory(lib/pkcs11)
add_subdirectory(lib/opensc-driver)

option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
