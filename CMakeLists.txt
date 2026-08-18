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

project(LibreMiddleware VERSION ${PROJECT_VERSION} LANGUAGES CXX C)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# 4.0 hardening: per-plugin manifest.json -> constexpr header codegen.
# Python is the build-time host for the lowering script; jsonschema is an
# optional runtime dep (the script warns and skips validation when missing).
find_package(Python3 REQUIRED COMPONENTS Interpreter)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/LibreSCRSAddPlugin.cmake)

# A2 (4.0 hardening): std::stop_token / std::stop_source ship behind
# `-fexperimental-library` on Apple Clang's libc++. The flag toggles the
# C++20 cancellation primitives without degrading them to a hand-rolled
# `shared_ptr<atomic<bool>>` workaround. Use the standard library and
# add the flag — never re-implement.
if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
    add_compile_options(-fexperimental-library)
    add_link_options(-fexperimental-library)
endif()

# Verify std::expected is available on this toolchain before any 4.0
# code that uses it compiles. Probe added per 2026-05-03 spec R1.
try_compile(LIBRESCRS_HAS_STD_EXPECTED
    SOURCE_FROM_FILE check-std-expected.cpp ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check-std-expected.cpp
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON)
if(NOT LIBRESCRS_HAS_STD_EXPECTED)
    message(FATAL_ERROR
        "std::expected is not available on this toolchain. "
        "LibreMiddleware 4.0 requires C++23 with <expected>. "
        "Update GCC to 13+, Clang/libc++ to 16+, or AppleClang to 16+.")
endif()

# Export certificates directory for consumers
set(LIBREMIDDLEWARE_CERTIFICATES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/thirdparty/certificates"
    CACHE PATH "Path to bundled CA certificates" FORCE)

# Installed counterpart of the above: the absolute directory the install rule
# further down drops the bundle into. Baked in alongside the source-tree path
# so an installed build still resolves its anchors under a split prefix, where
# the libraries and the data root share no parent and no relative walk from
# the binary can reach the certificates.
#
# GNUInstallDirs is included here rather than only before the install() rules
# because the subdirectories added below need CMAKE_INSTALL_FULL_DATAROOTDIR
# to compute this value. The module is idempotent and its cache entries are
# already created by the later include, so this only moves them earlier.
include(GNUInstallDirs)
set(LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR
    "${CMAKE_INSTALL_FULL_DATAROOTDIR}/librescrs/certificates"
    CACHE PATH "Installed location of the bundled CA certificates" FORCE)

# Vendored OpenSC fork (static archive) for the OpenScPKCS11Provider.
# Pinned at thirdparty/opensc-source. ON by default; set to OFF to skip
# the ~5-10 minute autoconf+make build (the resulting librescrs-opensc-pkcs11
# fallback module then will not be built either).
option(LIBRESCRS_VENDOR_OPENSC
    "Build vendored OpenSC fork as a static library for librescrs-opensc-pkcs11 fallback" ON)

if(NOT WIN32 AND LIBRESCRS_VENDOR_OPENSC)
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E env bash ${CMAKE_CURRENT_SOURCE_DIR}/tools/check-opensc-pin.sh
        RESULT_VARIABLE _opensc_pin_rc
        OUTPUT_VARIABLE _opensc_pin_out
        ERROR_VARIABLE _opensc_pin_err
    )
    if(NOT _opensc_pin_rc EQUAL 0)
        message(FATAL_ERROR "OpenSC pin check failed:\n${_opensc_pin_out}\n${_opensc_pin_err}")
    endif()
    message(STATUS "${_opensc_pin_out}")
endif()

# Shared-library mode. Default ON because LibreMiddleware is a plugin-
# oriented architecture: card plugins and the in-tree PKCS#11 module are
# always dynamic .so files, and SessionPresence (the in-process registry
# coordinating cross-reader secure messaging) is a process-local
# singleton whose ODR correctness requires a single SHARED definition
# visible to every plugin via DT_NEEDED. Static LibreMiddleware is only
# viable with LIBREMIDDLEWARE_BUILD_PLUGINS=OFF (monolithic SDK build).
# Defined before any add_subdirectory() so subordinate CMakeLists may
# read ${LIBREMIDDLEWARE_LIB_TYPE} during their target declarations.
option(LIBREMIDDLEWARE_BUILD_SHARED
       "Build public LibreSCRS_* targets as shared libraries" ON)

# Plugin and in-tree PKCS#11 module shared objects are built by default.
# Set OFF for monolithic SDK consumers (single-binary CLI tools, embedded
# hosts) that statically link LM and do not enumerate plugin .so files
# at runtime. STATIC + plugins is an unsupported configuration because
# the cross-`.so` SessionPresence singleton fractures across each
# plugin's privately-linked LM copy (see message below).
option(LIBREMIDDLEWARE_BUILD_PLUGINS
       "Build card plugins and the in-tree PKCS#11 module as shared libraries" ON)

if(NOT LIBREMIDDLEWARE_BUILD_SHARED AND LIBREMIDDLEWARE_BUILD_PLUGINS)
    message(FATAL_ERROR
        "STATIC LibreMiddleware (LIBREMIDDLEWARE_BUILD_SHARED=OFF) is "
        "incompatible with plugin .so files. SessionPresence (the in-process "
        "registry that gates cross-reader secure-messaging coordination) is a "
        "singleton whose correctness requires exactly one definition per "
        "process. With STATIC LM each plugin .so statically links its own copy "
        "and the registry silently fractures across modules.\n"
        "\n"
        "Resolution:\n"
        "  * Production builds: -DLIBREMIDDLEWARE_BUILD_SHARED=ON\n"
        "  * Monolithic SDK builds: -DLIBREMIDDLEWARE_BUILD_PLUGINS=OFF\n"
        "    (forgoes pkcs15-plugin/eu-vrc-plugin/etc. plus the in-tree "
        "    PKCS#11 module; you commit to single-binary linkage)\n"
        "\n"
        "See docs/SHARED-LIBRARY-CONSUMERS.md.")
endif()

if(LIBREMIDDLEWARE_BUILD_SHARED)
    set(LIBREMIDDLEWARE_LIB_TYPE SHARED)
else()
    set(LIBREMIDDLEWARE_LIB_TYPE STATIC)
endif()
message(STATUS "LibreMiddleware public libraries: ${LIBREMIDDLEWARE_LIB_TYPE}")
message(STATUS "LibreMiddleware plugins: "
    "${LIBREMIDDLEWARE_BUILD_PLUGINS}")

add_subdirectory(thirdparty)
add_subdirectory(lib/LibreSCRS)
add_subdirectory(lib/plugin)

# All card plugins build into a single directory for registry discovery
set(LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/plugins" CACHE PATH
    "Directory where card plugin .so files are placed")

# Export plugin directory for consumers (e.g. LibreCelik via FetchContent)
set(LIBREMIDDLEWARE_PLUGIN_DIR "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}" CACHE PATH
    "Directory containing LibreMiddleware card plugins (for consumers)")

add_subdirectory(lib/smartcard)
add_subdirectory(lib/rs-eid)
add_subdirectory(lib/eu-vrc)
add_subdirectory(lib/rs-health)
add_subdirectory(lib/emrtd-crypto)
add_subdirectory(lib/emrtd)
add_subdirectory(lib/pkcs15)
# Digital signing support (LibreSign library + DSS integration).
# pkcs11.so is always built — it's a standalone PKCS#11 module
# used by Firefox, pkcs11-tool, etc.
option(BUILD_SIGNING "Build digital signing support (LibreSign + DSS)" ON)
if(BUILD_SIGNING)
    add_subdirectory(lib/libresign)
    message(STATUS "Digital signing: enabled")
else()
    message(STATUS "Digital signing: disabled (set -DBUILD_SIGNING=ON to enable)")
endif()
# Export flag for consumers (LibreCelik)
set(LIBREMIDDLEWARE_HAS_SIGNING ${BUILD_SIGNING} CACHE BOOL
    "Whether LibreMiddleware was built with signing support" FORCE)

if(LIBRESCRS_VENDOR_OPENSC AND LIBREMIDDLEWARE_BUILD_PLUGINS)
    add_subdirectory(lib/opensc-pkcs11)
    # OpenSC fallback card plugin shares the vendored static archive with
    # the PKCS#11 module — both link `opensc_static_with_deps`. No system
    # libopensc package is needed; coverage is unified across Stack A
    # (CardPlugin chain → display) and Stack B (PKCS#11 providers → sign).
    add_subdirectory(lib/opensc-plugin)
endif()

# Card plugins + in-tree PKCS#11 module. The hard guard at the top of
# this file rejects LIBREMIDDLEWARE_BUILD_SHARED=OFF + BUILD_PLUGINS=ON,
# so reaching the OFF branch here implies a deliberate monolithic-SDK
# configuration.
if(LIBREMIDDLEWARE_BUILD_PLUGINS)
    add_subdirectory(lib/pkcs11)
    add_subdirectory(lib/rs-eid-plugin)
    add_subdirectory(lib/eu-vrc-plugin)
    add_subdirectory(lib/rs-health-plugin)
    add_subdirectory(lib/emrtd-plugin)
    add_subdirectory(lib/pkcs15-plugin)
endif()

option(BUILD_TESTING "Build tests" ON)
if(BUILD_TESTING)
    # Call enable_testing() at top level so add_test() calls in any
    # subdirectory (test/, examples/) are discoverable by a single
    # `ctest` run from the build root — previously only tests under
    # build/test/ were visible because enable_testing() lived there.
    enable_testing()
    if(LIBREMIDDLEWARE_BUILD_PLUGINS)
        add_subdirectory(test)
    else()
        # Monolithic SDK build (BUILD_PLUGINS=OFF). The in-tree test suite
        # exercises plugin loading and the in-tree PKCS#11 module, which do
        # not exist in this configuration. Downstream SDK consumers build
        # their own tests against the public LibreSCRS::* API instead.
        message(STATUS "LibreMiddleware tests: skipped (BUILD_PLUGINS=OFF)")
    endif()
endif()

option(LIBRESCRS_BUILD_FUZZ
    "Build libFuzzer harnesses for public parsers (Clang only)" OFF)
if(LIBRESCRS_BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()

option(LIBRESCRS_BUILD_BENCH
    "Build Google Benchmark micro-benchmarks for public hot paths" OFF)
if(LIBRESCRS_BUILD_BENCH)
    add_subdirectory(bench)
endif()

# Examples opt-in by default when SHARED build is active — the shared-build
# CLI example doubles as a smoke test for the SHARED-library link path.
if(LIBREMIDDLEWARE_BUILD_SHARED)
    set(_lm_examples_default ON)
else()
    set(_lm_examples_default OFF)
endif()
option(LIBRESCRS_BUILD_EXAMPLES "Build LibreMiddleware public-API consumer examples" ${_lm_examples_default})
# add_subdirectory unconditionally so IDE project trees (QtCreator, CLion)
# populate the examples/ source files in their file-tree view even when the
# build is disabled. The per-example CMakeLists gates its add_executable on
# LIBRESCRS_BUILD_EXAMPLES so the actual target only materialises when the
# option is ON — the source-file discovery cost is zero when disabled.
add_subdirectory(examples/sdk-consumer)
add_subdirectory(examples/shared-cli)
add_subdirectory(examples/visual_signature_layout)

add_subdirectory(tools)

# ──────────────────────────────────────────────────────────────────────────
# SDK install rule for public headers.
#
# LibreMiddleware is consumed in-tree (FetchContent) by LibreCelik today, so
# an install/export package is not the primary distribution channel. However,
# if/when an SDK package is produced, the `include/LibreSCRS/**/detail/`
# sub-trees MUST be excluded — those headers are compile-time-guarded with
# `#error !LIBRESCRS_INTERNAL_BUILD` but must never ship in the public SDK
# package.
#
# Active when:
#   * LIBRESCRS_INSTALL_SDK_HEADERS=ON       (explicit opt-in), OR
#   * LIBREMIDDLEWARE_BUILD_SHARED=ON        (Config-package consumers like
#                                             LibreKDE always need the
#                                             headers when they pick up the
#                                             shared libs)
#
# Public API lives under include/LibreSCRS/. Internal detail/ sub-directories
# are excluded via PATTERN — the regex+exclude is functionally equivalent to
# enumerating each public component subdir explicitly.
# ──────────────────────────────────────────────────────────────────────────
option(LIBRESCRS_INSTALL_SDK_HEADERS
    "Install LibreSCRS public SDK headers (detail/ sub-trees excluded)" OFF)
if(LIBRESCRS_INSTALL_SDK_HEADERS OR LIBREMIDDLEWARE_BUILD_SHARED)
    include(GNUInstallDirs)
    install(DIRECTORY include/LibreSCRS
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        FILES_MATCHING
            PATTERN "*.h"
            PATTERN "*.hpp"
        PATTERN "detail" EXCLUDE
    )
endif()

# ──────────────────────────────────────────────────────────────────────────
# CMake Config package generation.
#
# Active when LIBREMIDDLEWARE_BUILD_SHARED=ON. Produces a Config-package
# pair (`LibreMiddlewareConfig.cmake` + `LibreMiddlewareConfigVersion.cmake`)
# plus the namespaced Targets.cmake exported in lib/LibreSCRS/CMakeLists.txt
# (`install(EXPORT LibreMiddlewareTargets …)`) so downstream consumers can:
#
#   find_package(LibreMiddleware 4.0 REQUIRED CONFIG)
#   target_link_libraries(my_target PRIVATE LibreMiddleware::SmartCard …)
#
# Compatibility policy: SameMajorVersion. A consumer requesting 4.x.y is
# compatible iff the installed major is 4. 5.0 ABI break => consumers
# must update to a 5.x release first.
# ──────────────────────────────────────────────────────────────────────────
if(LIBREMIDDLEWARE_BUILD_SHARED)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    set(LIBREMIDDLEWARE_CMAKE_CONFIG_DIR
        "${CMAKE_INSTALL_LIBDIR}/cmake/LibreMiddleware")

    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LibreMiddlewareConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/LibreMiddlewareConfig.cmake"
        INSTALL_DESTINATION "${LIBREMIDDLEWARE_CMAKE_CONFIG_DIR}"
    )

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/LibreMiddlewareConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion
    )

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/LibreMiddlewareConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/LibreMiddlewareConfigVersion.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindPCSC.cmake"
        DESTINATION "${LIBREMIDDLEWARE_CMAKE_CONFIG_DIR}"
    )
endif()

# ──────────────────────────────────────────────────────────────────────────
# Bundled CA certificates install rule.
#
# LibreMiddleware ships a curated set of root + intermediate CA certificates
# under thirdparty/certificates/ (rs-mup/, rs-mup-format/, rs-pks/) that the
# chain-validation paths consume — notably LibreKDE's CardEdge purpose plugin,
# which needs the MUP intermediates to anchor RS eID certificate chains when
# the system trust store lacks them. Packaged builds (AppImage, .deb, .rpm,
# DMG) had no install rule for this tree, so the certificate directory pinned
# into the binary at configure time (`LIBREMIDDLEWARE_CERTIFICATES_DIR`)
# pointed at the build host's source checkout — a path that does not exist on
# the end-user machine. The runtime certificate walker resolves the directory
# dynamically by probing exe-relative, env-override, and FHS locations; this
# install rule produces the FHS share/ destination that the walker checks for
# system-wide installs.
#
# Destination: ${CMAKE_INSTALL_DATAROOTDIR}/librescrs/certificates (i.e.
# /usr/share/librescrs/certificates on standard Linux prefixes,
# /usr/local/share/librescrs/certificates on /usr/local prefixes,
# Contents/Resources/share/librescrs/certificates inside the macOS bundle
# layout). FILES_MATCHING preserves the rs-mup/ / rs-mup-format/ / rs-pks/
# subdirectory layout that the walker expects. README files are skipped.
# Component "runtime" lets distro packagers split docs/dev headers out into
# separate sub-packages.
# ──────────────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(DIRECTORY thirdparty/certificates/
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/librescrs/certificates
        COMPONENT runtime
        FILES_MATCHING
            PATTERN "*.crt"
            PATTERN "*.pem"
            PATTERN "*.cer"
            PATTERN "*.der"
            PATTERN "README*" EXCLUDE)

# ──────────────────────────────────────────────────────────────────────────
# p11-kit module registration.
#
# Dropping `librescrs.module` into ${datadir}/p11-kit/modules/ makes every
# p11-kit-aware application (Kleopatra, GnuPG / gpgsm, Firefox, Chromium,
# Thunderbird, Evolution, KMail, …) auto-discover LibreSCRS-supported
# smart cards alongside any other configured PKCS#11 token — with zero
# application-side configuration.
#
# Default ON because (a) it's a single 3-line file with no downstream
# cost when the .so isn't installed, and (b) the whole point of this
# integration is "Kleopatra sees our cards" for distro users who don't
# even have LibreCelik installed. Distro packagers who specifically want
# to OFF it (e.g. for a stripped SDK package) can do so explicitly.
# ──────────────────────────────────────────────────────────────────────────
option(LIBREMIDDLEWARE_INSTALL_P11KIT_MODULE
    "Install p11-kit module file so PKCS#11-aware applications auto-discover LibreSCRS cards" ON)
if(LIBREMIDDLEWARE_INSTALL_P11KIT_MODULE)
    include(GNUInstallDirs)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/packaging/librescrs.module"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/p11-kit/modules"
    )
endif()
