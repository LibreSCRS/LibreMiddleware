# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

configure_file(
    src/pkcs11_version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/pkcs11_version.h
    @ONLY
)

add_library(librescrs-pkcs11 SHARED
    src/pkcs11.cpp
    src/pkcs11_library.cpp
    src/pkcs11_library.h
    src/pkcs11_platform.h
    src/pkcs11_slot.cpp
    src/pkcs11_card.cpp
    src/slot_id_hash.cpp
    include/pkcs11/pkcs11.h
    include/pkcs11/pkcs11t.h
    include/pkcs11/pkcs11f.h
    include/internal/Crv.h
    include/internal/PKCS11TokenInfo.h
    include/internal/PKCS11ObjectInfo.h
    include/internal/PKCS11Slot.h
    include/internal/PKCS11Card.h
    include/internal/PKCS11CardProvider.h
    include/internal/SlotIdHash.h
)

target_compile_definitions(librescrs-pkcs11 PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)

target_include_directories(librescrs-pkcs11 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(librescrs-pkcs11 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src/native
    ${LibreMiddleware_SOURCE_DIR}/lib/pkcs15/src
    ${LibreMiddleware_SOURCE_DIR}/lib/smartcard/src
)

target_link_libraries(librescrs-pkcs11 PRIVATE PKCS15 OpenSSL_Crypto LibreSCRS::Secure)

# Optional vendored-OpenSC fallback provider. When LIBRESCRS_VENDOR_OPENSC
# is on, register the OpenScPKCS11Provider FIRST in C_Initialize (priority
# 1) so it gets a chance at any PKCS#15-shaped card before the project's
# custom Pkcs15PKCS11Provider runs.
if(LIBRESCRS_VENDOR_OPENSC)
    target_link_libraries(librescrs-pkcs11 PRIVATE librescrs-opensc-pkcs11)
    target_compile_definitions(librescrs-pkcs11 PRIVATE LIBRESCRS_HAS_VENDORED_OPENSC=1)
endif()

# Restrict the dylib's exported symbol set to the PKCS#11 standard C
# interface. Without this, statically linked OpenSSL crypto and the
# LibreSCRS internal namespaces all surface as exported symbols of the
# .dylib — a layering / supply-chain smell. CXX_VISIBILITY_PRESET hidden
# above hides LibreSCRS-built symbols, but it does NOT hide symbols
# brought in from the bundled static OpenSSL archive (those were compiled
# with default visibility into libcrypto.a). The allowlist approach below
# strips them at link time.
#
# Apple ld(1): -exported_symbols_list <file>  (allowlist of symbol names)
# GNU ld(1):   --version-script <file>          (version-tagged sections)
# Both formats encode the same allowlist; their syntax just differs. See
# the per-platform allowlist files for the rationale + symbol list.
if(APPLE)
    target_link_options(librescrs-pkcs11 PRIVATE
        "LINKER:-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/exports.list"
        # Apple ld(1) dead-strips by default; -dead_strip is explicit form.
        "LINKER:-dead_strip"
    )
elseif(UNIX)
    target_link_options(librescrs-pkcs11 PRIVATE
        "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map"
        # Pair with -ffunction-sections / -fdata-sections in vendored OpenSC
        # (see thirdparty/CMakeLists.txt OPENSC_CFLAGS): drops unused OpenSC
        # driver objects from the final .so. Hidden-visibility on LibreSCRS
        # symbols already ensures the project's own code shrinks; this flag
        # also reaches the bundled static archive.
        "LINKER:--gc-sections"
    )
endif()

set_target_properties(librescrs-pkcs11 PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    PREFIX "lib"
    OUTPUT_NAME "rescrs-pkcs11"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/pkcs11"
    # Module installs one level below its sibling LibreSCRS_*.so.4 chain;
    # relative RPATH avoids LD_LIBRARY_PATH at the call site.
    INSTALL_RPATH "$<IF:$<PLATFORM_ID:Darwin>,@loader_path/..,$ORIGIN/..>"
)

if(BUILD_TESTING)
    # The root CMakeLists.txt calls enable_testing() AFTER add_subdirectory(lib/pkcs11)
    # (alongside add_subdirectory(test)). We need testing enabled when this
    # subdirectory's CTestTestfile.cmake is emitted, otherwise the gtest_discover_tests()
    # below produces no add_test() entries. enable_testing() is idempotent, so calling
    # it again from the root scope (later) is harmless. See CMake docs on enable_testing.
    enable_testing()
    add_subdirectory(test)
endif()

# p11-kit module install rule. The .so lands in p11-kit's conventional
# module path ${libdir}/pkcs11/; the matching `librescrs.module`
# declaration installed by the root CMakeLists.txt references this
# filename so p11-kit auto-resolves it via its standard module-load
# path.
#
# Unconditional (not gated on LIBREMIDDLEWARE_BUILD_SHARED):
# librescrs-pkcs11 is always SHARED — a PKCS#11 module is a
# runtime-loaded .so by definition, self-contained (PRIVATE-links
# vendored OpenSC / PKCS15 / OpenSSL static archives, no PUBLIC
# linkage to LibreSCRS_*). Distros installing LM with `cmake --install`
# should always get the .so so the p11-kit-aware app ecosystem
# (Kleopatra, GnuPG, Firefox, ...) picks it up.
include(GNUInstallDirs)
install(TARGETS librescrs-pkcs11
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkcs11
)
