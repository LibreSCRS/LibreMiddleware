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
    include/pkcs11/pkcs11.h
    include/pkcs11/pkcs11t.h
    include/pkcs11/pkcs11f.h
)

target_compile_definitions(librescrs-pkcs11 PRIVATE LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD)

target_include_directories(librescrs-pkcs11 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(librescrs-pkcs11 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src/native
    ${LibreMiddleware_SOURCE_DIR}/lib/piv/src
    ${LibreMiddleware_SOURCE_DIR}/lib/cardedge/src
    ${LibreMiddleware_SOURCE_DIR}/lib/pkcs15/src
    ${LibreMiddleware_SOURCE_DIR}/lib/smartcard/src
)

target_link_libraries(librescrs-pkcs11 PRIVATE CardEdge PKCS15 PIV OpenSSL_Crypto)

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
    )
elseif(UNIX)
    target_link_options(librescrs-pkcs11 PRIVATE
        "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map"
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
)
