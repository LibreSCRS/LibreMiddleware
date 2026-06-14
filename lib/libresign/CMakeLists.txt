# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(SIGNING_BACKEND "native" CACHE STRING "Signing backend: native, dss, or both")
set_property(CACHE SIGNING_BACKEND PROPERTY STRINGS "native" "dss" "both")

if(SIGNING_BACKEND STREQUAL "dss")
    message(WARNING "DSS signing backend is intended as a cross-verification test oracle; the production signing path is 'native' (default). Set SIGNING_BACKEND=native unless you are running cross-backend tests.")
endif()

# libcurl is vendored (thirdparty/curl-source), built static against the
# bundled OpenSSL so the process loads exactly one OpenSSL. Linked below via
# the `curl_static_with_deps` INTERFACE target (NOT system find_package(CURL)).

include(${LibreMiddleware_SOURCE_DIR}/cmake/EmbedBinary.cmake)

set(LIBRESIGN_EMBED_FONT_CPP
    "${CMAKE_CURRENT_BINARY_DIR}/generated/liberation_sans_data.cpp")
embed_binary(
    VAR    LiberationSansRegular
    INPUT  ${LibreMiddleware_SOURCE_DIR}/thirdparty/liberation-sans/LiberationSans-Regular.ttf
    OUTPUT ${LIBRESIGN_EMBED_FONT_CPP}
)

# --- Core sources (always built) ---
set(LIBRESIGN_SOURCES
    src/signing_service_factory.cpp
    src/http_client.cpp
    src/trust/TrustedListProvider.cpp
)
set(LIBRESIGN_HEADERS
    src/types.h
    src/signing_service.h
    src/signing_service_factory.h
    src/http_client.h
    src/credentials.h
)

# --- DSS manager/resolver (POSIX-only, always built for test oracle) ---
if(NOT WIN32)
    list(APPEND LIBRESIGN_SOURCES
        src/dss/dss_service_manager.cpp
        src/dss/dss_path_resolver.cpp
    )
    list(APPEND LIBRESIGN_HEADERS
        src/dss/dss_service_manager.h
        src/dss/dss_path_resolver.h
    )
endif()

# --- DSS backend sources ---
if(SIGNING_BACKEND STREQUAL "dss" OR SIGNING_BACKEND STREQUAL "both")
    list(APPEND LIBRESIGN_SOURCES
        src/dss/dss_signing_service.cpp
    )
    list(APPEND LIBRESIGN_HEADERS
        src/dss/dss_signing_service.h
    )
endif()

# --- Native backend sources ---
if(SIGNING_BACKEND STREQUAL "native" OR SIGNING_BACKEND STREQUAL "both")
    list(APPEND LIBRESIGN_SOURCES
        src/native/native_utils.cpp
        src/native/pdf_value.cpp
        src/native/pdf_tokens.cpp
        src/native/pdf_parser.cpp
        src/native/pkcs11_module_manager.cpp
        src/native/pkcs11_token.cpp
        src/native/signing_provider.cpp
        src/native/signing_provider_keymgmt.cpp
        src/native/signing_provider_signature.cpp
        src/native/tsa_client.cpp
        src/native/revocation_client.cpp
        src/native/cades_module.cpp
        src/native/pades_module.cpp
        src/native/pdf_dss.cpp
        src/native/pdf_doc_timestamp.cpp
        src/native/jcs.cpp
        src/native/jades_module.cpp
        src/native/xades_module.cpp
        src/native/asic_module.cpp
        ${LibreMiddleware_SOURCE_DIR}/thirdparty/miniz/miniz.c
        src/native/pinned_tl_certs.cpp
        src/native/trusted_list_parser.cpp
        src/native/tl_signature_verifier.cpp
        src/native/tl_cache.cpp
        src/native/fetch_and_verify_tl.cpp
        ${LIBRESIGN_EMBED_FONT_CPP}
        src/native/ttf_parser.cpp
        src/native/ttf_subset.cpp
        src/native/pdf_font.cpp
        src/native/visual_signature_layout.cpp
        src/native/native_signing_service.cpp
    )
    list(APPEND LIBRESIGN_HEADERS
        src/native/pkcs11_module_manager.h
        src/native/pkcs11_token.h
        src/native/signing_provider.h
        src/native/signing_provider_keymgmt.h
        src/native/signing_provider_signature.h
        src/native/tsa_client.h
        src/native/revocation_client.h
        src/native/cades_module.h
        src/native/pades_module.h
        src/native/pdf_dss.h
        src/native/pdf_doc_timestamp.h
        src/native/jcs.h
        src/native/jades_module.h
        src/native/xades_module.h
        src/native/asic_module.h
        src/native/trusted_list_parser.h
        src/native/fetch_and_verify_tl.h
        src/native/native_signing_service.h
        src/native/der_utils.h
        src/native/digest_info.h
        src/native/native_utils.h
        src/native/openssl_raii.h
        src/native/pdf_value.h
        src/native/pdf_tokens.h
        src/native/pdf_parser.h
        src/native/pinned_tl_certs.h
        src/native/tl_cache.h
        src/native/tl_signature_verifier.h
        src/native/gid.h
        src/native/ttf_parser.h
        src/native/ttf_subset.h
        src/native/pdf_font.h
        src/native/xml_raii.h
    )
endif()

# --- Build library ---
add_library(LibreSign STATIC ${LIBRESIGN_SOURCES} ${LIBRESIGN_HEADERS})

# Ensure the vendored static libcurl is built before LibreSign links it.
if(TARGET curl_external)
    add_dependencies(LibreSign curl_external)
endif()

target_compile_definitions(LibreSign PRIVATE LIBRESCRS_INTERNAL_BUILD)

# LibreSign is a static archive consumed by LibreSCRS_Trust and
# LibreSCRS_Signing. When LIBREMIDDLEWARE_BUILD_SHARED=ON those become .so
# libraries; their object archives must therefore be position-independent.
# Sibling impl targets (SmartCard_Impl, CardPlugin_Impl) already carry
# POSITION_INDEPENDENT_CODE for plugin-link reasons; LibreSign now follows
# the same rule so it can be linked into a SHARED public-target .so.
set_target_properties(LibreSign PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Per-function/data sections enable downstream --gc-sections to dead-strip
# unreferenced TUs. LibreSCRS_Trust links only the TL-fetch/verify subset of
# this archive; without section splitting, the entire archive (including
# Pkcs11Token / PAdES / CAdES / etc.) lands in libLibreSCRS_Trust.so under
# LIBREMIDDLEWARE_BUILD_SHARED=ON, duplicating sign-path symbols already
# present in libLibreSCRS_Signing.so.
target_compile_options(LibreSign PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-ffunction-sections -fdata-sections>
)

# Vendored miniz.c was written against pre-C89 compilers and uses K&R-style
# function declarations in two spots, which clang flags with
# -Wstrict-prototypes under -Wall. Suppress the warning for just this file so
# we can keep the project's overall -Wall -Wextra -Wpedantic strictness
# without patching vendored code.
#
# 64-bit file-offset selection: only on Linux-glibc-style platforms.
# Apple libc already exposes 64-bit `off_t` by default, and miniz has a
# dedicated `__APPLE__` branch (miniz.c around line 3062) that uses plain
# `fopen` / `ftello` / `fseeko` / `stat`. Defining `_LARGEFILE64_SOURCE` on
# Apple would route miniz into its
# `defined(__GNUC__) && defined(_LARGEFILE64_SOURCE)` branch (Apple Clang
# sets `__GNUC__`), which references `ftello64` / `fseeko64` / `fopen64` —
# symbols that exist only in glibc, breaking the build. Keep the LFS macros
# restricted to non-Apple Unix targets.
if(SIGNING_BACKEND STREQUAL "native" OR SIGNING_BACKEND STREQUAL "both")
    if(APPLE)
        set_source_files_properties(
            ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/miniz/miniz.c
            PROPERTIES
                COMPILE_FLAGS "-Wno-strict-prototypes -Wno-unused-parameter"
        )
    else()
        set_source_files_properties(
            ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/miniz/miniz.c
            PROPERTIES
                COMPILE_FLAGS "-Wno-strict-prototypes -Wno-unused-parameter"
                COMPILE_DEFINITIONS "_FILE_OFFSET_BITS=64;_LARGEFILE64_SOURCE"
        )
    endif()
endif()

# API-POLICY §9 forward-compat hardening: format/packaging/level switch
# dispatchers must close over every enum value. Compiler-enforced.
# -Werror=switch-enum is targeted to the two files with these switches so
# the rest of LibreSign retains its existing -Wswitch posture (closed-on-
# all-arms-with-default is still acceptable elsewhere).
set_source_files_properties(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/native/native_signing_service.cpp
    PROPERTIES
        COMPILE_OPTIONS "-Werror=switch-enum"
)
if(SIGNING_BACKEND STREQUAL "dss" OR SIGNING_BACKEND STREQUAL "both")
    set_source_files_properties(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/dss/dss_signing_service.cpp
        PROPERTIES
            COMPILE_OPTIONS "-Werror=switch-enum"
    )
endif()

# LibreSign has no public surface. Internal headers (types.h,
# signing_service.h, signing_service_factory.h) live in src/. External
# consumers (LibreSCRS::Signing bridge, signing tests) PRIVATE-include
# ${PROJECT_SOURCE_DIR}/lib/libresign/src and set LIBRESCRS_INTERNAL_BUILD
# themselves to satisfy the #error guards. Within-LibreSign sources include
# these as "signing_service.h", "types.h", "native/foo.h", "dss/foo.h" —
# resolved by the PRIVATE src/ root below. The lifecycle owner of the trust
# store is LibreSCRS::Trust::TrustStoreService.
target_include_directories(LibreSign PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LibreMiddleware_SOURCE_DIR}/lib
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/miniz
)
target_compile_features(LibreSign PUBLIC cxx_std_23)

# --- Link dependencies ---
# SmartCard is header-only for our needs (SecureBuffer + PinStringScrubber
# from smartcard/secure_buffer.h), but PRIVATE linking is the cleanest way
# to pick up its include directory without leaking PCSC to LibreSign's
# public API.
#
# LibreSCRS_Auth is PUBLIC because internal libresign headers (types.h,
# http_client.h) now #include <LibreSCRS/Secure/String.h>. Tests and the
# LibreSCRS::Signing bridge that PRIVATE-include lib/libresign/src/ must
# be able to resolve the public header — transitive propagation of
# LibreSCRS_Auth's PUBLIC include directory is the least-friction fix.
# LibreSCRS_Auth itself is a leaf on LibreSign (no circular dependency).
# SHARED-build cycle break: LibreSign no longer PRIVATE-links
# LibreSCRS_Trust. Cross-target call edges that
# previously reached into Trust::detail::TrustStoreInternalAccess have
# been inverted via NativeSigningService::AnchorEmitter — libresign now
# emits TL anchors and the LibreSCRS_Signing-side bridge owns the merge
# into the public TrustStore. With this link edge gone, the
# Trust ↔ LibreSign target cycle (tolerated by static archives, rejected
# by CMake once a member becomes SHARED) dissolves into a one-way edge:
# LibreSCRS_Trust  PRIVATE  LibreSign. The LibreSCRS::Trust::TrustAnchor
# type used in the AnchorEmitter signature is reachable through
# LibreSCRS_Auth's PUBLIC include directory; no link symbol is needed
# for the data-only struct.
target_link_libraries(LibreSign PRIVATE OpenSSL_Crypto curl_static_with_deps SmartCard_Impl)
target_link_libraries(LibreSign PUBLIC LibreSCRS_Auth)

if(SIGNING_BACKEND STREQUAL "dss" OR SIGNING_BACKEND STREQUAL "both")
    target_compile_definitions(LibreSign PUBLIC LIBRESIGN_HAS_DSS=1)
endif()

if(SIGNING_BACKEND STREQUAL "native" OR SIGNING_BACKEND STREQUAL "both")
    target_compile_definitions(LibreSign PUBLIC LIBRESIGN_HAS_NATIVE=1)
    target_include_directories(LibreSign PRIVATE
        ${LibreMiddleware_SOURCE_DIR}/lib/pkcs11/include
    )

    find_package(LibXml2 REQUIRED)
    target_link_libraries(LibreSign PRIVATE
        ${CMAKE_DL_LIBS}
        LibXml2::LibXml2
    )
endif()
