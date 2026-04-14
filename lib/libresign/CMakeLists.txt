# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(SIGNING_BACKEND "native" CACHE STRING "Signing backend: native, dss, or both")
set_property(CACHE SIGNING_BACKEND PROPERTY STRINGS "native" "dss" "both")

find_package(CURL REQUIRED)

# --- Core sources (always built) ---
set(LIBRESIGN_SOURCES
    src/trust_store_manager.cpp
    src/signing_service_factory.cpp
    src/http_client.cpp
)
set(LIBRESIGN_HEADERS
    include/libresign/types.h
    include/libresign/signing_service.h
    include/libresign/signing_service_factory.h
    include/libresign/trust_store_manager.h
    include/libresign/http_client.h
)

# --- DSS backend sources ---
if(SIGNING_BACKEND STREQUAL "dss" OR SIGNING_BACKEND STREQUAL "both")
    list(APPEND LIBRESIGN_SOURCES
        src/dss/dss_signing_service.cpp
        src/dss/dss_service_manager.cpp
        src/dss/dss_path_resolver.cpp
    )
    list(APPEND LIBRESIGN_HEADERS
        include/libresign/dss/dss_service_manager.h
        include/libresign/dss/dss_signing_service.h
        include/libresign/dss/dss_path_resolver.h
    )
endif()

# --- Native backend sources ---
if(SIGNING_BACKEND STREQUAL "native" OR SIGNING_BACKEND STREQUAL "both")
    list(APPEND LIBRESIGN_SOURCES
        src/native/native_utils.cpp
        src/native/pdf_parser.cpp
        src/native/pkcs11_token.cpp
        src/native/signing_provider.cpp
        src/native/tsa_client.cpp
        src/native/revocation_client.cpp
        src/native/cades_module.cpp
        src/native/pades_module.cpp
        src/native/jades_module.cpp
        src/native/xades_module.cpp
        src/native/asic_module.cpp
        ${LibreMiddleware_SOURCE_DIR}/thirdparty/miniz/miniz.c
        src/native/trusted_list_parser.cpp
        src/native/native_signing_service.cpp
    )
    list(APPEND LIBRESIGN_HEADERS
        include/libresign/native/pkcs11_token.h
        include/libresign/native/signing_provider.h
        include/libresign/native/tsa_client.h
        include/libresign/native/revocation_client.h
        include/libresign/native/cades_module.h
        include/libresign/native/pades_module.h
        include/libresign/native/jades_module.h
        include/libresign/native/xades_module.h
        include/libresign/native/asic_module.h
        include/libresign/native/trusted_list_parser.h
        include/libresign/native/native_signing_service.h
    )
endif()

# --- Build library ---
add_library(LibreSign STATIC ${LIBRESIGN_SOURCES} ${LIBRESIGN_HEADERS})

# Vendored miniz.c was written against pre-C89 compilers and uses K&R-style
# function declarations in two spots, which clang flags with
# -Wstrict-prototypes under -Wall. Suppress the warning for just this file so
# we can keep the project's overall -Wall -Wextra -Wpedantic strictness
# without patching vendored code.
if(SIGNING_BACKEND STREQUAL "native" OR SIGNING_BACKEND STREQUAL "both")
    set_source_files_properties(
        ${CMAKE_CURRENT_SOURCE_DIR}/../../thirdparty/miniz/miniz.c
        PROPERTIES COMPILE_FLAGS "-Wno-strict-prototypes"
    )
endif()

target_include_directories(LibreSign PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_include_directories(LibreSign PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann
    ${LibreMiddleware_SOURCE_DIR}/thirdparty/miniz
)
target_compile_features(LibreSign PUBLIC cxx_std_20)

# --- Link dependencies ---
# SmartCard is header-only for our needs (SecureBuffer + PinStringScrubber
# from smartcard/secure_buffer.h), but PRIVATE linking is the cleanest way
# to pick up its include directory without leaking PCSC to LibreSign's
# public API.
target_link_libraries(LibreSign PRIVATE OpenSSL_Crypto CURL::libcurl SmartCard)

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
