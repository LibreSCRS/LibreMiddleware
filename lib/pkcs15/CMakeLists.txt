# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(PKCS15 STATIC
    src/pkcs15_parser.cpp
    src/pkcs15_card.cpp
    src/pkcs15_pkcs11_card.cpp
    src/pkcs15_pkcs11_slot.cpp
    src/pin_classification.cpp
    src/docp_parser.cpp
    include/internal/PinClassification.h
    src/pkcs15_types.h
    src/pkcs15_parser.h
    src/pkcs15_card.h
    src/pkcs15_pkcs11_card.h
    src/pkcs15_pkcs11_slot.h
    src/docp_parser.h
)

target_compile_definitions(PKCS15 PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(PKCS15
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/lib/emrtd-crypto/src
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/include
        ${PROJECT_SOURCE_DIR}/lib/plugin/src
        ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
)

target_link_libraries(PKCS15 PUBLIC SmartCard_Impl LibreSCRS::SmartCard LibreSCRS_SecureChannel PRIVATE OpenSSL_Crypto EMRTDCrypto LibreSCRS::Secure)

set_target_properties(PKCS15 PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(BUILD_TESTING AND LIBREMIDDLEWARE_BUILD_PLUGINS)
    # Root CMakeLists.txt enables testing AFTER add_subdirectory(lib/pkcs15);
    # call enable_testing() here so this subdirectory's CTestTestfile.cmake
    # is emitted with add_test() entries from gtest_discover_tests below.
    # Idempotent — second invocation from the root scope is a no-op.
    # Gated on BUILD_PLUGINS because GTest is fetched in test/CMakeLists.txt
    # (skipped in monolithic SDK mode).
    enable_testing()
    add_subdirectory(test)
endif()
