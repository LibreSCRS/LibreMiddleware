# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# E2E real-card tests for the multi-PIN PKCS#11 path.
# Every test is gated by env vars (LIBRESCRS_TEST_PIN,
# LIBRESCRS_TEST_PIN_QSCD, LIBRESCRS_TEST_CAN); without them set every
# test calls GTEST_SKIP() so the suite is safe to run on CI / dev
# workstations without a card present.
#
# UNLIKE lib/pkcs11/test/ — which deliberately recompiles the .cpp
# sources straight into the unit-test exe to avoid linking the .so —
# this exe MUST link librescrs-pkcs11.so, because its whole purpose is
# to validate the PUBLISHED C ABI surface (C_Initialize, C_GetSlotList,
# C_Login, C_Sign, ...). Those C symbols are exported by the .so
# (see lib/pkcs11/exports.list / exports.map); no internal LibreSCRS::
# symbols are referenced from these tests, so there's no ODR risk.

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GoogleTest)

add_executable(librescrs_pkcs11_e2e_tests
    Pkcs11GeoMultiPinTests.cpp
    Pkcs11NamSignTests.cpp
    Pkcs11PksSignTests.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/pin_guard.h
)

# Pkcs11PksSignTests verifies signatures against the on-card cert's
# public key with EVP_PKEY_verify, so this binary now needs OpenSSL.
target_link_libraries(librescrs_pkcs11_e2e_tests PRIVATE
    GTest::gtest_main
    librescrs-pkcs11
    OpenSSL_Crypto
)

target_include_directories(librescrs_pkcs11_e2e_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${LibreMiddleware_SOURCE_DIR}/lib/pkcs11/include
)

gtest_discover_tests(librescrs_pkcs11_e2e_tests)

# ---------------------------------------------------------------------------
# Opt-in real-card E2E tests.
#
# Gated on LIBRESCRS_BUILD_REAL_CARD_TESTS=ON because they are intended
# to be invoked manually with a real card present and correct PIN env
# vars; see each file's header comment for the operator protocol.
# NOT registered with gtest_discover_tests so a routine `ctest`
# invocation does not accidentally trigger card I/O.
# ---------------------------------------------------------------------------
option(LIBRESCRS_BUILD_REAL_CARD_TESTS
    "Build opt-in real-card E2E tests (manual operator runs only; not in default ctest set)"
    OFF)

if(LIBRESCRS_BUILD_REAL_CARD_TESTS)
    # 4.1.0 multi-card regression smoke. Iterates every reader, classifies
    # by ATR, runs sign on each recognised card profile with its own PIN
    # latch — a failure on one card does not poison the others.
    add_executable(Pkcs11MultiCardSignTests
        Pkcs11MultiCardSignTests.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/../include/pin_guard.h
    )
    target_link_libraries(Pkcs11MultiCardSignTests PRIVATE
        GTest::gtest_main
        LibreSCRS::SmartCard
        LibreSign
        OpenSSL_Crypto
        ${CMAKE_DL_LIBS}
    )
    target_include_directories(Pkcs11MultiCardSignTests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
        ${LibreMiddleware_SOURCE_DIR}/lib/pkcs11/include
    )
    target_compile_definitions(Pkcs11MultiCardSignTests PRIVATE
        LIBRESCRS_INTERNAL_BUILD=1
        LIBRESCRS_PKCS11_MODULE_PATH="$<TARGET_FILE:librescrs-pkcs11>"
    )
    add_dependencies(Pkcs11MultiCardSignTests librescrs-pkcs11)
endif()
