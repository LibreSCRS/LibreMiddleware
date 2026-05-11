# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# E2E real-card tests for the PKCS#11 multi-PIN refactor (Phase D.1).
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
    pin_guard.h
)

target_link_libraries(librescrs_pkcs11_e2e_tests PRIVATE
    GTest::gtest_main
    librescrs-pkcs11
)

target_include_directories(librescrs_pkcs11_e2e_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LibreMiddleware_SOURCE_DIR}/lib/pkcs11/include
)

gtest_discover_tests(librescrs_pkcs11_e2e_tests)
