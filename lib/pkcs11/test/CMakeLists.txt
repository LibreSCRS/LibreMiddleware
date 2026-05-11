# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# Type-contract tests for the multi-PIN PKCS#11 base classes.
# Header-only mocks plus a single test-executable.
#
# We deliberately recompile pkcs11_card.cpp / pkcs11_slot.cpp directly
# into the test executable rather than linking librescrs-pkcs11. The
# production .so restricts its exported symbol set to the PKCS#11 v2.40
# C ABI via exports.list / exports.map (see lib/pkcs11/CMakeLists.txt),
# which would hide LibreSCRS::Pkcs11::Internal::PKCS11Card et al. from
# any consumer linking the .so. Recompiling the small handful of TU
# sources into the test exe is the smallest-blast-radius way to keep
# the production export discipline intact while still being able to
# unit-test the abstract bases.
#
# IMPORTANT: librescrs_pkcs11_tests MUST NEVER be linked against
# librescrs-pkcs11 (the .so). Doing so would put two definitions of
# every internal symbol in the same address space (one from the .so,
# one from the recompiled TUs in this exe) — an ODR violation that
# silently breaks under any toolchain still resolving through
# RTLD_GLOBAL. The recompile-into-exe is mutually exclusive with
# linking the library; keep them separate.

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GoogleTest)

add_executable(librescrs_pkcs11_tests
    PKCS11CardSlotContractTests.cpp
    SlotIdHashTests.cpp
    MockProviderSanityTest.cpp
    MultiPinEnumerationTests.cpp
    LoginIsolationTests.cpp
    CanInPinParsingTests.cpp
    ReconnectTests.cpp
    ConcurrencyTests.cpp
    MockPKCS11CardSlot.h
    MockPKCS11CardProvider.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/pkcs11_card.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/pkcs11_slot.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/slot_id_hash.cpp
)

target_link_libraries(librescrs_pkcs11_tests PRIVATE
    GTest::gtest_main
    LibreSCRS::Secure
)

target_include_directories(librescrs_pkcs11_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

# The internal/ headers carry the LIBRESCRS_INTERNAL_BUILD #error guard;
# the type-contract tests are part of the LM build tree and may
# legitimately reach into the internal namespace.
target_compile_definitions(librescrs_pkcs11_tests PRIVATE
    LIBRESCRS_INTERNAL_BUILD
)

gtest_discover_tests(librescrs_pkcs11_tests)
