# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# Unit tests for PKCS15 internal helpers.
#
# Mirrors the lib/pkcs11/test/ pattern: small self-contained test
# executables that link against PKCS15 (the static internal library)
# and the LibreSCRS::SmartCard public library so they can construct
# CardSession instances via the detached-session test factory.

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GoogleTest)

add_executable(SessionRegistryTests SessionRegistryTests.cpp)

target_link_libraries(SessionRegistryTests PRIVATE
    PKCS15
    LibreSCRS::SmartCard
    GTest::gtest_main
)

target_include_directories(SessionRegistryTests PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/include
)

# SessionRegistry's header carries the LIBRESCRS_INTERNAL_BUILD #error
# guard; the test is part of the LM build tree and may legitimately
# reach into the internal namespace.
target_compile_definitions(SessionRegistryTests PRIVATE LIBRESCRS_INTERNAL_BUILD)

gtest_discover_tests(SessionRegistryTests)

# PKCS11 base-class symbols (PKCS11Card / PKCS11Slot) are produced into
# librescrs-pkcs11 (the SHARED module) which restricts its export table
# to the standard C ABI — Internal::PKCS11Card et al. are hidden. The
# sibling lib/pkcs11/test exe compiles those base TUs directly into its
# own binary for the same reason; this test follows the same recipe so
# Pkcs15Card (which inherits from PKCS11Card) links cleanly without
# pulling the production .so into the test address space.
add_executable(Pkcs15CardInjectBindTests
    Pkcs15CardInjectBindTests.cpp
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/pkcs11_card.cpp
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/pkcs11_slot.cpp
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/slot_id_hash.cpp
)

target_link_libraries(Pkcs15CardInjectBindTests PRIVATE
    PKCS15
    LibreSCRS::SmartCard
    LibreSCRS::Secure
    GTest::gtest_main
)

target_include_directories(Pkcs15CardInjectBindTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/include
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/src
)

target_compile_definitions(Pkcs15CardInjectBindTests PRIVATE LIBRESCRS_INTERNAL_BUILD)

gtest_discover_tests(Pkcs15CardInjectBindTests)

# CrossProviderCoordinationTests — regression anchor for the joint
# contract between SessionRegistry::peek, OpenScPKCS11Provider::probe,
# Pkcs15PKCS11Provider::probe, and CardSession::activateChannel*. Locks
# in the cross-provider invariants without hardware. Gated on
# LIBRESCRS_VENDOR_OPENSC because the OpenSc provider lives behind that
# option; the in-tree invariants it pins down are only at risk when that
# provider is in the picture.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(CrossProviderCoordinationTests
        CrossProviderCoordinationTests.cpp
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/pkcs11_card.cpp
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/pkcs11_slot.cpp
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/slot_id_hash.cpp
    )

    target_link_libraries(CrossProviderCoordinationTests PRIVATE
        PKCS15
        librescrs-opensc-pkcs11
        LibreSCRS::SmartCard
        LibreSCRS::Secure
        GTest::gtest_main
    )

    target_include_directories(CrossProviderCoordinationTests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/include
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/src
        ${PROJECT_SOURCE_DIR}/lib/opensc-pkcs11/include
        ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    )

    target_compile_definitions(CrossProviderCoordinationTests PRIVATE LIBRESCRS_INTERNAL_BUILD)

    gtest_discover_tests(CrossProviderCoordinationTests)
endif()
