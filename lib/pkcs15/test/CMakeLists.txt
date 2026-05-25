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

# CrossProviderCoordinationTests — regression anchor for the joint
# contract between SessionPresence::hasLiveSm, OpenScPKCS11Provider::probe,
# and CardSession::activateChannel*. Locks in the cross-provider
# invariants without hardware. Gated on LIBRESCRS_VENDOR_OPENSC because
# the OpenSc provider lives behind that option; the in-tree invariants
# it pins down are only at risk when that provider is in the picture.
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
        LibreSCRS_SmartCard_TestHelpers
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

# cardsession_reentrancy_test — regression anchor for the same-thread
# re-entrancy guard on CardSession. Independent of the OpenSc provider:
# it only needs the public CardSession surface plus the build-tree-only
# TestHelpers archive (detached-session factory + holder-acquisition seam).
add_executable(cardsession_reentrancy_test
    cardsession_reentrancy_test.cpp
)

target_link_libraries(cardsession_reentrancy_test PRIVATE
    LibreSCRS::SmartCard
    LibreSCRS::SecureChannel
    LibreSCRS_SmartCard_TestHelpers
    LibreSCRS::Secure
    PCSC::PCSC
    GTest::gtest_main
)

target_include_directories(cardsession_reentrancy_test PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    ${PROJECT_SOURCE_DIR}/lib/SecureChannel/include
)

target_compile_definitions(cardsession_reentrancy_test PRIVATE LIBRESCRS_INTERNAL_BUILD)

gtest_discover_tests(cardsession_reentrancy_test)
