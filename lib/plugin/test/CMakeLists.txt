# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(GoogleTest)

add_executable(ActivationProfileTests ActivationProfileTests.cpp)
target_link_libraries(ActivationProfileTests PRIVATE
    LibreSCRS::Plugin
    LibreSCRS::SmartCard
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(ActivationProfileTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(ActivationProfileTests)

# ActivatedProtocolTests — anchors the CardSession::activatedProtocol()
# no-channel contract (nullopt on a freshly detached session) that the
# eMRTD plugin's protocol-label fallback relies on. Reaches the LM-internal
# detached-session factory via the injection header, so it links the
# build-tree-only TestHelpers archive (which provides the factory
# definition) and compiles with LIBRESCRS_INTERNAL_BUILD.
add_executable(ActivatedProtocolTests ActivatedProtocolTests.cpp)
target_link_libraries(ActivatedProtocolTests PRIVATE
    LibreSCRS::SmartCard
    LibreSCRS_SmartCard_TestHelpers
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(ActivatedProtocolTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(ActivatedProtocolTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(ActivatedProtocolTests)

# PreReadAuthDerivationTests — anchors that CardPlugin::preReadAuth derives
# the pre-read unlock method from the plugin-published ActivationProfile.
# Needs the public CardPlugin surface (LibreSCRS::Plugin, which absorbs the
# CardPlugin_Impl out-of-line definitions) plus the build-tree-only
# detached-session factory (LibreSCRS_SmartCard_TestHelpers), so it combines
# the link/define wiring of ActivationProfileTests and ActivatedProtocolTests.
add_executable(PreReadAuthDerivationTests PreReadAuthDerivationTests.cpp)
target_link_libraries(PreReadAuthDerivationTests PRIVATE
    LibreSCRS::Plugin
    LibreSCRS::SmartCard
    LibreSCRS_SmartCard_TestHelpers
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(PreReadAuthDerivationTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(PreReadAuthDerivationTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PreReadAuthDerivationTests)
