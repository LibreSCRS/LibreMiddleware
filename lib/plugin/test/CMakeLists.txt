# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
include(GoogleTest)

# ActivationProfileTests exercises the internal isStopError /
# shouldTryFallback predicates (hidden visibility, declared only under
# LIBRESCRS_INTERNAL_BUILD) alongside the public acquireChannelForProfile.
# Reaches them by absorbing the CardPlugin_Impl object archive (default
# visibility, build-tree only) and compiling with LIBRESCRS_INTERNAL_BUILD so
# the internal declarations are visible — mirrors ActivatedProtocolTests.
add_executable(ActivationProfileTests ActivationProfileTests.cpp)
target_link_libraries(ActivationProfileTests PRIVATE
    LibreSCRS::Plugin
    $<BUILD_INTERFACE:CardPlugin_Impl>
    LibreSCRS::SmartCard
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(ActivationProfileTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(ActivationProfileTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(ActivationProfileTests)

# PinLifecycleFieldsTests — anchors the credential-lifecycle value contract
# on PinStatusEntry (conservative Unknown/false/nullopt defaults, member-wise
# equality over the appended fields, Unknown == 0 for every lifecycle enum).
# Mirrors the ActivationProfileTests wiring.
add_executable(PinLifecycleFieldsTests PinLifecycleFieldsTests.cpp)
target_link_libraries(PinLifecycleFieldsTests PRIVATE
    LibreSCRS::Plugin
    $<BUILD_INTERFACE:CardPlugin_Impl>
    LibreSCRS::SmartCard
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(PinLifecycleFieldsTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(PinLifecycleFieldsTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PinLifecycleFieldsTests)

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

# DecipherTypesTest — anchors the value-type contract for the raw on-card
# decrypt surface (DecipherResult::ok predicate, DecipherMechanism enum
# closedness). Pure header types, so it needs only the public Plugin surface.
add_executable(DecipherTypesTest DecipherTypesTest.cpp)
target_link_libraries(DecipherTypesTest PRIVATE
    LibreSCRS::Plugin
    GTest::gtest_main
)
target_include_directories(DecipherTypesTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
gtest_discover_tests(DecipherTypesTest)

# CardPluginDecipherDefaultTest — anchors the CardPlugin::decipher NVI default
# (NotImplemented) through the public wrapper, mirroring PreReadAuthDerivation's
# minimal-concrete-plugin shape. Uses the LM-internal detached-session factory
# so the wrapper receives a real (cancellable) CardSession reference.
add_executable(CardPluginDecipherDefaultTest CardPluginDecipherDefaultTest.cpp)
target_link_libraries(CardPluginDecipherDefaultTest PRIVATE
    LibreSCRS::Plugin
    LibreSCRS::SmartCard
    LibreSCRS_SmartCard_TestHelpers
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(CardPluginDecipherDefaultTest PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(CardPluginDecipherDefaultTest PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(CardPluginDecipherDefaultTest)

# PinLifecycleVirtualsTests — anchors the CardPlugin credential-lifecycle
# base defaults (activateTransportPin / activateSigningKey report
# Unsupported when not overridden), mirroring CardPluginDecipherDefaultTest's
# minimal-concrete-plugin shape. Uses the LM-internal detached-session
# factory so the defaults receive a real CardSession reference.
add_executable(PinLifecycleVirtualsTests PinLifecycleVirtualsTests.cpp)
target_link_libraries(PinLifecycleVirtualsTests PRIVATE
    LibreSCRS::Plugin
    LibreSCRS::SmartCard
    LibreSCRS_SmartCard_TestHelpers
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(PinLifecycleVirtualsTests PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(PinLifecycleVirtualsTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PinLifecycleVirtualsTests)

# PinFamilyQuirksTests — anchors the static per-family credential quirk
# table consumed by the lifecycle derivation: conservative rows (no family
# advertises an unverified unblock command form), Unknown family has no
# row. The table lives in an internal header under lib/plugin/src, so the
# test adds that src dir to its include path and compiles with
# LIBRESCRS_INTERNAL_BUILD, absorbing the table definition from the
# CardPlugin_Impl object archive — mirrors the ActivationProfileTests
# wiring.
add_executable(PinFamilyQuirksTests PinFamilyQuirksTests.cpp)
target_link_libraries(PinFamilyQuirksTests PRIVATE
    LibreSCRS::Plugin
    $<BUILD_INTERFACE:CardPlugin_Impl>
    LibreSCRS::SmartCard
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(PinFamilyQuirksTests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/lib/plugin/src
)
target_compile_definitions(PinFamilyQuirksTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PinFamilyQuirksTests)

# PinLifecycleDerivationTests — anchors the credential-lifecycle derivation
# engine (evidence + family quirks → PinStatusEntry): kind classification,
# state precedence, and the conservative unblock rule (chain + verified
# command form + presentable PUK, never advertised otherwise). The engine
# lives in an internal header under lib/plugin/src, so the test adds that
# src dir to its include path and compiles with LIBRESCRS_INTERNAL_BUILD,
# absorbing the definitions from the CardPlugin_Impl object archive —
# mirrors the PinFamilyQuirksTests wiring.
add_executable(PinLifecycleDerivationTests PinLifecycleDerivationTests.cpp)
target_link_libraries(PinLifecycleDerivationTests PRIVATE
    LibreSCRS::Plugin
    $<BUILD_INTERFACE:CardPlugin_Impl>
    LibreSCRS::SmartCard
    LibreSCRS::Secure
    GTest::gtest_main
)
target_include_directories(PinLifecycleDerivationTests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/lib/plugin/src
)
target_compile_definitions(PinLifecycleDerivationTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PinLifecycleDerivationTests)
