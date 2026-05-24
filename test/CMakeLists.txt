# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP ON
)
FetchContent_MakeAvailable(googletest)
enable_testing()

add_executable(LibreMiddlewareTests
    smartcard_test.cpp
    eu_vrc_test.cpp
    healthcard_test.cpp
)

target_link_libraries(LibreMiddlewareTests
    GTest::gtest_main
    RsEId
    EuVrc
    RsHealth
    SmartCard_Impl
)

target_include_directories(LibreMiddlewareTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-health/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/eu-vrc/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
)
# LM-internal test: includes internal headers via lib/*/src/; advertise the
# internal-build marker to satisfy the #error guard on those headers.
target_compile_definitions(LibreMiddlewareTests PRIVATE LIBRESCRS_INTERNAL_BUILD)

include(GoogleTest)
gtest_discover_tests(LibreMiddlewareTests)

# rs-eid driver unit tests (Wave 5.1 — flagship Serbian eID coverage).
# Drives CardReaderApollo / CardReaderGemalto / CardVerifier through a
# detached PCSCConnection with a TransmitFilter intercepting every APDU.
add_executable(RsEidDriverTests
    rs-eid/protocol_test.cpp
    rs-eid/card_reader_apollo_test.cpp
    rs-eid/card_reader_gemalto_test.cpp
    rs-eid/card_verifier_test.cpp
)
target_link_libraries(RsEidDriverTests
    GTest::gtest_main
    RsEId
    SmartCard_Impl
    OpenSSL_Crypto
)
target_include_directories(RsEidDriverTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/rs-eid/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
)
target_compile_definitions(RsEidDriverTests PRIVATE
    LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/test/test-data"
)
gtest_discover_tests(RsEidDriverTests)

add_executable(LibreSCRS_AuthTests LibreSCRS_Auth_test.cpp)
target_link_libraries(LibreSCRS_AuthTests GTest::gtest_main LibreSCRS_Auth CardPlugin_Impl SmartCard_Impl)
# ABI v6 removed LibreSCRS::Plugin::detail::ChangePinAdapter — the auth test
# no longer touches any internal detail/ header, so it builds against the
# public API without the LIBRESCRS_INTERNAL_BUILD marker.
gtest_discover_tests(LibreSCRS_AuthTests)

add_executable(LibreSCRS_LocalizedTextTests LibreSCRS_LocalizedTextTests.cpp)
target_link_libraries(LibreSCRS_LocalizedTextTests GTest::gtest_main LibreSCRS_Auth)
gtest_discover_tests(LibreSCRS_LocalizedTextTests)

add_executable(LibreSCRS_CancelTokenTests LibreSCRS_CancelTokenTests.cpp)
target_link_libraries(LibreSCRS_CancelTokenTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
target_compile_definitions(LibreSCRS_CancelTokenTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(LibreSCRS_CancelTokenTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib
)
gtest_discover_tests(LibreSCRS_CancelTokenTests)

add_executable(LibreSCRS_CredentialProviderTests LibreSCRS_CredentialProvider_test.cpp)
target_link_libraries(LibreSCRS_CredentialProviderTests GTest::gtest_main LibreSCRS_Auth)
gtest_discover_tests(LibreSCRS_CredentialProviderTests)

# CardMap — process-local cache of per-card discovered state. Public LM type
# consumed by both the pkcs15 card plugin and the internal PKCS#11 provider.
add_executable(LibreSCRS_CardMapTests LibreSCRS_CardMapTests.cpp)
target_link_libraries(LibreSCRS_CardMapTests GTest::gtest_main LibreSCRS::SmartCard)
gtest_discover_tests(LibreSCRS_CardMapTests)

# PlainChannel — pass-through implementation of ISecureChannel; exercises
# the FakePCSCConnection IConnection seam used by all SecureChannel tests.
add_executable(LibreSCRS_PlainChannelTests LibreSCRS_PlainChannelTests.cpp)
target_link_libraries(LibreSCRS_PlainChannelTests
    GTest::gtest_main
    LibreSCRS::SecureChannel
    LibreSCRS::SmartCard
    SmartCard_Impl)
target_include_directories(LibreSCRS_PlainChannelTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include)
target_compile_definitions(LibreSCRS_PlainChannelTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_PlainChannelTests)

# PaceChannel + BacChannel — SM-wrapping channels. Tests exercise state
# transitions, sentinel SW codes, and SW 6987/6988 external-invalidation
# detection. Full PACE/BAC handshake test vectors require BSI TR-03110 /
# ICAO Doc 9303 documents and are deferred.
add_executable(LibreSCRS_SmChannelTests LibreSCRS_SmChannelTests.cpp)
target_link_libraries(LibreSCRS_SmChannelTests
    GTest::gtest_main
    LibreSCRS::SecureChannel
    LibreSCRS::SmartCard
    SmartCard_Impl)
target_include_directories(LibreSCRS_SmChannelTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include)
target_compile_definitions(LibreSCRS_SmChannelTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_SmChannelTests)

# CardTransaction static contract — move-only, release() noexcept, owns()
# accessor present, PCSCConnection::isTransactionHeld() visible. Behavioural
# tests against a real reader live in the hardware suite.
add_executable(LibreSCRS_CardTransactionTests LibreSCRS_CardTransactionTests.cpp)
target_link_libraries(LibreSCRS_CardTransactionTests GTest::gtest_main SmartCard_Impl)
target_include_directories(LibreSCRS_CardTransactionTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
target_compile_definitions(LibreSCRS_CardTransactionTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_CardTransactionTests)

# AuthRequirement::forPaceSecret — PACE/BAC credential prompt factory.
add_executable(LibreSCRS_AuthRequirementPaceTests LibreSCRS_AuthRequirementPaceTests.cpp)
target_link_libraries(LibreSCRS_AuthRequirementPaceTests GTest::gtest_main LibreSCRS::Auth)
gtest_discover_tests(LibreSCRS_AuthRequirementPaceTests)

# OID database lookup tests — superset of OpenSSL/Rust/BC/ETSI/ICAO/Serbian.
add_executable(OidDatabaseTests oid_database_test.cpp)
target_link_libraries(OidDatabaseTests GTest::gtest_main LibreSCRS_Certificate)
gtest_discover_tests(OidDatabaseTests)

# ParsedCertificate public-API tests.
add_executable(ParsedCertificateTests parsed_certificate_test.cpp)
target_link_libraries(ParsedCertificateTests GTest::gtest_main LibreSCRS_Certificate)
target_compile_definitions(ParsedCertificateTests PRIVATE
    LIBREMIDDLEWARE_TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/test/test-data")
gtest_discover_tests(ParsedCertificateTests)

# ParsedCertificate::fromDer std::expected error-shape regression tests
# (locks SOTA invariant per spec §6.1: fallible factory returns
# std::expected<T, E>; failure E carries Kind + LocalizedText + diag).
add_executable(ParsedCertificateExpectedTests
    ${CMAKE_CURRENT_SOURCE_DIR}/cert/parsed_certificate_expected_test.cpp)
target_link_libraries(ParsedCertificateExpectedTests GTest::gtest_main LibreSCRS_Certificate)
gtest_discover_tests(ParsedCertificateExpectedTests)

# TrustStoreService — async lifecycle / observer / fetch tests.
add_executable(TrustStoreServiceTests trust_store_service_test.cpp)
target_link_libraries(TrustStoreServiceTests PRIVATE
    GTest::gtest_main
    LibreSCRS::Trust
    LibreSCRS::Signing
    OpenSSL_Crypto
)
target_compile_definitions(TrustStoreServiceTests PRIVATE
    LIBRESCRS_TEST_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
gtest_discover_tests(TrustStoreServiceTests)

# TrustStoreService::create std::expected error-shape regression tests
# (locks SOTA invariant per spec §6.1; mirrors ParsedCertificateExpectedTests).
add_executable(TrustStoreServiceCreateExpectedTests
    ${CMAKE_CURRENT_SOURCE_DIR}/trust/trust_store_service_create_expected_test.cpp)
target_link_libraries(TrustStoreServiceCreateExpectedTests PRIVATE
    GTest::gtest_main
    LibreSCRS::Trust
)
gtest_discover_tests(TrustStoreServiceCreateExpectedTests)

# PCSCConnection TransmitFilter tests
add_executable(pcsc_connection_filter_test pcsc_connection_filter_test.cpp)
target_link_libraries(pcsc_connection_filter_test SmartCard_Impl GTest::gtest_main)
target_include_directories(pcsc_connection_filter_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
# LM-internal test: reaches directly into lib/smartcard/src; must advertise
# the internal-build marker so the #error guard in apdu.h lets it in.
target_compile_definitions(pcsc_connection_filter_test PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(pcsc_connection_filter_test)

# selectByFileId P2 parameter test
add_executable(apdu_select_p2_test apdu_select_p2_test.cpp)
target_link_libraries(apdu_select_p2_test SmartCard_Impl GTest::gtest_main)
target_include_directories(apdu_select_p2_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
# LM-internal test: reaches directly into lib/smartcard/src; must advertise
# the internal-build marker so the #error guard in apdu.h lets it in.
target_compile_definitions(apdu_select_p2_test PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(apdu_select_p2_test)

# Plugin tests (CardData model + Registry + dlopen loading)
add_subdirectory(mock_card_plugin)

add_executable(PluginTests
    card_data_test.cpp
    card_plugin_registry_test.cpp
)
target_link_libraries(PluginTests
    GTest::gtest_main
    CardPlugin_Impl
    LibreSCRS_Plugin
)
# LibreSCRS_Plugin link: needed for the LibreSCRS::Plugin::textValue /
# textValueAt convenience accessors exercised by the CardDataAccessTest
# suite in card_data_test.cpp (Wave 6 / 6.2).
target_compile_definitions(PluginTests PRIVATE
    MOCK_PLUGIN_DIR="$<TARGET_FILE_DIR:mock-card-plugin>"
)
add_dependencies(PluginTests mock-card-plugin)
gtest_discover_tests(PluginTests)

# Integration test: loads all 4 real card plugins
add_executable(PluginIntegrationTests
    plugin_integration_test.cpp
)
target_link_libraries(PluginIntegrationTests
    GTest::gtest_main
    CardPlugin_Impl
)
target_compile_definitions(PluginIntegrationTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
add_dependencies(PluginIntegrationTests
    rs-eid-plugin
    eu-vrc-plugin
    rs-health-plugin
)

if(TARGET emrtd-plugin)
    add_dependencies(PluginIntegrationTests emrtd-plugin)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_EMRTD_PLUGIN=1)
endif()

if(TARGET pkcs15-plugin)
    add_dependencies(PluginIntegrationTests pkcs15-plugin)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_PKCS15_PLUGIN=1)
endif()

if(LIBRESCRS_VENDOR_OPENSC)
    add_dependencies(PluginIntegrationTests opensc-plugin)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_OPENSC_PLUGIN=1)
endif()

gtest_discover_tests(PluginIntegrationTests)

# eMRTD plugin tests
add_executable(EMRTDPluginTests
    emrtd_plugin_test.cpp
)
target_link_libraries(EMRTDPluginTests
    GTest::gtest_main
    CardPlugin_Impl
    SmartCard_Impl
)
target_include_directories(EMRTDPluginTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
target_compile_definitions(EMRTDPluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    LIBRESCRS_INTERNAL_BUILD
)
add_dependencies(EMRTDPluginTests emrtd-plugin)
gtest_discover_tests(EMRTDPluginTests)

add_executable(PKCS11Tests pkcs11_test.cpp)
target_link_libraries(PKCS11Tests GTest::gtest_main librescrs-pkcs11)
# Shared PIN-guard header lives under test/include/ — see test/e2e/CMakeLists.txt
# for the matching consumer. Per feedback_pin_guard_pattern the helper must
# stay byte-identical across real-card test binaries.
target_include_directories(PKCS11Tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
gtest_discover_tests(PKCS11Tests DISCOVERY_TIMEOUT 30)

# Internal-only test for the slot-disambiguation hash helpers shared by
# the LM PKCS#11 module and Pkcs11Token's reader-name lookup.
add_executable(SlotHashTests slot_hash_test.cpp)
target_link_libraries(SlotHashTests GTest::gtest_main)
target_include_directories(SlotHashTests PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/pkcs11/include)
target_compile_definitions(SlotHashTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(SlotHashTests)

# PKCS#15 card investigation probe (run with a physical card inserted)
add_executable(pkcs15_probe pkcs15_probe.cpp)
target_link_libraries(pkcs15_probe SmartCard_Impl)
target_include_directories(pkcs15_probe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
target_compile_definitions(pkcs15_probe PRIVATE LIBRESCRS_INTERNAL_BUILD)

# PKCS#15-after-PACE probe: authenticates via PACE then probes PKCS#15
add_executable(pkcs15_after_pace_probe pkcs15_after_pace_probe.cpp)
target_link_libraries(pkcs15_after_pace_probe SmartCard_Impl EMRTDCrypto EMRTD LibreSCRS_SmartCard)
target_include_directories(pkcs15_after_pace_probe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
)
target_compile_definitions(pkcs15_after_pace_probe PRIVATE LIBRESCRS_INTERNAL_BUILD)

# AODF + PIN reference probe
add_executable(aodf_probe aodf_probe.cpp)
target_link_libraries(aodf_probe SmartCard_Impl)
target_include_directories(aodf_probe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
target_compile_definitions(aodf_probe PRIVATE LIBRESCRS_INTERNAL_BUILD)

# FCI format probe: tests if CardEdge SELECT FILE returns ISO TLV-wrapped FCI
add_executable(fci_format_probe fci_format_probe.cpp)
target_link_libraries(fci_format_probe SmartCard_Impl)
target_include_directories(fci_format_probe PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
target_compile_definitions(fci_format_probe PRIVATE LIBRESCRS_INTERNAL_BUILD)

# eMRTD crypto tests
add_executable(EMRTDCryptoTests
    bac_test.cpp
    secure_messaging_test.cpp
    pace_test.cpp
    emrtd_crypto_test.cpp
)
target_link_libraries(EMRTDCryptoTests
    GTest::gtest_main
    EMRTDCrypto
    CardPlugin_Impl
    LibreSCRS_Plugin
)
target_include_directories(EMRTDCryptoTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
)
target_compile_definitions(EMRTDCryptoTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(EMRTDCryptoTests)

add_executable(EMRTDTests
    mrz_parse_test.cpp
    data_group_test.cpp
    pace_hardware_test.cpp
)
target_link_libraries(EMRTDTests
    GTest::gtest_main
    EMRTD
    LibreSCRS_SmartCard
)
target_include_directories(EMRTDTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/emrtd-crypto/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
)
target_compile_definitions(EMRTDTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(EMRTDTests)

# PKCS#15 parser tests
add_executable(PKCS15ParserTests pkcs15_parser_test.cpp)
target_link_libraries(PKCS15ParserTests GTest::gtest_main PKCS15)
target_include_directories(PKCS15ParserTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/pkcs15/src
)
target_compile_definitions(PKCS15ParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(PKCS15ParserTests)

# PKCS#15 plugin tests
add_executable(PKCS15PluginTests pkcs15_plugin_test.cpp)
target_link_libraries(PKCS15PluginTests GTest::gtest_main CardPlugin_Impl LibreSCRS::SmartCard LibreSCRS::Auth)
target_compile_definitions(PKCS15PluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
add_dependencies(PKCS15PluginTests pkcs15-plugin)
gtest_discover_tests(PKCS15PluginTests)

# opensc-pkcs11 driver unit tests (Wave 5.2 — fills the 0-dedicated-file
# gap for the shipped libresc-pkcs11.so). Deep bind/sign coverage already
# lives in lib/pkcs15/test/CrossProviderCoordinationTests.cpp and the
# hardware-gated opensc_fallback_integration_test.cpp; this binary pins
# down the unit-tier surface that runs without any PC/SC traffic.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenScPkcs11UnitTests
        opensc-pkcs11/sc_lock_guard_test.cpp
        opensc-pkcs11/provider_test.cpp
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/pkcs11_card.cpp
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/pkcs11_slot.cpp
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/src/slot_id_hash.cpp
    )
    target_link_libraries(OpenScPkcs11UnitTests PRIVATE
        GTest::gtest_main
        librescrs-opensc-pkcs11
        opensc_static_with_deps
        LibreSCRS::Secure
    )
    target_include_directories(OpenScPkcs11UnitTests PRIVATE
        ${PROJECT_SOURCE_DIR}/lib/opensc-pkcs11/src
        ${PROJECT_SOURCE_DIR}/lib/opensc-pkcs11/include
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/include
        ${PROJECT_SOURCE_DIR}/lib/pkcs11/src
    )
    target_compile_definitions(OpenScPkcs11UnitTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    gtest_discover_tests(OpenScPkcs11UnitTests)
endif()

# OpenSC fallback plugin tests (conditional on vendored OpenSC availability)
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenSCPluginTests
        opensc_plugin_test.cpp
    )
    target_link_libraries(OpenSCPluginTests
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        SmartCard_Impl
        opensc_static_with_deps
    )
    target_compile_definitions(OpenSCPluginTests PRIVATE
        PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
        LIBRESCRS_INTERNAL_BUILD
    )
    add_dependencies(OpenSCPluginTests opensc-plugin)
    gtest_discover_tests(OpenSCPluginTests)
endif()

# OpenSC fallback hardware integration test (spec 2026-04-24)
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(OpenSCFallbackIntegrationTest
        opensc_fallback_integration_test.cpp
    )
    # Link list mirrors the canonical sibling target OpenSCPluginTests.
    # LibreSCRS_Plugin is not needed: registry symbols come from CardPlugin_Impl.
    # LibreSCRS_Secure is not needed: Secure::String symbols come transitively
    # via CardPlugin_Impl → LibreSCRS_Auth.
    target_link_libraries(OpenSCFallbackIntegrationTest PRIVATE
        GTest::gtest_main
        CardPlugin_Impl
        LibreSCRS_SmartCard
        SmartCard_Impl
        opensc_static_with_deps
    )
    target_compile_definitions(OpenSCFallbackIntegrationTest PRIVATE
        PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    )
    # Shared PIN-guard header (single source of truth across real-card
    # test binaries) per feedback_pin_guard_pattern.
    target_include_directories(OpenSCFallbackIntegrationTest PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    add_dependencies(OpenSCFallbackIntegrationTest opensc-plugin)
    gtest_discover_tests(OpenSCFallbackIntegrationTest
        PROPERTIES LABELS "HARDWARE"
    )
endif()

# Downstream-patch presence guard for vendored OpenSC. Pure source-text
# inspection: no card, no opensc-static link; safe to run on every build.
if(LIBRESCRS_VENDOR_OPENSC)
    add_executable(PivAidPatchTest opensc-fallback/piv_aid_test.cpp)
    target_link_libraries(PivAidPatchTest PRIVATE GTest::gtest_main)
    target_compile_definitions(PivAidPatchTest PRIVATE
        LIBRESCRS_OPENSC_CARD_PIV_C="${PROJECT_SOURCE_DIR}/thirdparty/opensc-source/src/libopensc/card-piv.c"
    )
    # Auto-apply hook runs at configure time on the source tree itself, so
    # the source file is already patched before this test compiles.
    gtest_discover_tests(PivAidPatchTest)
endif()

# SmartCard Monitor tests
add_executable(MonitorTests monitor_test.cpp)
find_package(Threads REQUIRED)
target_link_libraries(MonitorTests PRIVATE SmartCard_Impl GTest::gtest_main Threads::Threads)
# <smartcard/monitor.h> transitively pulls "ipcsc_scan_provider.h" /
# "monitor_event.h" — ipcsc_scan_provider.h now lives in lib/smartcard/src/.
target_include_directories(MonitorTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
target_compile_definitions(MonitorTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(MonitorTests)

# AutoReaderService tests
add_executable(AutoReaderTests auto_reader_test.cpp)
target_link_libraries(AutoReaderTests PRIVATE LibreSCRS_Plugin CardPlugin_Impl LibreSCRS_SmartCard LibreSCRS_SmartCard_TestHelpers SmartCard_Impl GTest::gtest_main Threads::Threads)
# Grants access to detail/MonitorInjection.h (test-only mock injection) and
# to <ipcsc_scan_provider.h> used by the mock scan provider (relocated from
# include/smartcard/ to src/ in Chunk E).
target_compile_definitions(AutoReaderTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(AutoReaderTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
gtest_discover_tests(AutoReaderTests)

option(BUILD_DSS_ORACLE "Build DSS validation oracle for testing (requires Java + DSS JAR)" ON)

# Digital signing tests (only when BUILD_SIGNING is enabled)
if(BUILD_SIGNING)
    add_executable(LibreSignTests libresign_test.cpp)
    target_link_libraries(LibreSignTests PRIVATE LibreSign GTest::gtest_main OpenSSL_Crypto)
    # libresign has no PUBLIC include/. Tests reach types.h / signing_service.h
    # via the PRIVATE src/ root plus LIBRESCRS_INTERNAL_BUILD to satisfy the
    # #error guards.
    target_include_directories(LibreSignTests PRIVATE
        ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
    target_compile_definitions(LibreSignTests PRIVATE
        LIBRESCRS_INTERNAL_BUILD)
    gtest_discover_tests(LibreSignTests)

    # Shared test support library (must be defined before tests that use it)
    add_library(SigningTestSupport STATIC
        signing_test_support/signing_test_support.cpp
        signing_test_support/pkcs11_token_mock.cpp
        dss_validation_client.cpp)
    # LibreSign's bucket-B internal headers (http_client.h, dss/*, native/*)
    # live in src/. Tests reach them via this PUBLIC include root so they
    # propagate to every target that links SigningTestSupport.
    target_include_directories(SigningTestSupport PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/signing_test_support
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
        ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
    target_link_libraries(SigningTestSupport PUBLIC
        GTest::gtest LibreSign)
    # Support library reaches into bucket-B libresign internals (dss/*,
    # native/*). Propagate the internal-build marker to every consumer so the
    # #error guard lets them through.
    target_compile_definitions(SigningTestSupport PUBLIC
        CMAKE_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
        LIBRESCRS_INTERNAL_BUILD)

    if(BUILD_DSS_ORACLE AND NOT WIN32)
        target_compile_definitions(SigningTestSupport PUBLIC LIBRESIGN_HAS_DSS_ORACLE=1)
    endif()

    # Unified signing E2E tests (parameterized by backend, custom main)
    add_executable(SigningE2ETests signing_e2e_test.cpp)
    target_link_libraries(SigningE2ETests PRIVATE SigningTestSupport)
    gtest_discover_tests(SigningE2ETests DISCOVERY_TIMEOUT 30)

    # Signing-side cancellation / disconnect / concurrent-sign axes are not
    # yet wired to a mockable IPkcs11Token. The mock skeleton lives at
    # test/signing_test_support/pkcs11_token_mock.h; the in-tree CardPlugin
    # NVI cancellation contract is exercised by CancellationNviTests
    # (test/plugin/cancellation_test.cpp).

    # Signing provider unit tests
    add_executable(SigningProviderTests signing_provider_test.cpp)
    target_link_libraries(SigningProviderTests PRIVATE SigningTestSupport OpenSSL_Crypto GTest::gtest_main)
    gtest_discover_tests(SigningProviderTests)

    # HttpClient is core (used by both backends)
    add_executable(HttpClientTests http_client_test.cpp)
    target_link_libraries(HttpClientTests PRIVATE LibreSign GTest::gtest_main)
    target_include_directories(HttpClientTests PRIVATE
        ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
    target_compile_definitions(HttpClientTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
    gtest_discover_tests(HttpClientTests)

    # DSS backend tests
    if(SIGNING_BACKEND STREQUAL "dss" OR SIGNING_BACKEND STREQUAL "both")
        add_executable(DSSServiceManagerTests dss_service_manager_test.cpp)
        target_link_libraries(DSSServiceManagerTests PRIVATE LibreSign GTest::gmock GTest::gtest_main)
        target_include_directories(DSSServiceManagerTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(DSSServiceManagerTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(DSSServiceManagerTests)

        add_executable(DSSSigningServiceTests dss_signing_service_test.cpp)
        target_link_libraries(DSSSigningServiceTests PRIVATE LibreSign GTest::gtest_main)
        target_include_directories(DSSSigningServiceTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(DSSSigningServiceTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(DSSSigningServiceTests)

        # DSS integration tests (require JAR + Java on PATH)
        add_executable(DSSIntegrationTests dss_integration_test.cpp)
        target_link_libraries(DSSIntegrationTests PRIVATE LibreSign GTest::gtest_main)
        target_include_directories(DSSIntegrationTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(DSSIntegrationTests PRIVATE
            CMAKE_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
            LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(DSSIntegrationTests)

        # Signing integration tests (trust store + DSS service + optional real card)
        add_executable(SigningIntegrationTests signing_integration_test.cpp)
        target_link_libraries(SigningIntegrationTests PRIVATE SigningTestSupport GTest::gtest_main OpenSSL_Crypto)
        target_compile_definitions(SigningIntegrationTests PRIVATE
            CMAKE_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
        gtest_discover_tests(SigningIntegrationTests)
    endif()

    # Native backend tests
    if(SIGNING_BACKEND STREQUAL "native" OR SIGNING_BACKEND STREQUAL "both")
        # Internal-utility unit tests (derEncodeLength, sha256Base64 parity).
        # Includes internal headers from lib/libresign/src/native/, so links
        # LibreSign + OpenSSL directly.
        add_executable(NativeUtilsTests native_utils_test.cpp)
        target_link_libraries(NativeUtilsTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
        target_include_directories(NativeUtilsTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/thirdparty/miniz
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(NativeUtilsTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(NativeUtilsTests)

        add_executable(Pkcs11TokenTests pkcs11_token_test.cpp)
        target_link_libraries(Pkcs11TokenTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport)
        gtest_discover_tests(Pkcs11TokenTests)

        add_executable(Pkcs11ModuleManagerTests pkcs11_module_manager_test.cpp)
        target_link_libraries(Pkcs11ModuleManagerTests PRIVATE
            GTest::gtest_main LibreSign SigningTestSupport)
        target_include_directories(Pkcs11ModuleManagerTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
            ${LibreMiddleware_SOURCE_DIR}/lib/pkcs11/include)
        target_compile_definitions(Pkcs11ModuleManagerTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(Pkcs11ModuleManagerTests)

        add_executable(TSAClientTests tsa_client_test.cpp)
        target_link_libraries(TSAClientTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(TSAClientTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(TSAClientTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TSAClientTests)

        # TSA HTTP-auth integration: in-process mock server + TSAClient.
        # Confirms TSACredentials (Basic / Bearer / extraHeaders) thread
        # through HttpClient as actual Authorization headers on the wire.
        add_executable(TsaAuthIntegrationTests tsa_auth_integration_test.cpp)
        target_link_libraries(TsaAuthIntegrationTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(TsaAuthIntegrationTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(TsaAuthIntegrationTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TsaAuthIntegrationTests)

        # TSA / OCSP failure-mode coverage. Exercises body-parse rejection,
        # unreachable endpoint, timeout, plus module-level "B-T requires TSA"
        # contract via CAdES::addTimestamp throw site.
        add_executable(TsaFailureModesTests tsa_failure_modes_test.cpp)
        target_link_libraries(TsaFailureModesTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
        target_include_directories(TsaFailureModesTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(TsaFailureModesTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TsaFailureModesTests)

        add_executable(RevocationClientTests revocation_client_test.cpp)
        target_link_libraries(RevocationClientTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
        target_include_directories(RevocationClientTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(RevocationClientTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(RevocationClientTests)

        add_executable(CAdESModuleTests cades_module_test.cpp)
        target_link_libraries(CAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
        gtest_discover_tests(CAdESModuleTests)

        add_executable(PAdESModuleTests pades_module_test.cpp)
        target_link_libraries(PAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
        gtest_discover_tests(PAdESModuleTests)

        add_executable(PAdESUnicodeE2ETests pades_unicode_e2e_test.cpp)
        target_link_libraries(PAdESUnicodeE2ETests PRIVATE
            GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
        gtest_discover_tests(PAdESUnicodeE2ETests)

        # Visual-signature FILL_BOX cross-backend oracle. Self-
        # consistency (native emitter vs layoutVisualSignature) runs
        # under SIGNING_BACKEND=native|both. Full DSS oracle skips
        # silently unless SIGNING_BACKEND=both AND SoftHSM2 + DSS Java
        # service are reachable.
        add_executable(PAdESDssOracleTests pades_dss_oracle_test.cpp)
        target_link_libraries(PAdESDssOracleTests
            PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
        gtest_discover_tests(PAdESDssOracleTests)

        add_executable(TtfParserTests ttf_parser_test.cpp)
        target_link_libraries(TtfParserTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(TtfParserTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(TtfParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TtfParserTests)

        add_executable(TtfSubsetTests ttf_subset_test.cpp)
        target_link_libraries(TtfSubsetTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(TtfSubsetTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(TtfSubsetTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TtfSubsetTests)

        add_executable(PdfFontTests pdf_font_test.cpp)
        target_link_libraries(PdfFontTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(PdfFontTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(PdfFontTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(PdfFontTests)

        # Public visual-signature auto-fit layout API (rc2). Pure tests
        # over the LibreSCRS::Signing interface — no internals, no
        # libresign:: include path; LibreSCRS_Signing transitively pulls
        # the LibreSign archive at link time so the symbols resolve.
        add_executable(VisualSignatureLayoutTests visual_signature_layout_test.cpp)
        target_link_libraries(VisualSignatureLayoutTests
            PRIVATE GTest::gtest_main LibreSCRS_Signing)
        gtest_discover_tests(VisualSignatureLayoutTests)

        # Integration regression: public SigningRequest::contactInfo()
        # wired through the libresign bridge into the PDF /ContactInfo
        # signature-dictionary entry. Links LibreSCRS_Signing for the
        # public builder and LibreSign for the internal PAdES module.
        add_executable(ContactInfoIntegrationTests contact_info_integration_test.cpp)
        target_link_libraries(ContactInfoIntegrationTests
            PRIVATE GTest::gtest_main LibreSCRS_Signing LibreSign OpenSSL_Crypto SigningTestSupport)
        target_include_directories(ContactInfoIntegrationTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(ContactInfoIntegrationTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(ContactInfoIntegrationTests)

        add_executable(JAdESModuleTests jades_module_test.cpp)
        target_link_libraries(JAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
        target_include_directories(JAdESModuleTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
        gtest_discover_tests(JAdESModuleTests)

        # JCS (RFC 8785) canonical JSON serializer — internal LibreSign TU,
        # reached via LIBRESCRS_INTERNAL_BUILD plus the libresign src tree.
        add_executable(JcsTests jcs_test.cpp)
        target_link_libraries(JcsTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(JcsTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src
            ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
        target_compile_definitions(JcsTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(JcsTests)

        find_package(LibXml2 REQUIRED)
        add_executable(XAdESModuleTests xades_module_test.cpp)
        target_link_libraries(XAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto LibXml2::LibXml2 SigningTestSupport)
        gtest_discover_tests(XAdESModuleTests)

        add_executable(ASiCModuleTests asic_module_test.cpp)
        target_link_libraries(ASiCModuleTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport)
        target_include_directories(ASiCModuleTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/thirdparty/miniz)
        gtest_discover_tests(ASiCModuleTests)

        add_executable(TrustedListParserTests trusted_list_parser_test.cpp)
        target_link_libraries(TrustedListParserTests PRIVATE GTest::gtest_main LibreSign LibXml2::LibXml2)
        target_include_directories(TrustedListParserTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(TrustedListParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TrustedListParserTests)

        add_executable(TlSignatureVerifierTests tl_signature_verifier_test.cpp)
        target_link_libraries(TlSignatureVerifierTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto LibXml2::LibXml2)
        target_include_directories(TlSignatureVerifierTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src/native)
        target_compile_definitions(TlSignatureVerifierTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TlSignatureVerifierTests)

        add_executable(TlCacheTests tl_cache_test.cpp)
        target_link_libraries(TlCacheTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
        target_include_directories(TlCacheTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src/native)
        target_compile_definitions(TlCacheTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TlCacheTests)

        add_executable(TlConfigureTests tl_configure_test.cpp)
        target_link_libraries(TlConfigureTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
        target_include_directories(TlConfigureTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(TlConfigureTests PRIVATE
            CMAKE_SOURCE_DIR="${PROJECT_SOURCE_DIR}"
            LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(TlConfigureTests)

        add_executable(CrossBackendTests cross_backend_test.cpp)
        target_link_libraries(CrossBackendTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(CrossBackendTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/lib/libresign/src)
        target_compile_definitions(CrossBackendTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(CrossBackendTests)

        add_executable(PdfParserTests pdf_parser_test.cpp)
        target_link_libraries(PdfParserTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(PdfParserTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libresign/src/native)
        target_compile_definitions(PdfParserTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
        gtest_discover_tests(PdfParserTests)

        add_executable(ECSigningTests ec_signing_test.cpp)
        target_link_libraries(ECSigningTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport)
        gtest_discover_tests(ECSigningTests DISCOVERY_TIMEOUT 30)
    endif()
endif()

add_executable(LibreSCRS_SigningTests LibreSCRS_Signing_test.cpp)
# CardPlugin_Impl supplies the out-of-line ~CardPlugin() key function
#; StubPkiPlugin in this test derives from
# CardPlugin so the vtable + typeinfo are pulled in via CardPlugin_Impl.
target_link_libraries(LibreSCRS_SigningTests GTest::gtest_main LibreSCRS_Signing CardPlugin_Impl SmartCard_Impl LibreSign)
# Expose the internal Signing detail headers (lib/LibreSCRS/Signing/detail/*) so
# the classifier test can include ErrorClassifier.h without making it public API.
# Reach libresign's src/ for ErrorClassifier.h and <types.h>.
target_include_directories(LibreSCRS_SigningTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/Signing
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libresign/src)
# The ErrorClassifier.h header (an internal implementation detail) is guarded by
# LIBRESCRS_INTERNAL_BUILD; this test unit is allowed to include it.
target_compile_definitions(LibreSCRS_SigningTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_SigningTests)

# SignFailureKind cardinality + bridge-mapping lock test. Same include /
# definition pattern as LibreSCRS_SigningTests above — reaches into
# lib/LibreSCRS/Signing/detail/ErrorClassifier.h and lib/libresign/src/types.h.
add_executable(SigningFailureKindTests signing_failure_kind_test.cpp)
target_link_libraries(SigningFailureKindTests PRIVATE GTest::gtest_main LibreSCRS_Signing LibreSign)
target_include_directories(SigningFailureKindTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/LibreSCRS/Signing
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libresign/src)
target_compile_definitions(SigningFailureKindTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(SigningFailureKindTests)

add_executable(LibreSCRS_SecureBufferTests
    LibreSCRS_SecureBufferTests.cpp
)
target_link_libraries(LibreSCRS_SecureBufferTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
gtest_discover_tests(LibreSCRS_SecureBufferTests)

add_executable(LibreSCRS_SecureStringTests
    LibreSCRS_SecureStringTests.cpp
)
target_link_libraries(LibreSCRS_SecureStringTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
gtest_discover_tests(LibreSCRS_SecureStringTests)

add_executable(LibreSCRS_SecureAllocatorTests
    LibreSCRS_SecureAllocatorTests.cpp
)
target_link_libraries(LibreSCRS_SecureAllocatorTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
)
gtest_discover_tests(LibreSCRS_SecureAllocatorTests)

add_executable(LibreSCRS_CardSessionTests
    LibreSCRS_CardSessionTests.cpp
)
target_link_libraries(LibreSCRS_CardSessionTests PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
)
# Grants access to detail/CardSessionInjection.h for detached-session
# regression tests that exercise moved-from semantics without real hardware.
target_compile_definitions(LibreSCRS_CardSessionTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(LibreSCRS_CardSessionTests)

# SessionPresenceTest — unit tests for the process-local registry that
# CardSession self-registers into on SM activation. Exercises the
# weak_ptr storage contract, RAII Registration auto-removal, and the
# hasLiveSm reflection through CardSession::hasLiveSecureChannel.
add_executable(SessionPresenceTest SessionPresenceTest.cpp)
target_link_libraries(SessionPresenceTest PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
)
target_compile_definitions(SessionPresenceTest PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(SessionPresenceTest)

# SessionTransmitTest — drives the routing matrix of the SM-aware transmit
# funnel: live SM channel path, closed channel / no channel path,
# moved-from / detached session path, and the snapshot-keeps-channel-alive
# contract. Links against LibreSCRS_SmartCard_TestHelpers for the
# detail::ChannelInjector helper that swaps the active channel slot from
# outside the production translation unit.
add_executable(SessionTransmitTest SessionTransmitTest.cpp)
target_link_libraries(SessionTransmitTest PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
    LibreSCRS_SmartCard_TestHelpers
    LibreSCRS_SecureChannel
    SmartCard_Impl
)
target_include_directories(SessionTransmitTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src
)
target_compile_definitions(SessionTransmitTest PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(SessionTransmitTest)

# CardSessionApiInvariantTest — load-bearing compile-time check that the
# public @ref CardSession surface never sprouts a connection() /
# pcscConnection() accessor that would re-expose the PC/SC transport.
# The static_assert at namespace scope is the actual test; the
# placeholder TEST() exists only so gtest_main has a TU body to link.
add_executable(CardSessionApiInvariantTest CardSessionApiInvariantTest.cpp)
target_link_libraries(CardSessionApiInvariantTest PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
)
gtest_discover_tests(CardSessionApiInvariantTest)

# PkcsAttachApiDeletedTest — compile-time guard that the legacy
# SessionAttachment + AttachHook C ABI stays deleted. The
# SessionPresence auto-registration only holds its invariant if
# consumers cannot reach a manual-attach surface; reintroducing the
# headers or the SessionAttachment::attach member fails this TU at
# build time via the SFINAE-on-sentinel static_assert.
add_executable(PkcsAttachApiDeletedTest PkcsAttachApiDeletedTest.cpp)
target_link_libraries(PkcsAttachApiDeletedTest PRIVATE
    GTest::gtest_main
)
gtest_discover_tests(PkcsAttachApiDeletedTest)

add_executable(LibreSCRS_MonitorTests
    LibreSCRS_MonitorTests.cpp
)
target_link_libraries(LibreSCRS_MonitorTests PRIVATE
    GTest::gtest_main
    LibreSCRS_SmartCard
    LibreSCRS_SmartCard_TestHelpers
    SmartCard_Impl
    Threads::Threads
)
# Grants access to detail/MonitorInjection.h (test-only mock injection) and
# to <ipcsc_scan_provider.h> used by the mock scan provider (relocated from
# include/smartcard/ to src/ in Chunk E).
target_compile_definitions(LibreSCRS_MonitorTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(LibreSCRS_MonitorTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/smartcard/src)
gtest_discover_tests(LibreSCRS_MonitorTests)

add_executable(SigningRequestTsaOverrideTest
    SigningRequestTsaOverrideTest.cpp
)
target_link_libraries(SigningRequestTsaOverrideTest PRIVATE
    GTest::gtest_main
    LibreSCRS_Signing
)
gtest_discover_tests(SigningRequestTsaOverrideTest)

add_executable(PluginAbiVersionTest
    PluginAbiVersionTest.cpp
)
target_link_libraries(PluginAbiVersionTest PRIVATE
    GTest::gtest_main
    LibreSCRS::Plugin
)
gtest_discover_tests(PluginAbiVersionTest)

# A1 (4.0 hardening): Atr::matches semantics — exact + masked match cases.
add_executable(AtrMatchingTests
    plugin/atr_matching_test.cpp
)
target_link_libraries(AtrMatchingTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Plugin
    CardPlugin_Impl
)
gtest_discover_tests(AtrMatchingTests)

# NVI readCard wrapper observes a LibreSCRS::CancelToken and short-circuits
# before dispatching to doReadCard when isCancelled() returns true.
add_executable(CancellationNviTests
    plugin/cancellation_test.cpp
)
target_link_libraries(CancellationNviTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Plugin
    LibreSCRS_Auth
    LibreSCRS_SmartCard
    CardPlugin_Impl
    SmartCard_Impl
)
# The test reaches into LibreSCRS/SmartCard/detail/CardSessionInjection.h
# to obtain a detached session (no PCSC I/O) for the stub plugin to receive.
target_compile_definitions(CancellationNviTests PRIVATE LIBRESCRS_INTERNAL_BUILD)
gtest_discover_tests(CancellationNviTests)

# A3 (4.0 hardening): mandatory LocalizedText userMessage on ReadResult,
# SigningResult, and OpenError; ErrorKeys generic-builder set.
add_executable(LocalizedTextFactoriesTests
    plugin/localized_text_factories_test.cpp
)
target_link_libraries(LocalizedTextFactoriesTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
    LibreSCRS_Plugin
    LibreSCRS_SmartCard
    LibreSCRS_Signing
)
gtest_discover_tests(LocalizedTextFactoriesTests)

# A4 (4.0 hardening): compile-time SecretParameter concept enforcing
# Secure::String const& on credential-bearing parameters. Most of the work
# happens at compile time (static_asserts in the test source); the binary
# exists so GTest discovery picks it up.
add_executable(SecretParameterConceptTests
    plugin/secret_parameter_concept_test.cpp
)
target_link_libraries(SecretParameterConceptTests PRIVATE
    GTest::gtest_main
    LibreSCRS_Auth
    LibreSCRS_Secure
)
gtest_discover_tests(SecretParameterConceptTests)

# A5 (4.0 hardening): codegen golden-output test for manifest2header.py.
# The test invokes the Python tool against a fixture manifest at runtime
# and diffs the output against expected_manifest.h, then re-invokes with
# an invalid fixture and confirms the schema gate rejects it.
add_executable(ManifestCodegenTests
    build_system/manifest_codegen_test.cpp
)
target_link_libraries(ManifestCodegenTests PRIVATE GTest::gtest_main)
target_compile_definitions(ManifestCodegenTests PRIVATE
    LIBRESCRS_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/build_system/fixtures"
    LIBRESCRS_MANIFEST2HEADER_PATH="${PROJECT_SOURCE_DIR}/tools/manifest2header/manifest2header.py"
    LIBRESCRS_MANIFEST_SCHEMA_PATH="${PROJECT_SOURCE_DIR}/cmake/schemas/plugin-manifest.schema.json"
    LIBRESCRS_PYTHON_EXECUTABLE="${Python3_EXECUTABLE}"
)
gtest_discover_tests(ManifestCodegenTests)

# Real-card E2E tests for the multi-PIN PKCS#11 path against the live
# librescrs-pkcs11.so. Always built so the test exe compiles in CI;
# every test SKIPs at runtime when the env vars (LIBRESCRS_TEST_PIN,
# LIBRESCRS_TEST_PIN_QSCD, LIBRESCRS_TEST_CAN) are unset.
add_subdirectory(e2e)
add_subdirectory(smartcard)
add_subdirectory(pkcs15-plugin)
add_subdirectory(Trust)
