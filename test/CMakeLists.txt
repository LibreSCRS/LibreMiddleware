# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 20)
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
    eidcard_test.cpp
    eu_vrc_test.cpp
    healthcard_test.cpp
)

target_link_libraries(LibreMiddlewareTests
    GTest::gtest_main
    RsEId
    CardEdge
    EuVrc
    RsHealth
)

target_include_directories(LibreMiddlewareTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/eu-vrc/src
)

include(GoogleTest)
gtest_discover_tests(LibreMiddlewareTests)

# PCSCConnection TransmitFilter tests
add_executable(pcsc_connection_filter_test pcsc_connection_filter_test.cpp)
target_link_libraries(pcsc_connection_filter_test SmartCard GTest::gtest_main)
gtest_discover_tests(pcsc_connection_filter_test)

# selectByFileId P2 parameter test
add_executable(apdu_select_p2_test apdu_select_p2_test.cpp)
target_link_libraries(apdu_select_p2_test SmartCard GTest::gtest_main)
gtest_discover_tests(apdu_select_p2_test)

# Plugin tests (CardData model + Registry + dlopen loading)
add_subdirectory(mock_card_plugin)

add_executable(PluginTests
    card_data_test.cpp
    card_plugin_registry_test.cpp
)
target_link_libraries(PluginTests
    GTest::gtest_main
    CardPlugin
)
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
    CardPlugin
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

if(TARGET cardedge-plugin)
    add_dependencies(PluginIntegrationTests cardedge-plugin)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_CARDEDGE_PLUGIN=1)
endif()

if(TARGET piv-plugin)
    add_dependencies(PluginIntegrationTests piv-plugin)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_PIV_PLUGIN=1)
endif()

if(BUILD_OPENSC_PLUGIN AND OPENSC_FOUND)
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
    CardPlugin
    SmartCard
)
target_compile_definitions(EMRTDPluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
add_dependencies(EMRTDPluginTests emrtd-plugin)
gtest_discover_tests(EMRTDPluginTests)

add_executable(PKCS11Tests pkcs11_test.cpp)
target_link_libraries(PKCS11Tests GTest::gtest_main librescrs-pkcs11)
gtest_discover_tests(PKCS11Tests)

# CLI tool for manual PIN testing with a real card
add_executable(pin_test_cli pin_test_cli.cpp)
target_link_libraries(pin_test_cli CardEdge SmartCard)

# PKCS#15 card investigation probe (run with a physical card inserted)
add_executable(pkcs15_probe pkcs15_probe.cpp)
target_link_libraries(pkcs15_probe SmartCard)

# PKCS#15-after-PACE probe: authenticates via PACE then probes PKCS#15
add_executable(pkcs15_after_pace_probe pkcs15_after_pace_probe.cpp)
target_link_libraries(pkcs15_after_pace_probe SmartCard EMRTDCrypto EMRTD)

# AODF + PIN reference probe
add_executable(aodf_probe aodf_probe.cpp)
target_link_libraries(aodf_probe SmartCard)

# FCI format probe: tests if CardEdge SELECT FILE returns ISO TLV-wrapped FCI
add_executable(fci_format_probe fci_format_probe.cpp)
target_link_libraries(fci_format_probe SmartCard)

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
    CardPlugin
)
gtest_discover_tests(EMRTDCryptoTests)

add_executable(EMRTDTests
    mrz_parse_test.cpp
    data_group_test.cpp
    pace_hardware_test.cpp
)
target_link_libraries(EMRTDTests
    GTest::gtest_main
    EMRTD
)
gtest_discover_tests(EMRTDTests)

# PKCS#15 parser tests
add_executable(PKCS15ParserTests pkcs15_parser_test.cpp)
target_link_libraries(PKCS15ParserTests GTest::gtest_main PKCS15)
gtest_discover_tests(PKCS15ParserTests)

# PIV parser tests
add_executable(PIVParserTests piv_parser_test.cpp)
target_link_libraries(PIVParserTests GTest::gtest_main PIV)
gtest_discover_tests(PIVParserTests)

# PIV hardware tests (skipped when no PIV card present)
add_executable(PIVHardwareTests piv_hardware_test.cpp)
target_link_libraries(PIVHardwareTests GTest::gtest_main PIV SmartCard)
gtest_discover_tests(PIVHardwareTests)

# CardEdge plugin tests
add_executable(CardEdgePluginTests cardedge_plugin_test.cpp)
target_link_libraries(CardEdgePluginTests GTest::gtest_main CardPlugin)
target_compile_definitions(CardEdgePluginTests PRIVATE PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}")
add_dependencies(CardEdgePluginTests cardedge-plugin)
gtest_discover_tests(CardEdgePluginTests)

# PKCS#15 plugin tests
add_executable(PKCS15PluginTests pkcs15_plugin_test.cpp)
target_link_libraries(PKCS15PluginTests GTest::gtest_main CardPlugin)
target_compile_definitions(PKCS15PluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
add_dependencies(PKCS15PluginTests pkcs15-plugin)
gtest_discover_tests(PKCS15PluginTests)

# OpenSC fallback plugin tests (conditional on libopensc availability)
if(BUILD_OPENSC_PLUGIN AND OPENSC_FOUND)
    add_executable(OpenSCPluginTests
        opensc_plugin_test.cpp
    )
    target_link_libraries(OpenSCPluginTests
        GTest::gtest_main
        CardPlugin
        PkgConfig::OPENSC
    )
    target_compile_definitions(OpenSCPluginTests PRIVATE
        PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    )
    add_dependencies(OpenSCPluginTests opensc-plugin)
    gtest_discover_tests(OpenSCPluginTests)
endif()

# SmartCard Monitor tests
add_executable(MonitorTests monitor_test.cpp)
find_package(Threads REQUIRED)
target_link_libraries(MonitorTests PRIVATE SmartCard GTest::gtest_main Threads::Threads)
gtest_discover_tests(MonitorTests)

# AutoReader tests
add_executable(AutoReaderTests auto_reader_test.cpp)
target_link_libraries(AutoReaderTests PRIVATE CardPlugin SmartCard GTest::gtest_main Threads::Threads)
gtest_discover_tests(AutoReaderTests)

# Digital signing tests (only when BUILD_SIGNING is enabled)
if(BUILD_SIGNING)
    add_executable(LibreSignTests libresign_test.cpp)
    target_link_libraries(LibreSignTests PRIVATE LibreSign GTest::gtest_main OpenSSL_Crypto)
    target_compile_definitions(LibreSignTests PRIVATE
        LIBREMIDDLEWARE_CERT_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}")
    gtest_discover_tests(LibreSignTests)

    # Shared test support library (must be defined before tests that use it)
    add_library(SigningTestSupport STATIC
        signing_test_support/signing_test_support.cpp
        dss_validation_client.cpp)
    target_include_directories(SigningTestSupport PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/signing_test_support
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
    target_link_libraries(SigningTestSupport PUBLIC
        GTest::gtest LibreSign)
    target_compile_definitions(SigningTestSupport PUBLIC
        CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

    # Unified signing E2E tests (parameterized by backend, custom main)
    add_executable(SigningE2ETests signing_e2e_test.cpp)
    target_link_libraries(SigningE2ETests PRIVATE SigningTestSupport)
    gtest_discover_tests(SigningE2ETests)

    # Signing provider unit tests
    add_executable(SigningProviderTests signing_provider_test.cpp)
    target_link_libraries(SigningProviderTests PRIVATE SigningTestSupport OpenSSL_Crypto GTest::gtest_main)
    gtest_discover_tests(SigningProviderTests)

    # HttpClient is core (used by both backends)
    add_executable(HttpClientTests http_client_test.cpp)
    target_link_libraries(HttpClientTests PRIVATE LibreSign GTest::gtest_main)
    gtest_discover_tests(HttpClientTests)

    # DSS backend tests
    if(SIGNING_BACKEND STREQUAL "dss" OR SIGNING_BACKEND STREQUAL "both")
        add_executable(DSSServiceManagerTests dss_service_manager_test.cpp)
        target_link_libraries(DSSServiceManagerTests PRIVATE LibreSign GTest::gmock GTest::gtest_main)
        gtest_discover_tests(DSSServiceManagerTests)

        add_executable(DSSSigningServiceTests dss_signing_service_test.cpp)
        target_link_libraries(DSSSigningServiceTests PRIVATE LibreSign GTest::gtest_main)
        gtest_discover_tests(DSSSigningServiceTests)

        # DSS integration tests (require JAR + Java on PATH)
        add_executable(DSSIntegrationTests dss_integration_test.cpp)
        target_link_libraries(DSSIntegrationTests PRIVATE LibreSign GTest::gtest_main)
        target_compile_definitions(DSSIntegrationTests PRIVATE
            CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
        gtest_discover_tests(DSSIntegrationTests)

        # Signing integration tests (trust store + DSS service + optional real card)
        add_executable(SigningIntegrationTests signing_integration_test.cpp)
        target_link_libraries(SigningIntegrationTests PRIVATE SigningTestSupport GTest::gtest_main OpenSSL_Crypto)
        target_compile_definitions(SigningIntegrationTests PRIVATE
            CMAKE_SOURCE_DIR="${CMAKE_SOURCE_DIR}"
            LIBREMIDDLEWARE_CERT_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}")
        gtest_discover_tests(SigningIntegrationTests)
    endif()

    # Native backend tests
    if(SIGNING_BACKEND STREQUAL "native" OR SIGNING_BACKEND STREQUAL "both")
        # Internal-utility unit tests (derEncodeLength, sha256Base64 parity).
        # Includes internal headers from lib/libresign/src/native/, so links
        # LibreSign + OpenSSL directly.
        add_executable(NativeUtilsTests native_utils_test.cpp)
        target_link_libraries(NativeUtilsTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
        gtest_discover_tests(NativeUtilsTests)

        add_executable(Pkcs11TokenTests pkcs11_token_test.cpp)
        target_link_libraries(Pkcs11TokenTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport)
        gtest_discover_tests(Pkcs11TokenTests)

        add_executable(TSAClientTests tsa_client_test.cpp)
        target_link_libraries(TSAClientTests PRIVATE GTest::gtest_main LibreSign)
        gtest_discover_tests(TSAClientTests)

        add_executable(RevocationClientTests revocation_client_test.cpp)
        target_link_libraries(RevocationClientTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto)
        gtest_discover_tests(RevocationClientTests)

        add_executable(CAdESModuleTests cades_module_test.cpp)
        target_link_libraries(CAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
        gtest_discover_tests(CAdESModuleTests)

        add_executable(PAdESModuleTests pades_module_test.cpp)
        target_link_libraries(PAdESModuleTests PRIVATE GTest::gtest_main LibreSign OpenSSL_Crypto SigningTestSupport)
        gtest_discover_tests(PAdESModuleTests)

        add_executable(JAdESModuleTests jades_module_test.cpp)
        target_link_libraries(JAdESModuleTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport)
        target_include_directories(JAdESModuleTests PRIVATE
            ${LibreMiddleware_SOURCE_DIR}/thirdparty/nlohmann)
        gtest_discover_tests(JAdESModuleTests)

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
        gtest_discover_tests(TrustedListParserTests)

        add_executable(CrossBackendTests cross_backend_test.cpp)
        target_link_libraries(CrossBackendTests PRIVATE GTest::gtest_main LibreSign)
        gtest_discover_tests(CrossBackendTests)

        add_executable(PdfParserTests pdf_parser_test.cpp)
        target_link_libraries(PdfParserTests PRIVATE GTest::gtest_main LibreSign)
        target_include_directories(PdfParserTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../lib/libresign/src/native)
        gtest_discover_tests(PdfParserTests)

        add_executable(ECSigningTests ec_signing_test.cpp)
        target_link_libraries(ECSigningTests PRIVATE GTest::gtest_main LibreSign SigningTestSupport)
        gtest_discover_tests(ECSigningTests)
    endif()
endif()
