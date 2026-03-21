# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

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
    vehiclecard_test.cpp
    healthcard_test.cpp
)

target_link_libraries(LibreMiddlewareTests
    GTest::gtest_main
    EIdCard
    CardEdge
    VehicleCard
    HealthCard
)

include(GoogleTest)
gtest_discover_tests(LibreMiddlewareTests)

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
    rescrs-plugin-rs-eid
    rescrs-plugin-vehicle
    rescrs-plugin-rs-health
    rescrs-plugin-rs-pks
)

if(TARGET rescrs-plugin-emrtd)
    add_dependencies(PluginIntegrationTests rescrs-plugin-emrtd)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_EMRTD_PLUGIN=1)
endif()

if(TARGET rescrs-plugin-pkcs15)
    add_dependencies(PluginIntegrationTests rescrs-plugin-pkcs15)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_PKCS15_PLUGIN=1)
endif()

if(TARGET rescrs-plugin-cardedge)
    add_dependencies(PluginIntegrationTests rescrs-plugin-cardedge)
    target_compile_definitions(PluginIntegrationTests PRIVATE HAS_CARDEDGE_PLUGIN=1)
endif()

if(BUILD_OPENSC_PLUGIN AND OPENSC_FOUND)
    add_dependencies(PluginIntegrationTests rescrs-plugin-opensc)
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
)
target_compile_definitions(EMRTDPluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
add_dependencies(EMRTDPluginTests rescrs-plugin-emrtd)
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

# CLI tool for manual PIN testing with a real PKS Chamber of Commerce card
add_executable(pks_pin_test_cli pks_pin_test_cli.cpp)
target_link_libraries(pks_pin_test_cli PKSCard CardEdge)

# FCI format probe: tests if CardEdge SELECT FILE returns ISO TLV-wrapped FCI
add_executable(fci_format_probe fci_format_probe.cpp)
target_link_libraries(fci_format_probe SmartCard)

# eMRTD crypto tests
add_executable(EMRTDCryptoTests
    bac_test.cpp
    secure_messaging_test.cpp
    pace_test.cpp
)
target_link_libraries(EMRTDCryptoTests
    GTest::gtest_main
    EMRTDCrypto
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

# CardEdge plugin tests
add_executable(CardEdgePluginTests cardedge_plugin_test.cpp)
target_link_libraries(CardEdgePluginTests GTest::gtest_main CardPlugin)
target_compile_definitions(CardEdgePluginTests PRIVATE PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}")
add_dependencies(CardEdgePluginTests rescrs-plugin-cardedge)
gtest_discover_tests(CardEdgePluginTests)

# PKCS#15 plugin tests
add_executable(PKCS15PluginTests pkcs15_plugin_test.cpp)
target_link_libraries(PKCS15PluginTests GTest::gtest_main CardPlugin)
target_compile_definitions(PKCS15PluginTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
)
add_dependencies(PKCS15PluginTests rescrs-plugin-pkcs15)
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
    add_dependencies(OpenSCPluginTests rescrs-plugin-opensc)
    gtest_discover_tests(OpenSCPluginTests)
endif()
