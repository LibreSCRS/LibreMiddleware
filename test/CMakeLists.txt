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

add_dependencies(PluginIntegrationTests rescrs-plugin-emrtd)
target_compile_definitions(PluginIntegrationTests PRIVATE HAS_EMRTD_PLUGIN=1)

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
target_link_libraries(pin_test_cli EIdCard)

# PKCS#15 card investigation probe (run with a physical card inserted)
add_executable(pkcs15_probe pkcs15_probe.cpp)
target_link_libraries(pkcs15_probe SmartCard)

# CLI tool for manual PIN testing with a real PKS Chamber of Commerce card
add_executable(pks_pin_test_cli pks_pin_test_cli.cpp)
target_link_libraries(pks_pin_test_cli PKSCard)

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
