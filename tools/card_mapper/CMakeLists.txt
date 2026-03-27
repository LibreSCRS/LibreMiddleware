# SPDX-License-Identifier: LGPL-2.1-or-later

add_executable(card_mapper
    main.cpp
    cli_options.cpp
    output_formatter.cpp
    plugin_mapper.cpp
    card_scanner.cpp
    apdu_logger.cpp
    scaffold_generator.cpp
)

target_include_directories(card_mapper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/rs-eid/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/cardedge/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/rs-health/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/eu-vrc/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/emrtd/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/pkcs15/include
)

target_link_libraries(card_mapper PRIVATE SmartCard EMRTD PKCS15)
target_compile_features(card_mapper PRIVATE cxx_std_20)
target_compile_definitions(card_mapper PRIVATE
    CARD_MAPPER_VERSION="${PROJECT_VERSION}"
)

# Tests
if(BUILD_TESTING)
    add_executable(card_mapper_tests
        test/cli_test.cpp
        test/output_formatter_test.cpp
        test/plugin_mapper_test.cpp
        test/card_scanner_test.cpp
        test/apdu_logger_test.cpp
        test/scaffold_generator_test.cpp
        cli_options.cpp
        output_formatter.cpp
        plugin_mapper.cpp
        card_scanner.cpp
        apdu_logger.cpp
        scaffold_generator.cpp
    )
    target_include_directories(card_mapper_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/rs-eid/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/cardedge/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/rs-health/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/eu-vrc/src
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/emrtd/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/pkcs15/include
    )
    target_link_libraries(card_mapper_tests PRIVATE GTest::gtest_main SmartCard EMRTD PKCS15)
    target_compile_features(card_mapper_tests PRIVATE cxx_std_20)
    include(GoogleTest)
    gtest_discover_tests(card_mapper_tests)
endif()
