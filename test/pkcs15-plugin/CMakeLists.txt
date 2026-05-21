# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# Regression-anchor test exe for the pkcs15-plugin readTokenInfo
# defensive try/catch + empty-value skip behaviour. Loads the plugin
# via CardPluginService from LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR and
# drives it with a detached CardSession from the test-helpers archive.

include(GoogleTest)

add_executable(Pkcs15ReadTokenInfoPartialTests
    readtokeninfo_partial_test.cpp
)

target_link_libraries(Pkcs15ReadTokenInfoPartialTests PRIVATE
    GTest::gtest_main
    CardPlugin_Impl
    LibreSCRS::SmartCard
    LibreSCRS::Auth
    LibreSCRS_SmartCard_TestHelpers
)

target_compile_definitions(Pkcs15ReadTokenInfoPartialTests PRIVATE
    PLUGIN_DIR="${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
    LIBRESCRS_INTERNAL_BUILD
)

add_dependencies(Pkcs15ReadTokenInfoPartialTests pkcs15-plugin)

gtest_discover_tests(Pkcs15ReadTokenInfoPartialTests)
