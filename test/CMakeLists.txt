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
)

target_link_libraries(LibreMiddlewareTests
    GTest::gtest_main
    EIdCard
    VehicleCard
)

include(GoogleTest)
gtest_discover_tests(LibreMiddlewareTests)

# CLI tool for manual PIN testing with a real card
add_executable(pin_test_cli pin_test_cli.cpp)
target_link_libraries(pin_test_cli EIdCard)
