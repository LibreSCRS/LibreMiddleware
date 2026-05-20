# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_executable(monitor_coalescer_test monitor_coalescer_test.cpp)
target_link_libraries(monitor_coalescer_test
    PRIVATE
        LibreSCRS_SmartCard
        LibreSCRS_SmartCard_TestHelpers
        GTest::gtest
        GTest::gtest_main
)
add_test(NAME monitor_coalescer_test COMMAND monitor_coalescer_test)
