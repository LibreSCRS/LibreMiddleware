# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# End-to-end smoke test for the LibreMiddleware CMake Config package.
# Built standalone (out-of-source from LibreMiddleware) against a tree
# where LibreMiddleware was installed with LIBREMIDDLEWARE_BUILD_SHARED=ON.
# The build-and-run.sh sibling script automates the install +
# consumer-configure + build + run cycle. Acts as a regression test for
# the Config-package install layout: any broken find_package(...) state
# fails the CI run before downstream consumers hit the same problem.

cmake_minimum_required(VERSION 3.24)
project(sdk_consumer_config LANGUAGES CXX)

find_package(LibreMiddleware 4.0 REQUIRED CONFIG)

add_executable(sdk_consumer_config main.cpp)
target_compile_features(sdk_consumer_config PRIVATE cxx_std_23)
target_link_libraries(sdk_consumer_config
    PRIVATE LibreMiddleware::SmartCard LibreMiddleware::Plugin)
