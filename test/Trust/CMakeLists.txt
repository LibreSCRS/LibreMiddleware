# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# LibreSCRS_Trust is compiled with -fvisibility=hidden so the internal
# resolveBundledCertsDir() free function is not callable from a consumer
# that merely links the static archive. Pull the source file into this
# test executable directly so the function has internal linkage in the
# test binary. The test's LIBRESCRS_INTERNAL_BUILD define gates the
# matching internal header.
add_executable(bundled_certs_walker_test
    bundled_certs_walker_test.cpp
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/Trust/internal/BundledCertsProvider.cpp
)
target_link_libraries(bundled_certs_walker_test
    PRIVATE
        OpenSSL_Crypto
        GTest::gtest
        GTest::gtest_main
)
target_include_directories(bundled_certs_walker_test PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/Trust
    ${PROJECT_SOURCE_DIR}/include
)
target_compile_definitions(bundled_certs_walker_test PRIVATE
    LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}"
)
add_test(NAME bundled_certs_walker_test COMMAND bundled_certs_walker_test)
