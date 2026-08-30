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
        ${CMAKE_DL_LIBS}
)
target_include_directories(bundled_certs_walker_test PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/Trust
    ${PROJECT_SOURCE_DIR}/include
)
target_compile_definitions(bundled_certs_walker_test PRIVATE
    LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}"
    LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR="${LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR}"
)
add_test(NAME bundled_certs_walker_test COMMAND bundled_certs_walker_test)

# Second walker binary, compiled as a packaged runtime is: dev-tree define
# forced empty, installed-location define pointed at a staged data root that
# no relative walk from the binary can reach. Both are compile-time, so the
# installed-location rung of the ladder cannot be exercised from the target
# above — it needs its own executable.
set(LIBRESCRS_STAGED_CERTS_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/staged-prefix/share/librescrs/certificates")
file(MAKE_DIRECTORY "${LIBRESCRS_STAGED_CERTS_DIR}/rs-mup")
file(WRITE "${LIBRESCRS_STAGED_CERTS_DIR}/rs-mup/staged-anchor.crt" "stub")

add_executable(bundled_certs_install_layout_test
    bundled_certs_install_layout_test.cpp
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/Trust/internal/BundledCertsProvider.cpp
)
target_link_libraries(bundled_certs_install_layout_test
    PRIVATE
        OpenSSL_Crypto
        GTest::gtest
        GTest::gtest_main
        ${CMAKE_DL_LIBS}
)
target_include_directories(bundled_certs_install_layout_test PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/Trust
    ${PROJECT_SOURCE_DIR}/include
)
target_compile_definitions(bundled_certs_install_layout_test PRIVATE
    LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR=""
    LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR="${LIBRESCRS_STAGED_CERTS_DIR}"
    LIBRESCRS_STAGED_CERTS_DIR="${LIBRESCRS_STAGED_CERTS_DIR}"
)
add_test(NAME bundled_certs_install_layout_test COMMAND bundled_certs_install_layout_test)

# Third binary: asserts on the source-tree bundle itself rather than on a
# fixture — that it still holds loadable anchors, that its README and its
# subdirectories describe each other in both directions, and that the archived
# sibling tree stays out of the loaded set. Compiled against the real
# certificate-directory defines for that reason.
add_executable(bundled_certs_bundle_contents_test
    bundled_certs_bundle_contents_test.cpp
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/Trust/internal/BundledCertsProvider.cpp
)
target_link_libraries(bundled_certs_bundle_contents_test
    PRIVATE
        OpenSSL_Crypto
        GTest::gtest
        GTest::gtest_main
        ${CMAKE_DL_LIBS}
)
target_include_directories(bundled_certs_bundle_contents_test PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/Trust
    ${PROJECT_SOURCE_DIR}/include
)
target_compile_definitions(bundled_certs_bundle_contents_test PRIVATE
    LIBRESCRS_INTERNAL_BUILD
    LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}"
    LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR="${LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR}"
)
add_test(NAME bundled_certs_bundle_contents_test COMMAND bundled_certs_bundle_contents_test)

# The CSCA master-list facade, built the way a SEPARATE program is built.
#
# Everything absent here is the point, and each absence is load-bearing:
#   * no LIBRESCRS_INTERNAL_BUILD  — so <LibreSCRS/Trust/CscaMasterList.h> is
#     reached as a consumer reaches it and lib/emrtd-crypto/src/
#     csca_master_list.h stays behind its #error guard;
#   * no lib/emrtd-crypto/src on the include path — so the internal header is
#     not even findable from this translation unit;
#   * LibreSCRS::Trust and nothing else of LibreMiddleware — so the three
#     functions have to come across the library boundary, out of the export set
#     the version script allows, rather than out of an archive this executable
#     happens to compile.
# A test that took any of those shortcuts would pass on a build where the
# facade does not exist.
#
# OpenSSL_Crypto is linked for the FIXTURE only: synthetic_masterlist.cpp mints
# the certificates and signs the lists. The facade itself needs none of it —
# that is what the OpenSSL-free public header is about — and the test TU
# includes no OpenSSL header, which it asserts on itself.
add_executable(csca_master_list_public_api_test
    csca_master_list_public_api_test.cpp
    ${PROJECT_SOURCE_DIR}/test/emrtd-crypto/synthetic_masterlist.cpp
)
target_link_libraries(csca_master_list_public_api_test
    PRIVATE
        GTest::gtest
        GTest::gtest_main
        LibreSCRS::Trust
        OpenSSL_Crypto
)
target_include_directories(csca_master_list_public_api_test PRIVATE
    ${PROJECT_SOURCE_DIR}/test/emrtd-crypto
)
gtest_discover_tests(csca_master_list_public_api_test)
