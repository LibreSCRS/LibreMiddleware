# SPDX-License-Identifier: LGPL-2.1-or-later

# Opens the card through CardSession, as the library does. apdu.h and
# pcsc_connection.h come from the library's private sources, as for the other
# in-tree diagnostic tools.
add_executable(eid-sod-verify main.cpp)
target_include_directories(eid-sod-verify PRIVATE ${PROJECT_SOURCE_DIR}/lib/smartcard/src)
target_link_libraries(eid-sod-verify PRIVATE SmartCard_Impl LibreSCRS::SmartCard OpenSSL_Crypto)
target_compile_features(eid-sod-verify PRIVATE cxx_std_23)
target_compile_definitions(eid-sod-verify
    PRIVATE LIBRESCRS_INTERNAL_BUILD
            LIBREMIDDLEWARE_CERTIFICATES_DIR="${LIBREMIDDLEWARE_CERTIFICATES_DIR}"
            LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR="${LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR}")
