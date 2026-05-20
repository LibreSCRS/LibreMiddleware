# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# LibreSCRS_Pkcs11Inject — public C++ RAII wrapper around the
# librescrs-pkcs11 inject hook. Internal LM consumers (libresign) link
# this PUBLIC; external C / Rust / Python consumers may use the lower-
# level extern "C" hook directly via <LibreSCRS/Pkcs11/AttachHook.h>.

add_library(LibreSCRS_Pkcs11Inject STATIC
    src/session_attachment.cpp
)

add_library(LibreSCRS::Pkcs11Inject ALIAS LibreSCRS_Pkcs11Inject)

target_include_directories(LibreSCRS_Pkcs11Inject
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(LibreSCRS_Pkcs11Inject
    PUBLIC
        LibreSCRS::SmartCard
    PRIVATE
        ${CMAKE_DL_LIBS}
)

target_compile_features(LibreSCRS_Pkcs11Inject PUBLIC cxx_std_23)

set_target_properties(LibreSCRS_Pkcs11Inject PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

if(BUILD_TESTING)
    # Root CMakeLists.txt calls enable_testing() AFTER this
    # add_subdirectory; calling it locally here ensures this
    # subdirectory's CTestTestfile.cmake is emitted with add_test()
    # entries from gtest_discover_tests. Idempotent in CMake.
    enable_testing()
    add_subdirectory(test)
endif()
