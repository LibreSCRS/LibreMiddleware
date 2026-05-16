# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GoogleTest)

add_executable(SessionAttachmentTests SessionAttachmentTests.cpp)

target_link_libraries(SessionAttachmentTests PRIVATE
    LibreSCRS::Pkcs11Inject
    LibreSCRS::SmartCard
    GTest::gtest_main
    ${CMAKE_DL_LIBS}
)

# The suite-level fixture dlopens librescrs-pkcs11 and calls
# C_Initialize through C_GetFunctionList, so the test TU includes the
# vendored PKCS#11 headers from lib/pkcs11/include. The module is loaded
# at runtime via dlopen; no link-time dependency on librescrs-pkcs11.
target_include_directories(SessionAttachmentTests PRIVATE
    ${LibreMiddleware_SOURCE_DIR}/lib/pkcs11/include
)

# Detached-session test factory pulls
# <LibreSCRS/SmartCard/detail/CardSessionInjection.h>, gated by the
# internal-build define.
target_compile_definitions(SessionAttachmentTests PRIVATE
    LIBRESCRS_INTERNAL_BUILD=1
    LIBRESCRS_PKCS11_MODULE_PATH="$<TARGET_FILE:librescrs-pkcs11>"
)

add_dependencies(SessionAttachmentTests librescrs-pkcs11)

gtest_discover_tests(SessionAttachmentTests)
