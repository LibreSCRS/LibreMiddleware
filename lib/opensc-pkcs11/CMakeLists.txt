# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# OpenScPKCS11Provider — broadest-fallback PKCS#11 provider backed by the
# vendored static OpenSC archive. Registered FIRST (priority 1) by
# lib/pkcs11 when LIBRESCRS_VENDOR_OPENSC is on; any PKCS#15-shaped card
# that OpenSC's emulator chain or built-in driver recognises gets a
# chance to surface here before the project's custom Pkcs15PKCS11Provider
# runs.

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(librescrs-opensc-pkcs11 STATIC
    src/opensc_pkcs11_provider.cpp
    src/opensc_card.cpp
    src/opensc_slot.cpp
    include/internal/OpenScPKCS11Provider.h
    src/opensc_card.h
    src/opensc_slot.h
)

target_compile_definitions(librescrs-opensc-pkcs11 PRIVATE
    LIBRESCRS_BUILDING LIBRESCRS_INTERNAL_BUILD
)

target_include_directories(librescrs-opensc-pkcs11 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(librescrs-opensc-pkcs11 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LibreMiddleware_SOURCE_DIR}/lib/pkcs11/include
)

target_link_libraries(librescrs-opensc-pkcs11 PRIVATE
    opensc_static_with_deps
    LibreSCRS::Secure
)

set_target_properties(librescrs-opensc-pkcs11 PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
)
