# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# OpenScPKCS11Provider — broadest-fallback PKCS#11 provider backed by the
# vendored static OpenSC archive (Phase C.1 in the multi-PIN refactor).
# Registered FIRST (priority 1) by lib/pkcs11 when LIBRESCRS_VENDOR_OPENSC
# is on; any PKCS#15-shaped card that OpenSC's emulator chain or built-in
# driver recognises gets a chance to surface here before the project's
# custom Pkcs15PKCS11Provider runs.

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
    opensc_static
    OpenSSL_Crypto
    LibreSCRS::Secure
)

# The vendored OpenSC archive may include notify.o (autoconf auto-detects
# gio-2.0 unless --disable-notify is passed). When present, libopensc.a
# pulls undefined references to g_application_*, g_notification_* and
# g_object_unref into the consuming SHARED library. Resolve them by
# transitively linking the GIO/GLib system stack here. We probe with
# pkg-config and skip if absent (keeping the static-only build viable on
# minimal CI hosts where notify was elided).
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBRESCRS_OPENSC_GIO QUIET IMPORTED_TARGET gio-2.0)
    if(LIBRESCRS_OPENSC_GIO_FOUND)
        target_link_libraries(librescrs-opensc-pkcs11 PRIVATE PkgConfig::LIBRESCRS_OPENSC_GIO)
    endif()
endif()

# OpenSC also depends on PC/SC (libpcsclite on Linux) at link time when
# --enable-pcsc is passed (Option A; see thirdparty/CMakeLists.txt). The
# system libopensc package would resolve this transitively; here we wire
# it explicitly because the static archive carries undefined SCard*
# references.
if(PkgConfig_FOUND AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    pkg_check_modules(LIBRESCRS_OPENSC_PCSC QUIET IMPORTED_TARGET libpcsclite)
    if(LIBRESCRS_OPENSC_PCSC_FOUND)
        target_link_libraries(librescrs-opensc-pkcs11 PRIVATE PkgConfig::LIBRESCRS_OPENSC_PCSC)
    endif()
endif()

set_target_properties(librescrs-opensc-pkcs11 PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
)
