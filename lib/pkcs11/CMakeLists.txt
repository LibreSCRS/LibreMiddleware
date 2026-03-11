# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

configure_file(
    src/pkcs11_version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/pkcs11_version.h
    @ONLY
)

add_library(librescrs-pkcs11 SHARED
    src/pkcs11.cpp
    src/pkcs11_library.cpp
    src/pkcs11_library.h
    include/pkcs11/pkcs11.h
    include/pkcs11/pkcs11t.h
    include/pkcs11/pkcs11f.h
)

target_include_directories(librescrs-pkcs11 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(librescrs-pkcs11 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(librescrs-pkcs11 PRIVATE CardEdge OpenSSL_Crypto)

set_target_properties(librescrs-pkcs11 PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    PREFIX "lib"
    OUTPUT_NAME "rescrs-pkcs11"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
