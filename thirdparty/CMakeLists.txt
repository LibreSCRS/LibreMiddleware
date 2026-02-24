# Bundled OpenSSL 3.5.5 (static)
set(OPENSSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/openssl-3.5.5)
add_library(OpenSSL_Crypto STATIC IMPORTED GLOBAL)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set_target_properties(OpenSSL_Crypto PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_ROOT}/macosx/lib/libcrypto.a
        INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_ROOT}/macosx/include
    )
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(OpenSSL_Crypto PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_ROOT}/linux/lib/libcrypto.a
        INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_ROOT}/linux/include
    )
endif()
