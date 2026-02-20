# Bundled OpenSSL 3.5.5 (static)
set(OPENSSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/openssl-3.5.5)

add_library(OpenSSL_Crypto STATIC IMPORTED GLOBAL)
set_target_properties(OpenSSL_Crypto PROPERTIES
    IMPORTED_LOCATION ${OPENSSL_ROOT}/macosx/lib/libcrypto.a
    INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_ROOT}/include
)

# Linux support: use linux/ lib path when available
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set_target_properties(OpenSSL_Crypto PROPERTIES
        IMPORTED_LOCATION ${OPENSSL_ROOT}/linux/lib/libcrypto.a
    )
endif()
