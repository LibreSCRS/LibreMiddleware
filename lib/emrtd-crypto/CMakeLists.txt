# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(EMRTDCrypto STATIC
    src/crypto_utils.cpp
    src/crypto_utils.h
    src/bac.cpp
    src/pace.cpp
    src/passive_auth.cpp
    src/secure_messaging.cpp
    src/chip_auth.cpp
    src/active_auth.cpp
    src/csca_master_list.cpp
    src/types.h
    src/bac.h
    src/pace.h
    src/passive_auth.h
    src/secure_messaging.h
    src/chip_auth.h
    src/active_auth.h
    src/csca_master_list.h
    src/tlv_bounds.h
)

target_compile_definitions(EMRTDCrypto PRIVATE LIBRESCRS_INTERNAL_BUILD)

# fuzz/ compiles these same translation units into three instrumented
# harnesses, so the list lives in one place both read.
include(EmrtdCryptoPrivateIncludes)
target_include_directories(EMRTDCrypto PRIVATE
    ${LIBRESCRS_EMRTD_CRYPTO_PRIVATE_INCLUDES}
)

set_target_properties(EMRTDCrypto PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(EMRTDCrypto
    PUBLIC OpenSSL_Crypto
    PRIVATE SmartCard_Impl
)

librescrs_warnings_as_errors(EMRTDCrypto)
