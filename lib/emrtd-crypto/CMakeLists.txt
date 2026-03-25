# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

set(CMAKE_CXX_STANDARD 20)
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
    include/emrtd/crypto/types.h
    include/emrtd/crypto/bac.h
    include/emrtd/crypto/pace.h
    include/emrtd/crypto/passive_auth.h
    include/emrtd/crypto/secure_messaging.h
    include/emrtd/crypto/chip_auth.h
    include/emrtd/crypto/active_auth.h
)

target_include_directories(EMRTDCrypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(EMRTDCrypto PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(EMRTDCrypto
    PUBLIC OpenSSL_Crypto
    PRIVATE SmartCard
)
