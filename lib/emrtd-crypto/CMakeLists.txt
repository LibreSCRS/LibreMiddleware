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
    src/types.h
    src/bac.h
    src/pace.h
    src/passive_auth.h
    src/secure_messaging.h
    src/chip_auth.h
    src/active_auth.h
)

target_compile_definitions(EMRTDCrypto PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(EMRTDCrypto PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    # SecureChannel public + internal headers —
    # included via direct path rather than `LibreSCRS_SecureChannel` link to
    # avoid a circular target dependency: LibreSCRS_SecureChannel privately
    # links EMRTDCrypto for the BAC/PACE/CA protocol implementations. A
    # static<->static cycle is permitted, but a SHARED LibreSCRS_SecureChannel
    # cycle fails at generate time (LIBREMIDDLEWARE_BUILD_SHARED=ON / LibreKDE
    # consumer mode). All downstream targets that link EMRTDCrypto also link
    # LibreSCRS_SecureChannel directly, so no transitive surface is lost.
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/lib/SecureChannel/include
)

set_target_properties(EMRTDCrypto PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(EMRTDCrypto
    PUBLIC OpenSSL_Crypto
    PRIVATE SmartCard_Impl
)
