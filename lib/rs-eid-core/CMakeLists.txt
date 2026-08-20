# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(RsEIdCore STATIC
    src/rs_container.cpp
    src/rs_digest_binding.cpp
    src/rs_signed_object.cpp
    src/rs_trust_store.cpp
    # Private headers (IDE visibility)
    src/rs_container.h
    src/rs_digest_binding.h
    src/rs_signed_object.h
    src/rs_tags.h
    src/rs_trust_store.h
    src/rs_types.h
    src/detail/document_signer_policy.h
)

target_compile_definitions(RsEIdCore PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(RsEIdCore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(RsEIdCore PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/LibreSCRS/include
)

set_target_properties(RsEIdCore PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(RsEIdCore PUBLIC SmartCard_Impl PRIVATE OpenSSL_Crypto)

librescrs_warnings_as_errors(RsEIdCore)
