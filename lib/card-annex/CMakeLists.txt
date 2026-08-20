# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# A library rather than plugin-local sources: the plugin is a SHARED object that
# tests reach only through dlopen, so anything that needs unit tests has to live
# where a test can link it.
add_library(CardAnnex STATIC
    src/AnnexDispatch.cpp
    src/AnnexRegistry.cpp
    src/RsAnnexReader.cpp
    # Private headers (IDE visibility)
    src/AnnexDispatch.h
    src/AnnexRegistry.h
    src/IAnnexReader.h
    src/RsAnnexReader.h
)

target_compile_definitions(CardAnnex PRIVATE LIBRESCRS_INTERNAL_BUILD)

target_include_directories(CardAnnex PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(CardAnnex PRIVATE
    ${PROJECT_SOURCE_DIR}/lib/smartcard/src
    ${PROJECT_SOURCE_DIR}/lib/rs-eid-core/src
    ${PROJECT_SOURCE_DIR}/lib/smartcard/include
    ${PROJECT_SOURCE_DIR}/lib/SecureChannel/include
)

set_target_properties(CardAnnex PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(CardAnnex PUBLIC LibreSCRS_Plugin SmartCard_Impl RsEIdCore PRIVATE LibreSCRS_SecureChannel)

librescrs_warnings_as_errors(CardAnnex)
