# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright hirashix0@proton.me

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(CardEdge STATIC
    src/cardedge.cpp
    # Private headers (IDE visibility)
    src/cardedge_protocol.h
    # Public headers
    include/cardedge/cardedge.h
    include/cardedge/cardedgetypes.h
    include/cardedge/pki_applet_guard.h
)

target_include_directories(CardEdge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(CardEdge PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(CardEdge PUBLIC SmartCard z)
