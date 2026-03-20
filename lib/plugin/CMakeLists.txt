# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

add_library(CardPlugin STATIC
    src/card_plugin_registry.cpp
)
target_include_directories(CardPlugin PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(CardPlugin PUBLIC cxx_std_20)
target_link_libraries(CardPlugin PUBLIC ${CMAKE_DL_LIBS})
set_target_properties(CardPlugin PROPERTIES POSITION_INDEPENDENT_CODE ON)
