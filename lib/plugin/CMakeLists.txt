# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# card_plugin_key_function.cpp carries the out-of-line ~CardPlugin() key
# function. One and only one TU defines it; the Itanium C++ ABI uses it to
# anchor the CardPlugin vtable + typeinfo to exactly one library target,
# so cross-.so dynamic_cast and typeinfo identity work under macOS
# two-level namespaces and Windows dllimport-consumer builds. See Itanium
# C++ ABI §5.1.
#
# In STATIC builds every CardPlugin consumer links CardPlugin_Impl
# directly for the registry, so the key function rides in through the
# same dependency edge. In SHARED builds LibreSCRS_Plugin pulls the
# whole CardPlugin_Impl archive (lib/LibreSCRS/CMakeLists.txt) so the
# key function — and the vtable + typeinfo it anchors — also land in
# libLibreSCRS_Plugin.so where the public version script promotes them
# to default visibility for cross-`.so` consumers.
add_library(CardPlugin_Impl STATIC
    src/atr.cpp
    src/card_plugin.cpp
    src/card_plugin_key_function.cpp
    src/card_plugin_registry.cpp
)
target_compile_definitions(CardPlugin_Impl PRIVATE LIBRESCRS_INTERNAL_BUILD)
# PRIVATE include: public consumers get LibreSCRS/Plugin/*.h via LibreSCRS::Plugin.
# BUILD_INTERFACE-only so even internal LM libs that link CardPlugin_Impl as PUBLIC
# do not re-export the top-level include/ tree into external packages.
target_include_directories(CardPlugin_Impl PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)
target_compile_features(CardPlugin_Impl PUBLIC cxx_std_23)
target_link_libraries(CardPlugin_Impl PUBLIC ${CMAKE_DL_LIBS} SmartCard_Impl)
target_link_libraries(CardPlugin_Impl PUBLIC LibreSCRS_Auth LibreSCRS_SmartCard)
set_target_properties(CardPlugin_Impl PROPERTIES POSITION_INDEPENDENT_CODE ON)
