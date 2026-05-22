# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# CardPlugin_Impl: registry + ATR matching + plugin loading machinery +
# the out-of-line ~CardPlugin() key function (Itanium C++ ABI §5.1 vtable +
# typeinfo anchor for cross-`.so` dynamic_cast / typeinfo identity).
#
# Built as OBJECT so consumers (LibreSCRS_Plugin SHARED, plugin .so files,
# test executables) absorb the .o files directly via
# target_link_libraries(... PRIVATE CardPlugin_Impl). The OBJECT linkage
# pulls every TU into the consumer — including the key function — so the
# vtable + typeinfo land in libLibreSCRS_Plugin.so where the
# `*LibreSCRS::*` version-script glob promotes them to default visibility.
# No archive-extraction policy or `--whole-archive` generator expression
# needed (mirrors the LibreSCRS_SmartCard_TestHelpers OBJECT pattern in
# ../LibreSCRS/CMakeLists.txt).
add_library(CardPlugin_Impl OBJECT
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
