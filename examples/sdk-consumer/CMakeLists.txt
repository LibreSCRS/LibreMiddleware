# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Standalone LibreSCRS consumer — mirrors what a third-party downstream
# project would write in its own CMakeLists.txt.
#
# Always entered as a subdirectory (see top-level CMakeLists.txt comment)
# so IDEs see the source in their project tree. The actual executable
# target is only added when -DLIBRESCRS_BUILD_EXAMPLES=ON.

if(NOT LIBRESCRS_BUILD_EXAMPLES)
    # Fully-configured executable target excluded from the default build.
    # Rationale:
    #   - `add_custom_target(... SOURCES main.cpp)` lists the file in IDE
    #     trees but produces no compile_commands.json entry, so clangd has
    #     no include paths for it — every `LibreSCRS::*` identifier and
    #     every `#include <LibreSCRS/...>` surfaces as unresolved red-
    #     underlined garbage in QtCreator / VS Code / neovim-lsp.
    #   - `add_executable(... EXCLUDE_FROM_ALL ...)` is the right shape:
    #     the target is in the project graph with its transitive include
    #     paths populated via LibreSCRS::All, compile_commands.json carries
    #     the correct flags, and `cmake --build .` does NOT build it unless
    #     someone passes `--target sdk-consumer` explicitly.
    # To build on demand: `cmake --build build --target sdk-consumer`.
    # To opt every build in: `-DLIBRESCRS_BUILD_EXAMPLES=ON`.
    add_executable(sdk-consumer EXCLUDE_FROM_ALL main.cpp)
    target_link_libraries(sdk-consumer PRIVATE LibreSCRS::All)
    return()
endif()

add_executable(sdk-consumer main.cpp)

# Link ONLY the public umbrella target. Transitively provides
# LibreSCRS::{Auth, SmartCard, Plugin, Signing} — and ONLY their public
# include dirs (${PROJECT_SOURCE_DIR}/include). No lib/*/include, no
# lib/*/src, no LibreSCRS::SmartCard::Internal:: / libresign:: reachable.
target_link_libraries(sdk-consumer PRIVATE LibreSCRS::All)

# Registering sdk-consumer as a ctest entry makes its build + run part of
# the default ctest pass — if a future change leaks an internal header
# into a public one, ctest fails here instead of waiting for someone to
# flip -DLIBRESCRS_BUILD_EXAMPLES=ON by hand.
if(BUILD_TESTING)
    add_test(NAME sdk-consumer COMMAND sdk-consumer)
endif()
