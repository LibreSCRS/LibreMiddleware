# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Standalone Qt-free demonstration of LibreSCRS::Signing::layoutVisualSignature.
#
# Mirrors examples/sdk-consumer/CMakeLists.txt: always entered as a
# subdirectory so IDEs (QtCreator, CLion, VS Code CMake Tools) see the
# source in their project tree, but the executable is only added when
# -DLIBRESCRS_BUILD_EXAMPLES=ON.

if(NOT LIBRESCRS_BUILD_EXAMPLES)
    add_executable(visual_signature_layout_example EXCLUDE_FROM_ALL main.cpp)
    target_link_libraries(visual_signature_layout_example PRIVATE LibreSCRS::Signing)
    return()
endif()

add_executable(visual_signature_layout_example main.cpp)
target_link_libraries(visual_signature_layout_example PRIVATE LibreSCRS::Signing)

if(BUILD_TESTING)
    # Smoke-test the binary as a ctest entry — sign-of-life that the
    # public API is callable from a Qt-free program.
    add_test(NAME visual_signature_layout_example_smoke
             COMMAND visual_signature_layout_example "Hello World")
endif()
