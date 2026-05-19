# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Shared-build CLI example. Demonstrates LibreSCRS consumption against the
# SHARED libLibreSCRS_* artefacts (LIBREMIDDLEWARE_BUILD_SHARED=ON).
#
# The example sits inside the LM source tree because the in-tree
# LibreSCRS::All alias is the canonical public-target umbrella — no
# install() round-trip needed to exercise the surface. For a true
# find_package(LibreMiddleware CONFIG) walkthrough see the sibling
# examples/sdk-consumer-config/ directory.
#
# Always entered as a subdirectory so IDE project trees pick up main.cpp;
# the actual executable target is only added when
# LIBRESCRS_BUILD_EXAMPLES=ON. Default ON when LIBREMIDDLEWARE_BUILD_SHARED
# is ON (set at top level).

if(NOT LIBRESCRS_BUILD_EXAMPLES)
    add_executable(librescrs-example-shared-cli EXCLUDE_FROM_ALL main.cpp)
    target_link_libraries(librescrs-example-shared-cli PRIVATE LibreSCRS::All)
    return()
endif()

add_executable(librescrs-example-shared-cli main.cpp)
target_link_libraries(librescrs-example-shared-cli PRIVATE LibreSCRS::All)

# Register as a ctest entry so a future regression that hides a public
# header or breaks the SHARED-build link path fails here.
if(BUILD_TESTING)
    add_test(NAME librescrs-example-shared-cli COMMAND librescrs-example-shared-cli)
endif()
