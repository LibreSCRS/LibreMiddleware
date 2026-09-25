# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# A counting PC/SC provider, loaded by OpenSC in place of libpcsclite.
#
# It deliberately does NOT link PCSC::PCSC: it DEFINES the winscard surface
# rather than calling it, and dragging libpcsclite in as a dependency would put
# a second definition of every one of these names in the same dlopen scope. The
# headers are all this needs from the package.
#
# Test-tree only: nothing installs it and nothing in lib/ links it. It is found
# at runtime through the path the consuming test compiles in, so it needs no
# stable name or location.
add_library(pcsc_counting_shim SHARED counting_pcsc_shim.c)

target_include_directories(pcsc_counting_shim PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(pcsc_counting_shim SYSTEM PRIVATE ${PCSC_INCLUDE_DIRS})

set_target_properties(pcsc_counting_shim PROPERTIES POSITION_INDEPENDENT_CODE ON)

librescrs_warnings_as_errors(pcsc_counting_shim)
