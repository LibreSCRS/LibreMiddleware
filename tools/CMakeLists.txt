# SPDX-License-Identifier: LGPL-2.1-or-later
add_subdirectory(card_mapper)
# Reads the card through PC/SC directly; macOS reaches cards through
# CryptoTokenKit only.
if(NOT APPLE)
    add_subdirectory(eid-sod-verify)
endif()
