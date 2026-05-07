// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include <cstddef>

/// @file
/// @brief Bundled Liberation Sans Regular TTF, embedded as a C array
/// at build time by cmake/EmbedBinary.cmake.
///
/// The PAdES native engine (lib/libresign/src/native/pades_module.cpp)
/// subsets and embeds this font into every signed PDF so visible
/// signature text correctly renders Serbian Latin and Cyrillic
/// characters.
///
/// Source: thirdparty/liberation-sans/LiberationSans-Regular.ttf
/// Licence: SIL Open Font License 1.1 (see thirdparty/liberation-sans/
/// LICENSE-OFL-1.1.txt).

extern "C" {
extern const unsigned char LiberationSansRegular[];
extern const std::size_t LiberationSansRegularSize;
}
