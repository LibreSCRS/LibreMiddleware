// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <span>
#include <string>

namespace LibreSCRS::SmartCard::Internal {

// Decode UTF-16 little-endian bytes to UTF-8. Basic Multilingual Plane only,
// which covers every Serbian script; a trailing odd byte is dropped.
std::string decodeUtf16Le(std::span<const std::uint8_t> bytes);

} // namespace LibreSCRS::SmartCard::Internal
