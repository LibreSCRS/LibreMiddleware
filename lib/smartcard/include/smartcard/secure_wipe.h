// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstddef>

namespace LibreSCRS::SmartCard::Internal {

/// Zeroize @p n bytes at @p p so the write cannot be optimized away.
/// Declared out-of-line so the guaranteed-wipe primitive stays confined to
/// secure_wipe.cpp — this header pulls in no crypto dependency, keeping it out
/// of every public consumer of <smartcard/secure_buffer.h>.
void secureWipe(void* p, std::size_t n) noexcept;

} // namespace LibreSCRS::SmartCard::Internal
