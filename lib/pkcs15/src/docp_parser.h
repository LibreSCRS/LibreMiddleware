// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once
#include <LibreSCRS/Plugin/CredentialCounters.h>
#include <cstdint>
#include <span>

namespace LibreSCRS::pkcs15 {

/// Parse the DOCP counters out of a GET DATA (ODD) response value
/// (`70 .. BF80xx .. 62 .. <tags>`, status word already stripped).
/// Tags: 9A max tries, 9B remaining tries, 9C max uses (2B signed),
/// 9D remaining uses (2B signed), 99 remaining resets. Missing tags stay
/// absent; a malformed buffer yields an all-absent result.
[[nodiscard]] LibreSCRS::Plugin::CredentialCounters
parseDocpCounters(std::span<const std::uint8_t> getDataResponse) noexcept;

} // namespace LibreSCRS::pkcs15
