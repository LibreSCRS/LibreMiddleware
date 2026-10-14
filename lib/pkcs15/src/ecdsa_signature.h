// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace pkcs15 {

/// Answers whether a candidate r || s is a valid signature by the key the
/// caller expects; see ecdsaRawFromCardReply.
using EcdsaRawCheck = std::function<bool(std::span<const std::uint8_t> rawRs)>;

/// The card's answer to an ECDSA PSO as the plugin contract's raw r || s: two
/// big-endian integers of exactly @p fieldBytes each, left-padded with zeros --
/// returned only when @p verifies accepts it.
///
/// Read tolerantly, because cards that write r and s at the full field width
/// do not write DER. A SEQUENCE { INTEGER, INTEGER } is read with each
/// INTEGER's content taken as an unsigned big-endian number: a set top bit is
/// magnitude, not a sign, and leading 00 bytes, however many, are dropped; what
/// remains must fit in @p fieldBytes. Lengths are definite, in the short form
/// or as 81 xx (a P-521 SEQUENCE is longer than 127 bytes), and nothing may
/// follow the SEQUENCE. A reply of exactly 2 * fieldBytes bytes is also read as
/// raw r || s. Every reading goes to @p verifies -- the plugin checks it with
/// the certificate's public key -- and the one reading it accepts is the
/// answer. The lenient read is safe only because of that check: what comes
/// back is a signature by the key, whatever shape the card gave it.
/// @return std::nullopt when no reading passes or two do, when @p verifies is
///         empty, and for @p fieldBytes of 0 or wider than P-521's 66.
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
ecdsaRawFromCardReply(std::span<const std::uint8_t> reply, std::size_t fieldBytes, const EcdsaRawCheck& verifies);

/// True when @p rawRs (r || s, each half exactly the curve's byte width) is a
/// valid ECDSA signature over @p hash by the EC public key of the X.509
/// certificate @p certDer.
[[nodiscard]] bool ecdsaRawVerifiesWithCertificate(std::span<const std::uint8_t> certDer,
                                                   std::span<const std::uint8_t> hash,
                                                   std::span<const std::uint8_t> rawRs) noexcept;

} // namespace pkcs15
