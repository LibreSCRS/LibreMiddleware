// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace LibreSCRS::RsEId::Core {

/// @brief Byte length of one digest slot in a signed object's content.
inline constexpr std::size_t kDigestSize = 32;

/// @brief How a covered file's digest may match the signed content.
enum class DigestBinding : std::uint8_t {
    /// Block @c i must match slot @c i, so two covered files cannot swap places.
    Positional,
    /// A block may match any slot. Retained only for the CardEdge generations,
    /// whose on-card slot order was never measured; it permits substitution and
    /// must not be chosen for a generation whose order is known.
    AnywhereLegacy,
};

/// @brief Candidate encodings of one covered file, in preference order.
///
/// A generation unsure which encoding the issuer hashed supplies several; a
/// generation that measured it supplies exactly one.
using BlockCandidates = std::vector<std::vector<std::uint8_t>>;

/// @brief SHA-256 of @p data, or nullopt if the digest could not be computed.
///
/// Returning a value on failure would hand back zeros, and a signed object with
/// a zeroed slot would then read as a match. A verifier must fail closed.
[[nodiscard]] std::optional<std::array<std::uint8_t, kDigestSize>> sha256(std::span<const std::uint8_t> data);

/// @brief Check every covered block against the signed digest content.
///
/// Passing fewer blocks than the object has slots checks only those blocks: the
/// rest go unexamined and the result is still true. Callers that know how many
/// files the object covers must assert that themselves.
///
/// @param signedContent Concatenated digest slots recovered from the signed object.
/// @param blocks        Covered files, in the order the object covers them.
/// @return False unless every block matches under @p binding.
[[nodiscard]] bool matchDigests(std::span<const std::uint8_t> signedContent, std::span<const BlockCandidates> blocks,
                                DigestBinding binding);

} // namespace LibreSCRS::RsEId::Core
