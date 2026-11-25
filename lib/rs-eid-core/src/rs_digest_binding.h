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
#include <variant>
#include <vector>

namespace LibreSCRS::RsEId::Core {

/// @brief Byte length of one digest slot in a signed object's content.
inline constexpr std::size_t kDigestSize = 32;

/// @brief Candidate encodings of one covered file, in preference order.
///
/// A generation unsure which encoding the issuer hashed supplies several; a
/// generation that measured it supplies exactly one.
using BlockCandidates = std::vector<std::vector<std::uint8_t>>;

/// @brief A slot the verifier knowingly leaves unchecked.
///
/// Distinct from an empty @ref BlockCandidates, which never matches: a slot may
/// only go unexamined when the profile says so (a file unreadable without
/// authentication), never because a file happened to be missing.
struct SkipSlot
{};

/// @brief What stands at one digest slot: candidate encodings to match, or a skip.
using SlotInput = std::variant<BlockCandidates, SkipSlot>;

/// @brief SHA-256 of @p data, or nullopt if the digest could not be computed.
///
/// Returning a value on failure would hand back zeros, and a signed object with
/// a zeroed slot would then read as a match. A verifier must fail closed.
[[nodiscard]] std::optional<std::array<std::uint8_t, kDigestSize>> sha256(std::span<const std::uint8_t> data);

/// @brief Strictly positional check of every slot of a signed object.
///
/// True only when the content holds exactly one digest per entry of @p slots,
/// at least one slot is not skipped, and every non-skipped slot matches the
/// digest at its own position. An entry with no candidates is a mismatch.
///
/// @param signedContent Concatenated digest slots recovered from the signed object.
/// @param slots         One entry per slot, in the order the object covers them.
[[nodiscard]] bool matchDigests(std::span<const std::uint8_t> signedContent, std::span<const SlotInput> slots);

} // namespace LibreSCRS::RsEId::Core
