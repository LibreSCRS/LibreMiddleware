// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace LibreSCRS::RsEId::Core {

/// @brief Byte length of a container header: tag(2, LE) + length(2, LE).
inline constexpr std::size_t kContainerHeaderSize = 4;

/// @brief Which annex files each signed object covers, in coverage order.
struct AnnexCoverage
{
    std::vector<std::uint16_t> fixed;
    std::vector<std::uint16_t> variable;
};

/// @brief Tag of the outer container, which repeats the file's own id.
/// @return Nullopt when @p file is too short to carry a header.
[[nodiscard]] std::optional<std::uint16_t> outerTag(std::span<const std::uint8_t> file) noexcept;

/// @brief The leading container of @p file with trailing file padding removed.
///
/// A signed digest covers exactly this span. Cards pad a file out to its
/// allocated size and that padding is not signed, so hashing the whole file
/// matches nothing.
///
/// @return Nullopt when the header is absent or the declared length overruns.
[[nodiscard]] std::optional<std::span<const std::uint8_t>> leadingTlv(std::span<const std::uint8_t> file) noexcept;

/// @brief The payload of the inner TLV that a signed object carries between its
///        container and the CMS proper.
///
/// Returns @p content unchanged when nothing wraps it -- content that already
/// starts with an ASN.1 SEQUENCE, or that is too short to carry a header.
[[nodiscard]] std::span<const std::uint8_t> innerTlvPayload(std::span<const std::uint8_t> content) noexcept;

/// @brief File ids advertised by the annex manifest, in on-card order.
/// The manifest does not list itself.
[[nodiscard]] std::vector<std::uint16_t> parseManifest(std::span<const std::uint8_t> manifestFile);

/// @brief Coverage order derived from @p manifestIds rather than hardcoded.
///
/// The fixed object covers the manifest first, then every listed file that is
/// neither the variable file nor one of the two signed objects.
[[nodiscard]] AnnexCoverage annexCoverage(std::span<const std::uint16_t> manifestIds);

} // namespace LibreSCRS::RsEId::Core
