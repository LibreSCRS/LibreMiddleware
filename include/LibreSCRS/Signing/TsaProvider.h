// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Signing::TsaProvider — the time-stamping authority a
///        signature at B-T or above contacts — and its factories.
/// @since 4.0

#include <LibreSCRS/Export.h>

#include <string>
#include <string_view>

namespace LibreSCRS::Signing {

/// @brief The time-stamping authority a signature at B-T or above contacts.
///
/// A default-constructed provider names no authority: B-B signatures still
/// succeed, while B-T / B-LT / B-LTA requests fail with
/// @ref LibreSCRS::Signing::SigningResult::Status::TsaUnreachable.
///
/// @par Thread-safety
/// thread-compatible (see API-POLICY §8).
/// @since 4.0
struct TsaProvider
{
    /// @brief The authority's URL. Empty when no authority is configured.
    std::string url;
};

/// @brief Convenience factory: the authority at @p url.
/// @param url TSA endpoint URL. Accepted as-is — no syntactic validation.
/// @note Permissive of non-http TSA transports and unusual URL syntaxes;
///       use `staticTsaChecked` when you want the factory to reject
///       obviously malformed URLs up-front.
[[nodiscard]] LIBRESCRS_PUBLIC_API TsaProvider staticTsa(std::string url);

/// @brief Validating variant of `staticTsa`.
///
/// Performs a basic syntactic check on @p url:
///   - non-empty;
///   - begins with `http://` or `https://`;
///   - the scheme is followed by a non-empty authority (host token).
///
/// This is a lightweight pre-flight filter — it catches "forgot the scheme"
/// / empty-string / "http://" configuration mistakes before they reach the
/// signing engine, without attempting full RFC 3986 validation. Rigorous
/// URL parsing is delegated to libcurl at transport time.
///
/// @param url TSA endpoint URL.
/// @throws std::invalid_argument if @p url fails any of the checks above.
///         See API-POLICY §5.1.
[[nodiscard]] LIBRESCRS_PUBLIC_API TsaProvider staticTsaChecked(std::string_view url);

} // namespace LibreSCRS::Signing
