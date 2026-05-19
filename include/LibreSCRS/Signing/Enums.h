// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Signing vocabulary enums —
///        @ref LibreSCRS::Signing::SignatureFormat,
///        @ref LibreSCRS::Signing::SignatureLevel, and
///        @ref LibreSCRS::Signing::PackagingMode — exposed to the public
///        API so consumers never have to include the internal
///        signing-engine headers.
/// @since 4.0

#include <cstdint>

namespace LibreSCRS::Signing {

// Deliberately decoupled from the internal signing-engine enum: this
// public form can grow without breaking the public ABI of
// LibreSCRS::Signing. ASiC-S intentionally absent — the engine does not
// support it (backlog item).

/// @brief Advanced electronic signature container format.
/// @note ASiC-S is intentionally absent; libresign does not currently support
///       it (tracked as a backlog item).
enum class SignatureFormat : std::uint8_t {
    Pades, ///< PDF Advanced Electronic Signature.
    Cades, ///< CMS Advanced Electronic Signature.
    Xades, ///< XML Advanced Electronic Signature.
    Jades, ///< JSON Advanced Electronic Signature.
    AsicE, ///< ASiC-E container (multi-document).
};

/// @brief ETSI baseline profile determining the depth of long-term validation data.
enum class SignatureLevel : std::uint8_t {
    B_B,   ///< Basic signature.
    B_T,   ///< Basic + trusted timestamp.
    B_LT,  ///< Basic + timestamp + long-term validation material.
    B_LTA, ///< Basic + timestamp + LTV + archive timestamp.
};

/// @brief How the signature is packaged relative to the signed payload.
/// @note "Enveloping" is intentionally absent; libresign does not currently
///       support it (tracked as a backlog item).
enum class PackagingMode : std::uint8_t {
    Enveloped, ///< Signature embedded inside the signed document.
    Detached,  ///< Signature stored separately from the payload.
};

} // namespace LibreSCRS::Signing
