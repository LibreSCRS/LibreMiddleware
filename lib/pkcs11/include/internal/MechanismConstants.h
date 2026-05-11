// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief PKCS#11 v2.40 raw mechanism numeric values shared by the
///        PKCS#11 slot translation units.
///
/// Centralised so a future mechanism addition (PSS-512 / EdDSA / etc.)
/// is a single-edit change and providers cannot drift on the numeric
/// values they advertise. Raw values kept here instead of @c pkcs11t.h
/// to avoid pulling the upstream vendor header into translation units
/// that otherwise stay free of it.

namespace LibreSCRS::Pkcs11::Internal {

inline constexpr unsigned long kCkmRsaPkcs = 0x00000001UL;
inline constexpr unsigned long kCkmRsaPkcsSha256 = 0x00000040UL;
inline constexpr unsigned long kCkmRsaPkcsSha384 = 0x00000041UL;
inline constexpr unsigned long kCkmRsaPkcsSha512 = 0x00000042UL;
inline constexpr unsigned long kCkmRsaPssSha256 = 0x00000043UL;
inline constexpr unsigned long kCkmRsaPssSha384 = 0x00000044UL;
inline constexpr unsigned long kCkmRsaPssSha512 = 0x00000045UL;
inline constexpr unsigned long kCkmEcdsa = 0x00001041UL;
inline constexpr unsigned long kCkmEcdsaSha256 = 0x00001044UL;
inline constexpr unsigned long kCkmEcdsaSha384 = 0x00001045UL;
inline constexpr unsigned long kCkmEcdsaSha512 = 0x00001046UL;

/// @brief PKCS#11 object class constants (CKO_*).
inline constexpr unsigned long kCkoCertificate = 1UL;
inline constexpr unsigned long kCkoPublicKey = 2UL;
inline constexpr unsigned long kCkoPrivateKey = 3UL;

/// @brief PKCS#11 key type constants (CKK_*).
inline constexpr unsigned long kCkkRsa = 0UL;
inline constexpr unsigned long kCkkEc = 3UL;

} // namespace LibreSCRS::Pkcs11::Internal
