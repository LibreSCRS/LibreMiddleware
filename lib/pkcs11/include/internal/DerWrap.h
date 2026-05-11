// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief DER OCTET STRING wrap helper shared by the PKCS#11 slot
///        translation units.
///
/// Wraps a raw payload in an ASN.1 OCTET STRING (tag 0x04) with the
/// minimal-length encoding required by PKCS#11 @c CKA_EC_POINT. Both the
/// in-tree @c Pkcs15Slot and the OpenSC-backed @c OpenScSlot need this
/// when surfacing EC public-key points so consumers see identical bytes
/// regardless of which provider answers.

#include <cstdint>
#include <span>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal {

/// @brief Wrap @p raw in an ASN.1 DER OCTET STRING (tag 0x04) using the
///        shortest valid length encoding (short / long form 1 byte /
///        long form 2 bytes).
/// @param raw Payload bytes to wrap.
/// @return DER OCTET STRING bytes (tag + length + payload).
/// @par Thread-safety
/// Pure function over its inputs.
/// @since 4.1
[[nodiscard]] inline std::vector<std::uint8_t> derOctetStringWrap(std::span<const std::uint8_t> raw)
{
    std::vector<std::uint8_t> out;
    out.reserve(raw.size() + 4);
    out.push_back(0x04); // OCTET STRING tag.
    if (raw.size() < 0x80) {
        out.push_back(static_cast<std::uint8_t>(raw.size()));
    } else if (raw.size() <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(raw.size()));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<std::uint8_t>((raw.size() >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(raw.size() & 0xFF));
    }
    out.insert(out.end(), raw.begin(), raw.end());
    return out;
}

} // namespace LibreSCRS::Pkcs11::Internal
