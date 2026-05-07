// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace libresign {

// ASN.1 DER encoding utilities.

// Encode a DER definite-length field (short or long form).
inline std::vector<uint8_t> derEncodeLength(size_t len)
{
    std::vector<uint8_t> out;
    if (len < 128) {
        out.push_back(static_cast<uint8_t>(len));
    } else if (len < 256) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(len));
    } else if (len < 65536) {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
    } else if (len < 0x1000000) {
        out.push_back(0x83);
        out.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        // Anything ≥ 16 MiB would need 0x84 (4-byte) encoding, which is
        // legal DER but far exceeds any signature-adjacent payload we
        // produce. Fail loudly rather than silently truncating the high
        // bits and writing a corrupt structure.
        throw std::length_error("derEncodeLength: content ≥ 16 MiB is not supported");
    }
    return out;
}

// Wrap content with a DER tag + length.
inline std::vector<uint8_t> derWrap(uint8_t tag, std::span<const uint8_t> content)
{
    std::vector<uint8_t> out;
    out.push_back(tag);
    auto lenBytes = derEncodeLength(content.size());
    out.insert(out.end(), lenBytes.begin(), lenBytes.end());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// Shorthand: SEQUENCE (tag 0x30).
inline std::vector<uint8_t> derSequence(std::span<const uint8_t> content)
{
    return derWrap(0x30, content);
}

// Shorthand: OCTET STRING (tag 0x04).
inline std::vector<uint8_t> derOctetString(std::span<const uint8_t> content)
{
    return derWrap(0x04, content);
}

} // namespace libresign
