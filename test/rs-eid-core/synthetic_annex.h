// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Builders for synthetic annex containers and signed objects.
//
// Real card bytes are deliberately absent: a card's signed objects embed the
// issuer's certificates, and this is a public repository. Every fixture here is
// built from the format itself, which is also what the tests are about.

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <algorithm>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::RsEId::Core::TestData {

inline void appendLe16(std::vector<std::uint8_t>& out, std::uint16_t v)
{
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v >> 8));
}

/// @brief One annex container: tag(2 LE) || len(2 LE) || inner TLVs, then padding.
///
/// @param paddedSize Allocated file size on card; the tail past the container is
///                   padding and is not covered by any signature.
inline std::vector<std::uint8_t> makeContainer(std::uint16_t fid,
                                               const std::vector<std::pair<std::uint16_t, std::string>>& fields,
                                               std::size_t paddedSize = 0)
{
    std::vector<std::uint8_t> body;
    for (const auto& [tag, value] : fields) {
        appendLe16(body, tag);
        appendLe16(body, static_cast<std::uint16_t>(value.size()));
        body.insert(body.end(), value.begin(), value.end());
    }

    std::vector<std::uint8_t> out;
    appendLe16(out, fid);
    appendLe16(out, static_cast<std::uint16_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    out.resize(std::max(paddedSize, out.size()), 0x00);
    return out;
}

/// @brief Manifest container: tag 1539 lists the annex file ids little-endian.
/// The manifest never lists itself.
inline std::vector<std::uint8_t> makeManifest(const std::vector<std::uint16_t>& ids, std::size_t paddedSize = 0)
{
    std::string list;
    for (const std::uint16_t id : ids) {
        list.push_back(static_cast<char>(id & 0xFF));
        list.push_back(static_cast<char>(id >> 8));
    }
    return makeContainer(0x0F1B, {{1537, "05"}, {1538, "01"}, {1539, list}}, paddedSize);
}

/// @brief A signed object plus the anchor needed to make its chain verify.
struct SignedObjectFixture
{
    std::vector<std::uint8_t> cms;           ///< BER indefinite-length PKCS#7 SignedData
    std::vector<std::uint8_t> signerCertDer; ///< the ephemeral self-signed signer
};

/// @brief A PKCS#7 SignedData over @p content, signed by an ephemeral self-signed
///        key. Streamed output is BER indefinite-length, as the card emits.
/// @param expiredSigner Backdate the signer so its validity window has closed.
[[nodiscard]] SignedObjectFixture makeSignedObject(std::span<const std::uint8_t> content, bool expiredSigner = false);

} // namespace LibreSCRS::RsEId::Core::TestData
