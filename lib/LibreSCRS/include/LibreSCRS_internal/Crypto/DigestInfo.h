// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include <openssl/evp.h>

namespace LibreSCRS::Internal::Crypto {

// DigestInfo ASN.1 prefixes for PKCS#1 v1.5 (RFC 8017 Section 9.2 Note 1)
// Each prefix encodes AlgorithmIdentifier + OCTET STRING tag+length.

inline constexpr std::uint8_t kDigestInfoSha1Prefix[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                                                         0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};

inline constexpr std::uint8_t kDigestInfoSha256Prefix[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                           0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

inline constexpr std::uint8_t kDigestInfoSha384Prefix[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                           0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};

inline constexpr std::uint8_t kDigestInfoSha512Prefix[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                           0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

/// The hashes a PKCS#1 v1.5 DigestInfo is built for here.
enum class DigestInfoHash : std::uint8_t { Sha1, Sha256, Sha384, Sha512 };

/// The DigestInfo over @p message hashed with @p hash: the input a card signs
/// for an RSA PKCS#1 v1.5 signature it does not hash itself. Empty when
/// OpenSSL fails to hash.
[[nodiscard]] inline std::vector<std::uint8_t> digestInfoOf(DigestInfoHash hash, std::span<const std::uint8_t> message)
{
    const EVP_MD* md = nullptr;
    std::span<const std::uint8_t> prefix;
    switch (hash) {
    case DigestInfoHash::Sha1:
        md = EVP_sha1();
        prefix = kDigestInfoSha1Prefix;
        break;
    case DigestInfoHash::Sha256:
        md = EVP_sha256();
        prefix = kDigestInfoSha256Prefix;
        break;
    case DigestInfoHash::Sha384:
        md = EVP_sha384();
        prefix = kDigestInfoSha384Prefix;
        break;
    case DigestInfoHash::Sha512:
        md = EVP_sha512();
        prefix = kDigestInfoSha512Prefix;
        break;
    }
    std::vector<std::uint8_t> out(prefix.begin(), prefix.end());
    out.resize(prefix.size() + static_cast<std::size_t>(EVP_MD_get_size(md)));
    unsigned int length = 0;
    if (EVP_Digest(message.data(), message.size(), out.data() + prefix.size(), &length, md, nullptr) != 1 ||
        prefix.size() + length != out.size())
        return {};
    return out;
}

} // namespace LibreSCRS::Internal::Crypto
