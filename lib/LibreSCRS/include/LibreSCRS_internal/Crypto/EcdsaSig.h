// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief An ECDSA signature as raw `r || s` turned into the DER
///        `Ecdsa-Sig-Value SEQUENCE { r INTEGER, s INTEGER }` that CMS and
///        OpenSSL's verifier take. Header-inline: the libraries that need it
///        share no internal library, so one definition is compiled into each.

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>

#include <climits>
#include <cstdint>
#include <span>
#include <vector>

namespace LibreSCRS::Internal::Crypto {

/// @brief DER of the signature whose halves are @p raw's two equal halves;
///        empty for an empty or odd-length input.
[[nodiscard]] inline std::vector<std::uint8_t> ecdsaRawToDer(std::span<const std::uint8_t> raw)
{
    if (raw.empty() || raw.size() % 2 != 0 || raw.size() / 2 > static_cast<std::size_t>(INT_MAX))
        return {};
    const int half = static_cast<int>(raw.size() / 2);
    BnPtr r(BN_bin2bn(raw.data(), half, nullptr));
    BnPtr s(BN_bin2bn(raw.data() + half, half, nullptr));
    EcdsaSigPtr sig(ECDSA_SIG_new());
    if (!r || !s || !sig || ECDSA_SIG_set0(sig.get(), r.get(), s.get()) != 1)
        return {};
    (void)r.release(); // owned by sig from here on
    (void)s.release();
    unsigned char* der = nullptr;
    const int derLength = i2d_ECDSA_SIG(sig.get(), &der);
    if (derLength <= 0 || der == nullptr)
        return {};
    std::vector<std::uint8_t> out(der, der + derLength);
    OPENSSL_free(der);
    return out;
}

} // namespace LibreSCRS::Internal::Crypto
