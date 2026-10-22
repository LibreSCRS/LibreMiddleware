// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware (card plugins)."
#endif

#pragma once

#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS_internal/Crypto/DigestInfo.h>

#include <cstddef>
#include <optional>

namespace LibreSCRS::Plugin::Internal {

/// The three ECDSA mechanisms: their input is the caller's hash.
[[nodiscard]] constexpr bool isEcdsaMechanism(SignMechanism mechanism) noexcept
{
    return mechanism == SignMechanism::ECDSA_SHA256 || mechanism == SignMechanism::ECDSA_SHA384 ||
           mechanism == SignMechanism::ECDSA_SHA512;
}

/// An ECDSA mechanism's input length: a SHA-256, -384 or -512 hash. Anything
/// else is not a hash and must not reach the card -- under PACE secure
/// messaging a card's plain refusal of a malformed input ends the session.
[[nodiscard]] constexpr bool isEcdsaDigestLength(std::size_t length) noexcept
{
    return length == 32 || length == 48 || length == 64;
}

/// The hash an RSA PKCS#1 v1.5 mechanism over a raw message names, or none for
/// a mechanism whose input is not a raw message. The PKCS#11 module answers
/// CKM_SHA{1,256,384,512}_RSA_PKCS with the DigestInfo over that hash and the
/// raw message both, and so do the plugins.
[[nodiscard]] constexpr std::optional<LibreSCRS::Internal::Crypto::DigestInfoHash>
rsaMessageHash(SignMechanism mechanism) noexcept
{
    using LibreSCRS::Internal::Crypto::DigestInfoHash;
    switch (mechanism) {
    case SignMechanism::RSA_SHA1:
        return DigestInfoHash::Sha1;
    case SignMechanism::RSA_SHA256:
        return DigestInfoHash::Sha256;
    case SignMechanism::RSA_SHA384:
        return DigestInfoHash::Sha384;
    case SignMechanism::RSA_SHA512:
        return DigestInfoHash::Sha512;
    case SignMechanism::RSA_PKCS:
    case SignMechanism::ECDSA_SHA256:
    case SignMechanism::ECDSA_SHA384:
    case SignMechanism::ECDSA_SHA512:
        return std::nullopt;
    }
    return std::nullopt;
}

static_assert(isEcdsaDigestLength(32) && isEcdsaDigestLength(48) && isEcdsaDigestLength(64));
static_assert(!isEcdsaDigestLength(20) && !isEcdsaDigestLength(51) && !isEcdsaDigestLength(0));
static_assert(isEcdsaMechanism(SignMechanism::ECDSA_SHA384) && !isEcdsaMechanism(SignMechanism::RSA_SHA256) &&
              !isEcdsaMechanism(SignMechanism::RSA_PKCS));
static_assert(rsaMessageHash(SignMechanism::RSA_SHA384) == LibreSCRS::Internal::Crypto::DigestInfoHash::Sha384 &&
              !rsaMessageHash(SignMechanism::RSA_PKCS) && !rsaMessageHash(SignMechanism::ECDSA_SHA256));
// The mechanism travels as one byte, and the RSA mechanisms over a raw message
// were appended after RSA_SHA256: an enumerator inserted before them would
// renumber what an older plugin already receives.
static_assert(sizeof(SignMechanism) == 1);
static_assert(static_cast<int>(SignMechanism::RSA_SHA256) == 4 && static_cast<int>(SignMechanism::RSA_SHA1) == 5 &&
              static_cast<int>(SignMechanism::RSA_SHA384) == 6 && static_cast<int>(SignMechanism::RSA_SHA512) == 7);

} // namespace LibreSCRS::Plugin::Internal
