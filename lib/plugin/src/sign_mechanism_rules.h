// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware (card plugins)."
#endif

#pragma once

#include <LibreSCRS/Plugin/PluginTypes.h>

#include <cstddef>

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

static_assert(isEcdsaDigestLength(32) && isEcdsaDigestLength(48) && isEcdsaDigestLength(64));
static_assert(!isEcdsaDigestLength(20) && !isEcdsaDigestLength(51) && !isEcdsaDigestLength(0));
static_assert(isEcdsaMechanism(SignMechanism::ECDSA_SHA384) && !isEcdsaMechanism(SignMechanism::RSA_SHA256) &&
              !isEcdsaMechanism(SignMechanism::RSA_PKCS));

} // namespace LibreSCRS::Plugin::Internal
