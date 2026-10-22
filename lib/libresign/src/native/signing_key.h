// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "../types.h" // ChainTermination

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace libresign {

/// @brief The key a document signature is made with, as every format module
///        and the OpenSSL provider see it.
///
/// In production it signs through the card plugin on a session the host
/// already holds; the tests hand in keys held in memory. Neither the formats
/// nor the provider know which one they were handed.
class SigningKey
{
public:
    virtual ~SigningKey() = default;

    /// @brief Sign @p hash -- the DigestInfo for RSA PKCS#1 v1.5, the hash
    ///        itself for ECDSA -- under @p algorithm (e.g. "SHA256withRSA").
    ///        @p rawData, when not empty, is the message @p hash was computed
    ///        over, for a key that can only sign a message it hashes itself;
    ///        an empty span means only @p hash is available.
    [[nodiscard]] virtual std::vector<std::uint8_t>
    sign(std::span<const std::uint8_t> hash, const std::string& algorithm, std::span<const std::uint8_t> rawData) = 0;

    /// @brief The signer's certificate, DER.
    [[nodiscard]] virtual std::vector<std::uint8_t> certificate() const = 0;

    /// @brief The signer's chain, DER, leaf first: the one set with
    ///        @ref setResolvedChain, else what the key's own store holds.
    [[nodiscard]] virtual std::vector<std::vector<std::uint8_t>> certificateChain() const = 0;

    /// @brief Override @ref certificateChain with a caller-resolved chain
    ///        (DER, leaf first); an empty vector restores the key's own one.
    ///
    ///        @p termination is the CALLER's proof obligation: assert
    ///        AnchorTerminated ONLY for a chain whose last element is a
    ///        Trusted-List anchor by construction. The revocation gate exempts
    ///        the chain's tail on this assertion -- a wrong claim reopens a
    ///        fail-open.
    virtual void setResolvedChain(std::vector<std::vector<std::uint8_t>> chain, ChainTermination termination) = 0;

    /// @brief The termination asserted by the last @ref setResolvedChain, or
    ///        Unterminated while the key's own chain is in use.
    [[nodiscard]] virtual ChainTermination chainTermination() const = 0;

protected:
    SigningKey() = default;
    SigningKey(const SigningKey&) = default;
    SigningKey& operator=(const SigningKey&) = default;
};

} // namespace libresign
