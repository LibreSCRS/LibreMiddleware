// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "signing_key.h"

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Plugin {
class CardPlugin;
}

namespace LibreSCRS::SmartCard {
class CardSession;
}

namespace libresign {

/// @brief A SigningKey that signs through the card plugin on a session the
///        host already holds for the reader: no PKCS#11 module, no second
///        connection to the card.
///
/// The PIN is presented the way the agent's raw-crypto path presents it: it is
/// deposited with the plugin (`setCredentials("pin")`) just before the plugin's
/// own sign, which verifies it and signs in one card transaction, and it is
/// erased again on every way out for a key the card protects per operation
/// (@c CertificateData::alwaysAuthenticate). An ordinary key keeps it deposited
/// after a successful signature only. The PIN is never presented twice for one
/// signature, and nothing is retried after a cancel or after the session to the
/// card was lost: the error goes to the caller, and the next operation starts
/// afresh.
///
/// A refused PIN is thrown as SignFailureException with
/// @ref SignFailureKind::PinFailed, a blocked one with
/// @ref SignFailureKind::PinBlocked, a cancel with
/// @ref SignFailureKind::UserCancelled, and any other failure of the plugin with
/// @ref SignFailureKind::CardError.
///
/// Not thread-safe: one signature at a time, as a document signature is made.
class PluginSigningKey final : public SigningKey
{
public:
    /// @param plugin         the plugin that claimed the card for @p session.
    /// @param session        the session the host holds for the reader.
    /// @param cert           the signer's candidate: its certificate, the plugin's
    ///                       key handle (@c keyFID) and the card's PIN rule.
    /// @param pin            the signing PIN; copied, never empty.
    /// @param candidateChain every certificate the candidates exposed (DER).
    /// @param keyId          the request's CKA_ID selector, empty when none; it
    ///                       must name @p cert's key.
    /// @param token          observed before each signature and by the plugin.
    /// @throws std::invalid_argument before any card call for an empty PIN, a
    ///         candidate without a key handle, a @p keyId longer than a PKCS#15
    ///         identifier (255 bytes) or one that names another key.
    PluginSigningKey(std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> plugin,
                     std::shared_ptr<LibreSCRS::SmartCard::CardSession> session,
                     LibreSCRS::Plugin::CertificateData cert, const LibreSCRS::Secure::Buffer& pin,
                     std::vector<std::vector<std::uint8_t>> candidateChain, std::span<const std::uint8_t> keyId,
                     LibreSCRS::CancelToken token);

    PluginSigningKey(const PluginSigningKey&) = delete;
    PluginSigningKey& operator=(const PluginSigningKey&) = delete;

    /// @p algorithm names the mechanism: "SHA{1,256,384,512}withRSA" or
    /// "RS{256,384,512}" sign the raw message in @p rawData when the plugin
    /// signs that hash, and the DigestInfo in @p hash (RSA_PKCS) when it does
    /// not -- or when @p rawData is empty; "SHA{256,384,512}withECDSA" or
    /// "ES{256,384,512}" sign @p hash. Anything else throws
    /// std::invalid_argument before any card call.
    std::vector<std::uint8_t> sign(std::span<const std::uint8_t> hash, const std::string& algorithm,
                                   std::span<const std::uint8_t> rawData) override;
    std::vector<std::uint8_t> certificate() const override;
    std::vector<std::vector<std::uint8_t>> certificateChain() const override;
    void setResolvedChain(std::vector<std::vector<std::uint8_t>> chain, ChainTermination termination) override;
    [[nodiscard]] ChainTermination chainTermination() const override;

    /// PKCS#15 bounds an object identifier at 255 bytes (pkcs15-ub-identifier).
    static constexpr std::size_t kMaxKeyIdLength = 255;

private:
    std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> plugin;
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
    LibreSCRS::Plugin::CertificateData cert;
    LibreSCRS::Secure::String pin;
    std::vector<std::vector<std::uint8_t>> candidateChain;
    std::vector<std::vector<std::uint8_t>> resolvedChain;
    ChainTermination termination = ChainTermination::Unterminated;
    LibreSCRS::CancelToken token;
};

} // namespace libresign
