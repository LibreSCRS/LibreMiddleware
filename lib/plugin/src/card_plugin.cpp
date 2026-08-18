// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Out-of-line definitions for the non-virtual base
///        @ref LibreSCRS::Plugin::CardPlugin::canHandle (NVI over
///        @ref LibreSCRS::Plugin::CardPlugin::supportedAtrs) and the
///        cancel-aware @c readCard / @c sign / @c setTrustStore funnels.
///
/// Lives alongside @c card_plugin_key_function.cpp in the @c CardPlugin_Impl
/// translation unit so consumers of the registry get the symbol "for free"
/// — no separate library link required. Per Meyers, *Effective C++* 3e
/// Item 39 (NVI), the public non-virtual @c canHandle calls the protected
/// virtual @c supportedAtrs so the matching policy is centralised here and
/// derived plugins never re-implement the byte loop.

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS_internal/Plugin/PreReadAuthDerivation.h>

#include <atomic>
#include <memory>
#include <string>
#include <utility>
#include <variant>

namespace LibreSCRS::Plugin {

bool CardPlugin::canHandle(std::span<const std::uint8_t> atr) const noexcept
{
    for (const auto& entry : supportedAtrs()) {
        if (entry.matches(atr)) {
            return true;
        }
    }
    return false;
}

Auth::PreReadAuthMethod CardPlugin::preReadAuth(SmartCard::CardSession& session) const
{
    // The mapping lives in the shared internal header so report-side
    // overrides (answering from a hypothetical profile) can never diverge
    // from this base derivation on the same profile.
    return detail::preReadAuthForProfile(activationProfile(session));
}

ReadResult CardPlugin::readCard(SmartCard::CardSession& session, GroupCallback onGroup, CancelToken token) const
{
    if (token.isCancelled()) {
        return ReadResult::cancelled();
    }

    const ActivationProfile profile = activationProfile(session);
    if (!profile.requiresActivation()) {
        // Plain channel: no secure-messaging activation; read directly.
        return doReadCard(session, std::move(onGroup));
    }

    // Seed any plugin-retained secrets into the per-session cache before the
    // activation walk resolves credentials, then acquire the channel.
    seedCredentials(session, profile);
    auto holder = acquireChannelForProfile(session, profile, token);
    if (!holder) {
        using E = SecureChannel::ChannelActivationError;
        if (holder.error() == E::UserCancelled || holder.error() == E::Cancelled) {
            return ReadResult::cancelled();
        }
        if (holder.error() == E::PaceUnsupported) {
            // Structural: the document exposes no PACE. Distinct from a
            // wrong-credential rejection so downstream flows stop punishing the
            // credential (they map this to an unsupported-card outcome).
            return ReadResult::authenticationFailed(Auth::ErrorKeys::paceUnsupported(),
                                                    std::string{"document does not support PACE"});
        }
        if (holder.error() == E::PaceDowngradeDetected) {
            // A detected secure-channel downgrade is an attack signal, not a
            // wrong credential: surface it on the generic (non-auth) failure
            // shape so nothing evicts or marks the credential wrong.
            return ReadResult::communicationError(Auth::ErrorKeys::paceDowngradeDetected(),
                                                  std::string{"secure-channel downgrade detected"});
        }
        return ReadResult::authenticationFailed(Auth::ErrorKeys::authFailed(),
                                                std::string{"channel activation failed"});
    }

    // `holder` is a named local that lives to function end, so the active
    // secure channel stays open for the whole read; doReadCard transmits over
    // the live channel and must never re-activate.
    return doReadCard(session, std::move(onGroup));
}

SignResult CardPlugin::sign(SmartCard::CardSession& session, std::uint16_t keyReference,
                            std::span<const std::uint8_t> data, SignMechanism mechanism, CancelToken token) const
{
    if (token.isCancelled()) {
        return SignResult::cancelled();
    }
    return doSign(session, keyReference, data, mechanism);
}

DecipherResult CardPlugin::decipher(SmartCard::CardSession& session, std::uint16_t keyReference,
                                    std::span<const std::uint8_t> ciphertext, DecipherMechanism mechanism,
                                    CancelToken token) const
{
    if (token.isCancelled()) {
        return DecipherResult::cancelled();
    }
    return doDecipher(session, keyReference, ciphertext, mechanism);
}

void CardPlugin::setTrustStore(std::shared_ptr<const LibreSCRS::Trust::TrustStore> trustStore) noexcept
{
    // Single-shot: test_and_set returns the prior flag value. First
    // caller observes false (publish path runs), every later caller
    // observes true (no-op). std::memory_order_acq_rel pairs an
    // acquire on this read with a release on doSetTrustStore's writes
    // becoming visible to subsequent threads.
    if (trustStoreInjectedFlag.test_and_set(std::memory_order_acq_rel))
        return;
    doSetTrustStore(std::move(trustStore));
}

} // namespace LibreSCRS::Plugin
