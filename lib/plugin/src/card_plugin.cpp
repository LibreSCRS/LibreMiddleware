// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Out-of-line definitions for the non-virtual base
///        @ref LibreSCRS::Plugin::CardPlugin::canHandle (NVI over
///        @ref LibreSCRS::Plugin::CardPlugin::supportedAtrs), the
///        @c setTrustStore funnel, and the card-operation wrappers that
///        observe cancellation and keep a plugin's exception from reaching
///        the host.
///
/// Lives alongside @c card_plugin_key_function.cpp in the @c CardPlugin_Impl
/// translation unit so consumers of the registry get the symbol "for free"
/// — no separate library link required. Per Meyers, *Effective C++* 3e
/// Item 39 (NVI), the public non-virtual @c canHandle calls the protected
/// virtual @c supportedAtrs so the matching policy is centralised here and
/// derived plugins never re-implement the byte loop.

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Logging.h>
#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SecureChannel/ChannelErrors.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS_internal/Plugin/PreReadAuthDerivation.h>

#include <atomic>
#include <exception>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace LibreSCRS::Plugin {

namespace {

// Called from inside a catch handler. The report allocates and runs the
// host's sink, either of which can throw, and nothing may leave a wrapper
// whose whole purpose is that nothing leaves it.
void reportContainedThrow(const CardPlugin& plugin, std::string_view entry) noexcept
{
    try {
        try {
            throw;
        } catch (const std::exception& e) {
            log::errorf("{}: plugin '{}' failed: {}", entry, plugin.pluginId(), e.what());
        } catch (...) {
            log::errorf("{}: plugin '{}' failed with a non-standard exception", entry, plugin.pluginId());
        }
    } catch (...) {
        // Nothing left to report through.
    }
}

// The one exception policy for the card-operation entry points: the
// override's throw becomes the failure its result type already has. @p fail
// builds that failure; it runs after the report, outside any handler.
template <class Op, class Fail>
auto contained(const CardPlugin& plugin, std::string_view entry, Op&& op, Fail&& fail) -> decltype(op())
{
    try {
        return op();
    } catch (...) {
        reportContainedThrow(plugin, entry);
    }
    return fail();
}

PINResult pinPluginError() noexcept
{
    PINResult r;
    r.outcome = PINResultOutcome::PluginError;
    return r;
}

} // namespace

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
    return contained(
        *this, "readCard",
        [&]() -> ReadResult {
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
        },
        [] {
            return ReadResult::communicationError(Auth::ErrorKeys::genericComm(),
                                                  std::string{"the card plugin failed while reading"});
        });
}

std::vector<CertificateData> CardPlugin::readCertificates(SmartCard::CardSession& session) const
{
    return contained(
        *this, "readCertificates", [&] { return doReadCertificates(session); },
        [] { return std::vector<CertificateData>{}; });
}

std::vector<PinStatusEntry> CardPlugin::getPINList(SmartCard::CardSession& session) const
{
    return contained(
        *this, "getPINList", [&] { return doGetPINList(session); }, [] { return std::vector<PinStatusEntry>{}; });
}

PINResult CardPlugin::changePIN(SmartCard::CardSession& session, std::string_view pinLabel,
                                const Secure::String& oldPin, const Secure::String& newPin) const
{
    return contained(
        *this, "changePIN", [&] { return doChangePIN(session, pinLabel, oldPin, newPin); }, pinPluginError);
}

SignResult CardPlugin::sign(SmartCard::CardSession& session, std::uint16_t keyReference,
                            std::span<const std::uint8_t> data, SignMechanism mechanism, CancelToken token) const
{
    if (token.isCancelled()) {
        return SignResult::cancelled();
    }
    return contained(
        *this, "sign", [&] { return doSign(session, keyReference, data, mechanism); },
        [] {
            SignResult r;
            r.outcome = SignResultOutcome::PluginError;
            return r;
        });
}

DecipherResult CardPlugin::decipher(SmartCard::CardSession& session, std::uint16_t keyReference,
                                    std::span<const std::uint8_t> ciphertext, DecipherMechanism mechanism,
                                    CancelToken token) const
{
    if (token.isCancelled()) {
        return DecipherResult::cancelled();
    }
    return contained(
        *this, "decipher", [&] { return doDecipher(session, keyReference, ciphertext, mechanism); },
        [] {
            DecipherResult r;
            r.outcome = DecipherResultOutcome::PluginError;
            return r;
        });
}

PINResult CardPlugin::activateTransportPin(SmartCard::CardSession& session, std::string_view pinLabel,
                                           const Secure::String& transportValue, const Secure::String& newPin) const
{
    return contained(
        *this, "activateTransportPin",
        [&] { return doActivateTransportPin(session, pinLabel, transportValue, newPin); }, pinPluginError);
}

PINResult CardPlugin::activateSigningKey(SmartCard::CardSession& session, const Secure::String& signPin) const
{
    return contained(
        *this, "activateSigningKey", [&] { return doActivateSigningKey(session, signPin); }, pinPluginError);
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

void CardPlugin::setCscaAnchorDirectory(std::filesystem::path dir)
{
    std::lock_guard lock(cscaAnchorDirectoryMtx);
    // Single-shot: the first publication wins. A later caller is not an
    // error and is not reported as one -- a host that publishes twice has
    // done nothing wrong -- but it cannot re-point a plugin that is already
    // answering documents against a directory somebody vouched for.
    if (cscaAnchorDirectoryPublished)
        return;
    cscaAnchorDirectoryPublished = true;
    cscaAnchorDirectoryValue = std::move(dir);
}

std::filesystem::path CardPlugin::cscaAnchorDirectory() const
{
    std::lock_guard lock(cscaAnchorDirectoryMtx);
    // By value, under the lock. A reference would hand a caller a path a
    // concurrent first publication is assigning to.
    return cscaAnchorDirectoryValue;
}

} // namespace LibreSCRS::Plugin
