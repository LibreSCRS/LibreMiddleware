// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/plugin_signing_key.h"

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <algorithm>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace libresign {

namespace {

using LibreSCRS::Plugin::SignMechanism;
using LibreSCRS::Plugin::SignResultOutcome;

struct RequestedMechanism
{
    SignMechanism mechanism;      ///< what the plugin is asked first
    bool takesTheMessage = false; ///< `mechanism` signs the raw message, not @p hash
};

// The mechanism an algorithm name asks for; the RSA names ask for the one that
// signs the raw message, which falls back to RSA_PKCS over the DigestInfo.
std::optional<RequestedMechanism> requestedMechanismFor(std::string_view algorithm)
{
    static constexpr std::pair<std::string_view, SignMechanism> kRsa[] = {
        {"SHA1withRSA", SignMechanism::RSA_SHA1}, {"SHA256withRSA", SignMechanism::RSA_SHA256},
        {"RS256", SignMechanism::RSA_SHA256},     {"SHA384withRSA", SignMechanism::RSA_SHA384},
        {"RS384", SignMechanism::RSA_SHA384},     {"SHA512withRSA", SignMechanism::RSA_SHA512},
        {"RS512", SignMechanism::RSA_SHA512},
    };
    static constexpr std::pair<std::string_view, SignMechanism> kEcdsa[] = {
        {"SHA256withECDSA", SignMechanism::ECDSA_SHA256}, {"ES256", SignMechanism::ECDSA_SHA256},
        {"SHA384withECDSA", SignMechanism::ECDSA_SHA384}, {"ES384", SignMechanism::ECDSA_SHA384},
        {"SHA512withECDSA", SignMechanism::ECDSA_SHA512}, {"ES512", SignMechanism::ECDSA_SHA512},
    };
    for (const auto& [name, mechanism] : kRsa) {
        if (algorithm == name)
            return RequestedMechanism{mechanism, true};
    }
    for (const auto& [name, mechanism] : kEcdsa) {
        if (algorithm == name)
            return RequestedMechanism{mechanism, false};
    }
    return std::nullopt;
}

// Erases the deposited PIN on the way out unless keep() was called: the PIN
// of a per-operation key never outlives its signature, and an ordinary key's
// only outlives a successful one. Armed before the deposit, so a deposit that
// throws half-way is erased as well.
class PinDepositEraser
{
public:
    PinDepositEraser(LibreSCRS::Plugin::CardPlugin& plugin, LibreSCRS::SmartCard::CardSession& session) noexcept
        : plugin(&plugin), session(session)
    {}
    ~PinDepositEraser()
    {
        if (plugin == nullptr)
            return;
        try {
            plugin->setCredentials(session, "pin", LibreSCRS::Secure::String{});
        } catch (...) {
            // Destructor: an erase that fails leaves the plugin's own session
            // teardown to forget the PIN.
        }
    }
    void keep() noexcept
    {
        plugin = nullptr;
    }
    PinDepositEraser(const PinDepositEraser&) = delete;
    PinDepositEraser& operator=(const PinDepositEraser&) = delete;

private:
    LibreSCRS::Plugin::CardPlugin* plugin;
    LibreSCRS::SmartCard::CardSession& session;
};

[[noreturn]] void throwFor(SignResultOutcome outcome)
{
    switch (outcome) {
    case SignResultOutcome::PinIncorrect:
        throw SignFailureException(SignFailureKind::PinFailed, "the card refused the PIN");
    case SignResultOutcome::PinBlocked:
        throw SignFailureException(SignFailureKind::PinBlocked, "the card reports the PIN blocked");
    case SignResultOutcome::Cancelled:
        throw SignFailureException(SignFailureKind::UserCancelled, "the signature was cancelled");
    default:
        throw SignFailureException(SignFailureKind::CardError, "the card plugin did not sign (outcome " +
                                                                   std::to_string(static_cast<int>(outcome)) + ")");
    }
}

} // namespace

PluginSigningKey::PluginSigningKey(std::shared_ptr<const LibreSCRS::Plugin::CardPlugin> plugin,
                                   std::shared_ptr<LibreSCRS::SmartCard::CardSession> session,
                                   LibreSCRS::Plugin::CertificateData cert, const LibreSCRS::Secure::Buffer& pin,
                                   std::vector<std::vector<std::uint8_t>> candidateChain,
                                   std::span<const std::uint8_t> keyId, LibreSCRS::CancelToken token)
    : plugin(std::move(plugin)), session(std::move(session)), cert(std::move(cert)),
      pin(std::string_view{reinterpret_cast<const char*>(pin.data()), pin.size()}),
      candidateChain(std::move(candidateChain)), token(std::move(token))
{
    if (!this->plugin || !this->session)
        throw std::invalid_argument("PluginSigningKey: no plugin or no session");
    // An empty "pin" deposit erases the deposit: the card would then sign on
    // whatever the held session is already verified for.
    if (pin.size() == 0)
        throw std::invalid_argument("PluginSigningKey: an empty PIN is never deposited");
    if (!this->cert.keyFID)
        throw std::invalid_argument("PluginSigningKey: the candidate carries no key handle");
    if (keyId.size() > kMaxKeyIdLength)
        throw std::invalid_argument("PluginSigningKey: the key id is longer than a PKCS#15 identifier");
    if (!keyId.empty() && !std::ranges::equal(keyId, this->cert.ckaId))
        throw std::invalid_argument("PluginSigningKey: the key id names another key than the candidate's");
}

std::vector<std::uint8_t> PluginSigningKey::sign(std::span<const std::uint8_t> hash, const std::string& algorithm,
                                                 std::span<const std::uint8_t> rawData)
{
    const auto requested = requestedMechanismFor(algorithm);
    if (!requested)
        throw std::invalid_argument("PluginSigningKey: no card plugin mechanism for \"" + algorithm + "\"");
    if (token.isCancelled())
        throw SignFailureException(SignFailureKind::UserCancelled, "the signature was cancelled");

    // Without the raw message an RSA name can only be signed over the DigestInfo.
    const bool messageFirst = requested->takesTheMessage && !rawData.empty();
    const SignMechanism first =
        requested->takesTheMessage && !messageFirst ? SignMechanism::RSA_PKCS : requested->mechanism;

    // setCredentials is non-const while the plugin's crypto entry points are
    // const, so the routing holds the plugin as const; a per-session credential
    // is kept in the plugin's session-keyed, mutex-guarded storage, which makes
    // the deposit a logically const call on a plugin object that is not const.
    auto& depositTo = const_cast<LibreSCRS::Plugin::CardPlugin&>(*plugin);
    PinDepositEraser eraser{depositTo, *session};
    depositTo.setCredentials(*session, "pin", pin);

    // A transport failure or a lost session throws out of here, the PIN is
    // erased, and nothing is sent again: the plugin's sign carries the VERIFY.
    auto result = plugin->sign(*session, *cert.keyFID, messageFirst ? rawData : hash, first, token);
    // NotImplemented is the plugin's answer before it touches the card, so the
    // PIN has not been presented: the DigestInfo may be tried. Any other
    // failure may have presented it, and it is never presented twice.
    if (messageFirst && result.outcome == SignResultOutcome::NotImplemented)
        result = plugin->sign(*session, *cert.keyFID, hash, SignMechanism::RSA_PKCS, token);

    if (result.outcome != SignResultOutcome::Ok)
        throwFor(result.outcome);
    if (!cert.alwaysAuthenticate)
        eraser.keep();
    return std::move(result.signature);
}

std::vector<std::uint8_t> PluginSigningKey::certificate() const
{
    return cert.derBytes;
}

std::vector<std::vector<std::uint8_t>> PluginSigningKey::certificateChain() const
{
    return resolvedChain.empty() ? candidateChain : resolvedChain;
}

void PluginSigningKey::setResolvedChain(std::vector<std::vector<std::uint8_t>> chain, ChainTermination termination)
{
    resolvedChain = std::move(chain);
    this->termination = resolvedChain.empty() ? ChainTermination::Unterminated : termination;
}

ChainTermination PluginSigningKey::chainTermination() const
{
    return termination;
}

} // namespace libresign
