// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS_internal/SecureChannel/PaceChannel.h>

#include "sm_channel_impl.h"

#include "pace.h"
#include "secure_messaging.h"

#include <LibreSCRS/Secure/Buffer.h>

#include <openssl/crypto.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace LibreSCRS::SecureChannel {

PaceChannel::PaceChannel(LibreSCRS::SmartCard::IConnection& connection,
                         LibreSCRS::SmartCard::AppletAid currentAppletAid, SessionKeys keys)
    : pImpl(std::make_unique<detail::PaceChannelImpl>(connection, std::move(currentAppletAid), std::move(keys)))
{}

PaceChannel::~PaceChannel() = default;

const LibreSCRS::SmartCard::AppletAid& PaceChannel::currentApplet() const noexcept
{
    return pImpl->currentApplet();
}

ChannelState PaceChannel::state() const noexcept
{
    return pImpl->state();
}

LibreSCRS::SmartCard::Internal::APDUResponse
PaceChannel::transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    return pImpl->transmit(cmd, std::move(token));
}

void PaceChannel::close()
{
    pImpl->close();
}

void PaceChannel::setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept
{
    pImpl->setCurrentApplet(std::move(aid));
}

void PaceChannel::replaceKeys(SessionKeys keys) noexcept
{
    pImpl->replaceKeys(std::move(keys));
}

namespace {

// Map an emrtd::crypto PACE OID to the SmCipher carried by the public
// SessionKeys wrapper. emrtd::crypto::paceOIDToSMAlgorithm yields DES3 or
// AES; the public surface mirrors the same two-value enum.
SmCipher cipherForPaceOid(const std::string& oid) noexcept
{
    return emrtd::crypto::paceOIDToSMAlgorithm(oid) == emrtd::crypto::SMAlgorithm::DES3 ? SmCipher::Des3
                                                                                        : SmCipher::Aes;
}

emrtd::crypto::PACEPasswordType toCryptoPwType(LibreSCRS::Auth::PaceSecretKind t) noexcept
{
    switch (t) {
    case LibreSCRS::Auth::PaceSecretKind::Mrz:
        return emrtd::crypto::PACEPasswordType::MRZ;
    case LibreSCRS::Auth::PaceSecretKind::Can:
        return emrtd::crypto::PACEPasswordType::CAN;
    case LibreSCRS::Auth::PaceSecretKind::Pin:
        return emrtd::crypto::PACEPasswordType::PIN;
    case LibreSCRS::Auth::PaceSecretKind::Puk:
        return emrtd::crypto::PACEPasswordType::PUK;
    }
    return emrtd::crypto::PACEPasswordType::CAN;
}

} // namespace

std::expected<std::unique_ptr<PaceChannel>, ChannelActivationError>
PaceChannel::establish(LibreSCRS::SmartCard::IConnection& connection, const PaceParams& params,
                       LibreSCRS::CancelToken token) noexcept
{
    try {
        if (token.isCancellable() && token.isCancelled()) {
            return std::unexpected{ChannelActivationError::Cancelled};
        }

        auto view = params.password.view();
        emrtd::crypto::PACEParams cryptoParams;
        cryptoParams.oid = params.oid;
        cryptoParams.passwordType = toCryptoPwType(params.passwordType);
        cryptoParams.password.assign(view.begin(), view.end());
        cryptoParams.paramId = static_cast<int>(params.paramId);

        std::expected<emrtd::crypto::SessionKeys, emrtd::crypto::PaceFailure> derived =
            std::unexpected{emrtd::crypto::PaceFailure::Failed};
        try {
            derived = emrtd::crypto::performPACE(connection, cryptoParams);
        } catch (...) {
            // Cleanse the local password copy before propagating the
            // failure.
            if (!cryptoParams.password.empty()) {
                OPENSSL_cleanse(cryptoParams.password.data(), cryptoParams.password.size());
            }
            return std::unexpected{ChannelActivationError::PaceProtocolFailure};
        }

        if (!cryptoParams.password.empty()) {
            OPENSSL_cleanse(cryptoParams.password.data(), cryptoParams.password.size());
        }

        if (!derived.has_value()) {
            // The card refusing MSE:Set AT is about this OID, not the
            // secret: PaceUnsupported, and the caller may try the next OID
            // the card lists. Every later failure maps to PaceWrongSecret,
            // which the retry contract answers by evicting the cached
            // secret and prompting again; the card's General Authenticate
            // answers do not tell a wrong secret from other refusals.
            if (derived.error() == emrtd::crypto::PaceFailure::MechanismRefused)
                return std::unexpected{ChannelActivationError::PaceUnsupported};
            return std::unexpected{ChannelActivationError::PaceWrongSecret};
        }

        SessionKeys publicKeys;
        // Buffer adopts a copy of the bytes through its cleansing
        // allocator. The source emrtd::crypto::SessionKeys vectors are
        // cleansed in turn by their own destructor when `derived` drops
        // at end-of-scope; the two cleansing contracts cover the move
        // boundary symmetrically.
        publicKeys.encKey = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{derived->encKey}};
        publicKeys.macKey = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{derived->macKey}};
        publicKeys.ssc = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{derived->ssc}};
        publicKeys.cipher = cipherForPaceOid(params.oid);

        // PACE is session-scoped, not applet-scoped: the channel emerges
        // with an empty currentApplet. The caller
        // (CardSession::activateChannelWithSm) issues a wrapped SELECT
        // through the channel and updates the AID via setCurrentApplet.
        return std::make_unique<PaceChannel>(connection, LibreSCRS::SmartCard::AppletAid{}, std::move(publicKeys));
    } catch (...) {
        // Honour the `noexcept` contract (API-POLICY §5.1 noexcept-alloc
        // rule): translate any escaping allocation failure into the
        // Internal category rather than std::terminate.
        return std::unexpected{ChannelActivationError::Internal};
    }
}

} // namespace LibreSCRS::SecureChannel
