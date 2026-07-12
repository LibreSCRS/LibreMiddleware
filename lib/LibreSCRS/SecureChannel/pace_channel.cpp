// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS_internal/SecureChannel/PaceChannel.h>

#include "sm_channel_impl.h"

#include "pace.h"
#include "secure_messaging.h"
#include <pcsc_connection.h>

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

        // emrtd::crypto::performPACE binds to the concrete PCSCConnection
        // because the underlying handshake issues several plain APDUs
        // through it. IConnection is the seam used by the post-handshake
        // transmit path (FakePCSCConnection), but the handshake itself
        // requires the real transport. A non-PCSCConnection IConnection
        // therefore surfaces as Internal — tests cover this path explicitly.
        auto* pcsc = dynamic_cast<LibreSCRS::SmartCard::Internal::PCSCConnection*>(&connection);
        if (pcsc == nullptr) {
            return std::unexpected{ChannelActivationError::Internal};
        }

        auto view = params.password.view();
        emrtd::crypto::PACEParams cryptoParams;
        cryptoParams.oid = params.oid;
        cryptoParams.passwordType = toCryptoPwType(params.passwordType);
        cryptoParams.password.assign(view.begin(), view.end());
        cryptoParams.paramId = static_cast<int>(params.paramId);

        std::optional<emrtd::crypto::SessionKeys> derived;
        try {
            derived = emrtd::crypto::performPACE(*pcsc, cryptoParams);
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
            // emrtd::crypto::performPACE returns nullopt for any
            // handshake-level failure (wrong CAN/MRZ, unsupported OID,
            // card-side SW != 9000 at any step). Mapping all failures to
            // PaceWrongSecret is consistent with the retry contract: the
            // caller evicts the cached secret and re-prompts.
            // PacePinBlocked / PaceUnsupported are reserved for future
            // protocol-aware paths that can distinguish those categories at
            // the wire level.
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
