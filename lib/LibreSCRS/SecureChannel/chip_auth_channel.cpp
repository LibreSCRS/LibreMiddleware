// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS_internal/SecureChannel/ChipAuthChannel.h>

#include "sm_channel_impl.h"

#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS_internal/SecureChannel/detail/ChannelStateMutator.h>

#include "apdu.h"
#include "chip_auth.h"

#include <span>
#include <utility>

namespace LibreSCRS::SecureChannel {

ChipAuthChannel::ChipAuthChannel(LibreSCRS::SmartCard::IConnection& connection,
                                 LibreSCRS::SmartCard::AppletAid currentAppletAid, SessionKeys keys)
    : pImpl(std::make_unique<detail::ChipAuthChannelImpl>(connection, std::move(currentAppletAid), std::move(keys)))
{}

ChipAuthChannel::~ChipAuthChannel() = default;

const LibreSCRS::SmartCard::AppletAid& ChipAuthChannel::currentApplet() const noexcept
{
    return pImpl->currentApplet();
}

ChannelState ChipAuthChannel::state() const noexcept
{
    return pImpl->state();
}

LibreSCRS::SmartCard::Internal::APDUResponse
ChipAuthChannel::transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    return pImpl->transmit(cmd, std::move(token));
}

void ChipAuthChannel::close()
{
    pImpl->close();
}

void ChipAuthChannel::setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept
{
    pImpl->setCurrentApplet(std::move(aid));
}

void ChipAuthChannel::replaceKeys(SessionKeys keys) noexcept
{
    pImpl->replaceKeys(std::move(keys));
}

std::expected<std::unique_ptr<ChipAuthChannel>, ChipAuthEstablishError>
ChipAuthChannel::establish(LibreSCRS::SmartCard::IConnection& connection, ISecureChannel& current,
                           const std::vector<std::uint8_t>& dg14Raw, LibreSCRS::SmartCard::AppletAid aid,
                           LibreSCRS::CancelToken token) noexcept
{
    try {
        if (token.isCancellable() && token.isCancelled()) {
            return std::unexpected{ChipAuthEstablishError{
                ChipAuthEstablishError::Kind::Cancelled, {}, "cancelled before chip authentication"}};
        }

        // Run the CA key agreement (MSE:Set AT + GENERAL AUTHENTICATE + ECDH +
        // KDF) over the current channel — plain on a contact read, wrapped when
        // an SM tunnel already exists.
        const auto ca = emrtd::crypto::performChipAuth(current, dg14Raw, token);
        if (ca.chipAuthentication != emrtd::crypto::ChipAuthResult::PASSED || !ca.newSessionKeys.has_value()) {
            ChipAuthEstablishError err;
            err.protocol = ca.protocol;
            err.detail = ca.errorDetail;
            // Cancellation outranks every chip-side classification: a failure
            // observed while the caller was aborting says nothing about the
            // chip, so it must not surface as any genuineness verdict.
            if (token.isCancellable() && token.isCancelled()) {
                err.kind = ChipAuthEstablishError::Kind::Cancelled;
            } else if (ca.chipAuthentication == emrtd::crypto::ChipAuthResult::NOT_SUPPORTED) {
                err.kind = ChipAuthEstablishError::Kind::NotSupported;
            } else if (ca.chipRefusedProtocol) {
                err.kind = ChipAuthEstablishError::Kind::ProtocolRefused;
            } else {
                err.kind = ChipAuthEstablishError::Kind::LocalCryptoFailure;
            }
            return std::unexpected{std::move(err)};
        }

        // The card has switched to CA-derived SM after GENERAL AUTHENTICATE.
        // Build the matching host-side channel from the derived keys.
        SessionKeys keys;
        keys.encKey = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{ca.newSessionKeys->encKey}};
        keys.macKey = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{ca.newSessionKeys->macKey}};
        keys.ssc = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{ca.newSessionKeys->ssc}};
        keys.cipher = (ca.newAlgorithm == emrtd::crypto::SMAlgorithm::DES3) ? SmCipher::Des3 : SmCipher::Aes;

        auto channel = std::make_unique<ChipAuthChannel>(connection, aid, std::move(keys));
        channel->caProtocolOid = ca.protocol;

        // Proof exchange: the first wrapped command either carries a valid MAC
        // or it does not. Only a channel that survives this is handed back, so
        // a downstream PASSED verdict is never taken on faith.
        if (!confirmSmAfterKeyChange(*channel, aid, token)) {
            // A cancel that lands inside the proof exchange is not the clone
            // signal — the exchange was aborted, not answered wrongly.
            if (token.isCancellable() && token.isCancelled()) {
                return std::unexpected{ChipAuthEstablishError{ChipAuthEstablishError::Kind::Cancelled, ca.protocol,
                                                              "cancelled during chip authentication"}};
            }
            return std::unexpected{ChipAuthEstablishError{ChipAuthEstablishError::Kind::SmProofFailed, ca.protocol,
                                                          "secure-messaging proof exchange failed"}};
        }
        LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*channel, aid);
        return channel;
    } catch (...) {
        return std::unexpected{ChipAuthEstablishError{
            ChipAuthEstablishError::Kind::LocalCryptoFailure, {}, "unexpected error during chip authentication"}};
    }
}

bool confirmSmAfterKeyChange(ISecureChannel& ch, const LibreSCRS::SmartCard::AppletAid& aid,
                             LibreSCRS::CancelToken token) noexcept
{
    try {
        // P2=0x0C: no FCI payload — the round-trip itself is the proof.
        auto resp = ch.transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid.asVector(), 0x0C), std::move(token));
        return resp.isSuccess();
    } catch (...) {
        return false;
    }
}

} // namespace LibreSCRS::SecureChannel
