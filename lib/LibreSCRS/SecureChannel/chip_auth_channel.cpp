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

std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError>
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
                           LibreSCRS::CancelToken token)
{
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
        } else if (ca.transportError) {
            err.kind = chipAuthKindFor(*ca.transportError);
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

    auto channel = std::make_unique<ChipAuthChannel>(connection, current.currentApplet(), std::move(keys));
    channel->caProtocolOid = ca.protocol;

    // Proof exchange: the first wrapped command either carries a valid MAC
    // or it does not. Only a channel that survives this is handed back, so
    // a downstream PASSED verdict is never taken on faith.
    const auto proof = confirmSmAfterKeyChange(*channel, aid, token);
    using Outcome = SmKeyProof::Outcome;
    switch (proof.outcome) {
    case Outcome::Proven:
        break;
    case Outcome::NotProven:
        return std::unexpected{ChipAuthEstablishError{ChipAuthEstablishError::Kind::SmProofFailed, ca.protocol,
                                                      "secure-messaging proof exchange failed"}};
    case Outcome::Cancelled:
        return std::unexpected{ChipAuthEstablishError{ChipAuthEstablishError::Kind::Cancelled, ca.protocol,
                                                      "cancelled during chip authentication"}};
    case Outcome::ReaderError:
        return std::unexpected{proofReaderFailure(proof, ca.protocol)};
    }
    if (proof.appletSelected) {
        LibreSCRS::SecureChannel::detail::ChannelStateMutator::setCurrentApplet(*channel, aid);
    }
    return channel;
}

SmKeyProof confirmSmAfterKeyChange(ISecureChannel& ch, const LibreSCRS::SmartCard::AppletAid& aid,
                                   LibreSCRS::CancelToken token)
{
    // P2=0x0C: no FCI payload — the round-trip itself is the proof. The
    // verdict comes from the value alone: the channel's state is not read.
    using Kind = LibreSCRS::SmartCard::TransportError::Kind;
    auto resp = ch.transmit(LibreSCRS::SmartCard::Internal::selectByAID(aid.asVector(), 0x0C), token);
    SmKeyProof proof;
    if (!resp) {
        if (resp.error().kind == Kind::Cancelled) {
            proof.outcome = SmKeyProof::Outcome::Cancelled;
        } else if (resp.error().kind == Kind::IntegrityFailure) {
            proof.outcome = SmKeyProof::Outcome::NotProven;
        } else {
            proof.outcome = SmKeyProof::Outcome::ReaderError;
            proof.error = std::move(resp.error());
        }
    } else if (resp->sw1 == 0x69 && (resp->sw2 == 0x87 || resp->sw2 == 0x88)) {
        // A card-side SM abort: the card does not hold the keys.
        proof.outcome = SmKeyProof::Outcome::NotProven;
    } else {
        proof.outcome = SmKeyProof::Outcome::Proven;
        proof.appletSelected = resp->isSuccess();
    }
    // A failure seen while the caller was aborting says nothing about the chip.
    if (proof.outcome != SmKeyProof::Outcome::Proven && token.isCancellable() && token.isCancelled()) {
        proof.outcome = SmKeyProof::Outcome::Cancelled;
        proof.error.reset();
    }
    return proof;
}

ChipAuthEstablishError proofReaderFailure(const SmKeyProof& proof, std::string protocol)
{
    return ChipAuthEstablishError{chipAuthKindFor(*proof.error), std::move(protocol), proof.error->detail};
}

ChipAuthEstablishError::Kind chipAuthKindFor(const LibreSCRS::SmartCard::TransportError& error) noexcept
{
    using Kind = LibreSCRS::SmartCard::TransportError::Kind;
    switch (error.kind) {
    case Kind::Cancelled:
        return ChipAuthEstablishError::Kind::Cancelled;
    case Kind::IntegrityFailure:
        return ChipAuthEstablishError::Kind::SmProofFailed;
    case Kind::ChannelUnusable:
    case Kind::SecureChannelActive:
    case Kind::InvalidCommand:
        // CA builds its own APDUs and never uses the raw path, so these mean
        // this side broke, not the reader.
        return ChipAuthEstablishError::Kind::LocalCryptoFailure;
    case Kind::ReaderUnavailable:
    case Kind::NoCardPresent:
    case Kind::CardReset:
    case Kind::ProtocolError:
    case Kind::SessionRefused:
        break;
    }
    return ChipAuthEstablishError::Kind::ReaderError;
}

} // namespace LibreSCRS::SecureChannel
