// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SecureChannel/BacChannel.h>

#include "sm_channel_impl.h"

#include "bac.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/secure_buffer.h"

#include <string>
#include <utility>

namespace LibreSCRS::SecureChannel {

BacChannel::BacChannel(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid currentAppletAid,
                       SessionKeys keys)
    : pImpl(std::make_unique<detail::BacChannelImpl>(connection, std::move(currentAppletAid), std::move(keys)))
{}

BacChannel::~BacChannel() = default;

const LibreSCRS::SmartCard::AppletAid& BacChannel::currentApplet() const noexcept
{
    return pImpl->currentApplet();
}

ChannelState BacChannel::state() const noexcept
{
    return pImpl->state();
}

LibreSCRS::SmartCard::Internal::APDUResponse
BacChannel::transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    return pImpl->transmit(cmd, std::move(token));
}

void BacChannel::close()
{
    pImpl->close();
}

void BacChannel::replaceKeys(SessionKeys keys) noexcept
{
    pImpl->replaceKeys(std::move(keys));
}

BacChannel::HandshakeResult BacChannel::establish(LibreSCRS::SmartCard::IConnection& connection,
                                                  LibreSCRS::SmartCard::AppletAid appletAid, const BacInput& input,
                                                  LibreSCRS::CancelToken token)
{
    HandshakeResult out;

    if (token.isCancellable() && token.isCancelled()) {
        out.error = ChannelActivationError::Cancelled;
        return out;
    }

    auto* pcsc = dynamic_cast<LibreSCRS::SmartCard::Internal::PCSCConnection*>(&connection);
    if (pcsc == nullptr) {
        out.error = ChannelActivationError::Internal;
        return out;
    }

    std::optional<emrtd::crypto::SessionKeys> derived;
    try {
        // emrtd::crypto::deriveBACKeys takes const std::string& — materialise
        // scrubbed scratch copies from the Secure::String fields and cleanse
        // them on scope exit via PinStringScrubber so the MRZ bytes do not
        // outlive this call frame.
        std::string docNoScratch{input.documentNumber.view()};
        std::string dobScratch{input.dateOfBirth.view()};
        std::string doeScratch{input.dateOfExpiry.view()};
        LibreSCRS::SmartCard::Internal::PinStringScrubber scrubDocNo{docNoScratch};
        LibreSCRS::SmartCard::Internal::PinStringScrubber scrubDob{dobScratch};
        LibreSCRS::SmartCard::Internal::PinStringScrubber scrubDoe{doeScratch};
        auto bacKeys = emrtd::crypto::deriveBACKeys(docNoScratch, dobScratch, doeScratch);
        derived = emrtd::crypto::performBAC(*pcsc, bacKeys);
    } catch (...) {
        out.error = ChannelActivationError::PaceProtocolFailure;
        return out;
    }

    if (!derived.has_value()) {
        // BAC mutual-auth failure (wrong MRZ or card-side rejection) maps
        // to PaceWrongSecret per the unified secret-failure category
        // documented in the spec; the enum's "Pace" prefix is a slight
        // misnomer for BAC but the retry semantics are identical (evict
        // cached MRZ + re-prompt).
        out.error = ChannelActivationError::PaceWrongSecret;
        return out;
    }

    SessionKeys publicKeys;
    publicKeys.encKey = std::move(derived->encKey);
    publicKeys.macKey = std::move(derived->macKey);
    publicKeys.ssc = std::move(derived->ssc);
    publicKeys.cipher = SmCipher::Des3;

    out.channel = std::make_unique<BacChannel>(connection, std::move(appletAid), std::move(publicKeys));
    out.error = ChannelActivationError::None;
    return out;
}

} // namespace LibreSCRS::SecureChannel
