// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS_internal/SecureChannel/BacChannel.h>

#include "sm_channel_impl.h"

#include "bac.h"
#include <pcsc_connection.h>
#include "smartcard/secure_buffer.h"

#include <LibreSCRS/Secure/Buffer.h>

#include <cstdint>
#include <span>
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

void BacChannel::setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept
{
    pImpl->setCurrentApplet(std::move(aid));
}

void BacChannel::replaceKeys(SessionKeys keys) noexcept
{
    pImpl->replaceKeys(std::move(keys));
}

std::expected<std::unique_ptr<BacChannel>, ChannelActivationError>
BacChannel::establish(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid appletAid,
                      const BacInput& input, LibreSCRS::CancelToken token) noexcept
{
    try {
        if (token.isCancellable() && token.isCancelled()) {
            return std::unexpected{ChannelActivationError::Cancelled};
        }

        auto* pcsc = dynamic_cast<LibreSCRS::SmartCard::Internal::PCSCConnection*>(&connection);
        if (pcsc == nullptr) {
            return std::unexpected{ChannelActivationError::Internal};
        }

        std::optional<emrtd::crypto::SessionKeys> derived;
        try {
            // emrtd::crypto::deriveBACKeys takes const std::string& —
            // materialise scrubbed scratch copies from the Secure::String
            // fields and cleanse them on scope exit via PinStringScrubber so
            // the MRZ bytes do not outlive this call frame.
            std::string docNoScratch{input.documentNumber.view()};
            std::string dobScratch{input.dateOfBirth.view()};
            std::string doeScratch{input.dateOfExpiry.view()};
            LibreSCRS::SmartCard::Internal::PinStringScrubber scrubDocNo{docNoScratch};
            LibreSCRS::SmartCard::Internal::PinStringScrubber scrubDob{dobScratch};
            LibreSCRS::SmartCard::Internal::PinStringScrubber scrubDoe{doeScratch};
            auto bacKeys = emrtd::crypto::deriveBACKeys(docNoScratch, dobScratch, doeScratch);
            derived = emrtd::crypto::performBAC(*pcsc, bacKeys);
        } catch (...) {
            return std::unexpected{ChannelActivationError::ProtocolFailure};
        }

        if (!derived.has_value()) {
            // BAC mutual-auth failure (wrong MRZ or card-side rejection) maps to
            // the protocol-neutral WrongSecret category — the retry semantics are
            // the same as the PACE path (evict the cached secret + re-prompt).
            return std::unexpected{ChannelActivationError::WrongSecret};
        }

        SessionKeys publicKeys;
        // Buffer copies through its cleansing allocator; the source
        // emrtd::crypto::SessionKeys vectors are cleansed by their own
        // destructor when `derived` drops at end-of-scope.
        publicKeys.encKey = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{derived->encKey}};
        publicKeys.macKey = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{derived->macKey}};
        publicKeys.ssc = LibreSCRS::Secure::Buffer{std::span<const std::uint8_t>{derived->ssc}};
        publicKeys.cipher = SmCipher::Des3;

        return std::make_unique<BacChannel>(connection, std::move(appletAid), std::move(publicKeys));
    } catch (...) {
        // Honour the `noexcept` contract (API-POLICY §5.1 noexcept-alloc
        // rule): translate any escaping allocation failure into the
        // Internal category rather than std::terminate.
        return std::unexpected{ChannelActivationError::Internal};
    }
}

} // namespace LibreSCRS::SecureChannel
