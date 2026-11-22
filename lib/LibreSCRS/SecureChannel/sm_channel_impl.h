// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SecureChannel/SessionKeys.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include "apdu.h"
#include <smartcard/i_connection.h>
#include <smartcard/secure_buffer.h>

#include "secure_messaging.h"

#include <expected>
#include <memory>
#include <new>
#include <optional>
#include <utility>

namespace LibreSCRS::SecureChannel::detail {

/// @brief Shared body for PaceChannel and BacChannel; differs only in
///        which SmCipher the SessionKeys block carries.
///
/// The actual SM wrap/unwrap is delegated to
/// @c emrtd::crypto::SecureMessaging, which already implements both 3DES
/// (BAC) and AES-CBC + CMAC (PACE) paths selected at construction by the
/// SMAlgorithm parameter. This shim keeps the public surface stable while
/// the primitive still lives in the eMRTD crypto module, so plugins can
/// migrate without waiting on the physical file relocation.
class SmChannelBody
{
public:
    SmChannelBody(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid aid, SessionKeys keys)
        : connection(connection), appletAid(std::move(aid))
    {
        // Buffer → std::vector copy at the boundary: emrtd::crypto's
        // SessionKeys consumes vectors directly through its own cleansing
        // contract (types.h). Both sides cleanse on destruction, so the
        // bytes never persist uncleansed across the move boundary.
        emrtd::crypto::SessionKeys cryptoKeys;
        cryptoKeys.encKey.assign(keys.encKey.data(), keys.encKey.data() + keys.encKey.size());
        cryptoKeys.macKey.assign(keys.macKey.data(), keys.macKey.data() + keys.macKey.size());
        cryptoKeys.ssc.assign(keys.ssc.data(), keys.ssc.data() + keys.ssc.size());
        auto algo = keys.cipher == SmCipher::Des3 ? emrtd::crypto::SMAlgorithm::DES3 : emrtd::crypto::SMAlgorithm::AES;
        sm = std::make_unique<emrtd::crypto::SecureMessaging>(std::move(cryptoKeys), algo);
    }

    [[nodiscard]] const LibreSCRS::SmartCard::AppletAid& currentApplet() const noexcept
    {
        return appletAid;
    }
    [[nodiscard]] ChannelState state() const noexcept
    {
        return channelState;
    }

    // Update the AID after a successful wrapped SELECT through this channel.
    // PACE/BAC SM is session-scoped; the selected applet is mutable state
    // on the channel that CardSession updates as applets are switched via
    // wrapped SELECT through the live channel.
    void setCurrentApplet(LibreSCRS::SmartCard::AppletAid aid) noexcept
    {
        appletAid = std::move(aid);
    }

    [[nodiscard]] std::expected<LibreSCRS::SmartCard::Internal::APDUResponse, LibreSCRS::SmartCard::TransportError>
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
    {
        using LibreSCRS::SmartCard::TransportError;
        if (channelState != ChannelState::Open) {
            return std::unexpected(TransportError{TransportError::Kind::ChannelUnusable,
                                                  "the secure-messaging channel is closed or has failed"});
        }
        if (token.isCancellable() && token.isCancelled()) {
            return std::unexpected(
                TransportError{TransportError::Kind::Cancelled, "cancelled before the command was sent"});
        }

        // SecureBuffer adoption: the plaintext serialization may carry
        // PIN/PUK bytes (PIN verbs through an SM channel), so it is
        // cleansed on every exit path. `wrapped` is SM ciphertext and
        // needs no cleansing.
        std::vector<std::uint8_t> wrapped;
        try {
            const LibreSCRS::SmartCard::Internal::SecureBuffer plainBytes(cmd.toBytes());
            wrapped = sm->protect(plainBytes);
        } catch (const std::bad_alloc&) {
            throw;
        } catch (...) {
            return fail(TransportError::Kind::ChannelUnusable, "secure messaging could not wrap the command");
        }
        if (wrapped.size() < 5) {
            return fail(TransportError::Kind::ChannelUnusable, "secure messaging produced a command too short");
        }

        // Ship the wrapped bytes verbatim. Round-tripping through an
        // APDUCommand structure here (parse → re-encode in connection.
        // transmit) used to truncate extended-length wrapped APDUs
        // (Case 4 sign with RSA-3072: SM protect emits a 0x00 LcH LcL
        // prefix that the parser misread as Lc=0, dropping the entire
        // encrypted DigestInfo body). transmitRaw goes straight to the
        // wire and bypasses the host-side filter stack.
        auto sent = connection.transmitRaw(wrapped);
        if (!sent) {
            // The card may have processed the command: the send sequence
            // counter is no longer known to be in step.
            channelState = ChannelState::Failed;
            return std::unexpected(std::move(sent.error()));
        }
        const LibreSCRS::SmartCard::Internal::APDUResponse& raw = *sent;

        // Detect external SM invalidation before attempting MAC unwrap: the
        // card's own answer is the value, and the channel is finished.
        if (raw.sw1 == 0x69 && (raw.sw2 == 0x87 || raw.sw2 == 0x88)) {
            channelState = ChannelState::Failed;
            LibreSCRS::SmartCard::Internal::APDUResponse out;
            out.sw1 = raw.sw1;
            out.sw2 = raw.sw2;
            return out;
        }

        std::vector<std::uint8_t> respBytes = raw.data;
        respBytes.push_back(raw.sw1);
        respBytes.push_back(raw.sw2);

        std::optional<emrtd::crypto::UnprotectResult> unwrapped;
        try {
            unwrapped = sm->unprotectWithSW(respBytes);
        } catch (const std::bad_alloc&) {
            throw;
        } catch (...) {
            return fail(TransportError::Kind::ChannelUnusable, "secure messaging could not unwrap the response");
        }
        if (!unwrapped) {
            return fail(TransportError::Kind::IntegrityFailure, "the response failed the secure-messaging check");
        }

        LibreSCRS::SmartCard::Internal::APDUResponse out;
        out.data = std::move(unwrapped->data);
        out.sw1 = unwrapped->sw1;
        out.sw2 = unwrapped->sw2;
        return out;
    }

    void close() noexcept
    {
        sm.reset(); // zeroises keys via SecureMessaging dtor
        channelState = ChannelState::Closed;
    }

    void replaceKeys(SessionKeys keys) noexcept
    try {
        emrtd::crypto::SessionKeys cryptoKeys;
        cryptoKeys.encKey.assign(keys.encKey.data(), keys.encKey.data() + keys.encKey.size());
        cryptoKeys.macKey.assign(keys.macKey.data(), keys.macKey.data() + keys.macKey.size());
        cryptoKeys.ssc.assign(keys.ssc.data(), keys.ssc.data() + keys.ssc.size());
        auto algo = keys.cipher == SmCipher::Des3 ? emrtd::crypto::SMAlgorithm::DES3 : emrtd::crypto::SMAlgorithm::AES;
        // make_unique may throw bad_alloc; the function is declared noexcept
        // so an uncaught throw would call std::terminate. Degrade to Failed
        // state instead and let the next transmit() report ChannelUnusable.
        sm = std::make_unique<emrtd::crypto::SecureMessaging>(std::move(cryptoKeys), algo);
        channelState = ChannelState::Open;
    } catch (...) {
        channelState = ChannelState::Failed;
    }

private:
    std::unexpected<LibreSCRS::SmartCard::TransportError> fail(LibreSCRS::SmartCard::TransportError::Kind kind,
                                                               const char* detail)
    {
        channelState = ChannelState::Failed;
        return std::unexpected(LibreSCRS::SmartCard::TransportError{kind, detail});
    }

    LibreSCRS::SmartCard::IConnection& connection;
    LibreSCRS::SmartCard::AppletAid appletAid;
    std::unique_ptr<emrtd::crypto::SecureMessaging> sm;
    ChannelState channelState = ChannelState::Open;
};

class PaceChannelImpl : public SmChannelBody
{
public:
    using SmChannelBody::SmChannelBody;
};

class BacChannelImpl : public SmChannelBody
{
public:
    using SmChannelBody::SmChannelBody;
};

class ChipAuthChannelImpl : public SmChannelBody
{
public:
    using SmChannelBody::SmChannelBody;
};

} // namespace LibreSCRS::SecureChannel::detail
