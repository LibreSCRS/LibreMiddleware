// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#include <LibreSCRS/SecureChannel/ISecureChannel.h>
#include <LibreSCRS/SecureChannel/SessionKeys.h>
#include <LibreSCRS/SmartCard/AppletAid.h>

#include "apdu.h"
#include <smartcard/i_connection.h>

#include "secure_messaging.h"

#include <memory>
#include <utility>

namespace LibreSCRS::SecureChannel::detail {

/// @brief Shared body for PaceChannel and BacChannel; differs only in
///        which SmCipher the SessionKeys block carries.
///
/// The actual SM wrap/unwrap is delegated to
/// @c emrtd::crypto::SecureMessaging, which already implements both 3DES
/// (BAC) and AES-CBC + CMAC (PACE) paths selected at construction by the
/// SMAlgorithm parameter. Physical relocation of that primitive into
/// LibreSCRS_SecureChannel is deferred (see plan Stage 2 Task 2.2);
/// this shim keeps the public surface stable so plugins can migrate
/// without waiting on the file move.
class SmChannelBody
{
public:
    SmChannelBody(LibreSCRS::SmartCard::IConnection& connection, LibreSCRS::SmartCard::AppletAid aid, SessionKeys keys)
        : connection(connection), appletAid(std::move(aid))
    {
        emrtd::crypto::SessionKeys cryptoKeys;
        cryptoKeys.encKey = std::move(keys.encKey);
        cryptoKeys.macKey = std::move(keys.macKey);
        cryptoKeys.ssc = std::move(keys.ssc);
        auto algo = keys.cipher == SmCipher::Des3 ? emrtd::crypto::SMAlgorithm::DES3 : emrtd::crypto::SMAlgorithm::AES;
        sm = std::make_unique<emrtd::crypto::SecureMessaging>(std::move(cryptoKeys), algo);
    }

    [[nodiscard]] LibreSCRS::SmartCard::AppletAid currentApplet() const noexcept
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

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse
    transmit(const LibreSCRS::SmartCard::Internal::APDUCommand& cmd, LibreSCRS::CancelToken token)
    {
        if (channelState == ChannelState::Closed) {
            return makeSentinel(0x6F, 0x00);
        }
        if (channelState == ChannelState::Failed) {
            return makeSentinel(0x6F, 0x02);
        }
        if (token.isCancellable() && token.isCancelled()) {
            return makeSentinel(0x6F, 0x01);
        }
        if (!sm) {
            channelState = ChannelState::Failed;
            return makeSentinel(0x6F, 0x02);
        }

        auto plainBytes = cmd.toBytes();
        auto wrapped = sm->protect(plainBytes);
        if (wrapped.size() < 5) {
            channelState = ChannelState::Failed;
            return makeSentinel(0x6F, 0x02);
        }

        LibreSCRS::SmartCard::Internal::APDUResponse raw = connection.transmit(parseWrapped(wrapped));

        std::vector<std::uint8_t> respBytes = raw.data;
        respBytes.push_back(raw.sw1);
        respBytes.push_back(raw.sw2);

        // Detect external SM invalidation before attempting MAC unwrap.
        if (raw.sw1 == 0x69 && (raw.sw2 == 0x87 || raw.sw2 == 0x88)) {
            channelState = ChannelState::Failed;
            LibreSCRS::SmartCard::Internal::APDUResponse out;
            out.sw1 = raw.sw1;
            out.sw2 = raw.sw2;
            return out;
        }

        auto unwrapped = sm->unprotectWithSW(respBytes);
        if (!unwrapped) {
            channelState = ChannelState::Failed;
            return makeSentinel(0x69, 0x88); // MAC verification failed; map to 6988
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
    {
        emrtd::crypto::SessionKeys cryptoKeys;
        cryptoKeys.encKey = std::move(keys.encKey);
        cryptoKeys.macKey = std::move(keys.macKey);
        cryptoKeys.ssc = std::move(keys.ssc);
        auto algo = keys.cipher == SmCipher::Des3 ? emrtd::crypto::SMAlgorithm::DES3 : emrtd::crypto::SMAlgorithm::AES;
        sm = std::make_unique<emrtd::crypto::SecureMessaging>(std::move(cryptoKeys), algo);
        channelState = ChannelState::Open;
    }

private:
    static LibreSCRS::SmartCard::Internal::APDUResponse makeSentinel(std::uint8_t sw1, std::uint8_t sw2)
    {
        LibreSCRS::SmartCard::Internal::APDUResponse r;
        r.sw1 = sw1;
        r.sw2 = sw2;
        return r;
    }

    /// @brief Translate the raw wrapped bytes returned by SecureMessaging::protect
    ///        back into an APDUCommand the connection layer expects.
    static LibreSCRS::SmartCard::Internal::APDUCommand parseWrapped(const std::vector<std::uint8_t>& wrapped)
    {
        LibreSCRS::SmartCard::Internal::APDUCommand cmd;
        cmd.cla = wrapped[0];
        cmd.ins = wrapped[1];
        cmd.p1 = wrapped[2];
        cmd.p2 = wrapped[3];

        // SecureMessaging::protect emits short-form Lc + data + Le for our
        // current use; extended-length wrapping isn't required for the
        // four-applet matrix this channel serves (NAM CL eMRTD/PKCS#15,
        // GEO CL eMRTD/PKCS#15). Extended wrapping is a Stage 2 relocation
        // follow-up alongside the physical move.
        std::uint8_t lc = wrapped[4];
        cmd.data.assign(wrapped.begin() + 5, wrapped.begin() + 5 + lc);
        cmd.le = wrapped.back();
        cmd.hasLe = true;
        return cmd;
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

} // namespace LibreSCRS::SecureChannel::detail
