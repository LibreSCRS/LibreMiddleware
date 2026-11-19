// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Card-side test oracles for Chip Authentication over AES secure
///        messaging. The terminal-side @c emrtd::crypto::SecureMessaging only
///        wraps commands and unwraps responses; a faithful fake chip must do
///        the opposite — verify the terminal's wrapped command MAC and build a
///        wrapped response the terminal will accept. These oracles do that
///        with the same @c emrtd::crypto::detail primitives the production
///        path uses, so a key mismatch fails on the wire exactly as a real
///        clone would, never silently.
///
/// Two layers:
///   - @ref AesSmCardOracle — the SM engine, keyed by known AES session keys.
///     Verifies a wrapped command and emits a wrapped response, keeping SSC in
///     lockstep with the terminal (+1 per direction).
///   - @ref ChipAuthCardOracle (added alongside the establish() work) — wraps
///     an @ref AesSmCardOracle behind the plain CA handshake (MSE:Set AT +
///     GENERAL AUTHENTICATE), deriving the SM keys card-side via ECDH so a
///     full plain→CA→SM flow can be driven without hardware.

#include "apdu.h"
#include "crypto_utils.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace LibreSCRS::Test {

/// @brief Card side of an AES-CBC + AES-CMAC secure-messaging session
///        (ICAO Doc 9303 Part 11 / BSI TR-03110 §E).
class AesSmCardOracle
{
public:
    AesSmCardOracle(std::vector<std::uint8_t> encKey, std::vector<std::uint8_t> macKey, std::vector<std::uint8_t> ssc)
        : enc(std::move(encKey)), macKey(std::move(macKey)), ssc(std::move(ssc))
    {}

    /// Next successful response's plaintext data (empty = no DO'87, e.g. a
    /// SELECT). Consumed and reset after one response.
    void setNextResponseData(std::vector<std::uint8_t> data)
    {
        nextData = std::move(data);
    }

    /// Count of wrapped commands whose MAC verified — the proof that the
    /// terminal held the matching keys.
    [[nodiscard]] int verifiedCommands() const noexcept
    {
        return verifiedCount;
    }

    /// Handle one wrapped command frame (the full bytes the terminal put on
    /// the wire) and return the transport-level response. A MAC mismatch
    /// yields SW 6988 unwrapped — exactly what production SmChannelBody maps
    /// to a failed channel, so a wrong-key terminal is rejected on the wire.
    /// Answers a verified command from its decrypted parts: INS, P1, P2 and
    /// the DO'87 plaintext. Its data and status word are wrapped in turn.
    using CommandHandler = std::function<LibreSCRS::SmartCard::Internal::APDUResponse(
        std::uint8_t ins, std::uint8_t p1, std::uint8_t p2, const std::vector<std::uint8_t>& data)>;

    [[nodiscard]] LibreSCRS::SmartCard::Internal::APDUResponse respond(std::span<const std::uint8_t> wrapped,
                                                                       const CommandHandler& handler = {})
    {
        namespace det = emrtd::crypto::detail;
        if (wrapped.size() < 4) {
            return {{}, 0x6F, 0x00};
        }
        const std::uint8_t cla = wrapped[0];
        const std::uint8_t ins = wrapped[1];
        const std::uint8_t p1 = wrapped[2];
        const std::uint8_t p2 = wrapped[3];

        // Locate DO'87 / DO'97 / DO'8E in the command body (after Lc).
        std::vector<std::uint8_t> do87;
        std::vector<std::uint8_t> do97;
        std::vector<std::uint8_t> receivedMac;
        if (!parseCommandBody(wrapped, do87, do97, receivedMac)) {
            return {{}, 0x6F, 0x00};
        }

        det::incrementSSC(ssc);

        // MAC input: SSC || pad(header) || DO'87 || DO'97, padded to 16.
        const std::vector<std::uint8_t> header = {cla, ins, p1, p2};
        const auto paddedHeader = det::pad(header, 16);
        std::vector<std::uint8_t> macInput = ssc;
        macInput.insert(macInput.end(), paddedHeader.begin(), paddedHeader.end());
        macInput.insert(macInput.end(), do87.begin(), do87.end());
        macInput.insert(macInput.end(), do97.begin(), do97.end());
        auto expected = det::aesCMAC(macKey, det::pad(macInput, 16));
        expected.resize(8);

        if (receivedMac.size() < 8 ||
            expected != std::vector<std::uint8_t>(receivedMac.begin(), receivedMac.begin() + 8)) {
            return {{}, 0x69, 0x88}; // MAC mismatch: reject like a real card
        }
        ++verifiedCount;
        lastIns = ins;
        lastData = decryptCommandData(do87);

        if (handler) {
            const auto answer = handler(ins, p1, p2, lastData);
            return wrapResponse(answer.data, answer.sw1, answer.sw2);
        }
        // Build a wrapped success response. SELECT (P2 with 0x0C etc.) usually
        // carries no data; a READ returns nextData if the test set it.
        std::vector<std::uint8_t> data = nextData;
        nextData.clear();
        return wrapResponse(data, 0x90, 0x00);
    }

    /// INS and decrypted DO'87 plaintext of the last command whose MAC
    /// verified (empty when it carried no data) — lets a fake chip act on a
    /// protected command, e.g. run its side of a key agreement.
    [[nodiscard]] std::uint8_t lastCommandIns() const noexcept
    {
        return lastIns;
    }
    [[nodiscard]] const std::vector<std::uint8_t>& lastCommandData() const noexcept
    {
        return lastData;
    }

private:
    // DO'87 = 87 len 01 <ciphertext>; IV = E(K_Enc, SSC) with the command's
    // SSC (BSI TR-03110 E.1), ISO 9797-1 method 2 padding.
    std::vector<std::uint8_t> decryptCommandData(const std::vector<std::uint8_t>& do87) const
    {
        namespace det = emrtd::crypto::detail;
        if (do87.size() < 3) {
            return {};
        }
        std::size_t pos = 1;
        if (do87[pos] < 0x80) {
            pos += 1;
        } else if (do87[pos] == 0x81) {
            pos += 2;
        } else {
            pos += 3;
        }
        if (pos >= do87.size() || do87[pos] != 0x01) {
            return {};
        }
        const std::vector<std::uint8_t> ct(do87.begin() + static_cast<std::ptrdiff_t>(pos + 1), do87.end());
        const auto iv = det::aesEncrypt(enc, ssc);
        return det::unpad(det::aesDecrypt(enc, ct, iv));
    }

    // Returns false on a malformed frame. do87/do97 come back as the FULL TLV
    // bytes (tag+len+value) for the MAC recompute; receivedMac is the DO'8E
    // value only.
    static bool parseCommandBody(std::span<const std::uint8_t> wrapped, std::vector<std::uint8_t>& do87,
                                 std::vector<std::uint8_t>& do97, std::vector<std::uint8_t>& receivedMac)
    {
        // Skip CLA INS P1 P2 and the Lc byte(s). Only short Lc is produced by
        // the production protect() for these small frames.
        std::size_t pos = 4;
        if (pos >= wrapped.size()) {
            return false;
        }
        // Lc: short form (single byte) is all the CA proof/READ frames need.
        if (wrapped[pos] == 0x00) {
            // Extended Lc: 00 hi lo
            if (pos + 3 > wrapped.size()) {
                return false;
            }
            pos += 3;
        } else {
            pos += 1;
        }
        while (pos + 2 <= wrapped.size()) {
            const std::uint8_t tag = wrapped[pos];
            std::size_t lenPos = pos + 1;
            std::size_t len = 0;
            std::size_t headerLen = 2;
            const std::uint8_t l0 = wrapped[lenPos];
            if (l0 < 0x80) {
                len = l0;
            } else if (l0 == 0x81 && lenPos + 1 < wrapped.size()) {
                len = wrapped[lenPos + 1];
                headerLen = 3;
            } else if (l0 == 0x82 && lenPos + 2 < wrapped.size()) {
                len = (static_cast<std::size_t>(wrapped[lenPos + 1]) << 8) | wrapped[lenPos + 2];
                headerLen = 4;
            } else {
                return false;
            }
            const std::size_t total = headerLen + len;
            if (pos + total > wrapped.size()) {
                return false;
            }
            if (tag == 0x87) {
                do87.assign(wrapped.begin() + static_cast<std::ptrdiff_t>(pos),
                            wrapped.begin() + static_cast<std::ptrdiff_t>(pos + total));
            } else if (tag == 0x97) {
                do97.assign(wrapped.begin() + static_cast<std::ptrdiff_t>(pos),
                            wrapped.begin() + static_cast<std::ptrdiff_t>(pos + total));
            } else if (tag == 0x8E) {
                receivedMac.assign(wrapped.begin() + static_cast<std::ptrdiff_t>(pos + headerLen),
                                   wrapped.begin() + static_cast<std::ptrdiff_t>(pos + total));
            }
            pos += total;
        }
        return !receivedMac.empty();
    }

    LibreSCRS::SmartCard::Internal::APDUResponse wrapResponse(const std::vector<std::uint8_t>& data, std::uint8_t sw1,
                                                              std::uint8_t sw2)
    {
        namespace det = emrtd::crypto::detail;
        det::incrementSSC(ssc);

        std::vector<std::uint8_t> do87;
        if (!data.empty()) {
            const auto iv = det::aesEncrypt(enc, ssc); // BSI E.1: IV = E(K_Enc, SSC)
            const auto ct = det::aesEncrypt(enc, det::pad(data, 16), iv);
            do87.push_back(0x87);
            appendLen(do87, 1 + ct.size());
            do87.push_back(0x01);
            do87.insert(do87.end(), ct.begin(), ct.end());
        }
        const std::vector<std::uint8_t> do99 = {0x99, 0x02, sw1, sw2};

        std::vector<std::uint8_t> macInput = ssc;
        macInput.insert(macInput.end(), do87.begin(), do87.end());
        macInput.insert(macInput.end(), do99.begin(), do99.end());
        auto mac = det::aesCMAC(macKey, det::pad(macInput, 16));
        mac.resize(8);

        std::vector<std::uint8_t> body = do87;
        body.insert(body.end(), do99.begin(), do99.end());
        body.push_back(0x8E);
        body.push_back(0x08);
        body.insert(body.end(), mac.begin(), mac.end());
        return {body, 0x90, 0x00};
    }

    static void appendLen(std::vector<std::uint8_t>& out, std::size_t len)
    {
        if (len < 0x80) {
            out.push_back(static_cast<std::uint8_t>(len));
        } else if (len <= 0xFF) {
            out.push_back(0x81);
            out.push_back(static_cast<std::uint8_t>(len));
        } else {
            out.push_back(0x82);
            out.push_back(static_cast<std::uint8_t>(len >> 8));
            out.push_back(static_cast<std::uint8_t>(len & 0xFF));
        }
    }

    std::vector<std::uint8_t> enc;
    std::vector<std::uint8_t> macKey;
    std::vector<std::uint8_t> ssc;
    std::vector<std::uint8_t> nextData;
    std::vector<std::uint8_t> lastData;
    std::uint8_t lastIns = 0;
    int verifiedCount = 0;
};

} // namespace LibreSCRS::Test
