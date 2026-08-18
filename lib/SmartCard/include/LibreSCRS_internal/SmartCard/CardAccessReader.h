// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/CardAccessReader.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief The ONE MF-scoped EF.CardAccess reader, shared by
///        @ref LibreSCRS::SmartCard::CardSession's PACE path, the eMRTD
///        plugin's pre-auth capability probe, and the plugin's
///        host-discovery leg.
///
/// EF.CardAccess lives at the MASTER FILE (path 3F00/011C), not inside any
/// application DF: reading it means SELECT 3F00 -> SELECT 011C -> READ
/// BINARY. Routing every consumer through this single helper guarantees the
/// capability verdict computed pre-auth by the plugin cannot diverge from
/// what CardSession reads at handshake time.
///
/// A bare byte-vector return cannot tell "the file is DEFINITIVELY unusable
/// for PACE" apart from "something went wrong" (MF select failed, transport
/// threw, a short read). The tri-state capability verdict needs that
/// distinction, so this reader reports the selection/read outcome alongside
/// the bytes. Exactly TWO chip-authoritative signals are definitive, both
/// requiring a real, successful MF selection first:
///   - a clean 6A82 on the EF selection ("no such file"), and
///   - SW 6283 on the EF selection ("selected file invalidated/deactivated",
///     ISO 7816-4): the file exists but the chip itself declares it unusable
///     — observed on BAC-only personalizations of PACE-capable OSes. No READ
///     BINARY is attempted after 6283: content of a deactivated file is not a
///     valid source of PACEInfo (ISO 7816-9 life-cycle), and skipping the
///     read keeps the definitive signal free of attacker-influenceable bits
///     when the reader runs over an SM tunnel (a select SW arrives MAC-
///     covered in DO'99; a read FAILURE is inducible by garbling).
/// Every other warning (including 6285 "termination state") stays
/// non-definitive and falls through to the read -> Unknown downstream.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>

#include <apdu.h>
#include <pcsc_connection.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

/// @brief Outcome detail of an MF-scoped EF.CardAccess read attempt.
struct CardAccessReadResult
{
    /// The master file (3F00) selection succeeded.
    bool mfSelected = false;
    /// EF.CardAccess (011C) selection, AFTER a successful MF selection,
    /// answered with one of the two DEFINITIVE "PACE parameters
    /// unobtainable" signals: a clean 6A82 (no such file) or SW 6283 (file
    /// deactivated — no READ attempted; see the file-level contract).
    bool efDefinitivelyAbsent = false;
    /// A READ BINARY was issued at the MF-selected EF.CardAccess and
    /// returned success (90 00). @ref data then holds its bytes.
    bool readSucceeded = false;
    /// EF.CardAccess bytes, ready for @c emrtd::crypto::parseCardAccess.
    /// Empty unless a READ BINARY was issued (behaviour-preserving: the
    /// pre-extraction reader returned the raw read bytes even on a
    /// non-success SW).
    std::vector<std::uint8_t> data;
};

namespace detail {

/// SM-aware transmit primitive for the reader: dispatch through @p activeChannel
/// when it is open (the PACE SM tunnel is session-scoped, so MF/EF.CardAccess
/// stays reachable over it), otherwise plain through @p conn.
inline APDUResponse cardAccessDispatch(LibreSCRS::SecureChannel::ISecureChannel* activeChannel, PCSCConnection& conn,
                                       const APDUCommand& cmd, LibreSCRS::CancelToken token)
{
    if (activeChannel != nullptr && activeChannel->state() == LibreSCRS::SecureChannel::ChannelState::Open)
        return activeChannel->transmit(cmd, std::move(token));
    return conn.transmit(cmd);
}

} // namespace detail

/// @brief Read EF.CardAccess from the master file, reporting outcome detail.
///
/// SELECT 3F00 -> SELECT 011C -> READ BINARY, each routed through
/// @ref detail::cardAccessDispatch. @c noexcept: any throw collapses to a
/// result with every flag false (an Unknown verdict downstream). Leaves the
/// MF selected — every caller re-SELECTs its DF/AID afterwards.
[[nodiscard]] inline CardAccessReadResult
readCardAccessDetailed(LibreSCRS::SecureChannel::ISecureChannel* activeChannel, PCSCConnection& conn,
                       LibreSCRS::CancelToken token) noexcept
{
    CardAccessReadResult result;
    try {
        auto mfSel = detail::cardAccessDispatch(activeChannel, conn, selectByFileId(0x3F, 0x00, 0x0C), token);
        if (!mfSel.isSuccess())
            mfSel = detail::cardAccessDispatch(activeChannel, conn, selectByFileId(0x3F, 0x00), token);
        if (!mfSel.isSuccess())
            return result; // mfSelected stays false -> Unknown downstream
        result.mfSelected = true;

        auto efSel = detail::cardAccessDispatch(activeChannel, conn, selectByFileId(0x01, 0x1C, 0x0C), token);
        if (!efSel.isSuccess())
            efSel = detail::cardAccessDispatch(activeChannel, conn, selectByFileId(0x01, 0x1C), token);
        // SW 6283 "selected file invalidated/deactivated" (ISO 7816-4) on the
        // FINAL selection attempt: the chip's own declaration that
        // EF.CardAccess is unusable — the second definitive signal. Return
        // WITHOUT reading: a deactivated file's content is not a valid
        // PACEInfo source, and the early return keeps the signal select-SW
        // only (MAC-authentic under SM). Exactly 6283 — other 62xx warnings
        // (incl. 6285) fall through to the read below.
        if (efSel.sw1 == 0x62 && efSel.sw2 == 0x83) {
            result.efDefinitivelyAbsent = true;
            return result;
        }
        if (efSel.sw1 != 0x90 && efSel.sw1 != 0x62) {
            // A clean 6A82 after a real MF selection is the definitive
            // "file not found" signal. Any other SW is an anomaly (Unknown).
            if (efSel.sw1 == 0x6A && efSel.sw2 == 0x82)
                result.efDefinitivelyAbsent = true;
            return result;
        }

        auto read =
            detail::cardAccessDispatch(activeChannel, conn, APDUCommand{0x00, 0xB0, 0x00, 0x00, {}, 0, true}, token);
        result.readSucceeded = read.isSuccess();
        result.data = std::move(read.data);
        return result;
    } catch (...) {
        return CardAccessReadResult{};
    }
}

} // namespace LibreSCRS::SmartCard::Internal
