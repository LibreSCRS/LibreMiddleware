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
#include <smartcard/i_connection.h>
#include <smartcard/read_length_policy.h>
#include <LibreSCRS_internal/SmartCard/ChannelDispatch.h>

#include <LibreSCRS/SmartCard/TransportError.h>

#include <cstdint>
#include <expected>
#include <optional>
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
    /// The master file and EF.CardAccess were selected and the READ BINARY
    /// answered 9000 or 6282 (end of file reached): the plain read ran to its
    /// end, so no secure-messaging session was in the way. Wider than
    /// @ref readSucceeded, which stays 9000 only for the PACE verdicts.
    bool readReachedEnd = false;
    /// The reader failed to carry one of the exchanges. Set, every flag above
    /// is @c false and @ref data is empty; the caller reads it BEFORE
    /// classifying, because "could not read" is not "the document has no
    /// PACE".
    std::optional<LibreSCRS::SmartCard::TransportError> transportError;
    /// EF.CardAccess bytes, ready for @c emrtd::crypto::parseCardAccess.
    /// Empty unless a READ BINARY was issued (behaviour-preserving: the
    /// pre-extraction reader returned the raw read bytes even on a
    /// non-success SW).
    std::vector<std::uint8_t> data;
};

/// @brief Read EF.CardAccess from the master file, reporting outcome detail.
///
/// SELECT 3F00 -> SELECT 011C -> READ BINARY, each routed through
/// the shared dispatcher. @c noexcept: a reader failure is reported in
/// @ref CardAccessReadResult::transportError, any throw collapses to a result
/// with every flag false (an Unknown verdict downstream). Leaves the
/// MF selected — every caller re-SELECTs its DF/AID afterwards.
[[nodiscard]] inline CardAccessReadResult
readCardAccessDetailed(LibreSCRS::SecureChannel::ISecureChannel* activeChannel, LibreSCRS::SmartCard::IConnection& conn,
                       LibreSCRS::CancelToken token) noexcept
{
    CardAccessReadResult result;
    try {
        const auto failed = [](TransportError error) {
            CardAccessReadResult r;
            r.transportError = std::move(error);
            return r;
        };
        // One exchange through the session's dispatcher; when it is not
        // answered with success, the same SELECT is sent once more without
        // the FCI-suppressing P2 (some cards refuse 0x0C).
        const auto selectWithRetry = [&](const APDUCommand& first,
                                         const APDUCommand& second) -> std::expected<APDUResponse, TransportError> {
            auto answer = dispatchCommand(activeChannel, conn, first, token);
            if (answer && !answer->isSuccess())
                answer = dispatchCommand(activeChannel, conn, second, token);
            return answer;
        };
        auto mfSel = selectWithRetry(selectByFileId(0x3F, 0x00, 0x0C), selectByFileId(0x3F, 0x00));
        if (!mfSel)
            return failed(std::move(mfSel.error()));
        if (!mfSel->isSuccess())
            return result; // mfSelected stays false -> Unknown downstream
        result.mfSelected = true;

        auto efSelAnswer = selectWithRetry(selectByFileId(0x01, 0x1C, 0x0C), selectByFileId(0x01, 0x1C));
        if (!efSelAnswer)
            return failed(std::move(efSelAnswer.error()));
        const auto& efSel = *efSelAnswer;
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

        auto read = dispatchCommand(activeChannel, conn, APDUCommand{0x00, 0xB0, 0x00, 0x00, {}, 0, true}, token);
        if (!read)
            return failed(std::move(read.error()));
        result.readSucceeded = read->isSuccess();
        result.readReachedEnd = isReadSuccess(*read);
        result.data = std::move(read->data);
        return result;
    } catch (...) {
        return CardAccessReadResult{};
    }
}

} // namespace LibreSCRS::SmartCard::Internal
