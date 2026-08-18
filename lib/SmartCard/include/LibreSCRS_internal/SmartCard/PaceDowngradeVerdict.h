// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/PaceDowngradeVerdict.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief The post-BAC downgrade verdict: the pure, fail-closed three-outcome
///        decision over an SM-authenticated EF.CardAccess re-read.
///
/// After @ref LibreSCRS::SecureChannel::BacChannel establishes, the pre-auth
/// "PACE absent" verdict that selected BAC is re-verified by re-reading
/// EF.CardAccess THROUGH the established secure channel (SM-wrapped by
/// construction). A contactless man-in-the-middle that forged the pre-auth
/// verdict to force a PACE-capable document onto BAC can garble but not forge
/// an SM-authenticated answer, so the verdict fails closed on anything but an
/// SM-authenticated definitive absence:
///
///   - definitive absence (clean 6A82, or 6283 "file deactivated", after a
///     real MF selection — both SWs arrive MAC-covered in DO'99 inside the
///     tunnel), OR a COMPLETE well-formed read whose parse yields ZERO PACE
///     OIDs -> Proceed;
///   - >= 1 PACE OID in the SM-authenticated answer -> Downgrade (forged);
///   - anything else — MAC/integrity failure (surfaced as the channel's
///     sentinel SWs, never as an accepted status), undecodable, truncated,
///     not-a-SecurityInfos-SET, empty, or any throw -> Downgrade (fail closed).
///
/// The verdict is a pure function over the reader's outcome detail; the caller
/// performs the SM re-read (via @ref readCardAccessDetailed over the active
/// channel) and feeds the result here. It intentionally mirrors the pre-auth
/// capability probe's tri-state so the authenticated re-read cannot reach a
/// weaker conclusion than the unauthenticated probe on identical bytes.

#include <LibreSCRS_internal/SmartCard/CardAccessReader.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

/// @brief Outcome of the post-BAC downgrade cross-check.
enum class PaceDowngradeVerdict : std::uint8_t {
    /// PACE is SM-authenticated as genuinely absent — keep the BAC channel.
    Proceed,
    /// PACE detected, or the re-read was anything but a clean authenticated
    /// absence — tear the channel down and report a forged downgrade.
    Downgrade,
};

/// @brief True iff the outer DER length octet(s) at @p data[1..] describe a
///        value wholly contained in @p data. @p data[0] is assumed 0x31.
///        Rejects the indefinite form and any > 64 KiB length (a single READ
///        BINARY can never return the whole file). Mirrors the pre-auth
///        probe's @c outerBerLengthContained so a truncated read is never
///        mistaken for a complete no-PACE document.
[[nodiscard]] inline bool cardAccessOuterLengthContained(const std::vector<std::uint8_t>& data) noexcept
{
    if (data.size() < 2)
        return false;
    const std::uint8_t lead = data[1];
    std::size_t header = 2;
    std::size_t contentLen = 0;
    if (lead < 0x80) {
        contentLen = lead;
    } else if (lead == 0x81) {
        if (data.size() < 3)
            return false;
        header = 3;
        contentLen = data[2];
    } else if (lead == 0x82) {
        if (data.size() < 4)
            return false;
        header = 4;
        contentLen = (static_cast<std::size_t>(data[2]) << 8) | data[3];
    } else {
        return false; // 0x80 indefinite, or 0x83+ (> 64 KiB)
    }
    return header + contentLen <= data.size();
}

namespace detail {

/// Read a short/0x81/0x82 DER length at @p pos (advancing it past the length
/// octets). Returns false on the indefinite form, a > 64 KiB length, or an
/// overrun of @p end.
[[nodiscard]] inline bool readDerLength(const std::vector<std::uint8_t>& d, std::size_t& pos, std::size_t end,
                                        std::size_t& len) noexcept
{
    if (pos >= end)
        return false;
    const std::uint8_t lead = d[pos++];
    if (lead < 0x80) {
        len = lead;
        return true;
    }
    if (lead == 0x81) {
        if (pos >= end)
            return false;
        len = d[pos++];
        return true;
    }
    if (lead == 0x82) {
        if (pos + 1 >= end)
            return false;
        len = (static_cast<std::size_t>(d[pos]) << 8) | d[pos + 1];
        pos += 2;
        return true;
    }
    return false;
}

} // namespace detail

/// @brief Fail-closed scan for a PACE advertisement in a structurally validated
///        EF.CardAccess (@p data[0] == 0x31 and the outer length contained).
///
/// Returns @c true if any SecurityInfo advertises a PACE OID (DER content
/// prefix 04 00 7F 00 07 02 02 04 == id-PACE, 0.4.0.127.0.7.2.2.4) OR the
/// inner structure is malformed — both are downgrade-worthy. Returns @c false
/// only on a clean, complete walk that finds zero PACE OIDs. This is the
/// OID-only test the pre-auth capability probe applies (it matches PACE
/// regardless of the parameterId, so the authenticated re-read can never reach
/// a weaker verdict than the unauthenticated probe on identical bytes); it is
/// deliberately co-located with the verdict so a security decision trusts no
/// larger parser across a module boundary.
[[nodiscard]] inline bool cardAccessAdvertisesPaceOrIsMalformed(const std::vector<std::uint8_t>& data) noexcept
{
    static constexpr std::uint8_t kPaceOidPrefix[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04};

    std::size_t pos = 1; // past the SET (0x31) tag
    std::size_t setLen = 0;
    if (!detail::readDerLength(data, pos, data.size(), setLen))
        return true;
    const std::size_t setEnd = pos + setLen;
    if (setEnd > data.size())
        return true;

    while (pos < setEnd) {
        // Each SecurityInfo is a SEQUENCE whose first element is its OID.
        if (data[pos] != 0x30)
            return true;
        ++pos;
        std::size_t seqLen = 0;
        if (!detail::readDerLength(data, pos, setEnd, seqLen))
            return true;
        const std::size_t seqEnd = pos + seqLen;
        if (seqEnd > setEnd)
            return true;
        if (pos >= seqEnd || data[pos] != 0x06) // first element must be an OID
            return true;
        ++pos;
        std::size_t oidLen = 0;
        if (!detail::readDerLength(data, pos, seqEnd, oidLen))
            return true;
        const std::size_t oidEnd = pos + oidLen;
        if (oidEnd > seqEnd)
            return true;
        if (oidLen >= sizeof(kPaceOidPrefix)) {
            bool match = true;
            for (std::size_t i = 0; i < sizeof(kPaceOidPrefix); ++i)
                if (data[pos + i] != kPaceOidPrefix[i]) {
                    match = false;
                    break;
                }
            if (match)
                return true; // PACE advertised
        }
        pos = seqEnd; // skip the remainder of this SecurityInfo
    }
    return false; // clean walk, no PACE OID
}

/// @brief The fail-closed post-BAC downgrade verdict over an SM-authenticated
///        EF.CardAccess re-read. @c noexcept: any throw (e.g. from the OID
///        parser) fails closed to @ref PaceDowngradeVerdict::Downgrade.
[[nodiscard]] inline PaceDowngradeVerdict classifyPostBacCardAccess(const CardAccessReadResult& read) noexcept
{
    try {
        // Definitive absence: a clean 6A82 (no such file) or 6283 (file
        // deactivated) on EF.CardAccess after a real MF selection, delivered
        // inside the authenticated SM tunnel.
        if (read.efDefinitivelyAbsent)
            return PaceDowngradeVerdict::Proceed;
        // Everything below requires a COMPLETE, well-formed successful read.
        if (!read.readSucceeded)
            return PaceDowngradeVerdict::Downgrade; // MAC/integrity failure, anomaly, no read
        const auto& data = read.data;
        if (data.empty() || data[0] != 0x31)
            return PaceDowngradeVerdict::Downgrade; // not a SecurityInfos SET
        if (!cardAccessOuterLengthContained(data))
            return PaceDowngradeVerdict::Downgrade; // truncated / > 64 KiB
        // Structurally complete outer SET: >= 1 PACE OID (or any inner
        // malformation) is a forged downgrade; a clean zero-PACE walk is a
        // genuine no-PACE document.
        return cardAccessAdvertisesPaceOrIsMalformed(data) ? PaceDowngradeVerdict::Downgrade
                                                           : PaceDowngradeVerdict::Proceed;
    } catch (...) {
        return PaceDowngradeVerdict::Downgrade; // fail closed on any throw
    }
}

} // namespace LibreSCRS::SmartCard::Internal
