// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <LibreSCRS/Export.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {

// Hidden visibility, deliberately and on every name below. This decoder was
// reachable from no public shared library until the secure-messaging path
// stopped carrying its own copy of the length decode; folding the copies onto
// this one pulled the whole translation unit into a shipped .so and put six
// internal symbols into the versioned ABI. Removing a duplicate must not
// enlarge what this project promises to keep, so the surface is pinned back
// down here rather than the baseline being widened to match.

// ISO 7816-4 BER-TLV field (used by Serbian vehicle registration cards)
struct LIBRESCRS_INTERNAL BERField
{
    uint32_t tag = 0;
    bool constructed = false;
    std::vector<uint8_t> value;     // raw value (for primitive fields)
    std::vector<BERField> children; // nested fields (for constructed fields)

    std::string asString() const;
};

// Parse BER-TLV data. Returns a synthetic root node containing all top-level fields as children.
LIBRESCRS_INTERNAL BERField parseBER(const uint8_t* data, size_t length);

// --- one decoder, two error policies -------------------------------------
//
// Three copies of this decode lived in this tree, and their only real
// difference was what they did when the bytes were wrong: this one throws, the
// secure-messaging path broke out of its loop, the DOCP parser set an `ok`
// flag. The bodies below are the flag-returning pair; the throwing pair is
// written over them, so there is one decode and two ways of refusing.
//
// What is NOT shared is how much a caller ACCEPTS. Secure messaging takes a
// one-byte tag and a length field of at most three bytes, and the DOCP parser
// at most two; those ceilings stay at their call sites, because widening what a
// card path accepts is not a deduplication.

struct TagResult
{
    std::uint32_t tag = 0;
    std::size_t next = 0; ///< offset just past the tag bytes; valid only when ok
    bool ok = false;
};

struct LengthResult
{
    std::size_t length = 0;
    std::size_t next = 0; ///< offset just past the length bytes; valid only when ok
    bool ok = false;
};

// Parse a single BER tag (1, 2, or 3 bytes) starting at `pos`. Never throws.
[[nodiscard]] LIBRESCRS_INTERNAL TagResult tryParseTag(const uint8_t* data, size_t length, size_t pos) noexcept;

// Longest length field any ISO 7816-4 / ICAO 9303 / DER object needs: four
// octets already describe a 4 GiB value. Both directions stop here.
inline constexpr std::size_t kMaxLengthOctets = 4;

// Parse a BER length (short or long form) starting at `pos`. Never throws;
// indefinite (0x80), oversized and truncated encodings all report !ok.
//
// Defined here rather than in ber.cpp so that compile-time callers (the eMRTD
// bounds checks assert their cases with static_assert) decode through this
// body instead of carrying their own.
[[nodiscard]] LIBRESCRS_INTERNAL constexpr LengthResult tryParseLength(const uint8_t* data, size_t length,
                                                                       size_t pos) noexcept
{
    LengthResult out;
    if (pos >= length) {
        return out;
    }

    const uint8_t firstByte = data[pos++];

    if (firstByte < 0x80) {
        // Short form
        out.length = firstByte;
        out.next = pos;
        out.ok = true;
        return out;
    }

    if (firstByte == 0x80) {
        // Indefinite length not supported
        return out;
    }

    // Long form: firstByte & 0x7F = number of subsequent bytes. pos <= length
    // here, so the subtraction cannot wrap.
    const size_t numBytes = firstByte & 0x7F;
    if (numBytes > kMaxLengthOctets || numBytes > length - pos) {
        return out;
    }

    size_t len = 0;
    for (size_t i = 0; i < numBytes; i++) {
        len = (len << 8) | data[pos++];
    }
    out.length = len;
    out.next = pos;
    out.ok = true;
    return out;
}

// --- one encoder ---------------------------------------------------------
//
// The writing side of the same rules. PACE, Chip Authentication, secure
// messaging and the signing engine's DER writer all encode through these two,
// so a length is written one way: shortest form, at most kMaxLengthOctets
// octets after the 0x8n lead.

// Append the BER definite-length encoding of `valueLength` to `out`. Throws
// std::length_error for a length that does not fit in kMaxLengthOctets
// octets -- a length is never cut down to the octets that happen to fit.
LIBRESCRS_INTERNAL void appendLength(std::vector<std::uint8_t>& out, std::size_t valueLength);

// tag || length || value. The tag is written on as many octets as it occupies
// (0x86 is one octet, 0x7F49 two), the same packing tryParseTag returns.
[[nodiscard]] LIBRESCRS_INTERNAL std::vector<std::uint8_t> buildTlv(std::uint32_t tag,
                                                                    std::span<const std::uint8_t> value);

// Parse a single BER tag (1, 2, or 3 bytes) starting at `offset`.
// Returns the tag value and advances `offset` past the tag bytes.
// Throws std::runtime_error on truncated/oversized input.
LIBRESCRS_INTERNAL uint32_t parseTag(const uint8_t* data, size_t length, size_t& offset);

// Parse a BER length (short or long form) starting at `offset`.
// Returns the length value and advances `offset` past the length bytes.
// Throws std::runtime_error on indefinite/oversized/truncated encodings.
LIBRESCRS_INTERNAL size_t parseLength(const uint8_t* data, size_t length, size_t& offset);

// Merge two BER trees: appends src's children into dst
LIBRESCRS_INTERNAL void mergeBER(BERField& dst, const BERField& src);

// Access nested field by tag path, e.g. {0x71, 0xA3, 0x87}
LIBRESCRS_INTERNAL std::string berFindString(const BERField& root, std::initializer_list<uint32_t> path);

} // namespace LibreSCRS::SmartCard::Internal
