// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace emrtd::crypto::detail {

// Longest length encoding any ISO 7816-4 / ICAO 9303 object needs; four octets
// already describe a 4 GiB value and no chip file approaches it. The same cap
// the middleware's other BER walker applies.
inline constexpr std::size_t kMaxLengthOctets = 4;

// Read a BER-TLV length at data[pos], accepting it ONLY when the value it
// declares lies wholly inside `data`. Returns {length, lengthOctets}; a zero
// lengthOctets means reject -- the encoding is truncated, indefinite, longer
// than four octets, or claims more bytes than the chip actually sent.
//
// Containment is tested by subtraction, never by adding the decoded length to
// an offset: a chip can choose a length that makes that addition wrap, and a
// wrapped end offset passes a `> end` test and then drives a parse cursor
// backwards onto the tag it just read.
constexpr std::pair<std::size_t, std::size_t> readLength(std::span<const std::uint8_t> data, std::size_t pos) noexcept
{
    if (pos >= data.size()) {
        return {0, 0};
    }

    const std::uint8_t first = data[pos];
    std::size_t value = first;
    std::size_t lengthOctets = 1;

    if (first >= 0x80) {
        const std::size_t octets = static_cast<std::size_t>(first & 0x7FU);
        if (octets == 0 || octets > kMaxLengthOctets || octets > data.size() - pos - 1) {
            return {0, 0};
        }
        value = 0;
        for (std::size_t i = 0; i < octets; ++i) {
            value = (value << 8) | data[pos + 1 + i];
        }
        lengthOctets = 1 + octets;
    }

    // pos + lengthOctets <= data.size() on both branches above, so this
    // subtraction cannot wrap.
    if (value > data.size() - pos - lengthOctets) {
        return {0, 0};
    }

    return {value, lengthOctets};
}

// Read a BER-TLV length that is ALLOWED to describe more than the buffer holds,
// and clamp it to what is there. Card files larger than one READ BINARY block
// legitimately arrive truncated, and the outer wrapper of such a file declares
// the whole file: rejecting it would refuse a chip that answered correctly.
// Everything INSIDE the wrapper still goes through readLength(). {0, 0} still
// means the ENCODING itself is unusable.
constexpr std::pair<std::size_t, std::size_t> readLengthClamped(std::span<const std::uint8_t> data,
                                                                std::size_t pos) noexcept
{
    if (pos >= data.size()) {
        return {0, 0};
    }

    const std::uint8_t first = data[pos];
    std::size_t value = first;
    std::size_t lengthOctets = 1;

    if (first >= 0x80) {
        const std::size_t octets = static_cast<std::size_t>(first & 0x7FU);
        if (octets == 0 || octets > kMaxLengthOctets || octets > data.size() - pos - 1) {
            return {0, 0};
        }
        value = 0;
        for (std::size_t i = 0; i < octets; ++i) {
            value = (value << 8) | data[pos + 1 + i];
        }
        lengthOctets = 1 + octets;
    }

    const std::size_t available = data.size() - pos - lengthOctets;
    return {value > available ? available : value, lengthOctets};
}

namespace tlv_bounds_selftest {

// Compile-time cases. A rejected encoding returns {0, 0}; the second element
// is what callers test, because a legitimate length of zero is well-formed.
inline constexpr std::uint8_t kShort[] = {0x02, 0xAA, 0xBB};
static_assert(readLength(kShort, 0) == std::pair<std::size_t, std::size_t>{2, 1});

// Short form declaring one byte more than the buffer holds.
inline constexpr std::uint8_t kShortOverrun[] = {0x03, 0xAA, 0xBB};
static_assert(readLength(kShortOverrun, 0).second == 0);

// Long form, one octet, contained.
inline constexpr std::uint8_t kLong[] = {0x81, 0x02, 0xAA, 0xBB};
static_assert(readLength(kLong, 0) == std::pair<std::size_t, std::size_t>{2, 2});

// Eight length octets: the encoding this parser used to accept, and the one
// that produced both the out-of-bounds read and the wrapped cursor.
inline constexpr std::uint8_t kEightOctets[] = {0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF6, 0x00, 0x00};
static_assert(readLength(kEightOctets, 0).second == 0);

// Four octets, well-formed encoding, value far larger than the buffer.
inline constexpr std::uint8_t kFourOctetOverrun[] = {0x84, 0x40, 0x00, 0x00, 0x00, 0x00};
static_assert(readLength(kFourOctetOverrun, 0).second == 0);

// Indefinite form (0x80) is not a length.
inline constexpr std::uint8_t kIndefinite[] = {0x80, 0x00, 0x00};
static_assert(readLength(kIndefinite, 0).second == 0);

// Position past the end.
static_assert(readLength(kShort, 3).second == 0);

// The clamping read keeps the encoding and trims the value to what arrived.
static_assert(readLengthClamped(kShortOverrun, 0) == std::pair<std::size_t, std::size_t>{2, 1});
static_assert(readLengthClamped(kFourOctetOverrun, 0) == std::pair<std::size_t, std::size_t>{1, 5});
// An unusable ENCODING is still rejected, clamping or not.
static_assert(readLengthClamped(kEightOctets, 0).second == 0);
static_assert(readLengthClamped(kIndefinite, 0).second == 0);

} // namespace tlv_bounds_selftest

} // namespace emrtd::crypto::detail
