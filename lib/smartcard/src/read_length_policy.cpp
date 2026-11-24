// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <smartcard/read_length_policy.h>

#include "ber.h"

#include <algorithm>

namespace LibreSCRS::SmartCard::Internal {

namespace {

constexpr std::uint32_t kExtendedLengthInfoTag = 0x7F66;
constexpr std::uint8_t kIntegerTag = 0x02;
// A declared response of at most this much does not allow more than Le 256.
constexpr std::size_t kShortResponseMax = 258;

// Secure-messaging response around len plain bytes: DO'87' (padded data with
// the padding indicator), DO'99' and DO'8E', then SW.
std::size_t smResponseSize(std::size_t len, std::size_t block)
{
    const std::size_t padded = (len / block + 1) * block;
    const std::size_t v = 1 + padded;
    const std::size_t lengthOctets = v < 128 ? 1 : v < 256 ? 2 : 3;
    return 1 + lengthOctets + 1 + padded + 4 + 10 + 2;
}

} // namespace

void ReadLengthPolicy::learn(ReadLengthState s, std::size_t declaredResponseMax) noexcept
{
    declaredMax.store(declaredResponseMax, std::memory_order_relaxed);
    stateValue.store(s, std::memory_order_release);
}

ReadLengthState ReadLengthPolicy::state() const noexcept
{
    return stateValue.load(std::memory_order_acquire);
}

std::size_t ReadLengthPolicy::declaredResponseMax() const noexcept
{
    return declaredMax.load(std::memory_order_relaxed);
}

std::size_t ReadLengthPolicy::allowedLe(std::size_t smBlockSize) const noexcept
{
    switch (state()) {
    case ReadLengthState::Short:
        return kShortLe;
    case ReadLengthState::Declared: {
        const std::size_t declared = declaredMax.load(std::memory_order_relaxed);
        if (declared <= kShortResponseMax) {
            return kShortLe;
        }
        if (smBlockSize == 0) {
            return std::min(declared - 2, kMaxLe);
        }
        return std::min(maxSmProtectedData(declared, smBlockSize), kMaxLe);
    }
    case ReadLengthState::Untested:
    case ReadLengthState::Accepted:
        return smBlockSize == 0 ? kUndeclaredExtendedLe : kShortLe;
    }
    return kShortLe;
}

void ReadLengthPolicy::markAccepted() noexcept
{
    auto expected = ReadLengthState::Untested;
    stateValue.compare_exchange_strong(expected, ReadLengthState::Accepted, std::memory_order_acq_rel);
}

void ReadLengthPolicy::demoteToShort() noexcept
{
    stateValue.store(ReadLengthState::Short, std::memory_order_release);
}

APDUCommand learnReadLengthCommand()
{
    return APDUCommand{0x00, 0xB0, 0x81, 0x00, {}, kUndeclaredExtendedLe, true};
}

std::optional<std::size_t> parseExtendedLengthInfo(std::span<const std::uint8_t> efAtrInfo)
{
    const std::uint8_t* data = efAtrInfo.data();
    const std::size_t size = efAtrInfo.size();

    std::size_t pos = 0;
    while (pos < size) {
        const auto tag = tryParseTag(data, size, pos);
        if (!tag.ok) {
            return std::nullopt;
        }
        const auto len = tryParseLength(data, size, tag.next);
        if (!len.ok || len.length > size - len.next) {
            return std::nullopt;
        }
        if (tag.tag == kExtendedLengthInfoTag) {
            // Two INTEGERs: maximum command size, then maximum response size.
            std::size_t p = len.next;
            const std::size_t end = len.next + len.length;
            std::optional<std::size_t> second;
            for (int i = 0; i < 2; ++i) {
                if (p >= end || data[p] != kIntegerTag) {
                    return std::nullopt;
                }
                const auto il = tryParseLength(data, end, p + 1);
                if (!il.ok || il.length == 0 || il.length > 4 || il.length > end - il.next) {
                    return std::nullopt;
                }
                std::size_t v = 0;
                for (std::size_t k = 0; k < il.length; ++k) {
                    v = (v << 8) | data[il.next + k];
                }
                second = v;
                p = il.next + il.length;
            }
            return second;
        }
        pos = len.next + len.length;
    }
    return std::nullopt;
}

bool isReadSuccess(const APDUResponse& answer) noexcept
{
    const std::uint16_t sw = answer.statusWord();
    return sw == 0x9000 || sw == 0x6282;
}

std::pair<ReadLengthState, std::size_t> classifyLearnAnswer(const std::expected<APDUResponse, TransportError>& answer,
                                                            ReadLengthState before)
{
    if (!answer) {
        return {ReadLengthState::Short, 0};
    }
    if (isReadSuccess(*answer)) {
        if (const auto declared = parseExtendedLengthInfo(answer->data)) {
            if (*declared <= kShortResponseMax) {
                return {ReadLengthState::Short, 0};
            }
            return {ReadLengthState::Declared, *declared};
        }
        return {ReadLengthState::Accepted, 0};
    }
    if (answer->sw1 == 0x67 && before == ReadLengthState::Untested) {
        return {ReadLengthState::Short, 0};
    }
    return {before, 0};
}

std::size_t maxSmProtectedData(std::size_t responseMax, std::size_t blockSize)
{
    if (blockSize == 0) {
        return 0;
    }
    std::size_t len = std::min(responseMax, kMaxLe);
    while (len > 0 && smResponseSize(len, blockSize) > responseMax) {
        --len;
    }
    return len;
}

bool isReadBinary(const APDUCommand& cmd) noexcept
{
    return (cmd.ins == 0xB0 || cmd.ins == 0xB1) && cmd.hasLe;
}

std::size_t requestedLe(const APDUCommand& cmd) noexcept
{
    return cmd.le == 0 ? kShortLe : cmd.le;
}

} // namespace LibreSCRS::SmartCard::Internal
