// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "apdu.h"

#include <LibreSCRS/SmartCard/TransportError.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <utility>

namespace LibreSCRS::SmartCard::Internal {

// Le tried on a card that has not said what it accepts.
inline constexpr std::uint16_t kUndeclaredExtendedLe = 2048;
// The longest Le every card accepts.
inline constexpr std::uint16_t kShortLe = 256;
// The largest Le a command can carry (extended length).
inline constexpr std::size_t kMaxLe = 65535;

enum class ReadLengthState : std::uint8_t {
    Untested, // no answer yet
    Accepted, // a command with Le > 256 succeeded
    Declared, // the card announced its maximum response APDU size
    Short     // 256 only
};

// What Le the transport may send on one connection. Thread-safety: the state is
// atomic, and so is the declared size, which is written together with it in learn().
class ReadLengthPolicy
{
public:
    void learn(ReadLengthState s, std::size_t declaredResponseMax = 0) noexcept;
    [[nodiscard]] ReadLengthState state() const noexcept;
    [[nodiscard]] std::size_t declaredResponseMax() const noexcept;

    // Largest Le the transport may send; smBlockSize 0 is the plain channel.
    [[nodiscard]] std::size_t allowedLe(std::size_t smBlockSize) const noexcept;

    void markAccepted() noexcept; // only from Untested
    void demoteToShort() noexcept;

private:
    std::atomic<ReadLengthState> stateValue{ReadLengthState::Untested};
    std::atomic<std::size_t> declaredMax{0};
};

// READ BINARY on SFI 1 with Le 2048: the command whose answer shows which Le the card accepts.
// Sent in plain only, just before secure messaging starts, never while it is established.
APDUCommand learnReadLengthCommand();

// Maximum response APDU size from DO 7F66 of EF.ATR/INFO (the second INTEGER).
std::optional<std::size_t> parseExtendedLengthInfo(std::span<const std::uint8_t> efAtrInfo);

// An answer that carries data the card read: 9000, or 6282 (end of file reached).
bool isReadSuccess(const APDUResponse& answer) noexcept;

// Turns the answer to the learning command into a state, given the state the connection
// was in (Untested or Accepted); the second member is the declared size. A wrong-length
// answer shows a short-only card only from Untested, and any other refusal changes nothing.
std::pair<ReadLengthState, std::size_t> classifyLearnAnswer(const std::expected<APDUResponse, TransportError>& answer,
                                                            ReadLengthState before);

// Largest plain payload whose secure-messaging response still fits responseMax bytes.
std::size_t maxSmProtectedData(std::size_t responseMax, std::size_t blockSize);

bool isReadBinary(const APDUCommand& cmd) noexcept;
std::size_t requestedLe(const APDUCommand& cmd) noexcept; // le 0 means 256

} // namespace LibreSCRS::SmartCard::Internal
