// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief FNV-1a 32-bit derivation of @c CK_SLOT_ID from
///        @c (readerName, pinId, slotKind). See @ref
///        LibreSCRS::Pkcs11::Internal::computeSlotId.

#include "internal/SlotIdHash.h"

namespace LibreSCRS::Pkcs11::Internal {

namespace {

/// @brief FNV-1a 32-bit offset basis (per FNV reference spec).
constexpr std::uint32_t kFnv1aOffsetBasis = 0x811c9dc5UL;

/// @brief FNV-1a 32-bit prime (per FNV reference spec).
constexpr std::uint32_t kFnv1aPrime = 0x01000193UL;

/// @brief Mix one byte into the running FNV-1a hash.
[[nodiscard]] constexpr std::uint32_t fnv1aMixByte(std::uint32_t state, std::uint8_t byte) noexcept
{
    state ^= static_cast<std::uint32_t>(byte);
    state *= kFnv1aPrime;
    return state;
}

/// @brief Mix every byte of a string view into the running FNV-1a hash.
[[nodiscard]] std::uint32_t fnv1aMixBytes(std::uint32_t state, std::string_view bytes) noexcept
{
    for (char ch : bytes) {
        state = fnv1aMixByte(state, static_cast<std::uint8_t>(ch));
    }
    return state;
}

/// @brief Mix every byte of a span into the running FNV-1a hash.
[[nodiscard]] std::uint32_t fnv1aMixBytes(std::uint32_t state, std::span<const std::uint8_t> bytes) noexcept
{
    for (std::uint8_t byte : bytes) {
        state = fnv1aMixByte(state, byte);
    }
    return state;
}

} // namespace

std::string_view slotKindTag(SlotKind kind) noexcept
{
    switch (kind) {
    case SlotKind::Auth:
        return "auth";
    case SlotKind::Sign:
        return "sign";
    case SlotKind::Enc:
        return "enc";
    case SlotKind::Generic:
        return "generic";
    }
    // Unreachable — exhaustive enum covered above. Defensive fallback to
    // keep the compiler happy without a no-default-case warning.
    return "generic";
}

std::uint32_t computeSlotId(std::string_view readerName, std::span<const std::uint8_t> pinId, SlotKind kind) noexcept
{
    std::uint32_t state = kFnv1aOffsetBasis;
    state = fnv1aMixBytes(state, readerName);
    state = fnv1aMixByte(state, static_cast<std::uint8_t>(':'));
    state = fnv1aMixBytes(state, pinId);
    state = fnv1aMixByte(state, static_cast<std::uint8_t>(':'));
    state = fnv1aMixBytes(state, slotKindTag(kind));
    return state;
}

} // namespace LibreSCRS::Pkcs11::Internal
