// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief FNV-1a-based stable @c CK_SLOT_ID derivation for the
///        multi-PIN PKCS#11 slot model.
///
/// The PKCS#11 v2.40 ABI exposes slots through opaque numeric handles
/// (@c CK_SLOT_ID). In the multi-PIN refactor a single physical card
/// surfaces N slots — one per authenticator — and the same physical
/// (reader, PIN) pair must map back to the same numeric handle across
/// reconnects. Hashing @c (readerName, pinId, slotKind) with FNV-1a
/// gives us a deterministic 32-bit identifier that is collision-free
/// at realistic cardinalities (≤ 32 readers × 4 PINs × 4 kinds) and
/// trivially recomputable on reconnect.

#include <cstdint>
#include <span>
#include <string_view>

namespace LibreSCRS::Pkcs11::Internal {

/// @brief Logical kind of a PKCS#11 slot.
///
/// Used as one of three FNV-1a inputs alongside the reader name and the
/// PIN identifier to derive a stable @c CK_SLOT_ID. Distinguishing kind
/// lets the same physical (reader, pinId) pair surface multiple
/// independent slots when a card splits one PIN over several
/// mechanism-specific tokens.
///
/// @since 4.1
enum class SlotKind : std::uint8_t {
    /// @brief Authentication slot (e.g. eID Auth PIN).
    Auth,
    /// @brief Signing slot (e.g. eID Signing PIN).
    Sign,
    /// @brief Encryption / decryption slot.
    Enc,
    /// @brief Generic / single-PIN family slot.
    Generic,
};

/// @brief Compute a stable 32-bit @c CK_SLOT_ID from
///        @c (readerName, pinId, slotKind).
/// @param readerName PC/SC reader name.
/// @param pinId      PKCS#15 PIN identifier (path or ID byte string);
///                   may be empty for ref-only schemes.
/// @param kind       Logical slot kind; see @ref SlotKind.
/// @return FNV-1a 32-bit hash of the concatenation
///         @c readerName "::" pinId "::" slotKindTag(kind), suitable
///         for use as a @c CK_SLOT_ID.
/// @par Thread-safety
/// Pure function; no shared state. Safe from any thread.
/// @since 4.1
[[nodiscard]] std::uint32_t computeSlotId(std::string_view readerName, std::span<const std::uint8_t> pinId,
                                          SlotKind kind) noexcept;

/// @brief Stable ASCII tag for a @ref SlotKind, used both inside the
///        FNV-1a mixer and for diagnostic logging.
/// @param kind Slot kind to stringify.
/// @return One of @c "auth", @c "sign", @c "enc", @c "generic". Returned
///         @c string_view is backed by static storage and remains valid
///         indefinitely.
/// @par Thread-safety
/// Pure function; no shared state. Safe from any thread.
/// @since 4.1
[[nodiscard]] std::string_view slotKindTag(SlotKind kind) noexcept;

} // namespace LibreSCRS::Pkcs11::Internal
