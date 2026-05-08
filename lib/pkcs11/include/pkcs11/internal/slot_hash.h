// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// LibreMiddleware-internal helper. NOT part of the PKCS#11 public surface
// — third-party PKCS#11 consumers (Firefox, Adobe, Mozilla NSS) MUST NOT
// include this header. The `internal/` subdirectory is the convention.
//
// Purpose: a stable, self-contained 32-bit hash of an arbitrary-length
// PCSC reader name, used to disambiguate PKCS#11 slots when two readers
// share a 64-byte `CK_SLOT_INFO::slotDescription` prefix (the spec's
// fixed-buffer limit causes truncation on long real-world reader names).
//
// Both ends of the LM signing path agree on this single hash function:
//
//   1. `lib/pkcs11/src/pkcs11_library.cpp` — the LM PKCS#11 module
//      formats `slotDescription` as
//        "LibreSCRS [<8-hex-hash>] <readable-suffix>"
//      where <8-hex-hash> = fnv1a32(fullReaderName).
//
//   2. `lib/libresign/src/native/pkcs11_token.cpp` — Pkcs11Token's slot
//      lookup computes fnv1a32(callerSuppliedReaderName) and scans
//      `slotDescription` for the matching `[<hash>]` substring.
//
// The hash needs to be:
//   * deterministic (same bytes in → same bytes out across compilers,
//     archs, optimisation levels — `std::hash` is implementation-defined
//     and therefore unsuitable),
//   * collision-resistant enough for the use case (32 bits ≈ 4×10⁹ space;
//     collision probability for 100 distinct readers is ~5×10⁻⁶ — never
//     hit in practice),
//   * dependency-free (we don't pull zlib for one helper).
//
// FNV-1a 32-bit fits all three. Constants are RFC-grade fixed
// (offset basis 0x811c9dc5, prime 0x01000193); the algorithm is
// well-known, well-defined, and not deprecated. See
// http://www.isthe.com/chongo/tech/comp/fnv/ for the canonical
// reference.

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "<pkcs11/internal/slot_hash.h> is internal to LibreMiddleware. \
Public PKCS#11 consumers should use the standard <pkcs11/pkcs11.h> headers \
and discover slots via C_GetSlotList + C_GetSlotInfo."
#endif

#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace librescrs::pkcs11::internal {

/// @brief FNV-1a 32-bit hash of the given byte sequence.
///
/// Pure, `constexpr`, no allocations. Deterministic across compilers and
/// architectures by virtue of the fixed RFC constants (offset basis
/// 0x811c9dc5, prime 0x01000193) and the standard byte-wise traversal
/// order. Two LibreSCRS binaries (the PKCS#11 module dlopened into the
/// host process, and the libresign signing engine linked into the same
/// process) compiled separately MUST yield identical hashes for the
/// same input — and they will, because this is a pure header definition
/// with no implementation-defined behaviour.
///
/// @param data UTF-8 encoded reader name (`std::string_view` for
///        zero-copy at the call site).
/// @return 32-bit unsigned hash.
[[nodiscard]] constexpr std::uint32_t fnv1a32(std::string_view data) noexcept
{
    std::uint32_t hash = 0x811c9dc5u; // FNV offset basis
    for (char c : data) {
        hash ^= static_cast<std::uint8_t>(c);
        hash *= 0x01000193u; // FNV prime
    }
    return hash;
}

/// @brief Format the 32-bit hash as a fixed-width 8-character lowercase
///        hex string. The output is always exactly 8 ASCII characters
///        — never shorter, never longer — which makes it parseable from
///        a fixed-position substring inside @c CK_SLOT_INFO::slotDescription.
///
/// @return std::array<char, 8> filled with hex digits (no NUL terminator;
///         not a C string). Use `.data()` + size 8 to copy into a
///         char buffer or construct a `std::string_view`.
[[nodiscard]] constexpr std::array<char, 8> toHex8(std::uint32_t hash) noexcept
{
    constexpr std::array<char, 16> hexDigits{'0', '1', '2', '3', '4', '5', '6', '7',
                                              '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::array<char, 8> out{};
    for (int i = 7; i >= 0; --i) {
        out[i] = hexDigits[hash & 0xFu];
        hash >>= 4;
    }
    return out;
}

/// @brief Compile-time test vectors verifying canonical FNV-1a output.
///        These match the published reference test vectors at
///        http://www.isthe.com/chongo/tech/comp/fnv/test_vectors.html
///        (32-bit FNV-1a). Any maintainer that "optimises" the constants
///        or traversal order trips the static_assert at build time
///        rather than producing silently-divergent hashes.
static_assert(fnv1a32("") == 0x811c9dc5u, "FNV-1a empty-input invariant");
static_assert(fnv1a32("a") == 0xe40c292cu, "FNV-1a 'a' canonical vector");
static_assert(fnv1a32("foobar") == 0xbf9cf968u, "FNV-1a 'foobar' canonical vector");

/// @brief Length of the formatted hash bracket inside slotDescription:
///        `"[<8-hex>] "` = 11 ASCII chars.
inline constexpr std::size_t kSlotHashBracketLen = 11;

/// @brief Format a `CK_SLOT_INFO::slotDescription` for the given reader.
///
/// Writes
///
///     "[<8-hex-hash>] <readable-prefix-of-readerName>"
///
/// into @p out (assumed @c CK_SLOT_INFO::slotDescription[64], blank-padded
/// per PKCS#11 spec — caller MUST `std::memset(out, ' ', 64)` before
/// calling, NOT zero-pad). The bracket gives Pkcs11Token a stable,
/// truncation-immune handle for slot disambiguation; the readable suffix
/// gives `pkcs11-tool --list-slots` users a recognisable reader name.
///
/// `manufacturerID` is set separately by the caller to "LibreSCRS"; the
/// brand prefix is intentionally NOT duplicated here so the 53 bytes
/// after the bracket can hold as much of the reader name as possible.
inline void formatSlotDescription(std::string_view readerName, char* out) noexcept
{
    const auto hash = fnv1a32(readerName);
    const auto hex = toHex8(hash);
    out[0] = '[';
    for (std::size_t i = 0; i < 8; ++i)
        out[1 + i] = hex[i];
    out[9] = ']';
    out[10] = ' ';
    // Copy as much of readerName as fits into the remaining 53 bytes.
    // PKCS#11 spec mandates blank-padding to 64; caller pre-fills with
    // spaces, so unused tail stays 0x20 — no need to write spaces here.
    constexpr std::size_t kTailBudget = 64 - kSlotHashBracketLen;
    const auto copyLen = readerName.size() < kTailBudget ? readerName.size() : kTailBudget;
    for (std::size_t i = 0; i < copyLen; ++i)
        out[kSlotHashBracketLen + i] = readerName[i];
}

/// @brief Inverse of @ref formatSlotDescription: extract the embedded
///        hash from a slot's `slotDescription` if the bracket convention
///        is present.
///
/// @param slotDesc 64-byte view of `CK_SLOT_INFO::slotDescription`
///                 (caller may pass `std::string_view{buf, 64}`).
/// @return The 32-bit hash on success, or 0 on shape mismatch (i.e.
///         the slot was not produced by a LibreSCRS PKCS#11 module).
///         A return of 0 should be treated as "not our slot" by the
///         caller — fnv1a32 of any plausible reader name is essentially
///         never zero (the empty string is the only input that hashes
///         to 0x811c9dc5, never to 0).
[[nodiscard]] inline std::uint32_t parseSlotHash(std::string_view slotDesc) noexcept
{
    if (slotDesc.size() < kSlotHashBracketLen)
        return 0;
    if (slotDesc[0] != '[' || slotDesc[9] != ']' || slotDesc[10] != ' ')
        return 0;
    std::uint32_t hash = 0;
    for (std::size_t i = 1; i <= 8; ++i) {
        const char c = slotDesc[i];
        std::uint32_t nibble = 0;
        if (c >= '0' && c <= '9')
            nibble = static_cast<std::uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
            nibble = static_cast<std::uint32_t>(c - 'a' + 10);
        else
            return 0; // not a hex char — shape mismatch
        hash = (hash << 4) | nibble;
    }
    return hash;
}

} // namespace librescrs::pkcs11::internal
