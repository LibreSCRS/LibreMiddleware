// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Secure::Buffer — cleansing byte buffer for
///        short-lived secret material (PIN / PUK / key bytes); pimpl-backed,
///        move-only, zeroed on destruction and on move-from.

#include <LibreSCRS/Export.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace LibreSCRS::Secure {

/// @brief Cleansing byte buffer for short-lived secret material.
///
/// Zeroes its storage on destruction and on move-from; see @par Cleanse
/// semantics below. Domain-agnostic — used by credential collection, signing
/// internals, and any caller holding PIN/PUK/token/key bytes transiently.
///
/// Move-only; copy is deleted to prevent accidental duplication of secrets.
///
/// @par Copy semantics
/// @ref Buffer is **move-only** to prevent accidental duplication of secret
/// material. Sibling @ref Secure::String chooses the opposite stance —
/// copyable with per-copy cleansing — because string secrets (PINs, passwords)
/// are typically short-lived and benefit from `std::optional` /
/// container-of-string composability. The two stances are intentional, not
/// drift; secret-byte material is more often passed through a single
/// owner via `std::move` while text secrets often need optional/container
/// embedding. Choose @ref String for human-typed secrets, @ref Buffer for
/// derived/binary secrets.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). A @ref Buffer instance is NOT
/// internally synchronised: concurrent access from multiple threads to the
/// same instance is undefined. Treat each @ref Buffer as owned by a single
/// thread for the duration of a sign / verify / authenticate call; pass
/// ownership across threads via the move constructor. Distinct @ref Buffer
/// instances are independent and may be used in parallel without external
/// synchronisation.
///
/// @par Cleanse semantics
/// Cleansing happens in two places: the internal `secure_allocator<T>`'s
/// `deallocate` hook for heap-allocated bytes (every freed allocation is
/// passed through `OPENSSL_cleanse` before reaching `::operator delete`),
/// and the embedding pimpl's destructor for any in-line short-buffer-
/// optimised bytes that never reach the allocator. Together this
/// guarantees every byte that ever held secret material is zeroised
/// before the storage is freed. Future growth APIs (`reserve`,
/// `push_back`, etc.) automatically inherit the allocator-level path; no
/// per-method discipline is required.
///
/// @warning `Buffer(std::string_view)` copies into the buffer; it CANNOT
///          reach into the caller's storage to cleanse it. Callers holding
///          secret material in a std::string / QString must cleanse their
///          own copy after constructing the Buffer.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API Buffer
{
public:
    /// @brief Construct an empty buffer (size() == 0, data() == nullptr).
    /// @note No heap allocation — the pimpl is left unallocated until a
    ///       sized constructor is invoked or move-assignment installs one.
    /// @since 4.0
    Buffer();

    /// @brief Construct a buffer of @p size bytes, filled with @p fill.
    /// @param size Number of bytes to allocate.
    /// @param fill Byte value used to initialise every byte of the new
    ///             buffer. Defaults to @c 0.
    /// @throws std::bad_alloc on allocation failure.
    /// @since 4.0
    explicit Buffer(std::size_t size, std::uint8_t fill = 0);

    /// @brief Copy @p s into the buffer's storage.
    /// @note The caller's `s` is not cleansed by this constructor.
    /// @throws std::bad_alloc on allocation failure.
    explicit Buffer(std::string_view s);

    /// @brief Copy @p bytes into the buffer's storage.
    ///
    /// Binary-friendly companion to the @ref Buffer(std::string_view)
    /// overload; intended for APDU responses, raw key material, and any
    /// caller-owned buffer that is naturally a byte span rather than a
    /// character range.
    /// @note The caller's @p bytes is not cleansed by this constructor.
    /// @throws std::bad_alloc on allocation failure.
    /// @since 4.0
    explicit Buffer(std::span<const std::uint8_t> bytes);

    /// @brief Cleanse the buffer's storage.
    ~Buffer();

    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    /// @brief Move-construct; @p other is left empty (size() == 0, data() == nullptr).
    Buffer(Buffer&&) noexcept;
    /// @brief Move-assign; this buffer's current storage is cleansed before
    ///        adopting @p other. After return @p other is empty.
    Buffer& operator=(Buffer&&) noexcept;

    /// @brief True when this object owns a concrete pimpl.
    ///
    /// Equivalent to "not default-constructed AND not moved-from". The
    /// default ctor leaves the pimpl unallocated as an optimisation (empty
    /// buffers need no heap storage), so `Buffer{}` also evaluates to
    /// @c false here — distinct from a sized-but-all-zero buffer, which
    /// evaluates to @c true. Callers that need "is there any stored data?"
    /// should check @c size() > 0 instead. Accessors (@ref data, @ref size)
    /// remain safe to call on an unallocated buffer and report empty state.
    /// @since 4.0
    explicit operator bool() const noexcept;

    /// @brief Pointer to the first byte, or nullptr when empty.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3. Safe to call on
    ///       a default-constructed or moved-from buffer (returns @c nullptr).
    /// @note The returned pointer aliases storage owned by this buffer and
    ///       is invalidated by move-assign or destruction.
    /// @since 4.0
    [[nodiscard]] const std::uint8_t* data() const noexcept;

    /// @brief Number of bytes held.
    /// @note Pure accessor, @c noexcept per API-POLICY §5.3. Safe to call on
    ///       a default-constructed or moved-from buffer (returns @c 0).
    /// @since 4.0
    [[nodiscard]] std::size_t size() const noexcept;

    /// @brief Byte-identity equality.
    ///
    /// Returns @c true iff both buffers carry the same number of bytes
    /// AND those bytes are pairwise identical. Mirrors the equality
    /// semantics of @ref Secure::String (which has @c operator== for the
    /// same reason — typed equality without unwrapping the secret).
    ///
    /// @note Like @ref Secure::String::operator==, this comparator is
    ///       byte-wise NOT constant-time. For PIN/MAC/secret-equality
    ///       checks against an attacker-controlled side channel, use a
    ///       dedicated constant-time helper rather than this operator.
    ///       A constant-time comparator is on the 4.1 backlog.
    ///
    /// @since 4.0
    [[nodiscard]] bool operator==(const Buffer& other) const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Secure
