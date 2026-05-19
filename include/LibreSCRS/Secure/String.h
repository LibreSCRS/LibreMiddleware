// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Secure::String — cleansing string companion to
///        @ref LibreSCRS::Secure::Buffer, used for PIN text input and any
///        other @c std::string-shaped secret that must be zeroed on
///        destruction.

#include <LibreSCRS/Export.h>

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>

namespace LibreSCRS::Secure {

/// @brief Cleansing string-like type for short-lived secret text material.
///
/// Zeroes its storage on destruction, on assignment (before adopting the new
/// value), on @ref clear, and on move-from; see @par Cleanse semantics below.
/// Domain-agnostic — used by TSA credentials, bearer tokens, passphrases,
/// and any caller holding secret text bytes transiently.
///
/// Unlike @ref Buffer, this type is **copyable**. Each copy owns an
/// independent, separately-cleansed storage block. This is deliberate:
/// `std::optional<Secure::String>` composition and ergonomic value-semantic
/// use (passing credentials through function arguments, storing in
/// configuration structs) are worth more than the marginal safety gain of
/// forbidding duplication outright.
///
/// @par Copy semantics
/// @ref String is **copyable** with per-copy cleansing. Sibling @ref
/// Secure::Buffer chooses the opposite stance — move-only, copy deleted —
/// because byte/binary secret material (derived keys, APDU responses,
/// signing intermediates) is more naturally passed through a single owner
/// via `std::move`. The two stances are intentional, not drift; text
/// secrets such as human-typed PINs / passphrases benefit from
/// `std::optional` / container composability that `Buffer` deliberately
/// forgoes. Choose @ref String for human-typed secrets, @ref Buffer for
/// derived/binary secrets.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). A single @ref String instance is
/// NOT internally synchronised: concurrent access from multiple threads to
/// the same instance is undefined. Distinct @ref String instances (including
/// independently-allocated copies of the same secret) may be used in
/// parallel without external synchronisation. Pass ownership across threads via the move
/// constructor; share read-only access via independent copies, not via
/// references to a shared instance.
///
/// @par Cleanse semantics
/// Cleanse-on-free is implemented at the allocator level (an internal
/// `secure_allocator<T>`). Every freed allocation is passed through
/// `OPENSSL_cleanse` before reaching `::operator delete`. Future growth
/// APIs (`reserve`, `push_back`, etc.) automatically inherit this
/// invariant; no per-method discipline is required.
///
/// @warning @ref view returns a `std::string_view` that references memory
///          owned by this instance. The view is invalidated by any mutation
///          (@ref clear, @ref operator=, move-assign) and by destruction.
///          Callers must not let the view outlive the @ref String.
///
/// @warning Constructors from `std::string_view` / `const char*` copy into
///          this object's storage; they CANNOT reach into the caller's
///          source buffer to cleanse it. Callers holding secret material in
///          a `std::string` / `QString` must cleanse their own copy after
///          constructing the @ref String.
///
/// @note Comparison (@ref operator==) is byte-identity, not constant-time.
///       Credential-equality checks on untrusted input should use
///       @ref equalConstantTime — provided by this class — when timing
///       side-channels matter to the deployment.
///
/// @since 4.0
class LIBRESCRS_PUBLIC_API String
{
public:
    /// @brief Construct an empty string (size() == 0, view() is empty).
    /// @note No heap allocation — the pimpl is left unallocated until a
    ///       valued constructor is invoked or assignment installs one.
    /// @since 4.0
    String();

    /// @brief Copy @p s into the string's storage.
    /// @note The caller's @p s is not cleansed by this constructor.
    /// @throws std::bad_alloc on allocation failure.
    explicit String(std::string_view s);

    /// @brief Copy the null-terminated @p s into the string's storage.
    /// @param s Must be a valid null-terminated C string (not nullptr).
    /// @note The caller's @p s is not cleansed by this constructor.
    /// @throws std::bad_alloc on allocation failure.
    explicit String(const char* s);

    /// @brief Adopt-and-cleanse from an rvalue @c std::string.
    ///
    /// Bytes of @p src are copied into this object's cleansing storage; the
    /// source's bytes (whether held in the heap allocation or the SSO inline
    /// buffer) are then zeroed via @c OPENSSL_cleanse before the moved-from
    /// rvalue is destroyed. The cleanse runs on every exit path including
    /// exception propagation from the inner allocation, so a thrown
    /// @c std::bad_alloc still leaves @p src zeroed.
    ///
    /// Use this overload at boundaries where a callee returns secret text as
    /// a @c std::string (e.g. @c QString::toStdString, JSON parsers, env
    /// readers): wrap the rvalue directly so no plaintext copy outlives the
    /// constructor call.
    ///
    /// @par Allocator note
    /// The internal storage uses a cleansing allocator (see @par Cleanse
    /// semantics); allocations cannot be moved between allocator domains, so
    /// this constructor copies bytes rather than transferring ownership of
    /// @p src's allocation.
    /// @throws std::bad_alloc on allocation failure during the internal
    ///         copy; @p src is still zeroised before propagation (see body
    ///         description above).
    /// @since 4.0
    explicit String(std::string&& src);

    /// @brief Cleanse the string's storage.
    ~String();

    /// @brief Copy-construct; @p other is not modified. This String owns a
    ///        separate, independently-cleansed storage block.
    /// @throws std::bad_alloc on allocation failure.
    String(const String& other);

    /// @brief Copy-assign. This String's current storage is cleansed before
    ///        adopting a copy of @p other. After return, @p other is
    ///        unchanged and this String holds a separate cleansed block.
    /// @throws std::bad_alloc on allocation failure.
    String& operator=(const String& other);

    /// @brief Move-construct; @p other is left empty (size() == 0).
    String(String&& other) noexcept;

    /// @brief Move-assign; this String's current storage is cleansed before
    ///        adopting @p other. After return @p other is empty.
    String& operator=(String&& other) noexcept;

    /// @brief True when this object owns a concrete pimpl.
    ///
    /// Equivalent to "not default-constructed AND not moved-from". The
    /// default ctor leaves the pimpl unallocated (empty strings need no
    /// heap storage), so `String{}` evaluates to @c false here. Callers
    /// that need the "no stored bytes" predicate should use @ref empty
    /// — which remains well-defined on both unallocated and moved-from
    /// instances. Like the other accessors on this type, @ref empty,
    /// @ref size, @ref view and @ref clear are all null-safe.
    /// @since 4.0
    explicit operator bool() const noexcept;

    /// @brief True when size() == 0.
    [[nodiscard]] bool empty() const noexcept;

    /// @brief Number of bytes held (excluding any trailing NUL, since the
    ///        storage is not null-terminated).
    [[nodiscard]] std::size_t size() const noexcept;

    /// @brief View of the stored bytes. The returned view is valid only for
    ///        the lifetime of this @ref String and is invalidated by any
    ///        mutation or destruction. See class-level @warning.
    [[nodiscard]] std::string_view view() const noexcept;

    /// @brief Cleanse the current storage and leave the String empty. Any
    ///        previously-returned @ref view into this String becomes
    ///        invalid.
    void clear() noexcept;

    /// @brief Byte-identity comparison. Not constant-time; see @note above.
    /// @note C++20 synthesises @c operator!= from this declaration; no
    ///       hand-written inequality operator is required.
    [[nodiscard]] bool operator==(const String& other) const noexcept;

    /// @brief Constant-time byte-identity comparison.
    ///
    /// Use when comparing user-supplied secrets (PIN candidate vs. expected
    /// PIN, MAC tag vs. computed MAC, capability token vs. registered token)
    /// against a stored reference, where the comparison runtime must not
    /// vary with the position of the first differing byte. The
    /// implementation runs in time proportional to @ref size of the longer
    /// input regardless of how many leading bytes match. Inputs of unequal
    /// size compare unequal but the routine still consumes the bytes of the
    /// longer input to keep the timing profile stable across length
    /// differences.
    ///
    /// @par Implementation
    /// Uses OpenSSL's @c CRYPTO_memcmp internally. OpenSSL is a private LM
    /// dependency already linked by the Secure target; the .cpp is the only
    /// translation unit that pulls @c <openssl/crypto.h>, so consumers do
    /// not see the dependency.
    ///
    /// @param other The reference @ref String to compare against.
    /// @return @c true iff @c size() == other.size() AND every byte
    ///         matches; @c false otherwise.
    /// @note @c noexcept: no allocation, no exceptions thrown by
    ///       @c CRYPTO_memcmp.
    /// @since 4.0
    [[nodiscard]] bool equalConstantTime(const String& other) const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Secure
