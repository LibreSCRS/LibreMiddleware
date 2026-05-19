// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Public cooperative-cancellation primitive
///        @ref LibreSCRS::CancelToken (plus @ref LibreSCRS::CancelSource and
///        @ref LibreSCRS::CancelToken::Registration), and the @ref
///        LibreSCRS::Completion alias used by every async LibreMiddleware API.

#include <LibreSCRS/Export.h>

#include <functional>
#include <memory>

namespace LibreSCRS {

class CancelSource;

namespace detail {
class CancelTokenInternalAccess;
} // namespace detail

/// @brief Cooperative cancellation token. Pimpl-backed; semantically mirrors
///        @c std::stop_token (C++20 §32.3).
///
/// Default-constructed instances are never-cancellable and allocate nothing.
/// Tokens obtained from a @ref CancelSource share cancellation state with
/// the source.
///
/// @par Thread-safety
/// Mirrors @c std::stop_token's contract (C++20 §32.3.3 [stoptoken.intro]):
///  - **A single instance** of @ref CancelToken is NOT safe to use
///    concurrently from multiple threads. Concurrent copy / move / destroy
///    on the same instance, or concurrent observe (@ref isCancelled,
///    @ref isCancellable, @ref registerCallback) racing with copy / move /
///    destroy on that instance, is a data race. The internal
///    @c std::shared_ptr is bare, not @c std::atomic<std::shared_ptr>,
///    so only its control-block reference counting is atomic — the
///    pointer-pair instance itself is not.
///  - **Different instances** that share the same @ref CancelSource state
///    ARE safe to use concurrently from different threads. Each thread
///    holding its own copy of the token observes / registers / destroys
///    independently.
///  - @ref CancelSource::requestCancel and @ref isCancelled on
///    @ref CancelSource and @ref CancelToken are thread-safe (the
///    underlying @c std::stop_source / @c std::stop_token contract).
///
/// In practice every async LibreMiddleware API takes
/// @c CancelToken @c token by value, so the SDK implementation owns its
/// own copy on its own thread — the per-instance non-thread-safety is a
/// concern only when callers deliberately share a single instance across
/// threads.
/// @since 4.0
class LIBRESCRS_PUBLIC_API CancelToken
{
public:
    /// @brief Default: never-cancellable token. No allocation.
    /// @c isCancellable() returns false; @c isCancelled() returns false.
    CancelToken() noexcept;

    CancelToken(const CancelToken&) noexcept;
    CancelToken(CancelToken&&) noexcept;
    CancelToken& operator=(const CancelToken&) noexcept;
    CancelToken& operator=(CancelToken&&) noexcept;
    ~CancelToken();

    /// @par Moved-from state
    /// A moved-from @ref CancelToken is in a valid-but-unspecified state.
    /// The only operations that may be called on it are destruction and
    /// assignment; calling any observer (@ref isCancelled, @ref isCancellable,
    /// @ref registerCallback) on a moved-from token is undefined behaviour,
    /// matching @c std::stop_token (C++20 §32.3.3).

    /// @brief @c true if a @ref CancelSource owning this token's state has
    ///        called @ref CancelSource::requestCancel.
    [[nodiscard]] bool isCancelled() const noexcept;

    /// @brief @c true if a @ref CancelSource governs this token; @c false
    ///        for default-constructed tokens.
    [[nodiscard]] bool isCancellable() const noexcept;

    class Registration;

    /// @brief Register a callback invoked synchronously on the cancelling
    ///        thread when the associated @ref CancelSource is cancelled.
    /// @param callback Invocable; copied into internal storage.
    /// @return RAII handle. Destroying the handle unregisters the callback;
    ///         if the callback is currently executing on a different thread,
    ///         the destructor blocks until it completes
    ///         (per C++20 §32.3.4 [stopcallback.cons]/8).
    /// @warning Do NOT call @ref registerCallback from within an
    ///          already-firing callback on the same token; this deadlocks
    ///          @c std::stop_callback semantics. No runtime detection guard
    ///          is provided.
    /// @note If this token is the never-cancellable default, an empty
    ///       @ref Registration is returned and @p callback is discarded.
    /// @throws std::bad_alloc on allocation failure (internal
    ///         @c std::make_unique / @c std::stop_callback construction).
    ///         Callback move-construction may also propagate from the
    ///         supplied @c std::function. The function is therefore not
    ///         declared @c noexcept — keeping it so would route OOM
    ///         through @c std::terminate, which is wrong for an SDK
    ///         entry point that is reachable on every async API call.
    [[nodiscard]] Registration registerCallback(std::function<void()> callback);

private:
    friend class CancelSource;
    friend class detail::CancelTokenInternalAccess;

    class Impl;
    std::shared_ptr<Impl> d; // nullptr <=> never-cancellable
};

/// @brief RAII handle for a registered cancellation callback.
class LIBRESCRS_PUBLIC_API CancelToken::Registration
{
public:
    /// @brief Default: empty handle (no callback registered).
    Registration() noexcept;

    Registration(Registration&&) noexcept;
    Registration& operator=(Registration&&) noexcept;
    ~Registration();

    Registration(const Registration&) = delete;
    Registration& operator=(const Registration&) = delete;

private:
    friend class CancelToken;
    class Impl;
    /// @brief Pimpl pointer holding the wrapped @c std::stop_callback (if any).
    std::unique_ptr<Impl> d;
};

/// @brief Mirrors @c std::stop_source. Copyable; copies share cancellation
///        state. Allocates a single @c shared_ptr-managed @c Impl on
///        construction.
class LIBRESCRS_PUBLIC_API CancelSource
{
public:
    /// @brief Construct a fresh cancellation source. The associated
    ///        @ref token is cancellable.
    CancelSource();

    CancelSource(const CancelSource&) noexcept;
    CancelSource(CancelSource&&) noexcept;
    CancelSource& operator=(const CancelSource&) noexcept;
    CancelSource& operator=(CancelSource&&) noexcept;
    ~CancelSource();

    /// @par Moved-from state
    /// A moved-from @ref CancelSource is in a valid-but-unspecified state.
    /// The only operations that may be called on it are destruction and
    /// assignment; calling @ref token, @ref requestCancel, or
    /// @ref isCancelled on a moved-from source is undefined behaviour,
    /// matching @c std::stop_source (C++20 §32.3).

    /// @brief Returns a token that shares cancellation state with this source.
    [[nodiscard]] CancelToken token() const noexcept;

    /// @brief Idempotent. First call returns @c true and fires every
    ///        registered callback synchronously on the calling thread.
    ///        Subsequent calls return @c false.
    bool requestCancel() noexcept;

    /// @brief @c true once @ref requestCancel has succeeded.
    [[nodiscard]] bool isCancelled() const noexcept;

private:
    std::shared_ptr<CancelToken::Impl> d;
};

/// @brief Async completion callback. Always invoked on a LibreMiddleware-
///        managed background thread; consumers marshal to their UI thread
///        (e.g. @c QMetaObject::invokeMethod, Swift @c @MainActor).
///
/// Grouped with @ref CancelToken because the two compose into the
/// canonical async-API shape `(CancelToken, Completion<T>)`. Used by
/// inherently async LibreMiddleware APIs (e.g.
/// @ref LibreSCRS::Trust::TrustStoreService eager-fetch observer
/// notifications); synchronous public APIs do not require this type.
template <typename Result>
using Completion = std::function<void(Result)>;

} // namespace LibreSCRS
