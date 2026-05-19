// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "lib/LibreSCRS/detail/cancel_bridge.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief Internal-only bridge between @ref LibreSCRS::CancelToken and
///        @c std::stop_token, used by LibreMiddleware internals that
///        integrate with @c std::jthread (TrustStoreService, libresign).
///
/// @warning This header is **not** installed and is **not** part of the
///          public ABI. External consumers must not include it; future
///          releases may change or remove it without notice.
///
/// @par ABI rationale
/// `std::stop_token` deliberately does NOT appear in any exported symbol
/// of the LibreMiddleware public ABI: cross-toolchain `<stop_token>` ABI
/// (libstdc++ vs Apple libc++ with `-fexperimental-library`) is the
/// kind of standard-library
/// implementation detail the public API explicitly hides behind
/// @ref LibreSCRS::CancelToken. Both @ref CancelTokenInternalAccess and
/// @ref stopTokenFrom are therefore defined inline in this header so the
/// SHARED-build `.so` files do not export an `std::stop_token`-typed
/// entry point. Cross-`.so` calls to @ref stopTokenFrom are inlined into
/// the caller's translation unit — there is no symbol to resolve.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>

#include <memory>
#include <stop_token>

namespace LibreSCRS {

/// @brief LM-internal definition of @ref CancelToken's pimpl. Defined here
///        — not in the public header — so internal LM sources can inline
///        access to the underlying @c std::stop_source without any
///        @c std::stop_token-typed entry point appearing in the public
///        SHARED-build symbol set.
class LIBRESCRS_INTERNAL CancelToken::Impl
{
public:
    std::stop_source source;
};

namespace detail {

/// @brief LM-internal access to @ref CancelToken's pimpl. Friended by
///        @ref CancelToken (public-header forward declaration); fully
///        inline so no symbol is emitted for it.
class LIBRESCRS_INTERNAL CancelTokenInternalAccess
{
public:
    [[nodiscard]] static std::shared_ptr<CancelToken::Impl> impl(const CancelToken& token) noexcept
    {
        return token.d;
    }
};

/// @brief Internal: extract the underlying @c std::stop_token. Returns a
///        never-stoppable token (default-constructed @c std::stop_token)
///        when @p token is the never-cancellable default.
///
/// @note Fully inline — no @c .so symbol is emitted. Cross-`.so` callers
/// (e.g. `LibreSCRS_Trust` calling into the bridge from
/// `TrustStoreService.cpp`) inline the body in their own translation
/// unit. The public ABI therefore does not contain any
/// @c std::stop_token-typed entry point; the public cooperative-cancel
/// mechanism remains @ref CancelToken.
[[nodiscard]] inline std::stop_token stopTokenFrom(const CancelToken& token) noexcept
{
    auto impl = CancelTokenInternalAccess::impl(token);
    return impl ? impl->source.get_token() : std::stop_token{};
}

} // namespace detail
} // namespace LibreSCRS
