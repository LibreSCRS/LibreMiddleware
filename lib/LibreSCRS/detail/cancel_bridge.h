// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Internal-only bridge between @ref LibreSCRS::CancelToken and
///        @c std::stop_token, used by LibreMiddleware internals that
///        integrate with @c std::jthread (TrustStoreService, libresign).
///
/// @warning This header is **not** installed and is **not** part of the
///          public ABI. External consumers must not include it; future
///          releases may change or remove it without notice.

#include <LibreSCRS/CancelToken.h>

#include <stop_token>

namespace LibreSCRS::detail {

/// @brief Internal: extract the underlying @c std::stop_token. Returns a
///        never-stoppable token (default-constructed @c std::stop_token)
///        when @p token is the never-cancellable default.
[[nodiscard]] std::stop_token stopTokenFrom(const CancelToken& token) noexcept;

} // namespace LibreSCRS::detail
