// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/CancelToken.h>

// CancelToken::Impl + CancelTokenInternalAccess + stopTokenFrom (all inline,
// no exported symbols) live in this internal header so std::stop_token does
// not appear in the public SHARED-build ABI surface.
#include "detail/cancel_bridge.h"

#include <optional>
#include <stop_token>
#include <utility>

namespace LibreSCRS {

// CancelToken::Impl and detail::CancelTokenInternalAccess live in
// "detail/cancel_bridge.h" (see top-of-file include) so they can be
// reused by inline std::stop_token bridge code without any symbol
// being emitted by this translation unit.

class LIBRESCRS_INTERNAL CancelToken::Registration::Impl
{
public:
    // std::stop_callback is non-default-constructible; std::optional gives
    // an empty/disengaged state that matches the default Registration shape.
    std::optional<std::stop_callback<std::function<void()>>> callback;
};

// ---------- CancelToken ----------

CancelToken::CancelToken() noexcept = default;
CancelToken::CancelToken(const CancelToken&) noexcept = default;
CancelToken::CancelToken(CancelToken&&) noexcept = default;
CancelToken& CancelToken::operator=(const CancelToken&) noexcept = default;
CancelToken& CancelToken::operator=(CancelToken&&) noexcept = default;
CancelToken::~CancelToken() = default;

bool CancelToken::isCancelled() const noexcept
{
    return d && d->source.stop_requested();
}

bool CancelToken::isCancellable() const noexcept
{
    return static_cast<bool>(d);
}

CancelToken::Registration CancelToken::registerCallback(std::function<void()> callback)
{
    Registration reg;
    if (!d) {
        return reg; // never-cancellable: no-op handle
    }
    reg.d = std::make_unique<Registration::Impl>();
    reg.d->callback.emplace(d->source.get_token(), std::move(callback));
    return reg;
}

// ---------- CancelToken::Registration ----------

CancelToken::Registration::Registration() noexcept = default;
CancelToken::Registration::Registration(Registration&&) noexcept = default;
CancelToken::Registration& CancelToken::Registration::operator=(Registration&&) noexcept = default;
CancelToken::Registration::~Registration() = default;

// ---------- CancelSource ----------

CancelSource::CancelSource() : d(std::make_shared<CancelToken::Impl>()) {}

CancelSource::CancelSource(const CancelSource&) noexcept = default;
CancelSource::CancelSource(CancelSource&&) noexcept = default;
CancelSource& CancelSource::operator=(const CancelSource&) noexcept = default;
CancelSource& CancelSource::operator=(CancelSource&&) noexcept = default;
CancelSource::~CancelSource() = default;

CancelToken CancelSource::token() const noexcept
{
    CancelToken t;
    t.d = d;
    return t;
}

bool CancelSource::requestCancel() noexcept
{
    return d->source.request_stop();
}

bool CancelSource::isCancelled() const noexcept
{
    return d->source.stop_requested();
}

// detail::stopTokenFrom is defined inline in detail/cancel_bridge.h
// (header-only — the .so does not export an std::stop_token entry point;
// public cooperative cancel uses LibreSCRS::CancelToken).

} // namespace LibreSCRS
