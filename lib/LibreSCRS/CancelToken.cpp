// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/CancelToken.h>

#include <optional>
#include <stop_token>
#include <utility>

namespace LibreSCRS {

class LIBRESCRS_INTERNAL CancelToken::Impl
{
public:
    std::stop_source source;
};

class LIBRESCRS_INTERNAL CancelToken::Registration::Impl
{
public:
    // std::stop_callback is non-default-constructible; std::optional gives
    // an empty/disengaged state that matches the default Registration shape.
    std::optional<std::stop_callback<std::function<void()>>> callback;
};

class LIBRESCRS_INTERNAL detail::CancelTokenInternalAccess
{
public:
    static std::shared_ptr<CancelToken::Impl> impl(const CancelToken& token) noexcept
    {
        return token.pImpl;
    }
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
    return pImpl && pImpl->source.stop_requested();
}

bool CancelToken::isCancellable() const noexcept
{
    return static_cast<bool>(pImpl);
}

CancelToken::Registration CancelToken::registerCallback(std::function<void()> callback)
{
    Registration reg;
    if (!pImpl) {
        return reg; // never-cancellable: no-op handle
    }
    reg.pImpl = std::make_unique<Registration::Impl>();
    reg.pImpl->callback.emplace(pImpl->source.get_token(), std::move(callback));
    return reg;
}

// ---------- CancelToken::Registration ----------

CancelToken::Registration::Registration() noexcept = default;
CancelToken::Registration::Registration(Registration&&) noexcept = default;
CancelToken::Registration& CancelToken::Registration::operator=(Registration&&) noexcept = default;
CancelToken::Registration::~Registration() = default;

// ---------- CancelSource ----------

CancelSource::CancelSource() : pImpl(std::make_shared<CancelToken::Impl>()) {}

CancelSource::CancelSource(const CancelSource&) noexcept = default;
CancelSource::CancelSource(CancelSource&&) noexcept = default;
CancelSource& CancelSource::operator=(const CancelSource&) noexcept = default;
CancelSource& CancelSource::operator=(CancelSource&&) noexcept = default;
CancelSource::~CancelSource() = default;

CancelToken CancelSource::token() const noexcept
{
    CancelToken t;
    t.pImpl = pImpl;
    return t;
}

bool CancelSource::requestCancel() noexcept
{
    return pImpl->source.request_stop();
}

bool CancelSource::isCancelled() const noexcept
{
    return pImpl->source.stop_requested();
}

namespace detail {

std::stop_token stopTokenFrom(const CancelToken& token) noexcept
{
    auto impl = CancelTokenInternalAccess::impl(token);
    return impl ? impl->source.get_token() : std::stop_token{};
}

} // namespace detail

} // namespace LibreSCRS
