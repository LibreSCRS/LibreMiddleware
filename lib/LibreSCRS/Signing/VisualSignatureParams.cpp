// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include <stdexcept>
#include <utility>

namespace LibreSCRS::Signing {

struct LIBRESCRS_INTERNAL VisualSignatureParams::Impl
{
    int pageIndex = 0;
    int x = 0, y = 0, width = 200, height = 50;
    std::string textTemplate;
};

VisualSignatureParams::VisualSignatureParams() : d(std::make_unique<Impl>()) {}
VisualSignatureParams::~VisualSignatureParams() = default;
VisualSignatureParams::VisualSignatureParams(VisualSignatureParams&&) noexcept = default;
VisualSignatureParams& VisualSignatureParams::operator=(VisualSignatureParams&&) noexcept = default;

VisualSignatureParams::VisualSignatureParams(const VisualSignatureParams& other) : d(std::make_unique<Impl>(*other.d))
{}

VisualSignatureParams& VisualSignatureParams::operator=(const VisualSignatureParams& other)
{
    if (this != &other) {
        d = std::make_unique<Impl>(*other.d);
    }
    return *this;
}

int VisualSignatureParams::pageIndex() const noexcept
{
    return d->pageIndex;
}
int VisualSignatureParams::x() const noexcept
{
    return d->x;
}
int VisualSignatureParams::y() const noexcept
{
    return d->y;
}
int VisualSignatureParams::width() const noexcept
{
    return d->width;
}
int VisualSignatureParams::height() const noexcept
{
    return d->height;
}
const std::string& VisualSignatureParams::textTemplate() const noexcept
{
    return d->textTemplate;
}

struct LIBRESCRS_INTERNAL VisualSignatureParams::Builder::Impl
{
    VisualSignatureParams params;
};

VisualSignatureParams::Builder::Builder() : d(std::make_unique<Impl>()) {}
VisualSignatureParams::Builder::~Builder() = default;
VisualSignatureParams::Builder::Builder(Builder&&) noexcept = default;
VisualSignatureParams::Builder& VisualSignatureParams::Builder::operator=(Builder&&) noexcept = default;

VisualSignatureParams::Builder& VisualSignatureParams::Builder::pageIndex(int idx)
{
    if (idx < 0)
        throw std::invalid_argument("VisualSignatureParams: pageIndex must be >= 0");
    d->params.d->pageIndex = idx;
    return *this;
}
VisualSignatureParams::Builder& VisualSignatureParams::Builder::rect(const Rect& r)
{
    if (r.width <= 0 || r.height <= 0)
        throw std::invalid_argument("VisualSignatureParams: rect width/height must be positive");
    d->params.d->x = r.x;
    d->params.d->y = r.y;
    d->params.d->width = r.width;
    d->params.d->height = r.height;
    return *this;
}
VisualSignatureParams::Builder& VisualSignatureParams::Builder::textTemplate(std::string t)
{
    d->params.d->textTemplate = std::move(t);
    return *this;
}

VisualSignatureParams VisualSignatureParams::Builder::build() && noexcept
{
    // Infallible — see header doc and API-POLICY §5.1: all invariants are
    // enforced at setter-invocation time; defaults are independently valid.
    return std::move(d->params);
}

} // namespace LibreSCRS::Signing
