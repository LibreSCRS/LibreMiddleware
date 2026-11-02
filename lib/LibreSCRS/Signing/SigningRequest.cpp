// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/TsaProvider.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace LibreSCRS::Signing {

struct LIBRESCRS_INTERNAL SigningRequest::Impl
{
    SignatureFormat format = SignatureFormat::Pades;
    SignatureLevel level = SignatureLevel::B_T;
    PackagingMode packaging = PackagingMode::Enveloped;
    std::string reason;
    std::string location;
    std::string documentName;        // names the in-memory document
    std::vector<std::uint8_t> keyId; // CKA_ID of the signing key/cert pair (reuse-safe selector)
    std::optional<VisualSignatureParams> visualParams;
    TsaProvider tsaOverride; // empty URL: the service-level authority
    bool allowExpiredCert = false;
};

SigningRequest::SigningRequest() : d(std::make_unique<Impl>()) {}
SigningRequest::~SigningRequest() = default;
SigningRequest::SigningRequest(SigningRequest&&) noexcept = default;
SigningRequest& SigningRequest::operator=(SigningRequest&&) noexcept = default;

SignatureFormat SigningRequest::format() const noexcept
{
    return d->format;
}
SignatureLevel SigningRequest::level() const noexcept
{
    return d->level;
}
PackagingMode SigningRequest::packaging() const noexcept
{
    return d->packaging;
}
const std::string& SigningRequest::reason() const noexcept
{
    return d->reason;
}
const std::string& SigningRequest::location() const noexcept
{
    return d->location;
}
const std::string& SigningRequest::documentName() const noexcept
{
    return d->documentName;
}
const std::vector<std::uint8_t>& SigningRequest::keyId() const noexcept
{
    return d->keyId;
}
std::optional<VisualSignatureParams> SigningRequest::visualParams() const
{
    // Return by value (copy). VisualSignatureParams is pimpl-backed and
    // copyable; the copy is a pointer allocation + small-data clone
    // (page index, four rect ints, text template string). This avoids the
    // caller-invalidation footgun of returning a pointer into pimpl state
    // that would be moved out by `req = std::move(otherReq)`.
    return d->visualParams;
}
const TsaProvider& SigningRequest::tsaOverride() const noexcept
{
    return d->tsaOverride;
}

bool SigningRequest::allowExpiredCert() const noexcept
{
    return d->allowExpiredCert;
}

struct LIBRESCRS_INTERNAL SigningRequest::Builder::Impl
{
    SigningRequest req;
};

SigningRequest::Builder::Builder() : d(std::make_unique<Impl>()) {}
SigningRequest::Builder::~Builder() = default;
SigningRequest::Builder::Builder(Builder&&) noexcept = default;
SigningRequest::Builder& SigningRequest::Builder::operator=(Builder&&) noexcept = default;

SigningRequest::Builder& SigningRequest::Builder::format(SignatureFormat f) noexcept
{
    d->req.d->format = f;
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::level(SignatureLevel l) noexcept
{
    d->req.d->level = l;
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::packaging(PackagingMode p) noexcept
{
    d->req.d->packaging = p;
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::reason(std::string r)
{
    d->req.d->reason = std::move(r);
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::location(std::string loc)
{
    d->req.d->location = std::move(loc);
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::documentName(std::string name)
{
    // Stored verbatim. The path-component strip that makes the knob safe for
    // container entry names happens at translation time (RequestBridge), so
    // the accessor keeps returning exactly what the caller supplied.
    d->req.d->documentName = std::move(name);
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::keyId(std::vector<std::uint8_t> id)
{
    d->req.d->keyId = std::move(id);
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::visualParams(VisualSignatureParams&& v)
{
    d->req.d->visualParams.emplace(std::move(v));
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::tsaOverride(TsaProvider provider)
{
    d->req.d->tsaOverride = std::move(provider);
    return *this;
}
SigningRequest::Builder& SigningRequest::Builder::allowExpiredCert(bool allow) noexcept
{
    d->req.d->allowExpiredCert = allow;
    return *this;
}

SigningRequest SigningRequest::Builder::buildForBufferSign() &&
{
    // The document and the signed result travel in memory; the only check is
    // the cross-field combination.
    if (d->req.d->visualParams && d->req.d->format != SignatureFormat::Pades) {
        throw std::invalid_argument("SigningRequest: visualParams are only valid for PAdES format");
    }
    return std::move(d->req);
}

} // namespace LibreSCRS::Signing
