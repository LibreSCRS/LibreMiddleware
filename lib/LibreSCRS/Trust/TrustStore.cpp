// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Trust/TrustStore.h>

#include "internal/TrustStoreInternalAccess.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <cstring>
#include <iterator>
#include <mutex>
#include <shared_mutex>

namespace LibreSCRS::Trust {

namespace {

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;

struct StackX509Deleter
{
    void operator()(STACK_OF(X509) * p) const
    {
        sk_X509_free(p);
    }
};
using StackX509Ptr = std::unique_ptr<STACK_OF(X509), StackX509Deleter>;

X509Ptr parseDer(const std::uint8_t* data, std::size_t len)
{
    const std::uint8_t* p = data;
    return X509Ptr(d2i_X509(nullptr, &p, static_cast<long>(len)), X509_free);
}

X509Ptr parseDer(std::span<const std::uint8_t> der)
{
    return parseDer(der.data(), der.size());
}

bool sameDn(const X509_NAME* a, const X509_NAME* b)
{
    return a && b && X509_NAME_cmp(a, b) == 0;
}

// eIDAS-issued QC certificates routinely carry the QCStatements extension
// (id-pe-qcStatements, 1.3.6.1.5.5.7.1.3) marked CRITICAL per ETSI EN 319
// 412-5. OpenSSL's chain verifier does NOT whitelist qcStatements as a
// "supported" critical extension, so X509_verify_cert returns
// X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION (err=34) and the chain reads as
// "invalid" even when every other check (issuer signature, validity,
// revocation, KU) passes. We aren't a qualified-signature validator —
// the LC certificate viewer's purpose is to show the user "is this cert
// trusted by your trust anchors?" Downgrade the criticality bit on our
// in-memory X509 copy before verify so OpenSSL stops failing on it.
// We mutate only the parsed X509Ptr that lives in this scope; the
// original DER bytes (and any on-disk copy) are untouched.
void relaxKnownEidasCriticalExtensions(X509* cert)
{
    if (!cert)
        return;
    const int idx = X509_get_ext_by_NID(cert, NID_qcStatements, -1);
    if (idx < 0)
        return;
    X509_EXTENSION* ext = X509_get_ext(cert, idx);
    if (ext)
        X509_EXTENSION_set_critical(ext, 0);
}

} // namespace

TrustStore::TrustStore(std::unique_ptr<Impl> impl) : d(std::move(impl)) {}

TrustStore::~TrustStore() = default;
TrustStore::TrustStore(TrustStore&&) noexcept = default;
TrustStore& TrustStore::operator=(TrustStore&&) noexcept = default;

TrustStore::operator bool() const noexcept
{
    return d != nullptr;
}

TrustStore::ChainStatus TrustStore::validateChain(std::span<const CertificateView> chain) const
{
    if (!d || chain.empty())
        return ChainStatus::InvalidCertificate;

    std::shared_lock lock(d->mtx);

    X509StorePtr store(X509_STORE_new(), X509_STORE_free);
    if (!store)
        return ChainStatus::InvalidCertificate;
    if (d->includeSystemStore) {
        X509_STORE_set_default_paths(store.get());
    }
    for (const auto& provider : d->providers) {
        for (const auto& anchor : provider->anchors()) {
            auto cert = parseDer(anchor.certificateDer);
            if (cert) {
                X509_STORE_add_cert(store.get(), cert.get());
            }
        }
    }

    auto leaf = parseDer(chain.front());
    if (!leaf)
        return ChainStatus::InvalidCertificate;
    relaxKnownEidasCriticalExtensions(leaf.get());

    // Build STACK_OF(X509) for intermediates (chain elements 1..N-1).
    StackX509Ptr untrusted(sk_X509_new_null());
    if (!untrusted)
        return ChainStatus::InvalidCertificate;
    std::vector<X509Ptr> intermediates;
    for (std::size_t i = 1; i < chain.size(); ++i) {
        auto cert = parseDer(chain[i]);
        if (!cert)
            return ChainStatus::InvalidCertificate;
        relaxKnownEidasCriticalExtensions(cert.get());
        sk_X509_push(untrusted.get(), cert.get());
        intermediates.push_back(std::move(cert));
    }

    X509StoreCtxPtr ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (!ctx)
        return ChainStatus::InvalidCertificate;
    if (X509_STORE_CTX_init(ctx.get(), store.get(), leaf.get(), untrusted.get()) != 1) {
        return ChainStatus::InvalidCertificate;
    }

    int verifyResult = X509_verify_cert(ctx.get());
    if (verifyResult == 1)
        return ChainStatus::Trusted;

    int err = X509_STORE_CTX_get_error(ctx.get());
    switch (err) {
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        return ChainStatus::UntrustedRoot;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
        return ChainStatus::Expired;
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        return ChainStatus::BrokenChain;
    default:
        return ChainStatus::InvalidCertificate;
    }
}

std::optional<TrustAnchor> TrustStore::findIssuerOf(CertificateView certDer) const
{
    if (!d)
        return std::nullopt;

    std::shared_lock lock(d->mtx);

    auto cert = parseDer(certDer);
    if (!cert)
        return std::nullopt;

    X509_NAME* issuerName = X509_get_issuer_name(cert.get());
    if (!issuerName)
        return std::nullopt;

    for (const auto& provider : d->providers) {
        for (const auto& anchor : provider->anchors()) {
            auto candidate = parseDer(anchor.certificateDer);
            if (!candidate)
                continue;
            X509_NAME* candidateSubject = X509_get_subject_name(candidate.get());
            if (sameDn(issuerName, candidateSubject)) {
                return anchor;
            }
        }
    }
    return std::nullopt;
}

std::vector<TrustAnchor> TrustStore::enumerableAnchors() const
{
    if (!d)
        return {};
    std::shared_lock lock(d->mtx);
    std::vector<TrustAnchor> out;
    for (const auto& provider : d->providers) {
        auto anchors = provider->anchors();
        out.insert(out.end(), std::make_move_iterator(anchors.begin()), std::make_move_iterator(anchors.end()));
    }
    return out;
}

} // namespace LibreSCRS::Trust
