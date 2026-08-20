// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "rs_signed_object.h"

#include "detail/document_signer_policy.h"

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <iostream>
#include <string>
#include <vector>

namespace LibreSCRS::RsEId::Core {
namespace {

using LibreSCRS::Internal::Crypto::BioPtr;
using LibreSCRS::Internal::Crypto::Pkcs7Ptr;
using LibreSCRS::Internal::Crypto::StackX509Ptr;
using LibreSCRS::Internal::Crypto::X509StoreCtxPtr;

[[nodiscard]] VerificationResult verifyChainAndDomain(X509_STORE* store, X509* signerCert)
{
    if (!store || !signerCert) {
        return VerificationResult::Invalid;
    }

    X509StoreCtxPtr ctx(X509_STORE_CTX_new());
    if (!ctx || X509_STORE_CTX_init(ctx.get(), store, signerCert, nullptr) != 1) {
        return VerificationResult::Invalid;
    }
    if (X509_verify_cert(ctx.get()) != 1) {
        return VerificationResult::Invalid;
    }

    if (!detail::signerIsMupDocumentSigner(signerCert)) {
        char* issuerRaw = X509_NAME_oneline(X509_get_issuer_name(signerCert), nullptr, 0);
        const std::string issuer = issuerRaw ? issuerRaw : "?";
        if (issuerRaw) {
            OPENSSL_free(issuerRaw);
        }
        std::clog << "[librescrs.rs-eid] card SOD signer not attributable: issuer \"" << issuer
                  << "\" is outside the document-signer domain\n";
        return VerificationResult::Unknown;
    }
    return VerificationResult::Valid;
}

} // namespace

SignedObjectReport verifySignedObject(std::span<const std::uint8_t> cmsDer, std::span<const BlockCandidates> blocks,
                                      DigestBinding binding, const TrustStore& trust)
{
    SignedObjectReport report;
    if (cmsDer.empty()) {
        return report;
    }

    const std::uint8_t* p = cmsDer.data();
    Pkcs7Ptr pkcs7(d2i_PKCS7(nullptr, &p, static_cast<long>(cmsDer.size())));
    if (!pkcs7) {
        return report;
    }

    BioPtr contentBio(BIO_new(BIO_s_mem()));
    if (!contentBio) {
        return report;
    }

    // Signature first, chain deliberately skipped here: whether the bytes were
    // signed at all is a different question from whether we trust the signer.
    if (PKCS7_verify(pkcs7.get(), nullptr, nullptr, nullptr, contentBio.get(), PKCS7_NOVERIFY) != 1) {
        return report;
    }

    std::vector<std::uint8_t> content;
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(contentBio.get(), &bptr);
    if (bptr && bptr->length > 0) {
        content.assign(reinterpret_cast<const std::uint8_t*>(bptr->data),
                       reinterpret_cast<const std::uint8_t*>(bptr->data) + bptr->length);
    }
    report.slotCount = content.size() / kDigestSize;
    report.digestsBound = matchDigests(content, blocks, binding);

    // A genuine card Security Object carries exactly one signer. Pinning only
    // the first of several would leave the rest unexamined.
    StackX509Ptr signerCerts(PKCS7_get0_signers(pkcs7.get(), nullptr, 0));
    if (!signerCerts || sk_X509_num(signerCerts.get()) != 1) {
        return report;
    }
    report.signer = verifyChainAndDomain(trust.native(), sk_X509_value(signerCerts.get(), 0));
    return report;
}

VerificationResult verifySignerTrust(const TrustStore& trust, X509* signerCert)
{
    return verifyChainAndDomain(trust.native(), signerCert);
}

} // namespace LibreSCRS::RsEId::Core
