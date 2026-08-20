// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "synthetic_annex.h"

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace LibreSCRS::RsEId::Core::TestData {
namespace {

using LibreSCRS::Internal::Crypto::BioPtr;
using LibreSCRS::Internal::Crypto::EvpPkeyPtr;
using LibreSCRS::Internal::Crypto::Pkcs7Ptr;
using LibreSCRS::Internal::Crypto::X509Ptr;

std::vector<std::uint8_t> bioBytes(BIO* bio)
{
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (!mem || mem->length == 0) {
        return {};
    }
    return {reinterpret_cast<const std::uint8_t*>(mem->data),
            reinterpret_cast<const std::uint8_t*>(mem->data) + mem->length};
}

} // namespace

SignedObjectFixture makeSignedObject(std::span<const std::uint8_t> content, bool expiredSigner)
{
    SignedObjectFixture out;

    EvpPkeyPtr key(EVP_RSA_gen(2048));
    X509Ptr cert(X509_new());
    if (!key || !cert) {
        return out;
    }

    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), expiredSigner ? -7200 : 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), expiredSigner ? -3600 : 3600);
    X509_set_pubkey(cert.get(), key.get());

    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Synthetic Test Signer"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);

    // Self-signed anchors need CA:TRUE before a store will build a chain to them.
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert.get(), cert.get(), nullptr, nullptr, 0);
    if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE")) {
        X509_add_ext(cert.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(cert.get(), key.get(), EVP_sha256()) == 0) {
        return out;
    }

    BioPtr data(BIO_new_mem_buf(content.data(), static_cast<int>(content.size())));
    if (!data) {
        return out;
    }
    const int flags = PKCS7_BINARY | PKCS7_STREAM | PKCS7_NOATTR;
    Pkcs7Ptr p7(PKCS7_sign(cert.get(), key.get(), nullptr, data.get(), flags));
    if (!p7) {
        return out;
    }

    BioPtr sink(BIO_new(BIO_s_mem()));
    if (!sink || i2d_PKCS7_bio_stream(sink.get(), p7.get(), data.get(), flags) != 1) {
        return out;
    }
    out.cms = bioBytes(sink.get());

    unsigned char* der = nullptr;
    const int len = i2d_X509(cert.get(), &der);
    if (len > 0 && der) {
        out.signerCertDer.assign(der, der + len);
        OPENSSL_free(der);
    }
    return out;
}

} // namespace LibreSCRS::RsEId::Core::TestData
