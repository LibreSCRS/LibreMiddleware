// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The OpenSSL provider signs through whatever SigningKey it is handed. A key
// that is not a PKCS#11 token -- here one held in software -- has to come out
// of the provider's key-management import as itself: the provider used to
// cast the imported pointer to the token type.

#include <gtest/gtest.h>

#include "native/signing_key.h"
#include "native/signing_provider.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct EvpPkeyFree
{
    void operator()(EVP_PKEY* p) const
    {
        EVP_PKEY_free(p);
    }
};
struct EvpPkeyCtxFree
{
    void operator()(EVP_PKEY_CTX* p) const
    {
        EVP_PKEY_CTX_free(p);
    }
};
struct EvpMdCtxFree
{
    void operator()(EVP_MD_CTX* p) const
    {
        EVP_MD_CTX_free(p);
    }
};
struct X509Free
{
    void operator()(X509* p) const
    {
        X509_free(p);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyFree>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxFree>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxFree>;
using X509Ptr = std::unique_ptr<X509, X509Free>;

/// An RSA key in memory with a self-signed certificate: a SigningKey that has
/// nothing to do with PKCS#11.
class SoftwareKey final : public libresign::SigningKey
{
public:
    SoftwareKey() : key(EVP_RSA_gen(2048)), cert(X509_new())
    {
        if (!key || !cert)
            throw std::runtime_error("key or certificate allocation failed");
        X509_set_version(cert.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
        X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
        X509_NAME* name = X509_get_subject_name(cert.get());
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("software key"), -1,
                                   -1, 0);
        X509_set_issuer_name(cert.get(), name);
        if (X509_set_pubkey(cert.get(), key.get()) != 1 || X509_sign(cert.get(), key.get(), EVP_sha256()) <= 0)
            throw std::runtime_error("certificate signing failed");
    }

    std::vector<std::uint8_t> sign(std::span<const std::uint8_t> hash, const std::string& /*algorithm*/,
                                   std::span<const std::uint8_t> /*rawData*/) override
    {
        ++signCalls;
        // The provider hands an RSA key the DigestInfo: pad it, sign it.
        EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
        std::size_t length = 0;
        if (!ctx || EVP_PKEY_sign_init(ctx.get()) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) != 1 ||
            EVP_PKEY_sign(ctx.get(), nullptr, &length, hash.data(), hash.size()) != 1)
            return {};
        std::vector<std::uint8_t> signature(length);
        if (EVP_PKEY_sign(ctx.get(), signature.data(), &length, hash.data(), hash.size()) != 1)
            return {};
        signature.resize(length);
        return signature;
    }

    std::vector<std::uint8_t> certificate() const override
    {
        unsigned char* der = nullptr;
        const int length = i2d_X509(cert.get(), &der);
        std::vector<std::uint8_t> out(der, der + (length > 0 ? length : 0));
        OPENSSL_free(der);
        return out;
    }

    std::vector<std::vector<std::uint8_t>> certificateChain() const override
    {
        return {certificate()};
    }

    void setResolvedChain(std::vector<std::vector<std::uint8_t>> /*chain*/,
                          libresign::ChainTermination /*termination*/) override
    {}

    libresign::ChainTermination chainTermination() const override
    {
        return libresign::ChainTermination::Unterminated;
    }

    X509* x509() const
    {
        return cert.get();
    }

    int signCalls = 0;

private:
    EvpPkeyPtr key;
    X509Ptr cert;
};

} // namespace

TEST(SigningProviderKeymgmtTest, KeyPointerRoundTripsAsSigningKey)
{
    SoftwareKey key;
    libresign::SigningProviderLease provider;
    std::exception_ptr keyFailure;
    EvpPkeyPtr pkey(libresign::createSigningEvpKey(provider, key, key.x509(), keyFailure).release());
    ASSERT_NE(pkey, nullptr);

    const std::vector<std::uint8_t> data{'s', 'i', 'g', 'n', ' ', 'm', 'e'};
    EvpMdCtxPtr signCtx(EVP_MD_CTX_new());
    ASSERT_EQ(EVP_DigestSignInit(signCtx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()), 1);
    std::size_t sigLen = 0;
    ASSERT_EQ(EVP_DigestSign(signCtx.get(), nullptr, &sigLen, data.data(), data.size()), 1);
    std::vector<unsigned char> sig(sigLen);
    ASSERT_EQ(EVP_DigestSign(signCtx.get(), sig.data(), &sigLen, data.data(), data.size()), 1);
    sig.resize(sigLen);

    EXPECT_EQ(key.signCalls, 1) << "the provider signed through the key it was handed";
    EvpMdCtxPtr verifyCtx(EVP_MD_CTX_new());
    ASSERT_EQ(EVP_DigestVerifyInit(verifyCtx.get(), nullptr, EVP_sha256(), nullptr, X509_get0_pubkey(key.x509())), 1);
    EXPECT_EQ(EVP_DigestVerify(verifyCtx.get(), sig.data(), sig.size(), data.data(), data.size()), 1);
}
