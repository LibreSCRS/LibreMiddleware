// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "native/signing_provider.h"
#include "native/pkcs11_token.h"
#include "signing_service.h"
#include "signing_test_support/signing_test_support.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <memory>

using namespace libresign;
using namespace libresign::test;

// RAII helpers to prevent leaks on ASSERT failures
struct EvpPkeyFree
{
    void operator()(EVP_PKEY* p) const
    {
        EVP_PKEY_free(p);
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

using X509Ptr = std::unique_ptr<X509, X509Free>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyFree>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxFree>;

class SigningProviderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        SKIP_IF_PIN_FAILED();
        auto cfg = readTestConfig();
        if (!cfg.valid)
            GTEST_SKIP() << cfg.skipReason;
        config = cfg.config;
    }

    X509Ptr parseCertFromToken(Pkcs11Token& token)
    {
        auto certDer = token.certificate();
        if (certDer.empty())
            return nullptr;
        const unsigned char* p = certDer.data();
        return X509Ptr(d2i_X509(nullptr, &p, static_cast<long>(certDer.size())));
    }

    TestConfig config;
};

TEST_F(SigningProviderTest, InitProviderIsIdempotent)
{
    EXPECT_NO_THROW(initSigningProvider());
    EXPECT_NO_THROW(initSigningProvider());
}

TEST_F(SigningProviderTest, CreateEvpKeyFromCert)
{
    SKIP_IF_PIN_FAILED();
    Pkcs11Token token(config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);

    auto cert = parseCertFromToken(token);
    ASSERT_NE(cert, nullptr);

    EvpPkeyPtr pkey(createPkcs11EvpKey(token, cert.get()).release());
    ASSERT_NE(pkey, nullptr);

    EXPECT_GT(EVP_PKEY_get_bits(pkey.get()), 0);
    EXPECT_GT(EVP_PKEY_get_size(pkey.get()), 0);
}

TEST_F(SigningProviderTest, DigestSignAndVerify)
{
    SKIP_IF_PIN_FAILED();
    Pkcs11Token token(config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);

    auto cert = parseCertFromToken(token);
    ASSERT_NE(cert, nullptr);

    EvpPkeyPtr pkey(createPkcs11EvpKey(token, cert.get()).release());
    ASSERT_NE(pkey, nullptr);

    const unsigned char data[] = "Test data for signing via OpenSSL 3 provider";
    const size_t dataLen = sizeof(data) - 1;

    // Sign via EVP_DigestSign pipeline (the path CMS_final uses)
    EvpMdCtxPtr signCtx(EVP_MD_CTX_new());
    ASSERT_NE(signCtx, nullptr);

    ASSERT_EQ(EVP_DigestSignInit(signCtx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()), 1)
        << "DigestSignInit failed - provider may not be routing correctly";

    ASSERT_EQ(EVP_DigestSignUpdate(signCtx.get(), data, dataLen), 1);

    size_t sigLen = 0;
    ASSERT_EQ(EVP_DigestSignFinal(signCtx.get(), nullptr, &sigLen), 1);
    ASSERT_GT(sigLen, 0u);

    std::vector<unsigned char> sig(sigLen);
    ASSERT_EQ(EVP_DigestSignFinal(signCtx.get(), sig.data(), &sigLen), 1);
    sig.resize(sigLen);

    // Verify the signature using the certificate's public key
    EVP_PKEY* certPubKey = X509_get0_pubkey(cert.get());
    ASSERT_NE(certPubKey, nullptr);

    EvpMdCtxPtr verifyCtx(EVP_MD_CTX_new());
    ASSERT_NE(verifyCtx, nullptr);

    ASSERT_EQ(EVP_DigestVerifyInit(verifyCtx.get(), nullptr, EVP_sha256(), nullptr, certPubKey), 1);
    ASSERT_EQ(EVP_DigestVerifyUpdate(verifyCtx.get(), data, dataLen), 1);
    EXPECT_EQ(EVP_DigestVerifyFinal(verifyCtx.get(), sig.data(), sig.size()), 1)
        << "Signature verification failed - provider produced invalid signature";
}

TEST_F(SigningProviderTest, NullCertThrows)
{
    Pkcs11Token token(config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    EXPECT_THROW(createPkcs11EvpKey(token, nullptr), std::runtime_error);
}
