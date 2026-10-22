// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The OpenSSL provider signs through whatever SigningKey it is handed. A key
// held in software has to come out of the provider's key-management import as
// itself, and a key's own failure -- thrown inside OpenSSL's C callback, where
// it cannot propagate -- has to reach the caller that created the key.

#include <gtest/gtest.h>

#include "native/signing_key.h"
#include "native/signing_provider.h"
#include "signing_keys.h"
#include "types.h"

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstdint>
#include <exception>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using LibreSCRS::Internal::Crypto::EvpMdCtxPtr;
using LibreSCRS::Internal::Crypto::EvpPkeyPtr;
using LibreSCRS::Internal::Crypto::X509Ptr;

X509Ptr parseCert(const std::vector<std::uint8_t>& der)
{
    const unsigned char* p = der.data();
    return X509Ptr(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
}

/// A key whose card refuses the PIN: its certificate is the test signer's, its
/// sign throws the typed failure a card plugin's key throws.
class RefusingKey final : public libresign::SigningKey
{
public:
    std::vector<std::uint8_t> sign(std::span<const std::uint8_t>, const std::string&,
                                   std::span<const std::uint8_t>) override
    {
        throw libresign::SignFailureException(libresign::SignFailureKind::PinFailed, "the card refused the PIN");
    }
    std::vector<std::uint8_t> certificate() const override
    {
        return libresign::test::validSignerKey().certDer;
    }
    std::vector<std::vector<std::uint8_t>> certificateChain() const override
    {
        return {certificate()};
    }
    void setResolvedChain(std::vector<std::vector<std::uint8_t>>, libresign::ChainTermination) override {}
    libresign::ChainTermination chainTermination() const override
    {
        return libresign::ChainTermination::Unterminated;
    }
};

} // namespace

TEST(SigningProviderKeymgmtTest, KeyPointerRoundTripsAsSigningKey)
{
    libresign::test::SoftSigningKey key(libresign::test::validSignerKey());
    const auto cert = parseCert(key.certificate());
    ASSERT_NE(cert, nullptr);
    libresign::SigningProviderLease provider;
    std::exception_ptr keyFailure;
    EvpPkeyPtr pkey(libresign::createSigningEvpKey(provider, key, cert.get(), keyFailure).release());
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
    EXPECT_FALSE(keyFailure);
    EvpMdCtxPtr verifyCtx(EVP_MD_CTX_new());
    ASSERT_EQ(EVP_DigestVerifyInit(verifyCtx.get(), nullptr, EVP_sha256(), nullptr, X509_get0_pubkey(cert.get())), 1);
    EXPECT_EQ(EVP_DigestVerify(verifyCtx.get(), sig.data(), sig.size(), data.data(), data.size()), 1);
}

// OpenSSL learns only that the signature failed; the key's own failure, kind
// and all, is kept for the caller that created the key.
TEST(SigningProviderKeymgmtTest, KeysFailureIsKeptForTheCaller)
{
    RefusingKey key;
    const auto cert = parseCert(key.certificate());
    ASSERT_NE(cert, nullptr);
    libresign::SigningProviderLease provider;
    std::exception_ptr keyFailure;
    EvpPkeyPtr pkey(libresign::createSigningEvpKey(provider, key, cert.get(), keyFailure).release());
    ASSERT_NE(pkey, nullptr);

    const std::vector<std::uint8_t> data{'s', 'i', 'g', 'n', ' ', 'm', 'e'};
    EvpMdCtxPtr signCtx(EVP_MD_CTX_new());
    ASSERT_EQ(EVP_DigestSignInit(signCtx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()), 1);
    std::vector<unsigned char> sig(512);
    std::size_t sigLen = sig.size();
    EXPECT_NE(EVP_DigestSign(signCtx.get(), sig.data(), &sigLen, data.data(), data.size()), 1);

    ASSERT_TRUE(keyFailure);
    try {
        std::rethrow_exception(keyFailure);
    } catch (const libresign::SignFailureException& e) {
        EXPECT_EQ(e.kind, libresign::SignFailureKind::PinFailed);
    } catch (...) {
        ADD_FAILURE() << "the kept failure is not the key's typed one";
    }
}

TEST(SigningProviderKeymgmtTest, NullCertThrows)
{
    libresign::test::SoftSigningKey key(libresign::test::validSignerKey());
    libresign::SigningProviderLease provider;
    std::exception_ptr keyFailure;
    EXPECT_THROW((void)libresign::createSigningEvpKey(provider, key, nullptr, keyFailure), std::runtime_error);
}
