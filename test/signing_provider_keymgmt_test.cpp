// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// The OpenSSL provider signs through whatever SigningKey it is handed. A key
// held in software has to come out of the provider's key-management import as
// itself, and a key's own failure -- thrown inside OpenSSL's C callback, where
// it cannot propagate -- has to reach the caller that created the key.

#include <gtest/gtest.h>

#include "native/signing_key.h"
#include "native/signing_provider.h"
#include "native/signing_provider_keymgmt.h"
#include "signing_keys.h"
#include "types.h"

#include <LibreSCRS/Logging.h>
#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using LibreSCRS::Internal::Crypto::EvpMdCtxPtr;
using LibreSCRS::Internal::Crypto::EvpPkeyCtxPtr;
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

// A key imported without a failure slot has nowhere to keep its failure for a
// caller; what it threw then goes to the host's log sink, not to stderr.
TEST(SigningProviderKeymgmtTest, AFailureWithNowhereToGoIsLogged)
{
    std::vector<std::pair<LibreSCRS::log::Level, std::string>> lines;
    struct SinkReset
    {
        ~SinkReset()
        {
            LibreSCRS::log::resetForTest();
        }
    } sinkReset;
    LibreSCRS::log::init(
        [&](LibreSCRS::log::Level level, std::string_view line) { lines.emplace_back(level, std::string(line)); },
        "test.signing.provider");

    RefusingKey key;
    const auto cert = parseCert(key.certificate());
    ASSERT_NE(cert, nullptr);
    libresign::SigningProviderLease provider;

    // createSigningEvpKey's import, minus the failure slot.
    libresign::detail::ProviderKeyData pub;
    libresign::detail::populateKeyDataFromPkey(pub, X509_get0_pubkey(cert.get()));
    ASSERT_TRUE(pub.keyType == EVP_PKEY_RSA || pub.keyType == EVP_PKEY_EC);
    EvpPkeyCtxPtr pctx(
        EVP_PKEY_CTX_new_from_name(nullptr, pub.keyType == EVP_PKEY_RSA ? "RSA" : "EC", "provider=librescrs"));
    ASSERT_NE(pctx, nullptr);
    void* keyPtr = static_cast<libresign::SigningKey*>(&key);
    int keyType = pub.keyType;
    int keyBits = pub.keyBits;
    std::vector<OSSL_PARAM> params;
    params.push_back(OSSL_PARAM_construct_octet_ptr(libresign::detail::kParamTokenPtr, &keyPtr, sizeof(void*)));
    params.push_back(OSSL_PARAM_construct_int("librescrs-key-type", &keyType));
    params.push_back(OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, &keyBits));
    if (keyType == EVP_PKEY_RSA) {
        params.push_back(OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, pub.rsaN.data(), pub.rsaN.size()));
        params.push_back(OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, pub.rsaE.data(), pub.rsaE.size()));
    } else {
        params.push_back(
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, pub.ecGroup.data(), pub.ecGroup.size()));
        params.push_back(
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub.ecPub.data(), pub.ecPub.size()));
    }
    params.push_back(OSSL_PARAM_construct_end());
    ASSERT_EQ(EVP_PKEY_fromdata_init(pctx.get()), 1);
    EVP_PKEY* raw = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata(pctx.get(), &raw, OSSL_KEYMGMT_SELECT_ALL, params.data()), 1);
    EvpPkeyPtr pkey(raw);

    const std::vector<std::uint8_t> data{'s', 'i', 'g', 'n', ' ', 'm', 'e'};
    EvpMdCtxPtr signCtx(EVP_MD_CTX_new());
    ASSERT_EQ(EVP_DigestSignInit(signCtx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()), 1);
    std::vector<unsigned char> sig(512);
    std::size_t sigLen = sig.size();
    EXPECT_NE(EVP_DigestSign(signCtx.get(), sig.data(), &sigLen, data.data(), data.size()), 1);

    const bool logged = std::any_of(lines.begin(), lines.end(), [](const auto& entry) {
        return entry.first == LibreSCRS::log::Level::Error &&
               entry.second.find("the card refused the PIN") != std::string::npos;
    });
    EXPECT_TRUE(logged) << lines.size() << " line(s) captured";
}

TEST(SigningProviderKeymgmtTest, NullCertThrows)
{
    libresign::test::SoftSigningKey key(libresign::test::validSignerKey());
    libresign::SigningProviderLease provider;
    std::exception_ptr keyFailure;
    EXPECT_THROW((void)libresign::createSigningEvpKey(provider, key, nullptr, keyFailure), std::runtime_error);
}
