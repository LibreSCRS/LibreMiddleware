// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// Checks a card's signature over a known digest against the public key of the
// card's certificate, for the hardware tests that sign.

#include <gtest/gtest.h>

#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace LibreSCRS::Tests {

namespace detail {

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

inline EvpPkeyPtr publicKeyOf(const std::vector<std::uint8_t>& certDer)
{
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    const unsigned char* p = certDer.data();
    X509Ptr x{d2i_X509(nullptr, &p, static_cast<long>(certDer.size())), &X509_free};
    if (!x)
        return {nullptr, &EVP_PKEY_free};
    return {X509_get_pubkey(x.get()), &EVP_PKEY_free};
}

// EVP_PKEY_verify of @p sig over @p digest; @p setup prepares the context.
template <typename Setup>
::testing::AssertionResult verifyWith(EVP_PKEY* key, const unsigned char* sig, std::size_t sigLen,
                                      const std::vector<std::uint8_t>& digest, Setup&& setup)
{
    using CtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    CtxPtr vctx{EVP_PKEY_CTX_new(key, nullptr), &EVP_PKEY_CTX_free};
    if (!vctx || EVP_PKEY_verify_init(vctx.get()) != 1)
        return ::testing::AssertionFailure() << "verify init failed";
    if (!setup(vctx.get()))
        return ::testing::AssertionFailure() << "verify setup failed";
    const int vres = EVP_PKEY_verify(vctx.get(), sig, sigLen, digest.data(), digest.size());
    return vres == 1 ? ::testing::AssertionSuccess()
                     : ::testing::AssertionFailure() << "signature did not verify (vres=" << vres << ")";
}

} // namespace detail

/// Verify a raw r||s ECDSA signature against the certificate's EC public key.
/// A card returns the canonical fixed-width r||s; OpenSSL's verify wants a DER
/// ECDSA-Sig-Value, so one is rebuilt from the two halves.
inline ::testing::AssertionResult ecdsaVerifyRaw(const std::vector<std::uint8_t>& certDer,
                                                 const std::vector<std::uint8_t>& rawSig,
                                                 const std::vector<std::uint8_t>& digest)
{
    if (rawSig.size() % 2 != 0)
        return ::testing::AssertionFailure() << "raw signature length " << rawSig.size() << " is not even";
    const std::size_t half = rawSig.size() / 2;

    auto pkey = detail::publicKeyOf(certDer);
    if (!pkey)
        return ::testing::AssertionFailure() << "no public key in the certificate";

    using SigPtr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;
    SigPtr sig{ECDSA_SIG_new(), &ECDSA_SIG_free};
    BIGNUM* r = BN_bin2bn(rawSig.data(), static_cast<int>(half), nullptr);
    BIGNUM* s = BN_bin2bn(rawSig.data() + half, static_cast<int>(half), nullptr);
    if (!sig || !r || !s || ECDSA_SIG_set0(sig.get(), r, s) != 1)
        return ::testing::AssertionFailure() << "ECDSA_SIG assembly failed";

    unsigned char* der = nullptr;
    const int derLen = i2d_ECDSA_SIG(sig.get(), &der);
    if (derLen <= 0)
        return ::testing::AssertionFailure() << "i2d_ECDSA_SIG failed";
    // OPENSSL_free is a macro, not a callable — wrap it for the RAII deleter.
    const auto freeDer = [](unsigned char* p) { OPENSSL_free(p); };
    std::unique_ptr<unsigned char, decltype(freeDer)> derOwner{der, freeDer};

    return detail::verifyWith(pkey.get(), derOwner.get(), static_cast<std::size_t>(derLen), digest,
                              [](EVP_PKEY_CTX*) { return true; });
}

/// Verify an RSA PKCS#1 v1.5 signature over a SHA-256 @p digest against the
/// certificate's RSA public key.
inline ::testing::AssertionResult rsaPkcs1Sha256Verify(const std::vector<std::uint8_t>& certDer,
                                                       const std::vector<std::uint8_t>& signature,
                                                       const std::vector<std::uint8_t>& digest)
{
    auto pkey = detail::publicKeyOf(certDer);
    if (!pkey)
        return ::testing::AssertionFailure() << "no public key in the certificate";
    return detail::verifyWith(pkey.get(), signature.data(), signature.size(), digest, [](EVP_PKEY_CTX* ctx) {
        return EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1 &&
               EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1;
    });
}

} // namespace LibreSCRS::Tests
