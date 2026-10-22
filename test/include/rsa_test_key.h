// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// An RSA key pair with a self-signed certificate, standing in for a card's RSA
// key in tests that need OpenSSL to sign and to check what came back.

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace LibreSCRS::TestSupport {

struct RsaTestKey
{
    LibreSCRS::Internal::Crypto::EvpPkeyPtr key;
    std::vector<std::uint8_t> certDer;

    /// The PKCS#1 v1.5 signature a card's RSA key makes: over @p input hashed
    /// with @p md, or, when @p md is null, over @p input as it stands -- a
    /// DigestInfo the card only pads. Empty when OpenSSL refuses.
    [[nodiscard]] std::vector<std::uint8_t> signPkcs1(const EVP_MD* md, std::span<const std::uint8_t> input) const
    {
        std::vector<std::uint8_t> toSign(input.begin(), input.end());
        if (md != nullptr) {
            std::vector<std::uint8_t> hash(static_cast<std::size_t>(EVP_MD_get_size(md)));
            unsigned int length = 0;
            if (EVP_Digest(input.data(), input.size(), hash.data(), &length, md, nullptr) != 1)
                return {};
            toSign = std::move(hash);
        }
        LibreSCRS::Internal::Crypto::EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
        std::size_t length = 0;
        if (!ctx || EVP_PKEY_sign_init(ctx.get()) != 1 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PADDING) != 1 ||
            (md != nullptr && EVP_PKEY_CTX_set_signature_md(ctx.get(), md) != 1) ||
            EVP_PKEY_sign(ctx.get(), nullptr, &length, toSign.data(), toSign.size()) != 1)
            return {};
        std::vector<std::uint8_t> signature(length);
        if (EVP_PKEY_sign(ctx.get(), signature.data(), &length, toSign.data(), toSign.size()) != 1)
            return {};
        signature.resize(length);
        return signature;
    }

    /// Whether @p signature is this key's PKCS#1 v1.5 signature over @p message hashed with @p md.
    [[nodiscard]] bool verifies(const EVP_MD* md, std::span<const std::uint8_t> message,
                                std::span<const std::uint8_t> signature) const
    {
        LibreSCRS::Internal::Crypto::EvpMdCtxPtr ctx(EVP_MD_CTX_new());
        return ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, key.get()) == 1 &&
               EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
    }
};

/// A fresh 2048-bit key with a self-signed certificate named @p commonName,
/// valid from @p notBefore to @p notAfter seconds from now (both may be
/// negative: an expired certificate lies wholly in the past).
inline RsaTestKey makeRsaTestKey(const char* commonName = "RSA test key", long notBefore = 0, long notAfter = 3600)
{
    RsaTestKey k;
    k.key.reset(EVP_RSA_gen(2048));
    if (!k.key)
        throw std::runtime_error("EVP_RSA_gen failed");
    LibreSCRS::Internal::Crypto::X509Ptr cert(X509_new());
    if (!cert)
        throw std::runtime_error("X509_new failed");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), notBefore);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), notAfter);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    if (X509_set_pubkey(cert.get(), k.key.get()) != 1 || X509_sign(cert.get(), k.key.get(), EVP_sha256()) <= 0)
        throw std::runtime_error("certificate signing failed");
    unsigned char* der = nullptr;
    const int length = i2d_X509(cert.get(), &der);
    if (length <= 0)
        throw std::runtime_error("i2d_X509 failed");
    k.certDer.assign(der, der + length);
    OPENSSL_free(der);
    return k;
}

} // namespace LibreSCRS::TestSupport
