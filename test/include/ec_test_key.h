// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// An EC key pair with a self-signed certificate, standing in for a card's EC
// key in tests that need OpenSSL to sign and to check what came back.

#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>

namespace LibreSCRS::TestSupport {

/// DER SEQUENCE { INTEGER r, INTEGER s } for the unsigned big-endian @p r, @p s.
inline std::vector<std::uint8_t> ecdsaDer(std::span<const std::uint8_t> r, std::span<const std::uint8_t> s)
{
    using LibreSCRS::Internal::Crypto::BnPtr;
    using LibreSCRS::Internal::Crypto::EcdsaSigPtr;
    BnPtr rBn(BN_bin2bn(r.data(), static_cast<int>(r.size()), nullptr));
    BnPtr sBn(BN_bin2bn(s.data(), static_cast<int>(s.size()), nullptr));
    EcdsaSigPtr sig(ECDSA_SIG_new());
    if (!rBn || !sBn || !sig || ECDSA_SIG_set0(sig.get(), rBn.get(), sBn.get()) != 1)
        throw std::runtime_error("ECDSA_SIG_set0 failed");
    (void)rBn.release(); // owned by sig from here on
    (void)sBn.release();
    unsigned char* der = nullptr;
    const int length = i2d_ECDSA_SIG(sig.get(), &der);
    if (length <= 0)
        throw std::runtime_error("i2d_ECDSA_SIG failed");
    std::vector<std::uint8_t> out(der, der + length);
    OPENSSL_free(der);
    return out;
}

/// r || s, each left-padded to @p fieldBytes, read out of a DER signature.
inline std::vector<std::uint8_t> ecdsaRawOf(std::span<const std::uint8_t> der, std::size_t fieldBytes)
{
    const unsigned char* p = der.data();
    LibreSCRS::Internal::Crypto::EcdsaSigPtr sig(d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size())));
    if (!sig)
        throw std::runtime_error("d2i_ECDSA_SIG failed");
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    const int width = static_cast<int>(fieldBytes);
    std::vector<std::uint8_t> raw(2 * fieldBytes);
    if (BN_bn2binpad(r, raw.data(), width) != width || BN_bn2binpad(s, raw.data() + fieldBytes, width) != width)
        throw std::runtime_error("BN_bn2binpad failed");
    return raw;
}

/// Appends a definite DER length: the short form, or 81 xx up to 255.
inline void appendDerLength(std::vector<std::uint8_t>& out, std::size_t length)
{
    if (length > 0xFF)
        throw std::length_error("length past 81 xx");
    if (length >= 0x80)
        out.push_back(0x81);
    out.push_back(static_cast<std::uint8_t>(length));
}

/// SEQUENCE { INTEGER r, INTEGER s } the way a card that writes at the full
/// field width does: each INTEGER is r or s exactly as it stands in @p rawRs,
/// every byte of it, behind a 00 when @p zeroPrefix. DER would drop leading
/// zero bytes, and would read a set top bit (without the 00) as a sign.
inline std::vector<std::uint8_t> fixedWidthSequence(std::span<const std::uint8_t> rawRs, bool zeroPrefix)
{
    const std::size_t half = rawRs.size() / 2;
    std::vector<std::uint8_t> body;
    for (const auto part : {rawRs.first(half), rawRs.subspan(half)}) {
        body.push_back(0x02);
        appendDerLength(body, part.size() + (zeroPrefix ? 1 : 0));
        if (zeroPrefix)
            body.push_back(0x00);
        body.insert(body.end(), part.begin(), part.end());
    }
    std::vector<std::uint8_t> out{0x30};
    appendDerLength(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

struct EcTestKey
{
    LibreSCRS::Internal::Crypto::EvpPkeyPtr key;
    std::vector<std::uint8_t> certDer;
    std::size_t fieldBytes = 0;

    /// A signature over @p hash in the form a DER-answering card returns.
    [[nodiscard]] std::vector<std::uint8_t> signDer(std::span<const std::uint8_t> hash) const
    {
        LibreSCRS::Internal::Crypto::EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
        std::size_t length = 0;
        if (!ctx || EVP_PKEY_sign_init(ctx.get()) != 1 ||
            EVP_PKEY_sign(ctx.get(), nullptr, &length, hash.data(), hash.size()) != 1)
            throw std::runtime_error("EVP_PKEY_sign (size) failed");
        std::vector<std::uint8_t> der(length);
        if (EVP_PKEY_sign(ctx.get(), der.data(), &length, hash.data(), hash.size()) != 1)
            throw std::runtime_error("EVP_PKEY_sign failed");
        der.resize(length);
        return der;
    }

    /// Whether @p rawRs is r || s of a valid signature over @p hash by this key.
    [[nodiscard]] bool verifiesRaw(std::span<const std::uint8_t> hash, std::span<const std::uint8_t> rawRs) const
    {
        if (rawRs.size() != 2 * fieldBytes)
            return false;
        const auto der = ecdsaDer(rawRs.first(fieldBytes), rawRs.subspan(fieldBytes));
        LibreSCRS::Internal::Crypto::EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
        return ctx && EVP_PKEY_verify_init(ctx.get()) == 1 &&
               EVP_PKEY_verify(ctx.get(), der.data(), der.size(), hash.data(), hash.size()) == 1;
    }

    /// A signature over @p hash, as r || s, whose bytes satisfy @p wanted.
    /// ECDSA's random nonce makes every signature new, so it signs until one
    /// does; the caller sizes @p attempts from the property's odds.
    template <typename Predicate>
    [[nodiscard]] std::vector<std::uint8_t> rawSignatureWhere(std::span<const std::uint8_t> hash, Predicate&& wanted,
                                                              int attempts = 1 << 14) const
    {
        for (int i = 0; i < attempts; ++i) {
            auto raw = ecdsaRawOf(signDer(hash), fieldBytes);
            if (wanted(std::span<const std::uint8_t>(raw)))
                return raw;
        }
        throw std::runtime_error("no signature with the wanted bytes");
    }

    struct ChosenSignature
    {
        std::vector<std::uint8_t> hash; ///< fieldBytes long
        std::vector<std::uint8_t> der;  ///< exactly 2 * fieldBytes long
    };

    /// A VALID signature whose DER is exactly 2 * fieldBytes long -- the one
    /// reply that also reads as raw r || s. ECDSA leaves the hash free, so the
    /// nonce k and a short s are chosen and the hash solved for:
    /// s = k^-1 (h + r d)  =>  h = s k - r d (mod n). Every DER length here is
    /// short-form, so P-256 and P-384 only.
    [[nodiscard]] ChosenSignature signatureWithRawWidthDer() const
    {
        using LibreSCRS::Internal::Crypto::BnPtr;
        BIGNUM* privateOut = nullptr;
        if (EVP_PKEY_get_bn_param(key.get(), OSSL_PKEY_PARAM_PRIV_KEY, &privateOut) != 1)
            throw std::runtime_error("no private scalar");
        const BnPtr d(privateOut);
        char groupName[80] = {};
        std::size_t groupNameLength = 0;
        if (EVP_PKEY_get_utf8_string_param(key.get(), OSSL_PKEY_PARAM_GROUP_NAME, groupName, sizeof groupName,
                                           &groupNameLength) != 1)
            throw std::runtime_error("no group name");
        int nid = OBJ_txt2nid(groupName);
        if (nid == NID_undef)
            nid = EC_curve_nist2nid(groupName);
        const std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> group(EC_GROUP_new_by_curve_name(nid),
                                                                        &EC_GROUP_free);
        const std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> bnCtx(BN_CTX_new(), &BN_CTX_free);
        if (!group || !bnCtx)
            throw std::runtime_error("no group");
        const std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> point(EC_POINT_new(group.get()), &EC_POINT_free);
        const BIGNUM* n = EC_GROUP_get0_order(group.get());
        for (int attempt = 0; attempt < 64; ++attempt) {
            const BnPtr k(BN_new());
            const BnPtr x(BN_new());
            const BnPtr r(BN_new());
            const BnPtr s(BN_new());
            const BnPtr sk(BN_new());
            const BnPtr rd(BN_new());
            const BnPtr h(BN_new());
            if (!point || !k || !x || !r || !s || !sk || !rd || !h)
                throw std::runtime_error("allocation failed");
            if (BN_rand_range(k.get(), n) != 1 || BN_is_zero(k.get()))
                continue;
            if (EC_POINT_mul(group.get(), point.get(), k.get(), nullptr, nullptr, bnCtx.get()) != 1 ||
                EC_POINT_get_affine_coordinates(group.get(), point.get(), x.get(), nullptr, bnCtx.get()) != 1 ||
                BN_nnmod(r.get(), x.get(), n, bnCtx.get()) != 1 || BN_is_zero(r.get()))
                continue;
            // DER INTEGER content: the magnitude, plus a 00 when its top bit is set.
            const int rBytes = BN_num_bytes(r.get());
            const int rContent = rBytes + (BN_is_bit_set(r.get(), rBytes * 8 - 1) ? 1 : 0);
            // 30 L | 02 rContent r | 02 sContent s -- six header bytes.
            const int sContent = static_cast<int>(2 * fieldBytes) - 6 - rContent;
            if (sContent < 1)
                continue;
            std::vector<std::uint8_t> sBytes(static_cast<std::size_t>(sContent));
            if (RAND_bytes(sBytes.data(), sContent) != 1)
                throw std::runtime_error("RAND_bytes failed");
            sBytes[0] = static_cast<std::uint8_t>((sBytes[0] & 0x7F) | 0x01); // exactly sContent bytes, no pad
            if (BN_bin2bn(sBytes.data(), sContent, s.get()) == nullptr ||
                BN_mod_mul(sk.get(), s.get(), k.get(), n, bnCtx.get()) != 1 ||
                BN_mod_mul(rd.get(), r.get(), d.get(), n, bnCtx.get()) != 1 ||
                BN_mod_sub(h.get(), sk.get(), rd.get(), n, bnCtx.get()) != 1)
                throw std::runtime_error("BN arithmetic failed");
            ChosenSignature out;
            out.hash.resize(fieldBytes);
            if (BN_bn2binpad(h.get(), out.hash.data(), static_cast<int>(fieldBytes)) != static_cast<int>(fieldBytes))
                continue;
            std::vector<std::uint8_t> rBin(static_cast<std::size_t>(rBytes));
            (void)BN_bn2bin(r.get(), rBin.data());
            out.der = ecdsaDer(rBin, sBytes);
            if (out.der.size() != 2 * fieldBytes || !verifiesRaw(out.hash, ecdsaRawOf(out.der, fieldBytes)))
                continue;
            return out;
        }
        throw std::runtime_error("no signature whose DER has the raw width");
    }
};

/// A fresh key on @p group ("P-256", "P-384", "P-521") with a self-signed
/// certificate over it.
inline EcTestKey makeEcTestKey(const char* group)
{
    EcTestKey k;
    k.key.reset(EVP_EC_gen(group));
    if (!k.key)
        throw std::runtime_error("EVP_EC_gen failed");
    k.fieldBytes = (static_cast<std::size_t>(EVP_PKEY_get_bits(k.key.get())) + 7) / 8;
    LibreSCRS::Internal::Crypto::X509Ptr cert(X509_new());
    if (!cert)
        throw std::runtime_error("X509_new failed");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("EC test key"), -1, -1,
                               0);
    X509_set_issuer_name(cert.get(), name);
    if (X509_set_pubkey(cert.get(), k.key.get()) != 1 || X509_sign(cert.get(), k.key.get(), EVP_sha384()) <= 0)
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
