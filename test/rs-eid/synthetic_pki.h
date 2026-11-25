// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Synthetic issuer chain and signed objects for the CardEdge verification tests.
// Certificates use minimal-DER serials so they load on modern OpenSSL; nothing
// here is, or derives from, a real card's signed object or certificate.

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "rs-eid/document_fixtures.h"

#include <rs_document_profile.h>

#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace LibreSCRS::RsEId::Test {

namespace pki_detail {
struct EvpPkeyDel
{
    void operator()(EVP_PKEY* p) const noexcept
    {
        EVP_PKEY_free(p);
    }
};
struct X509Del
{
    void operator()(X509* p) const noexcept
    {
        X509_free(p);
    }
};
struct Pkcs7Del
{
    void operator()(PKCS7* p) const noexcept
    {
        PKCS7_free(p);
    }
};
struct BioDel
{
    void operator()(BIO* p) const noexcept
    {
        BIO_free(p);
    }
};
} // namespace pki_detail

using PkeyPtr = std::unique_ptr<EVP_PKEY, pki_detail::EvpPkeyDel>;
using CertPtr = std::unique_ptr<X509, pki_detail::X509Del>;

struct KeyCert
{
    PkeyPtr key;
    CertPtr cert;
};

/// Issue a certificate with subject CN @p cn signed by @p issuer (self-signed
/// when both issuer arguments are null). @p isCa sets a critical CA:TRUE.
inline KeyCert issue(const std::string& cn, const X509* issuer, EVP_PKEY* issuerKey, bool isCa, long serial)
{
    KeyCert kc;
    kc.key = PkeyPtr(EVP_RSA_gen(2048));
    kc.cert.reset(X509_new());
    X509* c = kc.cert.get();

    X509_set_version(c, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(c), serial);
    X509_gmtime_adj(X509_getm_notBefore(c), -3600);
    X509_gmtime_adj(X509_getm_notAfter(c), 3600 * 24 * 365);
    X509_set_pubkey(c, kc.key.get());

    X509_NAME* subj = X509_get_subject_name(c);
    X509_NAME_add_entry_by_NID(subj, NID_commonName, MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(cn.c_str()),
                               static_cast<int>(cn.size()), -1, 0);
    X509_set_issuer_name(c, issuer ? X509_get_subject_name(issuer) : subj);

    if (isCa) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
        X509_add_ext(c, ext, -1);
        X509_EXTENSION_free(ext);
    }

    X509_sign(c, issuerKey ? issuerKey : kc.key.get(), EVP_sha256());
    return kc;
}

inline std::vector<std::uint8_t> derOf(X509* cert)
{
    unsigned char* buf = nullptr;
    const int len = i2d_X509(cert, &buf);
    std::vector<std::uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

inline std::vector<std::uint8_t> sha256(const std::vector<std::uint8_t>& d)
{
    std::vector<std::uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(d.data(), d.size(), out.data());
    return out;
}

inline std::vector<std::uint8_t> der(PKCS7* p7)
{
    unsigned char* buf = nullptr;
    const int len = i2d_PKCS7(p7, &buf);
    std::vector<std::uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

/// A SignedData over @p content, signed by @p leaf.
inline std::vector<std::uint8_t> signContent(X509* leaf, EVP_PKEY* leafKey, const std::vector<std::uint8_t>& content)
{
    std::unique_ptr<BIO, pki_detail::BioDel> data(BIO_new_mem_buf(content.data(), static_cast<int>(content.size())));
    std::unique_ptr<PKCS7, pki_detail::Pkcs7Del> p7(PKCS7_sign(leaf, leafKey, nullptr, data.get(), PKCS7_BINARY));
    return p7 ? der(p7.get()) : std::vector<std::uint8_t>{};
}

/// A SignedData whose content is the given 32-byte slots, concatenated.
inline std::vector<std::uint8_t> signSlots(X509* leaf, EVP_PKEY* leafKey,
                                           const std::vector<std::vector<std::uint8_t>>& slots)
{
    std::vector<std::uint8_t> content;
    for (const auto& s : slots)
        content.insert(content.end(), s.begin(), s.end());
    return signContent(leaf, leafKey, content);
}

/// A SignedData carrying two signers.
inline std::vector<std::uint8_t> signWithTwoSigners(X509* a, EVP_PKEY* aKey, X509* b, EVP_PKEY* bKey)
{
    const std::string content = "card-security-object";
    std::unique_ptr<BIO, pki_detail::BioDel> data(BIO_new_mem_buf(content.data(), static_cast<int>(content.size())));
    std::unique_ptr<PKCS7, pki_detail::Pkcs7Del> p7(
        PKCS7_sign(nullptr, nullptr, nullptr, data.get(), PKCS7_BINARY | PKCS7_PARTIAL));
    PKCS7_sign_add_signer(p7.get(), a, aKey, nullptr, PKCS7_BINARY);
    PKCS7_sign_add_signer(p7.get(), b, bKey, nullptr, PKCS7_BINARY);
    PKCS7_final(p7.get(), data.get(), PKCS7_BINARY);
    return der(p7.get());
}

/// Root, "Resursi" issuing CA and a document signer under it: the shape the
/// verifier pins signers to.
struct ResursiChain
{
    KeyCert root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    KeyCert resursi = issue("MUPCA Resursi", root.cert.get(), root.key.get(), true, 2);
    KeyCert leaf = issue("StrongSecurityFormat", resursi.cert.get(), resursi.key.get(), false, 3);

    std::vector<std::vector<std::uint8_t>> anchors() const
    {
        return {derOf(root.cert.get()), derOf(resursi.cert.get())};
    }
    std::vector<std::uint8_t> sign(const std::vector<std::vector<std::uint8_t>>& slots) const
    {
        return signSlots(leaf.cert.get(), leaf.key.get(), slots);
    }
};

/// A signed-object file as the chip stores it: container, inner TLV, CMS.
/// An inner tag whose first byte is 0x30 (0x0830) is what the one-slot object
/// of the official ID carries.
inline std::vector<std::uint8_t> signedObjectFile(std::uint16_t fid, const std::vector<std::uint8_t>& cms,
                                                  std::uint16_t innerTag = 0x0801)
{
    std::vector<std::uint8_t> inner;
    Core::TestData::appendLe16(inner, innerTag);
    Core::TestData::appendLe16(inner, static_cast<std::uint16_t>(cms.size()));
    inner.insert(inner.end(), cms.begin(), cms.end());
    std::vector<std::uint8_t> out;
    Core::TestData::appendLe16(out, fid);
    Core::TestData::appendLe16(out, static_cast<std::uint16_t>(inner.size()));
    out.insert(out.end(), inner.begin(), inner.end());
    return out;
}

/// The digest the issuer put at each slot of @p sod, over the bytes @p files
/// holds; the protected slot gets a digest nothing can match.
inline std::vector<std::vector<std::uint8_t>> slotDigests(const Core::DocumentProfile& /*profile*/,
                                                          const Core::SodSpec& sod, const CardFiles& files)
{
    std::vector<std::vector<std::uint8_t>> out;
    for (const std::uint16_t fid : sod.slots) {
        if (fid == Core::kProtectedSlot) {
            out.push_back(sha256({'p', 'r', 'o', 't', 'e', 'c', 't', 'e', 'd'}));
            continue;
        }
        // Independent of the production block rule: the two files hashed whole
        // (public key, certificate digests) over every served byte, the rest
        // over header plus declared length.
        const auto& bytes = files.at(fid);
        if (fid == 0x0F12 || fid == 0x0D10) {
            out.push_back(sha256(bytes));
        } else {
            const std::size_t declared = 4u + bytes[2] + (static_cast<std::size_t>(bytes[3]) << 8);
            out.push_back(sha256({bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(declared)}));
        }
    }
    return out;
}

/// @p files plus every signed object of @p profile, signed by @p chain over the
/// files as they stand.
inline CardFiles withSignedObjects(const Core::DocumentProfile& profile, CardFiles files, const ResursiChain& chain)
{
    for (const auto& sod : profile.sods) {
        const auto inner = sod.slots.size() == 1 && profile.code == "EL" ? 0x0830 : 0x0801;
        files[sod.fid] =
            signedObjectFile(sod.fid, chain.sign(slotDigests(profile, sod, files)), static_cast<std::uint16_t>(inner));
    }
    return files;
}

} // namespace LibreSCRS::RsEId::Test
