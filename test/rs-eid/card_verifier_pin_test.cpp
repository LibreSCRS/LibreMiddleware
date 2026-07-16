// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end regression guard for the MUP document-signer pin: drives the PUBLIC
// CardVerifier::verifyCard(Gemalto2014) path with synthetic PKCS#7 Security Objects
// signed by different CA branches, and asserts the trust decision. This is the
// exploit-and-fix pair — a citizen-branch signer chains validly to the same root but
// must NOT be attributed to MUP. Synthetic certs use minimal-DER serials so they load
// on modern OpenSSL (unlike the bundled legacy MUP CAs), which is exactly why this
// exercises the pin logic independently of the separate legacy-cert load issue.

#include <gtest/gtest.h>

#include "card_protocol.h"
#include "card_reader_base.h"
#include "card_verifier.h"
#include "eidtypes.h"

#include "pcsc_connection.h"

#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace {

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
using PkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDel>;
using CertPtr = std::unique_ptr<X509, X509Del>;

struct KeyCert
{
    PkeyPtr key;
    CertPtr cert;
};

PkeyPtr genKey()
{
    return PkeyPtr(EVP_RSA_gen(2048));
}

// Issue a certificate with subject CN `cn`, signed by `issuer`/`issuerKey`
// (self-signed if both null). `isCa` sets a critical CA:TRUE basicConstraints.
KeyCert issue(const std::string& cn, const X509* issuer, EVP_PKEY* issuerKey, bool isCa, long serial)
{
    KeyCert kc;
    kc.key = genKey();
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

    if (issuer)
        X509_set_issuer_name(c, X509_get_subject_name(const_cast<X509*>(issuer)));
    else
        X509_set_issuer_name(c, subj); // self-signed root

    if (isCa) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "critical,CA:TRUE");
        X509_add_ext(c, ext, -1);
        X509_EXTENSION_free(ext);
    }

    X509_sign(c, issuerKey ? issuerKey : kc.key.get(), EVP_sha256());
    return kc;
}

std::vector<uint8_t> derOf(X509* cert)
{
    unsigned char* buf = nullptr;
    int len = i2d_X509(cert, &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

// Build a SOD-shaped PKCS#7 SignedData over arbitrary content, signed by `leaf`.
// (verifyGemaltoCardCert verifies the signer chain + domain, not the content, so the
// payload is irrelevant to this test.)
std::vector<uint8_t> makeSod(X509* leaf, EVP_PKEY* leafKey)
{
    std::unique_ptr<BIO, BioDel> data(BIO_new_mem_buf("card-security-object", -1));
    std::unique_ptr<PKCS7, Pkcs7Del> p7(PKCS7_sign(leaf, leafKey, nullptr, data.get(), PKCS7_BINARY));
    EXPECT_NE(p7.get(), nullptr);
    unsigned char* buf = nullptr;
    int len = i2d_PKCS7(p7.get(), &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

// Reader that returns the given SOD bytes for the fixed-data SOD file, empty otherwise.
class SodReader : public eidcard::CardReaderBase
{
public:
    explicit SodReader(std::vector<uint8_t> sod) : sod_(std::move(sod)) {}
    std::vector<uint8_t> readFile(LibreSCRS::SmartCard::Internal::PCSCConnection&, uint8_t h, uint8_t l) override
    {
        return (h == eidcard::protocol::FILE_SOD_FX_H && l == eidcard::protocol::FILE_SOD_FX_L)
                   ? sod_
                   : std::vector<uint8_t>{};
    }
    std::vector<uint8_t> readFileRaw(LibreSCRS::SmartCard::Internal::PCSCConnection& c, uint8_t h, uint8_t l) override
    {
        return readFile(c, h, l);
    }

private:
    std::vector<uint8_t> sod_;
};

eidcard::VerificationResult runVerifyCard(const std::vector<KeyCert*>& storeCerts, const std::vector<uint8_t>& sod)
{
    eidcard::CardVerifier v("");
    for (auto* kc : storeCerts)
        v.addCertificate(derOf(kc->cert.get()));

    LibreSCRS::SmartCard::Internal::PCSCConnection conn(LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{},
                                                        "fake");
    SodReader reader(sod);
    return v.verifyCard(conn, reader, eidcard::CardType::Gemalto2014);
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& d)
{
    std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(d.data(), d.size(), out.data());
    return out;
}

// A fixed-data SOD signs the concatenated SHA-256 of the data blocks. verifyGemaltoSOD
// searches that content for each block's hash, so matching blocks pass the hash check.
std::vector<uint8_t> makeSodOverHashes(X509* leaf, EVP_PKEY* leafKey, const std::vector<std::vector<uint8_t>>& blocks)
{
    std::vector<uint8_t> content;
    for (const auto& b : blocks) {
        auto h = sha256(b);
        content.insert(content.end(), h.begin(), h.end());
    }
    std::unique_ptr<BIO, BioDel> data(BIO_new_mem_buf(content.data(), static_cast<int>(content.size())));
    std::unique_ptr<PKCS7, Pkcs7Del> p7(PKCS7_sign(leaf, leafKey, nullptr, data.get(), PKCS7_BINARY));
    EXPECT_NE(p7.get(), nullptr);
    unsigned char* buf = nullptr;
    int len = i2d_PKCS7(p7.get(), &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

// A PKCS#7 SignedData carrying TWO SignerInfos (two distinct signers).
std::vector<uint8_t> makeMultiSignerSod(X509* a, EVP_PKEY* aKey, X509* b, EVP_PKEY* bKey)
{
    std::unique_ptr<BIO, BioDel> data(BIO_new_mem_buf("card-security-object", -1));
    std::unique_ptr<PKCS7, Pkcs7Del> p7(
        PKCS7_sign(nullptr, nullptr, nullptr, data.get(), PKCS7_BINARY | PKCS7_PARTIAL));
    EXPECT_NE(p7.get(), nullptr);
    EXPECT_NE(PKCS7_sign_add_signer(p7.get(), a, aKey, nullptr, PKCS7_BINARY), nullptr);
    EXPECT_NE(PKCS7_sign_add_signer(p7.get(), b, bKey, nullptr, PKCS7_BINARY), nullptr);
    EXPECT_EQ(PKCS7_final(p7.get(), data.get(), PKCS7_BINARY), 1);
    unsigned char* buf = nullptr;
    int len = i2d_PKCS7(p7.get(), &buf);
    std::vector<uint8_t> out(buf, buf + len);
    OPENSSL_free(buf);
    return out;
}

// Reader mapping (file-high, file-low) -> bytes, empty for unknown files.
class MultiFileReader : public eidcard::CardReaderBase
{
public:
    void set(uint8_t h, uint8_t l, std::vector<uint8_t> v)
    {
        files_[key(h, l)] = std::move(v);
    }
    std::vector<uint8_t> readFile(LibreSCRS::SmartCard::Internal::PCSCConnection&, uint8_t h, uint8_t l) override
    {
        auto it = files_.find(key(h, l));
        return it != files_.end() ? it->second : std::vector<uint8_t>{};
    }
    std::vector<uint8_t> readFileRaw(LibreSCRS::SmartCard::Internal::PCSCConnection& c, uint8_t h, uint8_t l) override
    {
        return readFile(c, h, l);
    }

private:
    static uint16_t key(uint8_t h, uint8_t l)
    {
        return static_cast<uint16_t>((h << 8) | l);
    }
    std::map<uint16_t, std::vector<uint8_t>> files_;
};

eidcard::VerificationResult runVerifyFixedData(const std::vector<KeyCert*>& storeCerts, MultiFileReader& reader)
{
    eidcard::CardVerifier v("");
    for (auto* kc : storeCerts)
        v.addCertificate(derOf(kc->cert.get()));
    LibreSCRS::SmartCard::Internal::PCSCConnection conn(LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag{},
                                                        "fake");
    return v.verifyFixedData(conn, reader, eidcard::CardType::Gemalto2014);
}

} // namespace

// A SOD signed by a document-signer under a "Resursi" CA, chaining to a trusted root,
// is Valid.
TEST(CardVerifierPin, AcceptsResursiSignedSod)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto resursi = issue("MUPCA Resursi", root.cert.get(), root.key.get(), true, 2);
    auto leaf = issue("StrongSecurityFormat", resursi.cert.get(), resursi.key.get(), false, 3);
    auto sod = makeSod(leaf.cert.get(), leaf.key.get());

    EXPECT_EQ(runVerifyCard({&root, &resursi}, sod), eidcard::VerificationResult::Valid);
}

// THE exploit case: a SOD signed by a certificate under the CITIZEN ("Gradjani") CA
// chains validly to the SAME trusted root, but is NOT a MUP document-signer, so it must
// NOT be Valid. The pin reports Unknown (indeterminate — cannot attribute to MUP), not
// a false "tampered" Invalid.
TEST(CardVerifierPin, RejectsCitizenSignedSodAsUnknown)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto gradjani = issue("MUPCA Gradjani", root.cert.get(), root.key.get(), true, 2);
    auto citizen = issue("Citizen Signing Cert", gradjani.cert.get(), gradjani.key.get(), false, 3);
    auto sod = makeSod(citizen.cert.get(), citizen.key.get());

    // Both the root and the citizen CA are trusted — the chain is cryptographically
    // valid — yet the pin denies the "valid" badge.
    EXPECT_EQ(runVerifyCard({&root, &gradjani}, sod), eidcard::VerificationResult::Unknown);
}

// A SOD whose signer does not chain to any trusted anchor is Invalid (broken chain).
TEST(CardVerifierPin, RejectsUntrustedSignerAsInvalid)
{
    auto foreignRoot = issue("Some Qualified CA", nullptr, nullptr, true, 1);
    auto foreignResursi = issue("MUPCA Resursi", foreignRoot.cert.get(), foreignRoot.key.get(), true, 2);
    auto leaf = issue("StrongSecurityFormat", foreignResursi.cert.get(), foreignResursi.key.get(), false, 3);
    auto sod = makeSod(leaf.cert.get(), leaf.key.get());

    // Only the intermediate is added, not the root → chain cannot terminate at a trusted
    // anchor. Even though the issuer CN says "Resursi", the chain fails first.
    EXPECT_EQ(runVerifyCard({&foreignResursi}, sod), eidcard::VerificationResult::Invalid);
}

// The card-DATA attestation path (verifyFixedData → verifyGemaltoSOD): a resursi-signed
// SOD whose hashes match the data blocks passes both the pin and the hash check → Valid.
TEST(CardVerifierPin, FixedDataResursiSignedWithMatchingHashesIsValid)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto resursi = issue("MUPCA Resursi", root.cert.get(), root.key.get(), true, 2);
    auto leaf = issue("StrongSecurityFormat", resursi.cert.get(), resursi.key.get(), false, 3);

    std::vector<uint8_t> doc{0x01, 0x02, 0x03}, pers{0x04, 0x05}, portrait{0x06, 0x07, 0x08, 0x09};
    auto sod = makeSodOverHashes(leaf.cert.get(), leaf.key.get(), {doc, pers, portrait});

    MultiFileReader reader;
    reader.set(eidcard::protocol::FILE_SOD_FX_H, eidcard::protocol::FILE_SOD_FX_L, sod);
    reader.set(eidcard::protocol::FILE_DOCUMENT_DATA_H, eidcard::protocol::FILE_DOCUMENT_DATA_L, doc);
    reader.set(eidcard::protocol::FILE_PERSONAL_DATA_H, eidcard::protocol::FILE_PERSONAL_DATA_L, pers);
    reader.set(eidcard::protocol::FILE_PORTRAIT_H, eidcard::protocol::FILE_PORTRAIT_L, portrait);

    EXPECT_EQ(runVerifyFixedData({&root, &resursi}, reader), eidcard::VerificationResult::Valid);
}

// THE data-path exploit: a citizen-signed SOD is built with hashes that DO match the
// data blocks (so it would sail through the hash check). The pin rejects it as Unknown
// BEFORE the hash loop even runs — the signer's domain is checked first. (The matching
// hashes are exercised by the resursi sibling above, which reaches the hash loop.)
TEST(CardVerifierPin, FixedDataCitizenSignedWithMatchingHashesIsUnknown)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto gradjani = issue("MUPCA Gradjani", root.cert.get(), root.key.get(), true, 2);
    auto citizen = issue("Citizen Signing Cert", gradjani.cert.get(), gradjani.key.get(), false, 3);

    std::vector<uint8_t> doc{0x01, 0x02, 0x03}, pers{0x04, 0x05}, portrait{0x06, 0x07, 0x08, 0x09};
    auto sod = makeSodOverHashes(citizen.cert.get(), citizen.key.get(), {doc, pers, portrait});

    MultiFileReader reader;
    reader.set(eidcard::protocol::FILE_SOD_FX_H, eidcard::protocol::FILE_SOD_FX_L, sod);
    reader.set(eidcard::protocol::FILE_DOCUMENT_DATA_H, eidcard::protocol::FILE_DOCUMENT_DATA_L, doc);
    reader.set(eidcard::protocol::FILE_PERSONAL_DATA_H, eidcard::protocol::FILE_PERSONAL_DATA_L, pers);
    reader.set(eidcard::protocol::FILE_PORTRAIT_H, eidcard::protocol::FILE_PORTRAIT_L, portrait);

    EXPECT_EQ(runVerifyFixedData({&root, &gradjani}, reader), eidcard::VerificationResult::Unknown);
}

// A SOD carrying two signers is rejected (exactly one signer required) — an attacker
// cannot append a second, legitimate-looking signer to smuggle a rogue one, or vice-versa.
TEST(CardVerifierPin, MultiSignerSodIsInvalid)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto resursi = issue("MUPCA Resursi", root.cert.get(), root.key.get(), true, 2);
    auto gradjani = issue("MUPCA Gradjani", root.cert.get(), root.key.get(), true, 3);
    auto resLeaf = issue("StrongSecurityFormat", resursi.cert.get(), resursi.key.get(), false, 4);
    auto citLeaf = issue("Citizen Signing Cert", gradjani.cert.get(), gradjani.key.get(), false, 5);

    auto sod = makeMultiSignerSod(resLeaf.cert.get(), resLeaf.key.get(), citLeaf.cert.get(), citLeaf.key.get());

    EXPECT_EQ(runVerifyCard({&root, &resursi, &gradjani}, sod), eidcard::VerificationResult::Invalid);
}

// A SOD whose bytes were altered after signing fails PKCS7 verification → Invalid, even
// with a genuine resources signer trusted in the store. Guards that the CMS signature is
// actually checked (PKCS7_NOVERIFY suppresses only chain building, not signature verify).
TEST(CardVerifierPin, CorruptedSodIsInvalid)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto resursi = issue("MUPCA Resursi", root.cert.get(), root.key.get(), true, 2);
    auto leaf = issue("StrongSecurityFormat", resursi.cert.get(), resursi.key.get(), false, 3);
    auto sod = makeSod(leaf.cert.get(), leaf.key.get());
    ASSERT_GT(sod.size(), 40u);
    sod[sod.size() - 20] ^= 0xFF; // flip a byte in the trailing signature region

    EXPECT_EQ(runVerifyCard({&root, &resursi}, sod), eidcard::VerificationResult::Invalid);
}
