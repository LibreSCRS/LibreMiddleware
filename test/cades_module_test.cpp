// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/cades_module.h"
#include "native/openssl_raii.h"
#include "native/pkcs11_module_manager.h"
#include "native/native_utils.h"
#include "native/pkcs11_token.h"
#include "signing_test_support/mock_tsa_server.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <string>
#include <vector>

using namespace libresign;

namespace {

// id-smime-aa-signatureTimeStamp (RFC 3161 token carrier, ETSI EN 319 122-1
// §5.3.1) — the unsigned attribute a B-T upgrade attaches to ONE SignerInfo.
constexpr const char* kSignatureTimeStampOid = "1.2.840.113549.1.9.16.2.14";

/// Parse a DER CMS or fail the calling test.
libresign::CmsPtr parseCmsOrDie(const std::vector<uint8_t>& der)
{
    const unsigned char* p = der.data();
    return libresign::CmsPtr(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(der.size())));
}

/// Number of unsigned attributes carrying @p oid on @p si. Counting per
/// SignerInfo (rather than per document) is the whole point of the per-signer
/// pins below: a document-level count cannot tell which signer was upgraded.
int unsignedAttrCount(CMS_SignerInfo* si, const char* oid)
{
    libresign::Asn1ObjectPtr obj(OBJ_txt2obj(oid, 1));
    if (!obj)
        return -1;
    int count = 0;
    const int attrCount = CMS_unsigned_get_attr_count(si);
    for (int i = 0; i < attrCount; ++i) {
        X509_ATTRIBUTE* attr = CMS_unsigned_get_attr(si, i);
        if (attr && OBJ_cmp(X509_ATTRIBUTE_get0_object(attr), obj.get()) == 0)
            ++count;
    }
    return count;
}

/// The SignerInfo built over @p certDer, or nullptr when none matches.
/// SignerInfos are an ASN.1 SET OF, which OpenSSL sorts by encoded octets at
/// i2d time — so a positional index is meaningless across a DER round-trip and
/// the signer has to be found by its certificate.
CMS_SignerInfo* signerInfoForCert(CMS_ContentInfo* cms, const std::vector<uint8_t>& certDer)
{
    const unsigned char* p = certDer.data();
    libresign::X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(certDer.size())));
    if (!cert)
        return nullptr;
    STACK_OF(CMS_SignerInfo)* sis = CMS_get0_SignerInfos(cms);
    for (int i = 0; i < sk_CMS_SignerInfo_num(sis); ++i) {
        CMS_SignerInfo* si = sk_CMS_SignerInfo_value(sis, i);
        if (CMS_SignerInfo_cert_cmp(si, cert.get()) == 0)
            return si;
    }
    return nullptr;
}

/// True when the SignedData certificate set carries @p certDer.
bool cmsCarriesCert(CMS_ContentInfo* cms, const std::vector<uint8_t>& certDer)
{
    const unsigned char* p = certDer.data();
    libresign::X509Ptr want(d2i_X509(nullptr, &p, static_cast<long>(certDer.size())));
    if (!want)
        return false;
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    if (!certs)
        return false;
    bool found = false;
    for (int i = 0; i < sk_X509_num(certs) && !found; ++i)
        found = X509_cmp(sk_X509_value(certs, i), want.get()) == 0;
    sk_X509_pop_free(certs, X509_free);
    return found;
}

int cmsCertCount(CMS_ContentInfo* cms)
{
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    if (!certs)
        return 0;
    const int n = sk_X509_num(certs);
    sk_X509_pop_free(certs, X509_free);
    return n;
}

/// Self-signed throwaway CA, DER. Stands in for path material that the token
/// does not carry, so the certificate-set union can be exercised with a
/// certificate that is provably not already in the set.
std::vector<uint8_t> makeSelfSignedCaDer(const std::string& cn)
{
    libresign::EvpPkeyPtr key(EVP_EC_gen("P-256"));
    if (!key)
        return {};
    libresign::X509Ptr x(X509_new());
    X509_set_version(x.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 42);
    X509_gmtime_adj(X509_getm_notBefore(x.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x.get()), 60L * 60 * 24 * 365);
    X509_set_pubkey(x.get(), key.get());
    X509_NAME_add_entry_by_txt(X509_get_subject_name(x.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(x.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_sign(x.get(), key.get(), EVP_sha256());
    return libresign::native_utils::derEncode(i2d_X509, x.get());
}

} // namespace

class CAdESModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        auto slot = libresign::test::findSoftHsmTestSlot(manager.acquire(softHsmPath));
        if (!slot)
            GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";
        testSlot = *slot;
    }

    /// Sign @p data at B-B with the valid signer; reports the signer's
    /// certificate through @p certDer so the caller can tell the two signers of
    /// the appended document apart.
    std::vector<uint8_t> signFirst(const std::vector<uint8_t>& data, std::vector<uint8_t>& certDer)
    {
        CAdESModule cades;
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                          libresign::Pkcs11Token::TestSlotId{testSlot});
        certDer = token.certificate();
        auto result = cades.sign(data, token, SignatureLevel::B_B, {});
        EXPECT_TRUE(result.success) << result.errorMessage;
        return result.signedDocument;
    }

    /// Append a second signer using the OTHER key pair on the token, so the two
    /// SignerInfos carry distinct certificates and per-signer assertions can
    /// name their target. The expired pair is the only second identity the
    /// SoftHSM store provides; module-level appendSigner applies no expiry
    /// policy (that lives in NativeSigningService), so it signs normally here.
    SigningResult appendSecond(const std::vector<uint8_t>& prior, const std::vector<uint8_t>& originalDoc,
                               SignatureLevel level, const TSAConfig& tsa, std::vector<uint8_t>& certDer)
    {
        CAdESModule cades;
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"),
                          libresign::test::kSoftHsmExpiredKeyLabel, libresign::Pkcs11Token::TestSlotId{testSlot});
        certDer = token.certificate();
        return cades.appendSigner(prior, originalDoc, token, level, tsa);
    }

    const char* softHsmPath = nullptr;
    libresign::Pkcs11ModuleManager manager;
    unsigned long testSlot = 0;
};

TEST_F(CAdESModuleTest, SignBB_ProducesValidCMS)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    CAdESModule cades;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto cms = cades.signBB(data, token);

    ASSERT_FALSE(cms.empty());

    // Verify it starts with SEQUENCE tag (valid ASN.1)
    ASSERT_EQ(cms[0], 0x30);

    // Parse and verify structure
    const unsigned char* p = cms.data();
    CMS_ContentInfo* info = d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(cms.size()));
    ASSERT_NE(info, nullptr);

    // Verify it has signer infos
    STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(info);
    ASSERT_NE(signers, nullptr);
    ASSERT_GE(sk_CMS_SignerInfo_num(signers), 1);

    // Verify the signer info has signed attributes
    CMS_SignerInfo* si = sk_CMS_SignerInfo_value(signers, 0);
    int attrCount = CMS_signed_get_attr_count(si);
    EXPECT_GE(attrCount, 3); // content-type, message-digest, signing-certificate-v2 (+ signing-time)

    // Verify signing-certificate-v2 attribute is present
    // OID: 1.2.840.113549.1.9.16.2.47
    ASN1_OBJECT* sigCertV2Oid = OBJ_txt2obj("1.2.840.113549.1.9.16.2.47", 1);
    ASSERT_NE(sigCertV2Oid, nullptr);
    int idx = CMS_signed_get_attr_by_OBJ(si, sigCertV2Oid, -1);
    EXPECT_GE(idx, 0) << "signing-certificate-v2 attribute not found";
    ASN1_OBJECT_free(sigCertV2Oid);

    // Verify signature value is non-empty
    ASN1_OCTET_STRING* sig = CMS_SignerInfo_get0_signature(si);
    ASSERT_NE(sig, nullptr);
    EXPECT_GT(ASN1_STRING_length(sig), 0);

    CMS_ContentInfo_free(info);
}

TEST_F(CAdESModuleTest, SignBB_IsDetached)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    CAdESModule cades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    auto cms = cades.signBB(data, token);
    ASSERT_FALSE(cms.empty());

    const unsigned char* p = cms.data();
    CMS_ContentInfo* info = d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(cms.size()));
    ASSERT_NE(info, nullptr);

    // Detached means no encapsulated content
    EXPECT_TRUE(CMS_is_detached(info));

    CMS_ContentInfo_free(info);
}

TEST_F(CAdESModuleTest, Sign_BB_Convenience)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    CAdESModule cades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    TSAConfig tsa; // empty -- not used for B-B
    auto result = cades.sign(data, token, SignatureLevel::B_B, tsa);

    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());
}

TEST_F(CAdESModuleTest, SignBB_DifferentDataProducesDifferentSignature)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    CAdESModule cades;

    std::vector<uint8_t> data1 = {'A', 'B', 'C'};
    std::vector<uint8_t> data2 = {'X', 'Y', 'Z'};

    auto cms1 = cades.signBB(data1, token);
    auto cms2 = cades.signBB(data2, token);

    ASSERT_FALSE(cms1.empty());
    ASSERT_FALSE(cms2.empty());
    EXPECT_NE(cms1, cms2);
}

// ---- Per-signer level upgrades (ETSI EN 319 122-1 §5.3) ----

// A signature timestamp belongs to the signer that requested it. Count the
// signature-timestamp attribute PER SignerInfo, not per document: a
// document-level count is satisfied by attaching the new signer's timestamp
// to the prior signer, which is exactly the failure mode being excluded.
TEST_F(CAdESModuleTest, AppendSignerAtBTTimestampsOnlyTheNewSigner)
{
    libresign::test::MockTsaServer tsaServer;
    const std::vector<uint8_t> data = {'M', 'u', 'l', 't', 'i'};

    std::vector<uint8_t> firstCert;
    auto prior = signFirst(data, firstCert);
    ASSERT_FALSE(prior.empty());

    TSAConfig tsa;
    tsa.url = tsaServer.url();
    std::vector<uint8_t> secondCert;
    auto appended = appendSecond(prior, data, SignatureLevel::B_T, tsa, secondCert);
    ASSERT_TRUE(appended.success) << appended.errorMessage;
    EXPECT_EQ(tsaServer.servedCount(), 1) << "exactly one RFC 3161 round-trip, for the new signer";

    auto cms = parseCmsOrDie(appended.signedDocument);
    ASSERT_NE(cms.get(), nullptr);
    ASSERT_EQ(sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(cms.get())), 2);

    CMS_SignerInfo* firstSi = signerInfoForCert(cms.get(), firstCert);
    CMS_SignerInfo* secondSi = signerInfoForCert(cms.get(), secondCert);
    ASSERT_NE(firstSi, nullptr) << "prior signer's SignerInfo must survive the append";
    ASSERT_NE(secondSi, nullptr) << "appended signer's SignerInfo must be present";

    EXPECT_EQ(unsignedAttrCount(secondSi, kSignatureTimeStampOid), 1)
        << "the appended signer must carry its OWN signature timestamp";
    EXPECT_EQ(unsignedAttrCount(firstSi, kSignatureTimeStampOid), 0)
        << "the prior signer signed at B-B and must not acquire a timestamp it never requested";
}

// Appending must not strip the certificates the prior signers depend on: a
// verifier that can no longer build the first signer's path cannot validate a
// signature that was valid before the append.
TEST_F(CAdESModuleTest, AppendSignerKeepsThePriorSignerCertificate)
{
    libresign::test::MockTsaServer tsaServer;
    const std::vector<uint8_t> data = {'U', 'n', 'i', 'o', 'n'};

    std::vector<uint8_t> firstCert;
    auto prior = signFirst(data, firstCert);
    ASSERT_FALSE(prior.empty());

    TSAConfig tsa;
    tsa.url = tsaServer.url();
    std::vector<uint8_t> secondCert;
    auto appended = appendSecond(prior, data, SignatureLevel::B_T, tsa, secondCert);
    ASSERT_TRUE(appended.success) << appended.errorMessage;
    ASSERT_NE(firstCert, secondCert) << "fixture must supply two distinct signer certificates";

    auto cms = parseCmsOrDie(appended.signedDocument);
    ASSERT_NE(cms.get(), nullptr);
    EXPECT_TRUE(cmsCarriesCert(cms.get(), firstCert)) << "prior signer's certificate was stripped by the append";
    EXPECT_TRUE(cmsCarriesCert(cms.get(), secondCert)) << "appended signer's certificate is missing";
}

// addCertificateChain embeds the new signer's path material. It must UNION
// into the SignedData certificate set — replacing the set would drop every
// prior signer's certificate. Driven directly (rather than through a B-LT
// signature) because the long-term gate fails closed on this token's
// single self-signed leaf before the chain is ever embedded.
TEST_F(CAdESModuleTest, AddCertificateChainUnionsIntoTheExistingCertificateSet)
{
    CAdESModule cades;
    const std::vector<uint8_t> data = {'C', 'h', 'a', 'i', 'n'};

    std::vector<uint8_t> firstCert;
    auto prior = signFirst(data, firstCert);
    ASSERT_FALSE(prior.empty());

    std::vector<uint8_t> secondCert;
    auto appended = appendSecond(prior, data, SignatureLevel::B_B, {}, secondCert);
    ASSERT_TRUE(appended.success) << appended.errorMessage;

    const auto extraCa = makeSelfSignedCaDer("LibreSCRS CAdES Union Test CA");
    ASSERT_FALSE(extraCa.empty());

    // chainDer[0] is by contract the leaf the SignerInfo already carries;
    // chainDer[1..] is the path material to embed.
    auto widened = cades.addCertificateChain(appended.signedDocument, {secondCert, extraCa});

    auto cms = parseCmsOrDie(widened);
    ASSERT_NE(cms.get(), nullptr);
    EXPECT_TRUE(cmsCarriesCert(cms.get(), firstCert))
        << "embedding the new signer's chain must not evict the first signer's certificate";
    EXPECT_TRUE(cmsCarriesCert(cms.get(), secondCert)) << "appended signer's certificate must remain";
    EXPECT_TRUE(cmsCarriesCert(cms.get(), extraCa)) << "supplied path material must be embedded";
    EXPECT_EQ(cmsCertCount(cms.get()), 3) << "union of {two signer leaves} and {one CA}, with no duplicates";
}

// B-LT on append now reaches the long-term revocation gate instead of being
// refused up front. The SoftHSM token's single self-signed leaf is a chain of
// length one: no Trusted-List anchor completed it and no issuer hop reaches a
// verified root, so the tail is unprovable and the gate must fail closed.
TEST_F(CAdESModuleTest, AppendSignerAtLongTermRejectsUnterminatedChain)
{
    libresign::test::MockTsaServer tsaServer;
    const std::vector<uint8_t> data = {'L', 'o', 'n', 'g'};

    std::vector<uint8_t> firstCert;
    auto prior = signFirst(data, firstCert);
    ASSERT_FALSE(prior.empty());

    TSAConfig tsa;
    tsa.url = tsaServer.url();
    std::vector<uint8_t> secondCert;
    auto appended = appendSecond(prior, data, SignatureLevel::B_LT, tsa, secondCert);
    EXPECT_FALSE(appended.success);
    ASSERT_TRUE(appended.failureKind.has_value()) << appended.errorMessage;
    EXPECT_EQ(*appended.failureKind, SignFailureKind::CertificateChainIncomplete) << appended.errorMessage;
}

// B-LTA stays refused on the append path. The archive-timestamp message
// imprint of ETSI EN 319 122-1 §5.5.4 covers the SignedData certificate set,
// so an archive timestamp minted for a newly appended signer would be computed
// over a certificate set that the prior signers' own archive timestamps do not
// describe. Refusing is honest; emitting would be a spec-wrong document.
TEST_F(CAdESModuleTest, AppendSignerRejectsArchiveLevel)
{
    libresign::test::MockTsaServer tsaServer;
    const std::vector<uint8_t> data = {'A', 'r', 'c', 'h'};

    std::vector<uint8_t> firstCert;
    auto prior = signFirst(data, firstCert);
    ASSERT_FALSE(prior.empty());

    TSAConfig tsa;
    tsa.url = tsaServer.url();
    std::vector<uint8_t> secondCert;
    auto appended = appendSecond(prior, data, SignatureLevel::B_LTA, tsa, secondCert);
    EXPECT_FALSE(appended.success);
    ASSERT_TRUE(appended.failureKind.has_value()) << appended.errorMessage;
    EXPECT_EQ(*appended.failureKind, SignFailureKind::PolicyViolation) << appended.errorMessage;
}

// Non-SoftHSM tests

TEST(CAdESModuleStandalone, RejectsEmptyInput)
{
    CAdESModule cades;
    std::vector<uint8_t> empty;
    // Token is never touched — sign() returns early on empty input.
    alignas(Pkcs11Token) char storage[sizeof(Pkcs11Token)]{};
    auto& dummyToken = *reinterpret_cast<Pkcs11Token*>(storage);
    auto result = cades.sign(empty, dummyToken, SignatureLevel::B_B, {});
    ASSERT_FALSE(result.success);
    EXPECT_NE(result.errorMessage.find("empty"), std::string::npos);
}

TEST(CAdESModuleStandalone, AddRevocationData_EmptyIsNoop)
{
    // Create a minimal CMS for testing (empty revocation data should be a no-op)
    // This test just verifies the empty-data path doesn't crash
    CAdESModule cades;
    RevocationData emptyRev;

    // With empty input it should just return the same bytes
    std::vector<uint8_t> fakeCms = {0x30, 0x00}; // minimal (invalid) SEQUENCE
    // This should throw because it's not a valid CMS, but empty rev returns early
    auto result = cades.addRevocationData(fakeCms, emptyRev);
    EXPECT_EQ(result, fakeCms);
}

#else
TEST(CAdESModuleTest, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif
