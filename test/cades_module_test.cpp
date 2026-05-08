// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/cades_module.h"
#include "native/pkcs11_token.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/objects.h>

using namespace libresign;

class CAdESModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
    }
    const char* softHsmPath = nullptr;
};

TEST_F(CAdESModuleTest, SignBB_ProducesValidCMS)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
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
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
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
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
    CAdESModule cades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    TSAConfig tsa; // empty -- not used for B-B
    auto result = cades.sign(data, token, SignatureLevel::B_B, tsa);

    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());
}

TEST_F(CAdESModuleTest, SignBB_DifferentDataProducesDifferentSignature)
{
    Pkcs11Token token(softHsmPath, libresign::as_pin("1234"), "test-key", libresign::Pkcs11Token::TestSlotId{0});
    CAdESModule cades;

    std::vector<uint8_t> data1 = {'A', 'B', 'C'};
    std::vector<uint8_t> data2 = {'X', 'Y', 'Z'};

    auto cms1 = cades.signBB(data1, token);
    auto cms2 = cades.signBB(data2, token);

    ASSERT_FALSE(cms1.empty());
    ASSERT_FALSE(cms2.empty());
    EXPECT_NE(cms1, cms2);
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
