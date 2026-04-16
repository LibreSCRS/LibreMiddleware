// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unified signing E2E tests. Parameterized by backend (Native, DSS).
// Uses SigningTestSupport shared library for config, PIN guard, and validation.

#include <gtest/gtest.h>
#include "signing_test_support.h"

#include "libresign/signing_service.h"
#include "libresign/signing_service_factory.h"

#ifdef LIBRESIGN_HAS_DSS
#include "libresign/dss/dss_service_manager.h"
#include "libresign/dss/dss_signing_service.h"
#endif

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace libresign;
using namespace libresign::test;

// ---------------------------------------------------------------------------
// Backend parameterization
// ---------------------------------------------------------------------------

struct BackendInfo
{
    std::string name;
    Backend backend;
};

std::ostream& operator<<(std::ostream& os, const BackendInfo& info)
{
    return os << info.name;
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

class SigningE2ETest : public ::testing::TestWithParam<BackendInfo>
{
protected:
    void SetUp() override
    {
        SKIP_IF_PIN_FAILED();

        auto cfgResult = readTestConfig();
        if (!cfgResult.valid)
            GTEST_SKIP() << cfgResult.skipReason;
        config = cfgResult.config;

        if (!fs::exists(config.pkcs11Module))
            GTEST_SKIP() << "PKCS#11 module not found: " << config.pkcs11Module;

        auto info = GetParam();

#ifdef LIBRESIGN_HAS_NATIVE
        if (info.backend == Backend::Native) {
            ownedService = createSigningService(Backend::Native);
            service = ownedService.get();
        }
#endif

#ifdef LIBRESIGN_HAS_DSS
        if (info.backend == Backend::DSS) {
            auto* mgr = static_cast<DSSServiceManager*>(SigningTestEnvironment::manager());
            if (!mgr)
                GTEST_SKIP() << "DSS service not available";

            dssService = std::make_unique<DSSSigningService>(*mgr);
            service = dssService.get();
        }
#endif

        if (!service)
            GTEST_SKIP() << "Backend " << info.name << " not available";

        if (!service->isAvailable())
            GTEST_SKIP() << "Backend " << info.name << " not available";
    }

    SigningResult signDocument(const std::vector<uint8_t>& data, const std::string& fileName, SignatureFormat format,
                               SignatureLevel level = SignatureLevel::B_B)
    {
        SigningRequest req;
        req.document = data;
        req.fileName = fileName;
        req.format = format;
        req.level = level;
        req.tsa.url = "http://timestamp.digicert.com";
        req.allowExpiredCertificate = true;

        auto result =
            service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
        checkPinFailure(result);
        return result;
    }

    void saveOutput(const SigningResult& result, const std::string& name)
    {
        if (!result.success || result.signedDocument.empty())
            return;
        auto path = fs::temp_directory_path() / ("librescrs-e2e-" + name);
        std::ofstream ofs(path, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(result.signedDocument.data()),
                  static_cast<std::streamsize>(result.signedDocument.size()));
        fprintf(stderr, "[E2E] Saved %s (%zu bytes)\n", path.c_str(), result.signedDocument.size());
    }

    TestConfig config;
    SigningService* service = nullptr;

    std::unique_ptr<SigningService> ownedService;
#ifdef LIBRESIGN_HAS_DSS
    std::unique_ptr<DSSSigningService> dssService;
#endif
};

// ===========================================================================
// CAdES
// ===========================================================================

TEST_P(SigningE2ETest, CAdES_BB)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "Hello, this is a test document for CAdES signing.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::CAdES,
                               SignatureLevel::B_B);
    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());
    EXPECT_EQ(result.signedDocument[0], 0x30); // ASN.1 SEQUENCE
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "CAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-cades-bb.p7s");
}

TEST_P(SigningE2ETest, CAdES_BT)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "CAdES B-T test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::CAdES,
                               SignatureLevel::B_T);
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_GT(result.signedDocument.size(), 1000u) << "B-T should be larger due to timestamp";
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "CAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-cades-bt.p7s");
}

TEST_P(SigningE2ETest, CAdES_BLT)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "CAdES B-LT test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::CAdES,
                               SignatureLevel::B_LT);
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_GT(result.signedDocument.size(), 1000u) << "B-LT should include revocation data";
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "CAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-cades-blt.p7s");
}

TEST_P(SigningE2ETest, CAdES_BLTA)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "CAdES B-LTA test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::CAdES,
                               SignatureLevel::B_LTA);
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_GT(result.signedDocument.size(), 1000u) << "B-LTA should include archive timestamp";
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "CAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-cades-blta.p7s");
}

// ===========================================================================
// PAdES
// ===========================================================================

TEST_P(SigningE2ETest, PAdES_BB)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::PAdES,
                               SignatureLevel::B_B);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::string hdr(result.signedDocument.begin(), result.signedDocument.begin() + 5);
    EXPECT_EQ(hdr, "%PDF-");
    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-bb.pdf");
}

TEST_P(SigningE2ETest, PAdES_BT)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::PAdES,
                               SignatureLevel::B_T);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-bt.pdf");
}

TEST_P(SigningE2ETest, PAdES_BLT)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::PAdES,
                               SignatureLevel::B_LT);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-blt.pdf");
}

TEST_P(SigningE2ETest, PAdES_BLTA)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::PAdES,
                               SignatureLevel::B_LTA);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-blta.pdf");
}

// ===========================================================================
// JAdES
// ===========================================================================

TEST_P(SigningE2ETest, JAdES_BB)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "JAdES test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::JAdES,
                               SignatureLevel::B_B);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::string json(result.signedDocument.begin(), result.signedDocument.end());
    EXPECT_TRUE(json.front() == '{' || json.substr(0, 3) == "eyJ") << "Expected JWS JSON or Compact";
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "JAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-jades-bb.json");
}

TEST_P(SigningE2ETest, JAdES_BT)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "JAdES B-T test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::JAdES,
                               SignatureLevel::B_T);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "JAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-jades-bt.json");
}

TEST_P(SigningE2ETest, JAdES_BLT)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "JAdES B-LT test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::JAdES,
                               SignatureLevel::B_LT);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "JAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-jades-blt.json");
}

TEST_P(SigningE2ETest, JAdES_BLTA)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "JAdES B-LTA test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::JAdES,
                               SignatureLevel::B_LTA);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "JAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-jades-blta.json");
}

// ===========================================================================
// XAdES
// ===========================================================================

TEST_P(SigningE2ETest, XAdES_BB_Detached)
{
    SKIP_IF_PIN_FAILED();

    SigningRequest req;
    req.document = {'D', 'a', 't', 'a'};
    req.fileName = "test.txt";
    req.format = SignatureFormat::XAdES;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::DETACHED;
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::string xml(result.signedDocument.begin(), result.signedDocument.end());
    EXPECT_TRUE(xml.find("<ds:Signature") != std::string::npos || xml.find("<Signature") != std::string::npos);
    validateSignature(result, "XAdES", "DETACHED", req.document);
    saveOutput(result, GetParam().name + "-xades-bb-detached.xml");
}

TEST_P(SigningE2ETest, XAdES_BT_Detached)
{
    SKIP_IF_PIN_FAILED();

    SigningRequest req;
    req.document = {'D', 'a', 't', 'a'};
    req.fileName = "test.txt";
    req.format = SignatureFormat::XAdES;
    req.level = SignatureLevel::B_T;
    req.packaging = SignaturePackaging::DETACHED;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "XAdES", "DETACHED", req.document);
    saveOutput(result, GetParam().name + "-xades-bt-detached.xml");
}

TEST_P(SigningE2ETest, XAdES_BLT_Detached)
{
    SKIP_IF_PIN_FAILED();

    SigningRequest req;
    req.document = {'D', 'a', 't', 'a'};
    req.fileName = "test.txt";
    req.format = SignatureFormat::XAdES;
    req.level = SignatureLevel::B_LT;
    req.packaging = SignaturePackaging::DETACHED;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "XAdES", "DETACHED", req.document);
    saveOutput(result, GetParam().name + "-xades-blt-detached.xml");
}

TEST_P(SigningE2ETest, XAdES_BLTA_Detached)
{
    SKIP_IF_PIN_FAILED();

    SigningRequest req;
    req.document = {'D', 'a', 't', 'a'};
    req.fileName = "test.txt";
    req.format = SignatureFormat::XAdES;
    req.level = SignatureLevel::B_LTA;
    req.packaging = SignaturePackaging::DETACHED;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "XAdES", "DETACHED", req.document);
    saveOutput(result, GetParam().name + "-xades-blta-detached.xml");
}

TEST_P(SigningE2ETest, XAdES_BB_Enveloped)
{
    SKIP_IF_PIN_FAILED();

    auto xmlDoc = buildTestXml();
    SigningRequest req;
    req.document = std::vector<uint8_t>(xmlDoc.begin(), xmlDoc.end());
    req.fileName = "test.xml";
    req.format = SignatureFormat::XAdES;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::ENVELOPED;
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::string xml(result.signedDocument.begin(), result.signedDocument.end());
    EXPECT_TRUE(xml.find("<body>") != std::string::npos) << "Original content missing";
    EXPECT_TRUE(xml.find("<ds:Signature") != std::string::npos || xml.find("<Signature") != std::string::npos)
        << "Signature element missing";
    validateSignature(result, "XAdES");
    saveOutput(result, GetParam().name + "-xades-bb-enveloped.xml");
}

TEST_P(SigningE2ETest, XAdES_BT_Enveloped)
{
    SKIP_IF_PIN_FAILED();

    auto xmlDoc = buildTestXml();
    SigningRequest req;
    req.document = std::vector<uint8_t>(xmlDoc.begin(), xmlDoc.end());
    req.fileName = "test.xml";
    req.format = SignatureFormat::XAdES;
    req.level = SignatureLevel::B_T;
    req.packaging = SignaturePackaging::ENVELOPED;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "XAdES");
    saveOutput(result, GetParam().name + "-xades-bt-enveloped.xml");
}

TEST_P(SigningE2ETest, XAdES_BLT_Enveloped)
{
    SKIP_IF_PIN_FAILED();

    auto xmlDoc = buildTestXml();
    SigningRequest req;
    req.document = std::vector<uint8_t>(xmlDoc.begin(), xmlDoc.end());
    req.fileName = "test.xml";
    req.format = SignatureFormat::XAdES;
    req.level = SignatureLevel::B_LT;
    req.packaging = SignaturePackaging::ENVELOPED;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "XAdES");
    saveOutput(result, GetParam().name + "-xades-blt-enveloped.xml");
}

TEST_P(SigningE2ETest, XAdES_BLTA_Enveloped)
{
    SKIP_IF_PIN_FAILED();

    auto xmlDoc = buildTestXml();
    SigningRequest req;
    req.document = std::vector<uint8_t>(xmlDoc.begin(), xmlDoc.end());
    req.fileName = "test.xml";
    req.format = SignatureFormat::XAdES;
    req.level = SignatureLevel::B_LTA;
    req.packaging = SignaturePackaging::ENVELOPED;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "XAdES");
    saveOutput(result, GetParam().name + "-xades-blta-enveloped.xml");
}

// ===========================================================================
// ASiC-E
// ===========================================================================

TEST_P(SigningE2ETest, ASiCE_BB)
{
    SKIP_IF_PIN_FAILED();
    auto result = signDocument({'Z', 'i', 'p'}, "test.txt", SignatureFormat::ASiC_E, SignatureLevel::B_B);
    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_GE(result.signedDocument.size(), 4u);
    EXPECT_EQ(result.signedDocument[0], 'P');
    EXPECT_EQ(result.signedDocument[1], 'K');
    validateSignature(result, "ASiC_E");
    saveOutput(result, GetParam().name + "-asice-bb.asice");
}

TEST_P(SigningE2ETest, ASiCE_BT)
{
    SKIP_IF_PIN_FAILED();
    auto result = signDocument({'Z', 'i', 'p'}, "test.txt", SignatureFormat::ASiC_E, SignatureLevel::B_T);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "ASiC_E");
    saveOutput(result, GetParam().name + "-asice-bt.asice");
}

TEST_P(SigningE2ETest, ASiCE_BLT)
{
    SKIP_IF_PIN_FAILED();
    auto result = signDocument({'Z', 'i', 'p'}, "test.txt", SignatureFormat::ASiC_E, SignatureLevel::B_LT);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "ASiC_E");
    saveOutput(result, GetParam().name + "-asice-blt.asice");
}

TEST_P(SigningE2ETest, ASiCE_BLTA)
{
    SKIP_IF_PIN_FAILED();
    auto result = signDocument({'Z', 'i', 'p'}, "test.txt", SignatureFormat::ASiC_E, SignatureLevel::B_LTA);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "ASiC_E");
    saveOutput(result, GetParam().name + "-asice-blta.asice");
}

// ===========================================================================
// PAdES Visual Signature
// ===========================================================================

TEST_P(SigningE2ETest, PAdES_BB_VisualSignature)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();

    SigningRequest req;
    req.document = std::vector<uint8_t>(pdf.begin(), pdf.end());
    req.fileName = "test-visual.pdf";
    req.format = SignatureFormat::PAdES;
    req.level = SignatureLevel::B_B;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;
    req.visual.enabled = true;
    req.visual.page = 1;
    req.visual.x = 50;
    req.visual.y = 50;
    req.visual.width = 200;
    req.visual.height = 60;
    req.visual.signerName = "Test User";
    req.visual.reason = "E2E test";
    req.visual.location = "Belgrade";

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_GT(result.signedDocument.size(), pdf.size());

    std::string hdr(result.signedDocument.begin(), result.signedDocument.begin() + 5);
    EXPECT_EQ(hdr, "%PDF-");

    std::string pdfStr(result.signedDocument.begin(), result.signedDocument.end());
    EXPECT_TRUE(pdfStr.find("/AP") != std::string::npos) << "Missing /AP (appearance) entry";
    EXPECT_TRUE(pdfStr.find("/Sig") != std::string::npos) << "Missing /Sig signature field";

    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-bb-visual.pdf");
}

// ===========================================================================
// Multiple Signatures (incremental updates)
// ===========================================================================

TEST_P(SigningE2ETest, PAdES_MultipleSignatures_BB)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    // First signature
    SigningRequest req1;
    req1.document = pdfVec;
    req1.fileName = "test-multi.pdf";
    req1.format = SignatureFormat::PAdES;
    req1.level = SignatureLevel::B_B;
    req1.allowExpiredCertificate = true;

    auto result1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result1);
    ASSERT_TRUE(result1.success) << "First signature: " << result1.errorMessage;
    ASSERT_GT(result1.signedDocument.size(), pdfVec.size());

    // Second signature on top of the first
    SigningRequest req2;
    req2.document = result1.signedDocument;
    req2.fileName = "test-multi.pdf";
    req2.format = SignatureFormat::PAdES;
    req2.level = SignatureLevel::B_B;
    req2.allowExpiredCertificate = true;

    auto result2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result2);
    ASSERT_TRUE(result2.success) << "Second signature: " << result2.errorMessage;
    ASSERT_GT(result2.signedDocument.size(), result1.signedDocument.size());

    std::string pdfStr(result2.signedDocument.begin(), result2.signedDocument.end());
    EXPECT_EQ(pdfStr.substr(0, 5), "%PDF-");

    size_t eofCount = 0;
    size_t pos = 0;
    while ((pos = pdfStr.find("%%EOF", pos)) != std::string::npos) {
        ++eofCount;
        pos += 5;
    }
    EXPECT_GE(eofCount, 3u) << "Expected at least 3 %%EOF (original + 2 signatures)";
    saveOutput(result2, GetParam().name + "-pades-multi-2sig.pdf");
}

TEST_P(SigningE2ETest, PAdES_MultiLevel_BB_then_BT)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    SigningRequest req1;
    req1.document = pdfVec;
    req1.fileName = "test-multilevel.pdf";
    req1.format = SignatureFormat::PAdES;
    req1.level = SignatureLevel::B_B;
    req1.allowExpiredCertificate = true;

    auto result1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result1);
    ASSERT_TRUE(result1.success) << "B-B signature: " << result1.errorMessage;

    SigningRequest req2;
    req2.document = result1.signedDocument;
    req2.fileName = "test-multilevel.pdf";
    req2.format = SignatureFormat::PAdES;
    req2.level = SignatureLevel::B_T;
    req2.tsa.url = "http://timestamp.digicert.com";
    req2.allowExpiredCertificate = true;

    auto result2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(result2);
    ASSERT_TRUE(result2.success) << "B-T signature: " << result2.errorMessage;
    ASSERT_GT(result2.signedDocument.size(), result1.signedDocument.size());
    saveOutput(result2, GetParam().name + "-pades-bb-then-bt.pdf");
}

TEST_P(SigningE2ETest, PAdES_MultiLevel_BT_then_BB)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    SigningRequest req1;
    req1.document = pdfVec;
    req1.fileName = "test.pdf";
    req1.format = SignatureFormat::PAdES;
    req1.level = SignatureLevel::B_T;
    req1.tsa.url = "http://timestamp.digicert.com";
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "B-T: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.pdf";
    req2.format = SignatureFormat::PAdES;
    req2.level = SignatureLevel::B_B;
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "B-B on top of B-T: " << r2.errorMessage;
    ASSERT_GT(r2.signedDocument.size(), r1.signedDocument.size());
    saveOutput(r2, GetParam().name + "-pades-bt-then-bb.pdf");
}

TEST_P(SigningE2ETest, PAdES_MultiLevel_BB_then_BLTA)
{
    SKIP_IF_PIN_FAILED();
    if (GetParam().backend == Backend::DSS && !SigningTestEnvironment::trustConfigured())
        GTEST_SKIP() << "B-LTA requires trust store (DSS trust not configured)";
    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    SigningRequest req1;
    req1.document = pdfVec;
    req1.fileName = "test.pdf";
    req1.format = SignatureFormat::PAdES;
    req1.level = SignatureLevel::B_B;
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "B-B: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.pdf";
    req2.format = SignatureFormat::PAdES;
    req2.level = SignatureLevel::B_LTA;
    req2.tsa.url = "http://timestamp.digicert.com";
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "B-LTA on top of B-B: " << r2.errorMessage;
    saveOutput(r2, GetParam().name + "-pades-bb-then-blta.pdf");
}

TEST_P(SigningE2ETest, PAdES_TripleSignature)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    auto doc = pdfVec;
    for (int i = 0; i < 3; ++i) {
        SigningRequest req;
        req.document = doc;
        req.fileName = "test.pdf";
        req.format = SignatureFormat::PAdES;
        req.level = SignatureLevel::B_B;
        req.allowExpiredCertificate = true;

        auto r =
            service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
        checkPinFailure(r);
        ASSERT_TRUE(r.success) << "Signature " << (i + 1) << ": " << r.errorMessage;
        doc = r.signedDocument;
    }

    std::string pdfStr(doc.begin(), doc.end());
    size_t eofCount = 0;
    size_t pos = 0;
    while ((pos = pdfStr.find("%%EOF", pos)) != std::string::npos) {
        ++eofCount;
        pos += 5;
    }
    EXPECT_GE(eofCount, 4u);
    saveOutput({true, doc, {}}, GetParam().name + "-pades-triple.pdf");
}

TEST_P(SigningE2ETest, PAdES_InvisibleThenVisual)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    SigningRequest req1;
    req1.document = pdfVec;
    req1.fileName = "test.pdf";
    req1.format = SignatureFormat::PAdES;
    req1.level = SignatureLevel::B_B;
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "Invisible: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.pdf";
    req2.format = SignatureFormat::PAdES;
    req2.level = SignatureLevel::B_B;
    req2.allowExpiredCertificate = true;
    req2.visual.enabled = true;
    req2.visual.page = 1;
    req2.visual.x = 50;
    req2.visual.y = 50;
    req2.visual.width = 200;
    req2.visual.height = 60;
    req2.visual.signerName = "Second Signer";
    req2.visual.reason = "Counter-sign";

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "Visual on top: " << r2.errorMessage;

    std::string pdfStr(r2.signedDocument.begin(), r2.signedDocument.end());
    EXPECT_GT(r2.signedDocument.size(), r1.signedDocument.size());
    saveOutput(r2, GetParam().name + "-pades-invis-then-visual.pdf");
}

// ===========================================================================
// XAdES enveloped double signature
// ===========================================================================

TEST_P(SigningE2ETest, XAdES_Enveloped_DoubleSignature)
{
    SKIP_IF_PIN_FAILED();
    auto xmlDoc = buildTestXml();

    SigningRequest req1;
    req1.document = std::vector<uint8_t>(xmlDoc.begin(), xmlDoc.end());
    req1.fileName = "test.xml";
    req1.format = SignatureFormat::XAdES;
    req1.level = SignatureLevel::B_B;
    req1.packaging = SignaturePackaging::ENVELOPED;
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "First XAdES: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.xml";
    req2.format = SignatureFormat::XAdES;
    req2.level = SignatureLevel::B_B;
    req2.packaging = SignaturePackaging::ENVELOPED;
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "Second XAdES: " << r2.errorMessage;

    std::string xml(r2.signedDocument.begin(), r2.signedDocument.end());
    size_t sigCount = 0;
    size_t pos = 0;
    while ((pos = xml.find("<ds:Signature", pos)) != std::string::npos) {
        ++sigCount;
        pos += 13;
    }
    EXPECT_GE(sigCount, 2u) << "Expected at least 2 <ds:Signature> elements";
    saveOutput(r2, GetParam().name + "-xades-double-enveloped.xml");
}

// ===========================================================================
// JAdES double sign
// ===========================================================================

TEST_P(SigningE2ETest, JAdES_SignTwice)
{
    SKIP_IF_PIN_FAILED();

    std::vector<uint8_t> data = {'O', 'r', 'i', 'g'};

    for (int i = 0; i < 2; ++i) {
        SigningRequest req;
        req.document = data;
        req.fileName = "test.txt";
        req.format = SignatureFormat::JAdES;
        req.level = SignatureLevel::B_B;
        req.packaging = SignaturePackaging::DETACHED;
        req.allowExpiredCertificate = true;

        auto r =
            service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.tokenLabel);
        checkPinFailure(r);
        ASSERT_TRUE(r.success) << "JAdES #" << (i + 1) << ": " << r.errorMessage;

        std::string output(r.signedDocument.begin(), r.signedDocument.end());
        EXPECT_TRUE(output.front() == '{' || output.substr(0, 3) == "eyJ") << "Expected JWS JSON or Compact";

        if (i == 1)
            saveOutput(r, GetParam().name + "-jades-double.json");
    }
}

// ===========================================================================
// ASiC-E: sign same content at different levels
// ===========================================================================

TEST_P(SigningE2ETest, ASiCE_BB_then_BT_separate)
{
    SKIP_IF_PIN_FAILED();
    std::vector<uint8_t> data = {'A', 'S', 'i', 'C'};

    auto r1 = signDocument(data, "test.txt", SignatureFormat::ASiC_E, SignatureLevel::B_B);
    ASSERT_TRUE(r1.success) << "ASiC-E B-B: " << r1.errorMessage;

    auto r2 = signDocument(data, "test.txt", SignatureFormat::ASiC_E, SignatureLevel::B_T);
    ASSERT_TRUE(r2.success) << "ASiC-E B-T: " << r2.errorMessage;

    EXPECT_GT(r2.signedDocument.size(), r1.signedDocument.size());
}

// ===========================================================================
// Factory tests (non-parameterized, Native only)
// ===========================================================================

#ifdef LIBRESIGN_HAS_NATIVE
TEST(NativeFactoryTest, CreateNativeBackend)
{
    auto service = createSigningService(Backend::Native);
    ASSERT_NE(service, nullptr);
    EXPECT_TRUE(service->isAvailable());
}

TEST(NativeFactoryTest, InvalidModuleFails)
{
    auto service = createSigningService(Backend::Native);
    ASSERT_NE(service, nullptr);

    SigningRequest req;
    req.document = {'T', 'e', 's', 't'};
    req.fileName = "test.txt";
    req.format = SignatureFormat::CAdES;
    req.level = SignatureLevel::B_B;

    auto result = service->sign(req, "/nonexistent/pkcs11.so", libresign::as_pin("0000"), "key");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
}
#endif

// ===========================================================================
// Instantiate for each available backend
// ===========================================================================

std::vector<BackendInfo> availableBackends()
{
    std::vector<BackendInfo> backends;
#ifdef LIBRESIGN_HAS_NATIVE
    backends.push_back({"Native", Backend::Native});
#endif
#ifdef LIBRESIGN_HAS_DSS
    backends.push_back({"DSS", Backend::DSS});
#endif
    return backends;
}

INSTANTIATE_TEST_SUITE_P(AllBackends, SigningE2ETest, ::testing::ValuesIn(availableBackends()),
                         [](const ::testing::TestParamInfo<BackendInfo>& info) { return info.param.name; });

// ===========================================================================
// Custom main: register SigningTestEnvironment for DSS validation
// ===========================================================================

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new libresign::test::SigningTestEnvironment);
    return RUN_ALL_TESTS();
}
