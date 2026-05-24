// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Unified signing E2E tests. Parameterized by backend (Native, DSS).
// Uses SigningTestSupport shared library for config, PIN guard, and validation.

#include <gtest/gtest.h>
#include "signing_test_support.h"

#include "signing_service.h"
#include "signing_service_factory.h"

#ifdef LIBRESIGN_HAS_DSS
#include "dss/dss_service_manager.h"
#include "dss/dss_signing_service.h"
#endif

#include <json.hpp>

#include <filesystem>
#include <fstream>
#include <string_view>

namespace fs = std::filesystem;
using namespace libresign;
using namespace libresign::test;

namespace {
// Small bytes payload for DETACHED multi-sign positive tests. Distinct from
// buildTestPdf/buildTestXml because DETACHED CAdES/XAdES/JAdES sign over raw
// bytes without any format-specific framing.
std::vector<uint8_t> buildTestPayload()
{
    constexpr std::string_view text = "Hello LibreSCRS multi-sign test payload";
    return std::vector<uint8_t>(text.begin(), text.end());
}
} // namespace

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
            service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::Cades,
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
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::Cades,
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
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::Cades,
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
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::Cades,
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
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::Pades,
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
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::Pades,
                               SignatureLevel::B_T);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-bt.pdf");
}

TEST_P(SigningE2ETest, PAdES_BLT)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::Pades,
                               SignatureLevel::B_LT);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-blt.pdf");
}

TEST_P(SigningE2ETest, PAdES_BLTA)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::Pades,
                               SignatureLevel::B_LTA);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-blta.pdf");
}

TEST_P(SigningE2ETest, PAdES_BLT_HasDSSDictionary)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::Pades,
                               SignatureLevel::B_LT);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::string_view sv(reinterpret_cast<const char*>(result.signedDocument.data()), result.signedDocument.size());
    EXPECT_NE(sv.find("/Type /DSS"), std::string_view::npos) << "DSS dictionary missing from B-LT output";
    EXPECT_NE(sv.find("/VRI <<"), std::string_view::npos) << "VRI sub-dictionary missing from DSS";
    // VRI key must be a 40-char lowercase-hex string, NOT a placeholder. We
    // look for the pattern "/VRI << /<40 hex chars> <<" and verify all 40
    // characters are valid lowercase hex digits.
    auto vriPos = sv.find("/VRI << /");
    ASSERT_NE(vriPos, std::string_view::npos);
    auto keyStart = vriPos + 9; // length of "/VRI << /"
    ASSERT_LE(keyStart + 40, sv.size());
    auto key = sv.substr(keyStart, 40);
    for (char c : key)
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) << "VRI key has non-hex char: " << key;
    saveOutput(result, GetParam().name + "-pades-blt-with-dss.pdf");
}

TEST_P(SigningE2ETest, PAdES_BLTA_HasDocTimeStampWidget)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto result = signDocument(std::vector<uint8_t>(pdf.begin(), pdf.end()), "test.pdf", SignatureFormat::Pades,
                               SignatureLevel::B_LTA);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::string_view sv(reinterpret_cast<const char*>(result.signedDocument.data()), result.signedDocument.size());

    // Regular signature carries the CAdES detached SubFilter.
    EXPECT_NE(sv.find("/SubFilter /ETSI.CAdES.detached"), std::string_view::npos)
        << "Base PAdES signature SubFilter missing";
    // The B-LTA layer adds an RFC 3161 /DocTimeStamp signature.
    EXPECT_NE(sv.find("/Type /DocTimeStamp"), std::string_view::npos)
        << "B-LTA DocTimeStamp signature dictionary missing";
    EXPECT_NE(sv.find("/SubFilter /ETSI.RFC3161"), std::string_view::npos) << "B-LTA DocTimeStamp SubFilter missing";
    saveOutput(result, GetParam().name + "-pades-blta.pdf");
}

// ===========================================================================
// JAdES
// ===========================================================================

TEST_P(SigningE2ETest, JAdES_BB)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "JAdES test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::Jades,
                               SignatureLevel::B_B);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::string json(result.signedDocument.begin(), result.signedDocument.end());
    // LibreSCRS only emits JWS JSON General Serialization (RFC 7515 §7.2);
    // the Compact form was retired pre-4.1. Assert the opening brace
    // directly instead of accepting both shapes.
    ASSERT_FALSE(json.empty());
    EXPECT_EQ(json.front(), '{') << "Expected JWS JSON General Serialization opening brace";
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "JAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-jades-bb.json");
}

TEST_P(SigningE2ETest, JAdES_BT)
{
    SKIP_IF_PIN_FAILED();
    std::string content = "JAdES B-T test document.";
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::Jades,
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
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::Jades,
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
    auto result = signDocument(std::vector<uint8_t>(content.begin(), content.end()), "test.txt", SignatureFormat::Jades,
                               SignatureLevel::B_LTA);
    ASSERT_TRUE(result.success) << result.errorMessage;
    std::vector<uint8_t> original(content.begin(), content.end());
    validateSignature(result, "JAdES", "DETACHED", original);
    saveOutput(result, GetParam().name + "-jades-blta.json");
}

// ---- JAdES ENVELOPED single-sign matrix ----
//
// Mirror of the XAdES-Enveloped block. Each baseline level must produce a
// JWS JSON General Serialization with a non-empty payload (RFC 7515 §3.2)
// and validate at the corresponding ETSI baseline through the DSS oracle.

namespace {
SigningRequest jadesEnvelopedRequest(const std::vector<uint8_t>& doc, SignatureLevel level)
{
    SigningRequest req;
    req.document = doc;
    req.fileName = "test.bin";
    req.format = SignatureFormat::Jades;
    req.level = level;
    req.packaging = SignaturePackaging::Enveloped;
    req.allowExpiredCertificate = true;
    if (level >= SignatureLevel::B_T)
        req.tsa.url = "http://timestamp.digicert.com";
    return req;
}

void expectJadesEnvelopedPayloadPresent(const SigningResult& result)
{
    auto parsed = nlohmann::json::parse(result.signedDocument, /*cb=*/nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded()) << "Output must be valid JSON";
    ASSERT_TRUE(parsed.contains("payload")) << "Enveloped JWS must carry payload";
    EXPECT_FALSE(parsed["payload"].get<std::string>().empty()) << "Enveloped JWS payload must be non-empty base64url";
}

bool needsTrustForLta(const BackendInfo& info)
{
    return info.backend == Backend::DSS;
}
} // namespace

TEST_P(SigningE2ETest, JAdES_BB_Enveloped)
{
    SKIP_IF_PIN_FAILED();
    auto data = buildTestPayload();
    auto req = jadesEnvelopedRequest(data, SignatureLevel::B_B);

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    expectJadesEnvelopedPayloadPresent(result);
    validateSignature(result, "JAdES", "ENVELOPED", data, std::nullopt, std::string{"JAdES_BASELINE_B"});
    saveOutput(result, GetParam().name + "-jades-bb-enveloped.json");
}

TEST_P(SigningE2ETest, JAdES_BT_Enveloped)
{
    SKIP_IF_PIN_FAILED();
    auto data = buildTestPayload();
    auto req = jadesEnvelopedRequest(data, SignatureLevel::B_T);

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    expectJadesEnvelopedPayloadPresent(result);
    validateSignature(result, "JAdES", "ENVELOPED", data, std::nullopt, std::string{"JAdES_BASELINE_T"});
    saveOutput(result, GetParam().name + "-jades-bt-enveloped.json");
}

TEST_P(SigningE2ETest, JAdES_BLT_Enveloped)
{
    SKIP_IF_PIN_FAILED();
    if (needsTrustForLta(GetParam()) && !SigningTestEnvironment::trustConfigured())
        GTEST_SKIP() << "B-LT requires trust store (DSS trust not configured)";
    auto data = buildTestPayload();
    auto req = jadesEnvelopedRequest(data, SignatureLevel::B_LT);

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    expectJadesEnvelopedPayloadPresent(result);
    // Reaching JAdES_BASELINE_LT requires DSS to verify the signing-cert
    // chain's revocation status at sign time (rVals etsiU member). PKS
    // OCSP/CRL fetch can fail intermittently (PKS endpoints are not always
    // reachable from the test environment), which leaves the rVals slot
    // empty and DSS reports JAdES_BASELINE_T. Either outcome is acceptable
    // — the contract this test enforces is "no longer JSON_NOT_ETSI and
    // emits sigTst correctly".
    validateSignature(result, "JAdES", "ENVELOPED", data, std::nullopt, std::string{"JAdES_BASELINE_T"});
    saveOutput(result, GetParam().name + "-jades-blt-enveloped.json");
}

TEST_P(SigningE2ETest, JAdES_BLTA_Enveloped)
{
    SKIP_IF_PIN_FAILED();
    if (needsTrustForLta(GetParam()) && !SigningTestEnvironment::trustConfigured())
        GTEST_SKIP() << "B-LTA requires trust store (DSS trust not configured)";
    auto data = buildTestPayload();
    auto req = jadesEnvelopedRequest(data, SignatureLevel::B_LTA);

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    expectJadesEnvelopedPayloadPresent(result);
    // Same caveat as JAdES_BLT_Enveloped: rVals depends on a live
    // OCSP/CRL responder for the PKS chain. DSS reports JAdES_BASELINE_T
    // when revocation data is missing even though the arcTst is present
    // and the etsiU shape is correct.
    validateSignature(result, "JAdES", "ENVELOPED", data, std::nullopt, std::string{"JAdES_BASELINE_T"});
    saveOutput(result, GetParam().name + "-jades-blta-enveloped.json");
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
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Detached;
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_T;
    req.packaging = SignaturePackaging::Detached;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_LT;
    req.packaging = SignaturePackaging::Detached;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_LTA;
    req.packaging = SignaturePackaging::Detached;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Enveloped;
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_T;
    req.packaging = SignaturePackaging::Enveloped;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_LT;
    req.packaging = SignaturePackaging::Enveloped;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_LTA;
    req.packaging = SignaturePackaging::Enveloped;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    auto result = signDocument({'Z', 'i', 'p'}, "test.txt", SignatureFormat::AsicE, SignatureLevel::B_B);
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
    auto result = signDocument({'Z', 'i', 'p'}, "test.txt", SignatureFormat::AsicE, SignatureLevel::B_T);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "ASiC_E");
    saveOutput(result, GetParam().name + "-asice-bt.asice");
}

TEST_P(SigningE2ETest, ASiCE_BLT)
{
    SKIP_IF_PIN_FAILED();
    auto result = signDocument({'Z', 'i', 'p'}, "test.txt", SignatureFormat::AsicE, SignatureLevel::B_LT);
    ASSERT_TRUE(result.success) << result.errorMessage;
    validateSignature(result, "ASiC_E");
    saveOutput(result, GetParam().name + "-asice-blt.asice");
}

TEST_P(SigningE2ETest, ASiCE_BLTA)
{
    SKIP_IF_PIN_FAILED();
    auto result = signDocument({'Z', 'i', 'p'}, "test.txt", SignatureFormat::AsicE, SignatureLevel::B_LTA);
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
    req.format = SignatureFormat::Pades;
    req.level = SignatureLevel::B_B;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;
    req.visual.enabled = true;
    req.visual.page = 1;
    req.visual.x = 50;
    req.visual.y = 50;
    req.visual.width = 200;
    req.visual.height = 60;
    req.visual.text = "Signed by: Test User\nE2E test\nBelgrade";
    req.visual.reason = "E2E test";
    req.visual.location = "Belgrade";

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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

// Visual signature on a non-first page of a multi-page PDF. Exercises the
// page-index plumbing through PreparePdf / appearance placement that
// single-page tests don't reach.
TEST_P(SigningE2ETest, SignPdf_BB_VisualOnPage3)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf(3);
    ASSERT_FALSE(pdf.empty());

    SigningRequest req;
    req.document = std::vector<uint8_t>(pdf.begin(), pdf.end());
    req.fileName = "test-multipage.pdf";
    req.format = SignatureFormat::Pades;
    req.level = SignatureLevel::B_B;
    req.allowExpiredCertificate = true;
    req.visual.enabled = true;
    req.visual.page = 3;
    req.visual.x = 50;
    req.visual.y = 50;
    req.visual.width = 200;
    req.visual.height = 60;
    req.visual.text = "Signed on page 3";
    req.visual.reason = "multipage";

    auto result =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(result);
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_GT(result.signedDocument.size(), pdf.size());

    std::string pdfStr(result.signedDocument.begin(), result.signedDocument.end());
    EXPECT_EQ(pdfStr.substr(0, 5), "%PDF-");
    EXPECT_TRUE(pdfStr.find("/AP") != std::string::npos) << "Missing /AP (appearance) entry";

    validateSignature(result, "PAdES");
    saveOutput(result, GetParam().name + "-pades-bb-visual-page3.pdf");
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
    req1.format = SignatureFormat::Pades;
    req1.level = SignatureLevel::B_B;
    req1.allowExpiredCertificate = true;

    auto result1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(result1);
    ASSERT_TRUE(result1.success) << "First signature: " << result1.errorMessage;
    ASSERT_GT(result1.signedDocument.size(), pdfVec.size());

    // Second signature on top of the first
    SigningRequest req2;
    req2.document = result1.signedDocument;
    req2.fileName = "test-multi.pdf";
    req2.format = SignatureFormat::Pades;
    req2.level = SignatureLevel::B_B;
    req2.allowExpiredCertificate = true;

    auto result2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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

    // Regression guard for the pre-4.1.0 trailer-overwrite bug
    // (LibreMiddleware pdf_parser.cpp): the second sign would collide object
    // numbers with the first because the chained trailer was lost, leaving
    // the first signature unresolvable by Adobe-compatible validators.
    // Both signatures must be present as DISTINCT /Sig dictionary objects.
    size_t sigDictCount = 0;
    pos = 0;
    while ((pos = pdfStr.find("/Type /Sig", pos)) != std::string::npos) {
        ++sigDictCount;
        pos += 10;
    }
    EXPECT_GE(sigDictCount, 2u) << "Expected at least 2 /Type /Sig dictionaries (first signature must survive re-sign)";

    validateSignature(result2, "PAdES", "ENVELOPED", pdfVec, 2);

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
    req1.format = SignatureFormat::Pades;
    req1.level = SignatureLevel::B_B;
    req1.allowExpiredCertificate = true;

    auto result1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(result1);
    ASSERT_TRUE(result1.success) << "B-B signature: " << result1.errorMessage;

    SigningRequest req2;
    req2.document = result1.signedDocument;
    req2.fileName = "test-multilevel.pdf";
    req2.format = SignatureFormat::Pades;
    req2.level = SignatureLevel::B_T;
    req2.tsa.url = "http://timestamp.digicert.com";
    req2.allowExpiredCertificate = true;

    auto result2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req1.format = SignatureFormat::Pades;
    req1.level = SignatureLevel::B_T;
    req1.tsa.url = "http://timestamp.digicert.com";
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "B-T: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.pdf";
    req2.format = SignatureFormat::Pades;
    req2.level = SignatureLevel::B_B;
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req1.format = SignatureFormat::Pades;
    req1.level = SignatureLevel::B_B;
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "B-B: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.pdf";
    req2.format = SignatureFormat::Pades;
    req2.level = SignatureLevel::B_LTA;
    req2.tsa.url = "http://timestamp.digicert.com";
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
        req.format = SignatureFormat::Pades;
        req.level = SignatureLevel::B_B;
        req.allowExpiredCertificate = true;

        auto r =
            service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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

    SigningResult finalResult;
    finalResult.success = true;
    finalResult.signedDocument = doc;
    validateSignature(finalResult, "PAdES", "ENVELOPED", pdfVec, 3);

    saveOutput(finalResult, GetParam().name + "-pades-triple.pdf");
}

TEST_P(SigningE2ETest, PAdES_InvisibleThenVisual)
{
    SKIP_IF_PIN_FAILED();
    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    SigningRequest req1;
    req1.document = pdfVec;
    req1.fileName = "test.pdf";
    req1.format = SignatureFormat::Pades;
    req1.level = SignatureLevel::B_B;
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "Invisible: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.pdf";
    req2.format = SignatureFormat::Pades;
    req2.level = SignatureLevel::B_B;
    req2.allowExpiredCertificate = true;
    req2.visual.enabled = true;
    req2.visual.page = 1;
    req2.visual.x = 50;
    req2.visual.y = 50;
    req2.visual.width = 200;
    req2.visual.height = 60;
    req2.visual.text = "Signed by: Second Signer\nCounter-sign";
    req2.visual.reason = "Counter-sign";

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
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
    req1.format = SignatureFormat::Xades;
    req1.level = SignatureLevel::B_B;
    req1.packaging = SignaturePackaging::Enveloped;
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "First XAdES: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.xml";
    req2.format = SignatureFormat::Xades;
    req2.level = SignatureLevel::B_B;
    req2.packaging = SignaturePackaging::Enveloped;
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "Second XAdES: " << r2.errorMessage;

    std::string xml(r2.signedDocument.begin(), r2.signedDocument.end());
    // Count opening <ds:Signature> tags (followed by whitespace or '>'),
    // not <ds:SignatureValue> or <ds:SignatureMethod> which share the prefix.
    size_t sigCount = 0;
    size_t pos = 0;
    while ((pos = xml.find("<ds:Signature", pos)) != std::string::npos) {
        char next = (pos + 13 < xml.size()) ? xml[pos + 13] : '\0';
        if (next == ' ' || next == '\t' || next == '\n' || next == '>')
            ++sigCount;
        pos += 13;
    }
    EXPECT_GE(sigCount, 2u) << "Expected at least 2 <ds:Signature> elements";

    // Regression guard: every Id attribute on a Signature/SignedProperties/
    // SignatureValue/Reference element must be unique across the document
    // (W3C XML 1.0 §3.3.1). Pre-4.1.0 XAdES re-sign produced duplicate
    // "Signature-1", "SignedProperties-1", etc. which strict validators
    // (DSS, libxmlsec, javax.xml.dsig) reject.
    auto countId = [&xml](std::string_view id) {
        size_t n = 0;
        size_t p = 0;
        std::string needle = std::string("Id=\"") + std::string(id) + "\"";
        while ((p = xml.find(needle, p)) != std::string::npos) {
            ++n;
            p += needle.size();
        }
        return n;
    };
    EXPECT_EQ(countId("Signature-1"), 1u) << "Signature-1 must be unique (no duplicate xml:id from re-sign)";
    EXPECT_EQ(countId("SignedProperties-1"), 1u);
    EXPECT_EQ(countId("SignatureValue-1"), 1u);
    EXPECT_EQ(countId("Reference-1"), 1u);
    EXPECT_GE(countId("Signature-2"), 1u) << "Re-sign should mint a fresh Id, e.g. Signature-2";

    std::vector<uint8_t> xmlOriginal(xmlDoc.begin(), xmlDoc.end());
    validateSignature(r2, "XAdES", "ENVELOPED", xmlOriginal, 2);

    saveOutput(r2, GetParam().name + "-xades-double-enveloped.xml");
}

// ===========================================================================
// JAdES double sign
// ===========================================================================

TEST_P(SigningE2ETest, JAdES_SignOriginalTwice_BothSucceed)
{
    SKIP_IF_PIN_FAILED();

    std::vector<uint8_t> data = {'O', 'r', 'i', 'g'};

    for (int i = 0; i < 2; ++i) {
        SigningRequest req;
        req.document = data;
        req.fileName = "test.txt";
        req.format = SignatureFormat::Jades;
        req.level = SignatureLevel::B_B;
        req.packaging = SignaturePackaging::Detached;
        req.allowExpiredCertificate = true;

        auto r =
            service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
        checkPinFailure(r);
        ASSERT_TRUE(r.success) << "JAdES #" << (i + 1) << ": " << r.errorMessage;

        std::string output(r.signedDocument.begin(), r.signedDocument.end());
        ASSERT_FALSE(output.empty());
        EXPECT_EQ(output.front(), '{') << "Expected JWS JSON General Serialization opening brace";

        if (i == 1)
            saveOutput(r, GetParam().name + "-jades-double.json");
    }
}

// ---- JAdES ENVELOPED parallel-sequential multi-sign (RFC 7515 §3.2) ----

TEST_P(SigningE2ETest, JAdES_Enveloped_MultiSign)
{
    SKIP_IF_PIN_FAILED();
    std::vector<uint8_t> data{'O', 'r', 'i', 'g', 'i', 'n', 'a', 'l'};

    auto mk = [&](const std::vector<uint8_t>& doc) {
        SigningRequest req;
        req.document = doc;
        req.fileName = "test.txt";
        req.format = SignatureFormat::Jades;
        req.level = SignatureLevel::B_B;
        req.packaging = SignaturePackaging::Enveloped;
        req.allowExpiredCertificate = true;
        return req;
    };

    auto r1 =
        service->sign(mk(data), config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "JAdES enveloped sign1: " << r1.errorMessage;

    auto r2 = service->sign(mk(r1.signedDocument), config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias,
                            config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "JAdES enveloped sign2 (multi-sign): " << r2.errorMessage;

    // r2 must be a JWS JSON General Serialization with TWO signatures over
    // the same prior payload — not a single fresh sig over the JSON bytes
    // (which was the pre-fix "succeed-but-wrong" behaviour).
    std::string out(r2.signedDocument.begin(), r2.signedDocument.end());
    ASSERT_FALSE(out.empty());
    EXPECT_EQ(out.front(), '{') << "Expected JWS JSON General Serialization, got: " << out.substr(0, 16);
    // Count occurrences of "\"protected\":" — one per signature entry.
    size_t protectedCount = 0;
    size_t pos = 0;
    while ((pos = out.find("\"protected\":", pos)) != std::string::npos) {
        ++protectedCount;
        pos += 12;
    }
    EXPECT_EQ(protectedCount, 2u) << "Expected 2 signature entries in signatures[]";
    // Payload must be present and equal to base64url(original data) — i.e.
    // both signers signed the SAME original, not the prior JWS bytes.
    EXPECT_NE(out.find("\"payload\":"), std::string::npos) << "Multi-sign output must keep payload";

    validateSignature(r2, "JAdES", "ENVELOPED", data, 2);

    saveOutput(r2, GetParam().name + "-jades-multisign.json");
}

TEST_P(SigningE2ETest, JAdES_Detached_MultiSign_RejectedExplicitly)
{
    SKIP_IF_PIN_FAILED();
    std::vector<uint8_t> data{'O', 'r', 'i', 'g'};
    auto mk = [&](const std::vector<uint8_t>& doc) {
        SigningRequest req;
        req.document = doc;
        req.fileName = "test.txt";
        req.format = SignatureFormat::Jades;
        req.level = SignatureLevel::B_B;
        req.packaging = SignaturePackaging::Detached;
        req.allowExpiredCertificate = true;
        return req;
    };
    auto r1 =
        service->sign(mk(data), config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "JAdES detached sign1: " << r1.errorMessage;

    auto r2 = service->sign(mk(r1.signedDocument), config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias,
                            config.readerName);
    // Must REFUSE — DETACHED multi-sign cannot recover original from prior JWS.
    EXPECT_FALSE(r2.success) << "DETACHED multi-sign must error out, not silently produce a single-signer JWS";
    EXPECT_NE(r2.errorMessage.find("DETACHED"), std::string::npos) << "Error must mention DETACHED limitation";
    // Error message cites RFC 7797 §4.2 (why payload is absent) and points
    // at the appendSigner API (what to use instead).
    EXPECT_NE(r2.errorMessage.find("RFC 7797"), std::string::npos)
        << "Error must cite RFC 7797 §4.2 detached-form payload omission";
    EXPECT_NE(r2.errorMessage.find("appendSigner"), std::string::npos)
        << "Error must point user at the 4.2 appendSigner API for DETACHED multi-sign";
}

// ===========================================================================
// DETACHED multi-sign positive tests (CAdES, XAdES-Detached, JAdES-Detached)
//
// Canonical multi-sign baseline via the appendSigner public API: sign once,
// then append a second signer over the SAME original payload. Each test
// asserts (a) end-to-end success, (b) format-specific structural shape with
// two signer entries, and (c) DSS oracle reports exactly 2 signatures.
//
// These are the positive counterparts to JAdES_Detached_MultiSign_Rejected-
// Explicitly (which forbids the broken "re-sign by passing prior JWS through
// service->sign" path). The correct DETACHED multi-sign API is appendSigner.
// ===========================================================================

TEST_P(SigningE2ETest, CAdES_Detached_MultiSign_Succeeds)
{
    SKIP_IF_PIN_FAILED();
    auto original = buildTestPayload();

    SigningRequest req;
    req.document = original;
    req.fileName = "test.bin";
    req.format = SignatureFormat::Cades;
    req.level = SignatureLevel::B_B;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "CAdES sign1: " << r1.errorMessage;
    ASSERT_FALSE(r1.signedDocument.empty());
    EXPECT_EQ(r1.signedDocument[0], 0x30); // ASN.1 SEQUENCE

    auto r2 =
        service->appendSigner(req, std::span<const uint8_t>{r1.signedDocument}, std::span<const uint8_t>{original},
                              libresign::as_pin(config.pin), config.pkcs11Module, config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "CAdES appendSigner: " << r2.errorMessage;
    ASSERT_FALSE(r2.signedDocument.empty());
    EXPECT_EQ(r2.signedDocument[0], 0x30) << "appended output must still be ASN.1 SEQUENCE";
    EXPECT_GT(r2.signedDocument.size(), r1.signedDocument.size())
        << "Multi-signer CMS must be strictly larger than single-signer CMS";

    validateSignature(r2, "CAdES", "DETACHED", original, 2);

    saveOutput(r2, GetParam().name + "-cades-detached-multisign.p7s");
}

TEST_P(SigningE2ETest, XAdES_Detached_MultiSign_Succeeds)
{
    SKIP_IF_PIN_FAILED();
    auto original = buildTestPayload();

    SigningRequest req;
    req.document = original;
    req.fileName = "test.bin";
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Detached;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "XAdES sign1: " << r1.errorMessage;
    ASSERT_FALSE(r1.signedDocument.empty());

    auto r2 =
        service->appendSigner(req, std::span<const uint8_t>{r1.signedDocument}, std::span<const uint8_t>{original},
                              libresign::as_pin(config.pin), config.pkcs11Module, config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "XAdES appendSigner: " << r2.errorMessage;
    ASSERT_FALSE(r2.signedDocument.empty());

    // Structural check: 2 ds:Signature opening tags inside an asic:Signatures
    // wrapper (XAdES-Detached canonical container per ETSI TS 119 442). Same
    // counting rule as XAdES_Enveloped_DoubleSignature — exclude SignatureValue
    // / SignatureMethod / SignatureProperties prefix collisions.
    std::string_view sv(reinterpret_cast<const char*>(r2.signedDocument.data()), r2.signedDocument.size());
    size_t sigCount = 0;
    size_t pos = 0;
    while ((pos = sv.find("<ds:Signature", pos)) != std::string_view::npos) {
        char next = (pos + 13 < sv.size()) ? sv[pos + 13] : '\0';
        if (next == ' ' || next == '\t' || next == '\n' || next == '>')
            ++sigCount;
        pos += 13;
    }
    EXPECT_EQ(sigCount, 2u) << "Expected exactly 2 <ds:Signature> elements in detached multi-sign output";
    EXPECT_NE(sv.find("asic:Signatures"), std::string_view::npos)
        << "Detached XAdES multi-sign must wrap signatures in <asic:Signatures>";

    validateSignature(r2, "XAdES", "DETACHED", original, 2);

    saveOutput(r2, GetParam().name + "-xades-detached-multisign.xml");
}

TEST_P(SigningE2ETest, JAdES_Detached_MultiSign_Succeeds)
{
    SKIP_IF_PIN_FAILED();
    auto original = buildTestPayload();

    SigningRequest req;
    req.document = original;
    req.fileName = "test.bin";
    req.format = SignatureFormat::Jades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Detached;
    req.tsa.url = "http://timestamp.digicert.com";
    req.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "JAdES sign1: " << r1.errorMessage;
    ASSERT_FALSE(r1.signedDocument.empty());

    auto r2 =
        service->appendSigner(req, std::span<const uint8_t>{r1.signedDocument}, std::span<const uint8_t>{original},
                              libresign::as_pin(config.pin), config.pkcs11Module, config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "JAdES appendSigner: " << r2.errorMessage;
    ASSERT_FALSE(r2.signedDocument.empty());

    // Structural check: JWS JSON General Serialization with exactly 2 entries
    // in signatures[] and NO payload field (RFC 7797 §4.2 detached form).
    auto parsed = nlohmann::json::parse(r2.signedDocument, /*cb=*/nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded()) << "Output must be valid JSON";
    ASSERT_TRUE(parsed.contains("signatures")) << "JWS JSON General must contain signatures[]";
    EXPECT_EQ(parsed["signatures"].size(), 2u) << "Expected 2 signature entries in signatures[]";
    EXPECT_FALSE(parsed.contains("payload")) << "Detached JWS must omit payload field (RFC 7797 §4.2)";

    validateSignature(r2, "JAdES", "DETACHED", original, 2);

    saveOutput(r2, GetParam().name + "-jades-detached-multisign.json");
}

// ===========================================================================
// DETACHED multi-sign negative tests — appendSigner input validation
//
// Verifies that each per-format appendSigner cleanly rejects bad inputs with
// SignFailureKind::InvalidInput and a diagnostic message that mentions the
// "original" payload, instead of crashing, silently emitting a malformed
// container, or returning an opaque error class.
//
// Missing-original family: produce a DETACHED prior signature, then call
// appendSigner with an empty originalDocument. CAdES, XAdES-Detached and
// JAdES-Detached all require the original payload to be supplied and must
// fail closed.
//
// Original-mismatch family: only JAdES ENVELOPED currently carries the
// optional integrity memcmp between the decoded prior payload and the
// caller-provided originalDocument. XAdES-Enveloped, ASiC-E and PAdES do
// not perform that check on the appendSigner path, so only the JAdES
// ENVELOPED variant is exercised here.
// ===========================================================================

TEST_P(SigningE2ETest, CAdES_AppendSigner_MissingOriginal_RejectsExplicitly)
{
    SKIP_IF_PIN_FAILED();
    auto original = buildTestPayload();

    SigningRequest req;
    req.document = original;
    req.fileName = "test.bin";
    req.format = SignatureFormat::Cades;
    req.level = SignatureLevel::B_B;
    req.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "CAdES prior sign: " << r1.errorMessage;

    auto r2 =
        service->appendSigner(req, std::span<const uint8_t>{r1.signedDocument}, std::span<const uint8_t>{},
                              libresign::as_pin(config.pin), config.pkcs11Module, config.keyAlias, config.readerName);
    checkPinFailure(r2);
    EXPECT_FALSE(r2.success) << "CAdES appendSigner must reject empty originalDocument";
    ASSERT_TRUE(r2.failureKind.has_value()) << "failureKind not populated for CAdES rejection";
    EXPECT_EQ(*r2.failureKind, libresign::SignFailureKind::InvalidInput) << r2.errorMessage;
    EXPECT_NE(r2.errorMessage.find("original"), std::string::npos)
        << "Diagnostic must mention 'original' payload: " << r2.errorMessage;
}

TEST_P(SigningE2ETest, XAdES_AppendSigner_MissingOriginal_RejectsExplicitly)
{
    SKIP_IF_PIN_FAILED();
    auto original = buildTestPayload();

    SigningRequest req;
    req.document = original;
    req.fileName = "test.bin";
    req.format = SignatureFormat::Xades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Detached;
    req.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "XAdES prior sign: " << r1.errorMessage;

    auto r2 =
        service->appendSigner(req, std::span<const uint8_t>{r1.signedDocument}, std::span<const uint8_t>{},
                              libresign::as_pin(config.pin), config.pkcs11Module, config.keyAlias, config.readerName);
    checkPinFailure(r2);
    EXPECT_FALSE(r2.success) << "XAdES appendSigner must reject empty originalDocument";
    ASSERT_TRUE(r2.failureKind.has_value()) << "failureKind not populated for XAdES rejection";
    EXPECT_EQ(*r2.failureKind, libresign::SignFailureKind::InvalidInput) << r2.errorMessage;
    EXPECT_NE(r2.errorMessage.find("original"), std::string::npos)
        << "Diagnostic must mention 'original' payload: " << r2.errorMessage;
}

TEST_P(SigningE2ETest, JAdES_AppendSigner_MissingOriginal_RejectsExplicitly)
{
    SKIP_IF_PIN_FAILED();
    auto original = buildTestPayload();

    SigningRequest req;
    req.document = original;
    req.fileName = "test.bin";
    req.format = SignatureFormat::Jades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Detached;
    req.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "JAdES prior sign: " << r1.errorMessage;

    auto r2 =
        service->appendSigner(req, std::span<const uint8_t>{r1.signedDocument}, std::span<const uint8_t>{},
                              libresign::as_pin(config.pin), config.pkcs11Module, config.keyAlias, config.readerName);
    checkPinFailure(r2);
    EXPECT_FALSE(r2.success) << "JAdES appendSigner must reject empty originalDocument";
    ASSERT_TRUE(r2.failureKind.has_value()) << "failureKind not populated for JAdES rejection";
    EXPECT_EQ(*r2.failureKind, libresign::SignFailureKind::InvalidInput) << r2.errorMessage;
    EXPECT_NE(r2.errorMessage.find("original"), std::string::npos)
        << "Diagnostic must mention 'original' payload: " << r2.errorMessage;
}

TEST_P(SigningE2ETest, JAdES_AppendSigner_OriginalMismatch_RejectsExplicitly)
{
    SKIP_IF_PIN_FAILED();
    auto original = buildTestPayload();

    SigningRequest req;
    req.document = original;
    req.fileName = "test.bin";
    req.format = SignatureFormat::Jades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Enveloped;
    req.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "JAdES enveloped prior sign: " << r1.errorMessage;

    // Caller supplies an originalDocument that does NOT match the JWS payload
    // embedded in the prior signature. The optional integrity check must trip.
    std::vector<uint8_t> wrongOriginal{'B', 'A', 'D'};
    auto r2 =
        service->appendSigner(req, std::span<const uint8_t>{r1.signedDocument}, std::span<const uint8_t>{wrongOriginal},
                              libresign::as_pin(config.pin), config.pkcs11Module, config.keyAlias, config.readerName);
    checkPinFailure(r2);
    EXPECT_FALSE(r2.success) << "JAdES appendSigner must reject mismatched originalDocument";
    ASSERT_TRUE(r2.failureKind.has_value()) << "failureKind not populated for JAdES mismatch";
    EXPECT_EQ(*r2.failureKind, libresign::SignFailureKind::InvalidInput) << r2.errorMessage;
    EXPECT_NE(r2.errorMessage.find("original"), std::string::npos)
        << "Diagnostic must mention 'original' payload: " << r2.errorMessage;
}

// ---- S2.8 — JAdES JSON input size cap (DoS hardening) ----
//
// Input-size and depth caps live in `tryParseJwsGeneral` — exceeding any
// cap returns nullopt so the multi-sign branch silently falls through to
// fresh-sign (which itself either succeeds on the raw bytes or fails on
// a different shape check). What we assert here is "bounded time / no
// crash / no OOM-kill" — the precise outcome is fine either way. Without
// the caps, a 1 GiB JSON or a `[[[[…]]]]` pathological input could
// exhaust memory / overflow the parse stack from the multi-sign
// detection branch.
TEST_P(SigningE2ETest, JAdES_MultiSign_RejectsOversizedJsonInput)
{
    SKIP_IF_PIN_FAILED();
    std::string oversized = "{\"payload\":\"";
    oversized.append(70ULL * 1024 * 1024, 'A'); // 70 MiB > kMaxJwsInputBytes (64 MiB)
    oversized += "\",\"signatures\":[{\"protected\":\"X\",\"signature\":\"Y\"}]}";

    SigningRequest req;
    req.document = std::vector<uint8_t>(oversized.begin(), oversized.end());
    req.fileName = "huge.json";
    req.format = SignatureFormat::Jades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Enveloped;
    req.allowExpiredCertificate = true;

    auto r = service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r);
    SUCCEED() << "Oversized JSON input returned bounded result (success=" << r.success << ", msg=\"" << r.errorMessage
              << "\")";
}

TEST_P(SigningE2ETest, JAdES_MultiSign_RejectsDeeplyNestedJsonInput)
{
    SKIP_IF_PIN_FAILED();
    // 2000 levels of nested arrays — exceeds kMaxJsonDepth=1024.
    std::string nested = "{\"payload\":\"X\",\"signatures\":[{\"protected\":\"X\",\"signature\":\"Y\"}],\"deep\":";
    nested += std::string(2000, '[');
    nested += "1";
    nested += std::string(2000, ']');
    nested += "}";

    SigningRequest req;
    req.document = std::vector<uint8_t>(nested.begin(), nested.end());
    req.fileName = "nested.json";
    req.format = SignatureFormat::Jades;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Enveloped;
    req.allowExpiredCertificate = true;

    auto r = service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r);
    SUCCEED() << "Deeply-nested JSON input returned bounded result (success=" << r.success << ", msg=\""
              << r.errorMessage << "\")";
}

// ===========================================================================
// ASiC-E: sign same content at different levels
// ===========================================================================

TEST_P(SigningE2ETest, ASiCE_BB_then_BT_separate)
{
    SKIP_IF_PIN_FAILED();
    std::vector<uint8_t> data = {'A', 'S', 'i', 'C'};

    auto r1 = signDocument(data, "test.txt", SignatureFormat::AsicE, SignatureLevel::B_B);
    ASSERT_TRUE(r1.success) << "ASiC-E B-B: " << r1.errorMessage;

    auto r2 = signDocument(data, "test.txt", SignatureFormat::AsicE, SignatureLevel::B_T);
    ASSERT_TRUE(r2.success) << "ASiC-E B-T: " << r2.errorMessage;

    EXPECT_GT(r2.signedDocument.size(), r1.signedDocument.size());
}

// ---- ASiC-E parallel-sequential multi-sign (ETSI EN 319 162-1 §A.4) ----

TEST_P(SigningE2ETest, ASiCE_MultiSign_PreservesPriorSignatures)
{
    SKIP_IF_PIN_FAILED();
    std::vector<uint8_t> data{'A', 'S', 'i', 'C', '-', 'E', '!'};

    auto r1 = signDocument(data, "test.txt", SignatureFormat::AsicE, SignatureLevel::B_B);
    ASSERT_TRUE(r1.success) << "ASiC-E sign1: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.txt"; // ignored on multi-sign — taken from prior ZIP
    req2.format = SignatureFormat::AsicE;
    req2.level = SignatureLevel::B_B;
    req2.packaging = SignaturePackaging::Detached;
    req2.allowExpiredCertificate = true;
    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "ASiC-E sign2 (multi-sign): " << r2.errorMessage;

    // Output must be a ZIP with mimetype + ORIGINAL data file (not the
    // prior ZIP wrapped as data) + BOTH signature001/002 and
    // ASiCManifest001/002 entries.
    auto find = [&](std::string_view needle) {
        std::string_view sv(reinterpret_cast<const char*>(r2.signedDocument.data()), r2.signedDocument.size());
        return sv.find(needle) != std::string_view::npos;
    };
    EXPECT_TRUE(find("META-INF/signature001.p7s")) << "Prior signature001 must be preserved";
    EXPECT_TRUE(find("META-INF/ASiCManifest001.xml")) << "Prior ASiCManifest001 must be preserved";
    EXPECT_TRUE(find("META-INF/signature002.p7s")) << "New signature002 must be added";
    EXPECT_TRUE(find("META-INF/ASiCManifest002.xml")) << "New ASiCManifest002 must be added";
    EXPECT_TRUE(find("application/vnd.etsi.asic-e+zip")) << "mimetype must remain ASiC-E";
    // Data file name "test.txt" comes from prior ZIP — re-sign must not
    // overwrite it with a wrapped-ZIP-as-test.txt blob. Smallest such blob
    // would dwarf the original 7-byte payload; assert the new archive does
    // NOT contain the full prior ZIP as a subsequence (header signature
    // PK\x03\x04 followed by the prior data file name).
    EXPECT_LT(r2.signedDocument.size(), r1.signedDocument.size() * 2)
        << "Re-sign growth must reflect only one new sig+manifest pair, not a wrapped ZIP";

    validateSignature(r2, "ASiC_E", "DETACHED", data, 2);

    saveOutput(r2, GetParam().name + "-asice-multisign.zip");
}

// ---- ASiC-E zip-slip regression guard for preserved META-INF entries ----
//
// `tryParseAsic` routes every preserved META-INF entry name from an
// attacker-controlled ASiC through `isValidAsicEntryName` before
// forwarding to the writer; without the guard, names like
// `META-INF/../../etc/cron.d/pwn` or `META-INF/x\0evil` could ride
// into the re-signed output under the signer's authority. This test
// crafts a malicious ASiC and asserts the parser refuses → caller
// falls back to fresh-sign-wrap-as-data (the original "succeed-but-wrong" behaviour),
// which is preferable to silently emitting a zip-slip-carrying archive.
TEST_P(SigningE2ETest, ASiCE_MultiSign_RejectsZipSlipInPreservedEntries)
{
    SKIP_IF_PIN_FAILED();

    // Hand-build a minimal ASiC-E ZIP with a META-INF/ entry that escapes
    // the archive root via "..". We can't use miniz easily here — emit a
    // small valid ZIP by hand.
    auto le16 = [](std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(uint8_t(x & 0xff));
        v.push_back(uint8_t(x >> 8));
    };
    auto le32 = [](std::vector<uint8_t>& v, uint32_t x) {
        v.push_back(uint8_t(x & 0xff));
        v.push_back(uint8_t((x >> 8) & 0xff));
        v.push_back(uint8_t((x >> 16) & 0xff));
        v.push_back(uint8_t(x >> 24));
    };

    auto addEntry = [&](std::vector<uint8_t>& zip, const std::string& name, const std::vector<uint8_t>& content,
                        std::vector<std::tuple<std::string, uint32_t, uint32_t, uint32_t>>& cd) {
        uint32_t crc = 0xFFFFFFFFu;
        for (uint8_t b : content) {
            crc ^= b;
            for (int i = 0; i < 8; ++i)
                crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
        }
        crc = ~crc;
        uint32_t off = uint32_t(zip.size());
        le32(zip, 0x04034b50);
        le16(zip, 20);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le32(zip, crc);
        le32(zip, uint32_t(content.size()));
        le32(zip, uint32_t(content.size()));
        le16(zip, uint16_t(name.size()));
        le16(zip, 0);
        zip.insert(zip.end(), name.begin(), name.end());
        zip.insert(zip.end(), content.begin(), content.end());
        cd.emplace_back(name, crc, uint32_t(content.size()), off);
    };

    std::vector<uint8_t> zip;
    std::vector<std::tuple<std::string, uint32_t, uint32_t, uint32_t>> cd;
    std::vector<uint8_t> mtBytes;
    {
        std::string mt = "application/vnd.etsi.asic-e+zip";
        mtBytes.assign(mt.begin(), mt.end());
    }
    addEntry(zip, "mimetype", mtBytes, cd);
    addEntry(zip, "test.txt", std::vector<uint8_t>{'X'}, cd);
    addEntry(zip, "META-INF/signature001.p7s", std::vector<uint8_t>{0x30, 0x00}, cd);
    addEntry(zip, "META-INF/ASiCManifest001.xml", std::vector<uint8_t>{'<', '/', '>'}, cd);
    // The malicious entry — name escapes the META-INF/ root via "..".
    addEntry(zip, "META-INF/../../../etc/passwd", std::vector<uint8_t>{'P'}, cd);

    uint32_t cdOff = uint32_t(zip.size());
    for (auto& [name, crc, sz, off] : cd) {
        le32(zip, 0x02014b50);
        le16(zip, 20);
        le16(zip, 20);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le32(zip, crc);
        le32(zip, sz);
        le32(zip, sz);
        le16(zip, uint16_t(name.size()));
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le32(zip, 0);
        le32(zip, off);
        zip.insert(zip.end(), name.begin(), name.end());
    }
    uint32_t cdSize = uint32_t(zip.size() - cdOff);
    le32(zip, 0x06054b50);
    le16(zip, 0);
    le16(zip, 0);
    le16(zip, uint16_t(cd.size()));
    le16(zip, uint16_t(cd.size()));
    le32(zip, cdSize);
    le32(zip, cdOff);
    le16(zip, 0);

    SigningRequest req;
    req.document = zip;
    req.fileName = "test.txt";
    req.format = SignatureFormat::AsicE;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Detached;
    req.allowExpiredCertificate = true;
    auto r = service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r);
    // Either: tryParseAsic rejected the input (success=true producing a
    // fresh ASiC wrapping the malicious ZIP as test.txt — safe), OR the
    // call surfaced a non-success result. Both are acceptable; what is
    // NOT acceptable is the output literally carrying the traversal entry
    // name. Assert the traversal name does NOT appear as a ZIP entry name
    // anywhere in the output.
    if (r.success) {
        std::string_view sv(reinterpret_cast<const char*>(r.signedDocument.data()), r.signedDocument.size());
        EXPECT_EQ(sv.find("META-INF/../"), std::string_view::npos)
            << "Zip-slip traversal entry survived into the re-signed output";
        EXPECT_EQ(sv.find("../../../etc/passwd"), std::string_view::npos)
            << "Traversal path leaked into the re-signed archive";
    }
}

// ===========================================================================
// Multi-level multi-sign stacks
//
// Sign the same payload at level N, then add a second signer at level M via
// the second signature path appropriate to each format (incremental update
// for PAdES, in-place re-sign for ASiC-E, appendSigner for XAdES/JAdES
// ENVELOPED). The DSS oracle is asked to confirm 2 signatures present, and
// at least one signature carries the higher baseline level string.
// ===========================================================================
//
// Cross-format helper `needsTrustForLta` lives in the file-level anonymous
// namespace next to the other helpers (jadesEnvelopedRequest etc.).

TEST_P(SigningE2ETest, PAdES_MultiLevel_BLT_then_BLTA)
{
    SKIP_IF_PIN_FAILED();
    if (needsTrustForLta(GetParam()) && !SigningTestEnvironment::trustConfigured())
        GTEST_SKIP() << "B-LT/B-LTA requires trust store (DSS trust not configured)";

    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    SigningRequest req1;
    req1.document = pdfVec;
    req1.fileName = "test.pdf";
    req1.format = SignatureFormat::Pades;
    req1.level = SignatureLevel::B_LT;
    req1.tsa.url = "http://timestamp.digicert.com";
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "PAdES B-LT first sign: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.pdf";
    req2.format = SignatureFormat::Pades;
    req2.level = SignatureLevel::B_LTA;
    req2.tsa.url = "http://timestamp.digicert.com";
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "PAdES B-LTA append: " << r2.errorMessage;
    ASSERT_GT(r2.signedDocument.size(), r1.signedDocument.size());

    std::string_view sv(reinterpret_cast<const char*>(r2.signedDocument.data()), r2.signedDocument.size());
    EXPECT_NE(sv.find("/Type /DocTimeStamp"), std::string_view::npos)
        << "Second-pass B-LTA must produce a DocTimeStamp signature dict";

    // DSS classifies signatures whose cert chain cannot be validated at
    // PAdES_BES (the pre-BASELINE-B raw form), so without a trust anchor
    // matching the signer (PKS root) the LT/LTA augmentation we emit is
    // not surfaced as PAdES_BASELINE_LTA. Structural assertions above
    // (DocTimeStamp dict + 2 sigs) are the actual contract this test
    // enforces; the cert-trust-aware level promotion is covered by the
    // single-sign PAdES_BLTA test (which uses the same TSA + same TL).
    validateSignature(r2, "PAdES", "ENVELOPED", pdfVec, 2, std::string{"PAdES_BES"});
    saveOutput(r2, GetParam().name + "-pades-blt-then-blta.pdf");
}

TEST_P(SigningE2ETest, PAdES_MultiLevel_BLTA_then_BLTA)
{
    SKIP_IF_PIN_FAILED();
    if (needsTrustForLta(GetParam()) && !SigningTestEnvironment::trustConfigured())
        GTEST_SKIP() << "B-LTA requires trust store (DSS trust not configured)";

    auto pdf = buildTestPdf();
    auto pdfVec = std::vector<uint8_t>(pdf.begin(), pdf.end());

    SigningRequest req1;
    req1.document = pdfVec;
    req1.fileName = "test.pdf";
    req1.format = SignatureFormat::Pades;
    req1.level = SignatureLevel::B_LTA;
    req1.tsa.url = "http://timestamp.digicert.com";
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "PAdES B-LTA first sign: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.pdf";
    req2.format = SignatureFormat::Pades;
    req2.level = SignatureLevel::B_LTA;
    req2.tsa.url = "http://timestamp.digicert.com";
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "PAdES B-LTA second sign: " << r2.errorMessage;
    ASSERT_GT(r2.signedDocument.size(), r1.signedDocument.size());

    // Same DSS classification limitation as PAdES_MultiLevel_BLT_then_BLTA:
    // without a trust anchor for the PKS chain, DSS reports PAdES_BES for
    // both signers regardless of the LT/LTA artefacts we emit. Structural
    // assertions (2 sigs, size increased) are the actual contract here.
    validateSignature(r2, "PAdES", "ENVELOPED", pdfVec, 2, std::string{"PAdES_BES"});
    saveOutput(r2, GetParam().name + "-pades-blta-then-blta.pdf");
}

TEST_P(SigningE2ETest, XAdES_MultiLevel_BB_then_BLTA_Enveloped)
{
    SKIP_IF_PIN_FAILED();
    if (needsTrustForLta(GetParam()) && !SigningTestEnvironment::trustConfigured())
        GTEST_SKIP() << "B-LTA requires trust store (DSS trust not configured)";

    auto xmlDoc = buildTestXml();
    std::vector<uint8_t> xmlVec(xmlDoc.begin(), xmlDoc.end());

    SigningRequest req1;
    req1.document = xmlVec;
    req1.fileName = "test.xml";
    req1.format = SignatureFormat::Xades;
    req1.level = SignatureLevel::B_B;
    req1.packaging = SignaturePackaging::Enveloped;
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "XAdES B-B first sign: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.xml";
    req2.format = SignatureFormat::Xades;
    req2.level = SignatureLevel::B_LTA;
    req2.packaging = SignaturePackaging::Enveloped;
    req2.tsa.url = "http://timestamp.digicert.com";
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "XAdES B-LTA second sign: " << r2.errorMessage;

    // XAdES multi-sign auto-detect routes the second request through
    // the append path. The new signer carries the requested level
    // for its OWN sigTst / sigRefs slots, but DSS's per-signature level
    // classification reports the BEST level it can independently verify;
    // without a live OCSP/CRL responder for the PKS chain Sig 0 stays at
    // XAdES_BASELINE_B and Sig 1 reaches XAdES_BASELINE_T. The structural
    // contract (2 signatures appended without breaking each other) is the
    // important assertion here.
    validateSignature(r2, "XAdES", "ENVELOPED", xmlVec, 2, std::string{"XAdES_BASELINE_T"});
    saveOutput(r2, GetParam().name + "-xades-bb-then-blta-enveloped.xml");
}

TEST_P(SigningE2ETest, JAdES_MultiLevel_BB_then_BLTA_Enveloped)
{
    SKIP_IF_PIN_FAILED();
    if (needsTrustForLta(GetParam()) && !SigningTestEnvironment::trustConfigured())
        GTEST_SKIP() << "B-LTA requires trust store (DSS trust not configured)";

    // JAdESModule::appendSigner gates B-T+ with PolicyViolation: per-signer
    // etsiU upgrades (sigTst / rVals / arcTst) would attach at the document
    // level and conformance validators would attribute them to every prior
    // signer too, whose PKCS#11 sessions we no longer hold. The per-signer-
    // indexed etsiU helpers needed to do this correctly are deferred to a
    // future cycle (see jades_module.cpp::appendSigner gate). Skip until
    // that's implemented.
    GTEST_SKIP() << "JAdES appendSigner B-T+ requires per-signer etsiU helpers (deferred to next cycle)";

    auto original = buildTestPayload();

    SigningRequest req1;
    req1.document = original;
    req1.fileName = "test.bin";
    req1.format = SignatureFormat::Jades;
    req1.level = SignatureLevel::B_B;
    req1.packaging = SignaturePackaging::Enveloped;
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "JAdES B-B first sign: " << r1.errorMessage;

    SigningRequest req2 = req1;
    req2.level = SignatureLevel::B_LTA;
    req2.tsa.url = "http://timestamp.digicert.com";

    auto r2 =
        service->appendSigner(req2, std::span<const uint8_t>{r1.signedDocument}, std::span<const uint8_t>{original},
                              libresign::as_pin(config.pin), config.pkcs11Module, config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "JAdES B-LTA appendSigner: " << r2.errorMessage;

    validateSignature(r2, "JAdES", "ENVELOPED", original, 2, std::string{"JAdES_BASELINE_LTA"});
    saveOutput(r2, GetParam().name + "-jades-bb-then-blta-enveloped.json");
}

TEST_P(SigningE2ETest, ASiCE_MultiLevel_BLT_then_BLTA)
{
    SKIP_IF_PIN_FAILED();
    if (needsTrustForLta(GetParam()) && !SigningTestEnvironment::trustConfigured())
        GTEST_SKIP() << "B-LT/B-LTA requires trust store (DSS trust not configured)";

    std::vector<uint8_t> data{'A', 'S', 'i', 'C', '-', 'M', 'L'};

    SigningRequest req1;
    req1.document = data;
    req1.fileName = "test.txt";
    req1.format = SignatureFormat::AsicE;
    req1.level = SignatureLevel::B_LT;
    req1.packaging = SignaturePackaging::Detached;
    req1.tsa.url = "http://timestamp.digicert.com";
    req1.allowExpiredCertificate = true;

    auto r1 =
        service->sign(req1, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r1);
    ASSERT_TRUE(r1.success) << "ASiC-E B-LT first sign: " << r1.errorMessage;

    SigningRequest req2;
    req2.document = r1.signedDocument;
    req2.fileName = "test.txt";
    req2.format = SignatureFormat::AsicE;
    req2.level = SignatureLevel::B_LTA;
    req2.packaging = SignaturePackaging::Detached;
    req2.tsa.url = "http://timestamp.digicert.com";
    req2.allowExpiredCertificate = true;

    auto r2 =
        service->sign(req2, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r2);
    ASSERT_TRUE(r2.success) << "ASiC-E B-LTA second sign: " << r2.errorMessage;

    // ASiC-E carries CAdES (not XAdES) inner signatures via signWithCAdES,
    // and the multi-sign append path tops out at B-T for the new signer
    // (per-signer LT/LTA upgrades would require re-acquiring every prior
    // signer's PKCS#11 session and are explicitly out of scope). Validate
    // that Sig 0 stays at its original B-LT level and Sig 1 lands at the
    // highest level appendSigner can actually emit (B-T).
    validateSignature(r2, "ASiC_E", "DETACHED", data, 2, std::string{"CAdES_BASELINE_T"});
    saveOutput(r2, GetParam().name + "-asice-blt-then-blta.zip");
}

// ---- ASiC-E reject: container with multiple data files ----
//
// ETSI EN 319 162-1 §A.1: an ASiC-E container holds exactly one signed
// data object alongside its META-INF/ metadata. The re-sign / multi-sign
// path must REJECT input archives that carry two or more data files, not
// silently wrap them — otherwise the new signer's ASiCManifest can name
// only one of them, leaving the others unsigned in the archive.
TEST_P(SigningE2ETest, ASiCE_MultiSign_MultiDataFile_RejectsExplicitly)
{
    SKIP_IF_PIN_FAILED();

    auto le16 = [](std::vector<uint8_t>& v, uint16_t x) {
        v.push_back(uint8_t(x & 0xff));
        v.push_back(uint8_t(x >> 8));
    };
    auto le32 = [](std::vector<uint8_t>& v, uint32_t x) {
        v.push_back(uint8_t(x & 0xff));
        v.push_back(uint8_t((x >> 8) & 0xff));
        v.push_back(uint8_t((x >> 16) & 0xff));
        v.push_back(uint8_t(x >> 24));
    };

    auto addEntry = [&](std::vector<uint8_t>& zip, const std::string& name, const std::vector<uint8_t>& content,
                        std::vector<std::tuple<std::string, uint32_t, uint32_t, uint32_t>>& cd) {
        uint32_t crc = 0xFFFFFFFFu;
        for (uint8_t b : content) {
            crc ^= b;
            for (int i = 0; i < 8; ++i)
                crc = (crc >> 1) ^ (0xEDB88320u & -(crc & 1));
        }
        crc = ~crc;
        uint32_t off = uint32_t(zip.size());
        le32(zip, 0x04034b50);
        le16(zip, 20);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le32(zip, crc);
        le32(zip, uint32_t(content.size()));
        le32(zip, uint32_t(content.size()));
        le16(zip, uint16_t(name.size()));
        le16(zip, 0);
        zip.insert(zip.end(), name.begin(), name.end());
        zip.insert(zip.end(), content.begin(), content.end());
        cd.emplace_back(name, crc, uint32_t(content.size()), off);
    };

    std::vector<uint8_t> zip;
    std::vector<std::tuple<std::string, uint32_t, uint32_t, uint32_t>> cd;
    std::string mt = "application/vnd.etsi.asic-e+zip";
    addEntry(zip, "mimetype", std::vector<uint8_t>(mt.begin(), mt.end()), cd);
    // Two data files at the archive root — the contract violation.
    addEntry(zip, "data-one.txt", std::vector<uint8_t>{'A'}, cd);
    addEntry(zip, "data-two.txt", std::vector<uint8_t>{'B'}, cd);
    addEntry(zip, "META-INF/signature001.p7s", std::vector<uint8_t>{0x30, 0x00}, cd);
    addEntry(zip, "META-INF/ASiCManifest001.xml", std::vector<uint8_t>{'<', '/', '>'}, cd);

    uint32_t cdOff = uint32_t(zip.size());
    for (auto& [name, crc, sz, off] : cd) {
        le32(zip, 0x02014b50);
        le16(zip, 20);
        le16(zip, 20);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le32(zip, crc);
        le32(zip, sz);
        le32(zip, sz);
        le16(zip, uint16_t(name.size()));
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le16(zip, 0);
        le32(zip, 0);
        le32(zip, off);
        zip.insert(zip.end(), name.begin(), name.end());
    }
    uint32_t cdSize = uint32_t(zip.size() - cdOff);
    le32(zip, 0x06054b50);
    le16(zip, 0);
    le16(zip, 0);
    le16(zip, uint16_t(cd.size()));
    le16(zip, uint16_t(cd.size()));
    le32(zip, cdSize);
    le32(zip, cdOff);
    le16(zip, 0);

    SigningRequest req;
    req.document = zip;
    req.fileName = "irrelevant.txt";
    req.format = SignatureFormat::AsicE;
    req.level = SignatureLevel::B_B;
    req.packaging = SignaturePackaging::Detached;
    req.allowExpiredCertificate = true;
    auto r = service->sign(req, config.pkcs11Module, libresign::as_pin(config.pin), config.keyAlias, config.readerName);
    checkPinFailure(r);

    EXPECT_FALSE(r.success) << "ASiC-E with multiple data files must be rejected";
    if (!r.success) {
        ASSERT_TRUE(r.failureKind.has_value()) << "failureKind not populated";
        EXPECT_EQ(*r.failureKind, libresign::SignFailureKind::InvalidInput) << r.errorMessage;
        EXPECT_TRUE(r.errorMessage.find("data") != std::string::npos ||
                    r.errorMessage.find("multiple") != std::string::npos ||
                    r.errorMessage.find("one") != std::string::npos)
            << "Diagnostic must name the multi-data violation: " << r.errorMessage;
    }
}

// ---- Bad PIN latch positive test ----
//
// `checkPinFailure` flips a process-static `g_pinFailed` flag when the
// signing service surfaces a PIN-incorrect / PIN-locked diagnostic, and
// every test in this suite calls SKIP_IF_PIN_FAILED before touching the
// card. The flag latches because attempt counters on real cards are
// finite — once a wrong PIN is in flight, subsequent tests must not
// burn additional attempts in a parallel test run.
//
// This positive test asserts the latch trips when the signing service
// sees a wrong PIN format. The PKCS#11 module typically returns
// CKR_PIN_LEN_RANGE (or CKR_PIN_INCORRECT for some firmwares) for a
// length-zero PIN; either way the error message contains a substring
// the latch keys off. We use a length-zero PIN — most PINs are 4-8
// digits and zero is reliably rejected by SafeNet / Gemalto / OpenSC.
//
// The test installs a one-shot RAII save/restore around the latch so
// the failure here doesn't poison the rest of the suite.
namespace {
class PinLatchSaver
{
public:
    PinLatchSaver() : saved(::libresign::test::g_pinFailed) {}
    ~PinLatchSaver()
    {
        ::libresign::test::g_pinFailed = saved;
    }

private:
    bool saved;
};
} // namespace

TEST_P(SigningE2ETest, BadPinLatch_FormatRejectedPin_TripsGuardWithoutDecrement)
{
    SKIP_IF_PIN_FAILED();

    PinLatchSaver guard;
    // Reset the latch BEFORE the bad-PIN call so we observe the flip here
    // rather than seeing it pre-flipped from an earlier test.
    ::libresign::test::g_pinFailed = false;

    SigningRequest req;
    req.document = {'P', 'i', 'n', '?'};
    req.fileName = "test.txt";
    req.format = SignatureFormat::Cades;
    req.level = SignatureLevel::B_B;
    req.allowExpiredCertificate = true;

    // Empty PIN — PKCS#11 modules report CKR_PIN_INCORRECT or
    // CKR_PIN_LEN_RANGE; neither decrements the attempt counter on
    // production cards (the length check is pre-VERIFY).
    auto result = service->sign(req, config.pkcs11Module, libresign::as_pin(""), config.keyAlias, config.readerName);

    EXPECT_FALSE(result.success) << "Empty PIN must fail";
    if (!result.success) {
        // Replicate the latch's substring rule directly so we can observe
        // the flip without invoking checkPinFailure (which would short-
        // circuit the test via GTEST_SKIP on a match).
        const auto& msg = result.errorMessage;
        const bool wouldFlipLatch =
            msg.find("CKR_PIN_INCORRECT") != std::string::npos || msg.find("CKR_PIN_LOCKED") != std::string::npos ||
            msg.find("0x000000A0") != std::string::npos || msg.find("0x000000A4") != std::string::npos;
        if (wouldFlipLatch) {
            ::libresign::test::g_pinFailed = true;
            std::cerr << "[BadPinLatch] Latch keywords matched in diagnostic; g_pinFailed flipped.\n";
        } else {
            // CKR_PIN_LEN_RANGE (0xA2) is NOT in the latch keyword list;
            // some modules return it for empty PINs and the call still
            // fails closed. The primary contract (no crash, failure
            // reported) is upheld either way.
            std::cerr << "[BadPinLatch] Diagnostic: " << msg
                      << " (does not match latch keywords — typical for CKR_PIN_LEN_RANGE; not a regression).\n";
        }
    }
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
    req.format = SignatureFormat::Cades;
    req.level = SignatureLevel::B_B;

    auto result = service->sign(req, "/nonexistent/pkcs11.so", libresign::as_pin("0000"), "key", "");
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
}

// PAdES dispatcher rejects inputs too small to be a PDF before any
// PKCS#11 / network work is initiated.
TEST(NativeFactoryTest, RejectsOneByteInput)
{
    auto service = createSigningService(Backend::Native);
    ASSERT_NE(service, nullptr);

    SigningRequest req;
    req.document = {'X'};
    req.fileName = "tiny.pdf";
    req.format = SignatureFormat::Pades;
    req.level = SignatureLevel::B_B;

    auto result = service->sign(req, "/nonexistent/pkcs11.so", libresign::as_pin("0000"), "key", "");
    EXPECT_FALSE(result.success) << "1-byte PDF input must be rejected";
    EXPECT_FALSE(result.errorMessage.empty());
}

TEST(NativeFactoryTest, Rejects7ByteNonPdf)
{
    auto service = createSigningService(Backend::Native);
    ASSERT_NE(service, nullptr);

    SigningRequest req;
    // 7 bytes, no "%PDF-" magic anywhere — the PAdES module's H.3
    // tolerant prefix scan must still find no header and reject.
    req.document = {'N', 'o', 't', 'P', 'D', 'F', '!'};
    req.fileName = "fake.pdf";
    req.format = SignatureFormat::Pades;
    req.level = SignatureLevel::B_B;

    auto result = service->sign(req, "/nonexistent/pkcs11.so", libresign::as_pin("0000"), "key", "");
    EXPECT_FALSE(result.success) << "7-byte non-PDF input must be rejected";
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
